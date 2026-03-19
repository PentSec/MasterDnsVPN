# MasterDnsVPN
# Author: MasterkinG32
# Github: https://github.com/masterking32
# Year: 2026

import base64
import json
import os
import time
from collections import OrderedDict


class DnsResponseCache:
    def __init__(
        self,
        max_records: int = 2000,
        ttl_seconds: float = 3600.0,
        file_path: str = "",
        persist_to_file: bool = False,
    ) -> None:
        self.max_records = max(1, int(max_records))
        self.ttl_seconds = max(1.0, float(ttl_seconds))
        self.file_path = str(file_path or "").strip()
        self.persist_to_file = bool(persist_to_file and self.file_path)
        self._cache = OrderedDict()
        self._dirty = False

    def _entry_expires_at(self, entry: dict) -> float:
        last_used_at = float(entry.get("last_used_at", 0.0) or 0.0)
        if last_used_at <= 0:
            last_used_at = float(entry.get("expires_at", 0.0) or 0.0) - self.ttl_seconds
        return last_used_at + self.ttl_seconds

    @staticmethod
    def normalize_query_key(raw_query: bytes) -> bytes:
        if not raw_query or len(raw_query) < 12:
            return b""
        try:
            qdcount = int.from_bytes(raw_query[4:6], "big")
            if qdcount < 1:
                return b""

            offset = 12
            labels = []
            label_loops = 0
            while True:
                if offset >= len(raw_query):
                    return b""
                length = raw_query[offset]
                offset += 1
                if length == 0:
                    break
                if length & 0xC0 or offset + length > len(raw_query):
                    return b""
                labels.append(raw_query[offset : offset + length].lower())
                offset += length
                label_loops += 1
                if label_loops > 127:
                    return b""

            if offset + 4 > len(raw_query):
                return b""

            qtype = raw_query[offset : offset + 2]
            qclass = raw_query[offset + 2 : offset + 4]
            qname = b".".join(labels)
            return qtype + qclass + b"\x00" + qname
        except Exception:
            return b""

    @staticmethod
    def patch_query_id(raw_response: bytes, query_id: bytes) -> bytes:
        if not raw_response or len(raw_response) < 2 or len(query_id) != 2:
            return raw_response or b""
        return query_id + raw_response[2:]

    @staticmethod
    def patch_response_for_query(raw_response: bytes, raw_query: bytes) -> bytes:
        if not raw_response:
            return b""
        if not raw_query or len(raw_query) < 2:
            return raw_response

        patched = bytearray(raw_response)
        patched[:2] = raw_query[:2]
        if len(patched) >= 4 and len(raw_query) >= 4:
            query_flags = int.from_bytes(raw_query[2:4], "big")
            response_flags = int.from_bytes(patched[2:4], "big")
            response_flags = (response_flags & ~0x0110) | (query_flags & 0x0110)
            patched[2:4] = response_flags.to_bytes(2, "big")
        return bytes(patched)

    def _evict_if_needed(self) -> None:
        while len(self._cache) > self.max_records:
            self._cache.popitem(last=False)

    def _purge_expired(self, now: float | None = None) -> None:
        now = time.time() if now is None else now
        expired = [
            key
            for key, entry in self._cache.items()
            if self._entry_expires_at(entry) <= now
        ]
        for key in expired:
            self._cache.pop(key, None)

    def get(
        self, cache_key: bytes, query_id: bytes = b"", raw_query: bytes = b""
    ) -> bytes:
        if not cache_key:
            return b""
        self._purge_expired()
        entry = self._cache.pop(cache_key, None)
        if not entry:
            return b""
        now = time.time()
        previous_last_used = float(entry.get("last_used_at", 0.0) or 0.0)
        if now - previous_last_used >= 1.0:
            entry["last_used_at"] = now
            self._dirty = True
        self._cache[cache_key] = entry
        response = bytes(entry.get("response", b"") or b"")
        if raw_query:
            return self.patch_response_for_query(response, raw_query)
        return self.patch_query_id(response, query_id)

    def set(self, cache_key: bytes, raw_response: bytes) -> None:
        if not cache_key or not raw_response or len(raw_response) < 2:
            return
        now = time.time()
        normalized_response = b"\x00\x00" + raw_response[2:]
        self._cache.pop(cache_key, None)
        self._cache[cache_key] = {
            "response": normalized_response,
            "last_used_at": now,
        }
        self._evict_if_needed()
        self._dirty = True

    def load_from_file(self) -> None:
        if not self.persist_to_file or not os.path.isfile(self.file_path):
            return
        try:
            with open(self.file_path, "r", encoding="utf-8") as fh:
                payload = json.load(fh)
            if not isinstance(payload, list):
                return
            now = time.time()
            self._cache.clear()
            for item in payload:
                if not isinstance(item, dict):
                    continue
                key_b64 = item.get("key")
                resp_b64 = item.get("response")
                last_used_at = float(item.get("last_used_at", 0.0) or 0.0)
                expires_at = float(item.get("expires_at", 0.0) or 0.0)
                if last_used_at <= 0.0 and expires_at > 0.0:
                    last_used_at = expires_at - self.ttl_seconds
                if (
                    not key_b64
                    or not resp_b64
                    or (last_used_at + self.ttl_seconds) <= now
                ):
                    continue
                try:
                    cache_key = base64.b64decode(key_b64)
                    response = base64.b64decode(resp_b64)
                except Exception:
                    continue
                if not cache_key or len(response) < 2:
                    continue
                self._cache[cache_key] = {
                    "response": response,
                    "last_used_at": last_used_at,
                }
            self._evict_if_needed()
            self._dirty = False
        except Exception:
            pass

    def save_to_file(self) -> None:
        if not self.persist_to_file or not self._dirty:
            return
        try:
            self._purge_expired()
            os.makedirs(os.path.dirname(self.file_path) or ".", exist_ok=True)
            payload = []
            for cache_key, entry in self._cache.items():
                payload.append(
                    {
                        "key": base64.b64encode(cache_key).decode("ascii"),
                        "response": base64.b64encode(
                            bytes(entry.get("response", b"") or b"")
                        ).decode("ascii"),
                        "last_used_at": float(entry.get("last_used_at", 0.0) or 0.0),
                    }
                )
            with open(self.file_path, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, ensure_ascii=True, separators=(",", ":"))
            self._dirty = False
        except Exception:
            pass

    def clear(self) -> None:
        self._cache.clear()
        self._dirty = False
