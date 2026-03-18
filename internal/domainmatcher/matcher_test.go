// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package domainmatcher

import (
	"testing"

	DnsParser "masterdnsvpn-go/internal/dnsparser"
	ENUMS "masterdnsvpn-go/internal/enums"
)

func TestMatcherReturnsNoDataForUnauthorizedDomain(t *testing.T) {
	matcher := New([]string{"a.com", "c.b.com", "cc.com"}, 3)

	decision := matcher.Match(litePacketWithQuestion("evil.com", ENUMS.DNSRecordTypeTXT))
	if decision.Action != ActionNoData {
		t.Fatalf("unexpected action: got=%d want=%d", decision.Action, ActionNoData)
	}
	if decision.Reason != "unauthorized-domain" {
		t.Fatalf("unexpected reason: got=%q", decision.Reason)
	}
}

func TestMatcherReturnsNoDataForExactAllowedDomain(t *testing.T) {
	matcher := New([]string{"a.com", "c.b.com", "cc.com"}, 3)

	decision := matcher.Match(litePacketWithQuestion("c.b.com", ENUMS.DNSRecordTypeTXT))
	if decision.Action != ActionNoData {
		t.Fatalf("unexpected action: got=%d want=%d", decision.Action, ActionNoData)
	}
	if decision.Reason != "missing-vpn-labels" {
		t.Fatalf("unexpected reason: got=%q", decision.Reason)
	}
}

func TestMatcherReturnsNoDataForUnsupportedType(t *testing.T) {
	matcher := New([]string{"a.com"}, 3)

	decision := matcher.Match(litePacketWithQuestion("vpn.a.com", ENUMS.DNSRecordTypeA))
	if decision.Action != ActionNoData {
		t.Fatalf("unexpected action: got=%d want=%d", decision.Action, ActionNoData)
	}
	if decision.Reason != "unsupported-qtype" {
		t.Fatalf("unexpected reason: got=%q", decision.Reason)
	}
}

func TestMatcherReturnsProcessForTXTWithExtraLabels(t *testing.T) {
	matcher := New([]string{"a.com", "c.b.com", "cc.com"}, 3)

	decision := matcher.Match(litePacketWithQuestion("vpn-01.c.b.com", ENUMS.DNSRecordTypeTXT))
	if decision.Action != ActionProcess {
		t.Fatalf("unexpected action: got=%d want=%d", decision.Action, ActionProcess)
	}
	if decision.BaseDomain != "c.b.com" {
		t.Fatalf("unexpected base domain: got=%q want=%q", decision.BaseDomain, "c.b.com")
	}
	if decision.Labels != "vpn-01" {
		t.Fatalf("unexpected labels: got=%q want=%q", decision.Labels, "vpn-01")
	}
}

func TestMatcherPreservesMultipleLabels(t *testing.T) {
	matcher := New([]string{"a.com"}, 3)

	decision := matcher.Match(litePacketWithQuestion("aa.bb.a.com", ENUMS.DNSRecordTypeTXT))
	if decision.Action != ActionProcess {
		t.Fatalf("unexpected action: got=%d want=%d", decision.Action, ActionProcess)
	}
	if decision.Labels != "aabb" {
		t.Fatalf("unexpected labels: got=%q want=%q", decision.Labels, "aabb")
	}
}

func TestMatcherRespectsBoundaryBeforeSuffix(t *testing.T) {
	matcher := New([]string{"a.com"}, 3)

	decision := matcher.Match(litePacketWithQuestion("notreallya.com", ENUMS.DNSRecordTypeTXT))
	if decision.Action != ActionNoData {
		t.Fatalf("unexpected action: got=%d want=%d", decision.Action, ActionNoData)
	}
	if decision.Reason != "unauthorized-domain" {
		t.Fatalf("unexpected reason: got=%q", decision.Reason)
	}
}

func litePacketWithQuestion(name string, qtype uint16) DnsParser.LitePacket {
	question := DnsParser.Question{
		Name:  name,
		Type:  qtype,
		Class: ENUMS.DNSQClassIN,
	}

	return DnsParser.LitePacket{
		Header:        DnsParser.Header{QDCount: 1},
		Questions:     []DnsParser.Question{question},
		FirstQuestion: question,
		HasQuestion:   true,
	}
}
