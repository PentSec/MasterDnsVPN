# MasterDnsVPN Server
# Author: MasterkinG32
# Github: https://github.com/masterking32
# Year: 2026

import asyncio
import time


class PingManager:
    def __init__(self, balancer, send_func):
        self.balancer = balancer
        self.send_func = send_func
        self.last_data_activity = time.time()
        self.last_ping_time = time.time()
        self.active_connections = 0

    def update_activity(self):
        self.last_data_activity = time.time()

    async def ping_loop(self):
        while True:
            await asyncio.sleep(0.1)

            if (
                self.active_connections == 0
                and self.last_data_activity + 20 < time.time()
            ):
                continue

            idle_time = time.time() - self.last_data_activity

            if idle_time >= 10.0:
                ping_interval = 3.0
            elif idle_time >= 5.0:
                ping_interval = 1.0
            else:
                ping_interval = 0.2

            if time.time() - self.last_ping_time < ping_interval:
                continue

            best_server = self.balancer.get_best_server()
            if best_server:
                await self.send_func(best_server, is_ping=True)
            self.last_ping_time = time.time()
