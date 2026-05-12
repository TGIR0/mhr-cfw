"""
dashboard_stream.py — Real-time monitoring client for Zero-Knowledge Dashboard.
"""
import asyncio
import json
import time
from collections import deque

class DashboardMonitor:
    def __init__(self, worker_url: str):
        self.url = worker_url
        self._stats = {}
        self._log_buffer = deque(maxlen=500)
        self._alerts = deque(maxlen=50)

    async def start(self):
        """Connect to WebTransport stream and start consuming."""
        from aioquic.asyncio import connect
        from aioquic.quic.configuration import QuicConfiguration

        conf = QuicConfiguration(alpn_protocols=["h3"], is_client=True)
        conf.verify_mode = None

        session = await connect(self.url, 443, configuration=conf)
        stream = await session.create_stream(
            f"https://{self.url}/dashboard",
            method="CONNECT",
            headers={"Upgrade": "webtransport"},
        )

        reader = stream.readable.getReader()
        while True:
            data = await reader.read()
            if not data:
                break
            msg = json.loads(data.decode())
            if msg["type"] == "stats":
                self._stats.update(msg)
            elif msg["type"] == "log":
                self._log_buffer.extend(msg.get("entries", []))
                self._check_anomalies()

    def _check_anomalies(self):
        """Simple anomaly detection: spike in error rate or unusual latency."""
        recent = list(self._log_buffer)[-10:]
        errors = sum(1 for e in recent if "ERROR" in e)
        if errors > 5:
            self._alerts.append({
                "time": time.time(),
                "type": "error_spike",
                "detail": f"High error rate: {errors}/10 requests",
            })