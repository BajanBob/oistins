"""IP → country / network owner, with caching.

online : ip-api.com batch lookups (free, no key; note it sends the remote
         IPs you talk to to ip-api.com, over plain HTTP)
offline: a local .mmdb file (DB-IP "IP to Country Lite" or MaxMind GeoLite2),
         needs `pip install maxminddb`; nothing leaves your computer
off    : no lookups
"""

from __future__ import annotations

import json
import threading
import time
import urllib.request

from netinfo import UA, is_public

FIELDS = "status,country,countryCode,city,isp,org,as,query"


class Geo:
    def __init__(self, mode: str = "online", db_path: str = "") -> None:
        self.mode = mode
        self.cache: dict[str, dict] = {}
        self.lock = threading.Lock()
        self.pending: set[str] = set()
        self._next_call = 0.0
        self.reader = None
        if mode == "offline":
            try:
                import maxminddb
                self.reader = maxminddb.open_database(db_path)
            except Exception:  # noqa: BLE001
                self.mode = "off"

    def get(self, ip: str | None) -> dict:
        if not ip:
            return {}
        if not is_public(ip):
            return {"cc": "LAN", "country": "Local network", "org": ""}
        with self.lock:
            hit = self.cache.get(ip)
            if hit is None and self.mode != "off":
                self.pending.add(ip)
        return hit or {}

    def resolve_pending(self) -> None:
        """Look up queued IPs. Called from a background thread."""
        with self.lock:
            ips = [ip for ip in self.pending if ip not in self.cache][:100]
            self.pending.difference_update(ips)
        if not ips:
            return
        if self.mode == "offline" and self.reader:
            for ip in ips:
                self._store(ip, self._offline(ip))
            return
        if self.mode != "online" or time.time() < self._next_call:
            with self.lock:
                self.pending.update(ips)
            return
        try:
            req = urllib.request.Request(f"http://ip-api.com/batch?fields={FIELDS}",
                                         data=json.dumps(ips).encode(), headers=UA)
            with urllib.request.urlopen(req, timeout=10) as r:
                left = int(r.headers.get("X-Rl", "10"))
                ttl = int(r.headers.get("X-Ttl", "60"))
                rows = json.loads(r.read())
            self._next_call = time.time() + (ttl + 1 if left <= 1 else 4.5)
            for row in rows:
                if row.get("status") == "success":
                    self._store(row["query"], {"cc": row.get("countryCode", ""),
                                               "country": row.get("country", ""),
                                               "city": row.get("city", ""),
                                               "org": row.get("org") or row.get("isp", ""),
                                               "asn": row.get("as", "")})
                else:
                    self._store(row.get("query", ""), {"cc": "??", "country": "Unknown", "org": ""})
        except Exception:  # noqa: BLE001
            self._next_call = time.time() + 30
            with self.lock:
                self.pending.update(ips)

    def _offline(self, ip: str) -> dict:
        try:
            r = self.reader.get(ip) or {}
        except Exception:  # noqa: BLE001
            r = {}
        c = r.get("country") or {}
        name = (c.get("names") or {}).get("en", "Unknown")
        city = ((r.get("city") or {}).get("names") or {}).get("en", "")
        return {"cc": c.get("iso_code", "??"), "country": name, "city": city, "org": ""}

    def _store(self, ip: str, info: dict) -> None:
        with self.lock:
            self.cache[ip] = info
