"""Settings, learned baselines and the alert book, saved in ~/.oistins/."""

from __future__ import annotations

import json
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

HOME = Path.home() / ".oistins"

DEFAULT_CONFIG = {
    "geo_mode": "online",        # online (ip-api.com) | offline (.mmdb file) | off
    "geo_db": "",                # path to a country/city .mmdb (DB-IP lite or MaxMind GeoLite2)
    "trace_targets": ["1.1.1.1", "8.8.8.8"],
    "trace_interval_min": 10,
    "speed_interval_min": 30,
    "security_interval_s": 60,
    "quiet_hours": [0, 6],       # local hours [start, end) when new open ports are extra suspicious
    "trusted_ports": [],         # listening ports you have approved
    "trusted_countries": [],     # e.g. ["BB", "US"]; empty = don't warn by country
    "ping_threshold": 20,        # echo requests per minute from one source
    "scan_threshold": 15,        # distinct ports per minute from one source
}


class Store:
    def __init__(self, home: Path = HOME) -> None:
        self.home = home
        self.home.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self.config = {**DEFAULT_CONFIG, **self._load("config.json")}
        self.baseline: dict = self._load("baseline.json")
        self._save("config.json", self.config)

    def _load(self, name: str) -> dict:
        try:
            return json.loads((self.home / name).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}

    def _save(self, name: str, data: dict) -> None:
        tmp = self.home / f"{name}.tmp"
        tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
        tmp.replace(self.home / name)

    def save(self) -> None:
        with self.lock:
            self._save("config.json", self.config)
            self._save("baseline.json", self.baseline)

    def net_baseline(self, net_id: str) -> dict:
        """Baselines are kept per network, so moving home → café isn't an alarm."""
        with self.lock:
            return self.baseline.setdefault("networks", {}).setdefault(net_id, {})

    def reset_baseline(self) -> None:
        with self.lock:
            self.baseline = {}
            self.save()


LEVELS = {"info": 0, "warn": 1, "crit": 2}


@dataclass
class Alert:
    key: str
    level: str          # info | warn | crit
    category: str
    title: str
    detail: str = ""
    first: float = field(default_factory=time.time)
    last: float = field(default_factory=time.time)
    count: int = 1
    acked: bool = False


class AlertBook:
    def __init__(self, store: Store, limit: int = 300) -> None:
        self.store = store
        self.limit = limit
        self.lock = threading.Lock()
        self.alerts: dict[str, Alert] = {}
        self.log = store.home / "alerts.log"

    def raise_(self, key: str, level: str, category: str, title: str, detail: str = "") -> None:
        now = time.time()
        with self.lock:
            a = self.alerts.get(key)
            if a and (not a.acked or now - a.last < 600):
                a.last, a.count, a.detail = now, a.count + 1, detail or a.detail
                if LEVELS[level] > LEVELS[a.level]:
                    a.level, a.acked = level, False
                return
            self.alerts[key] = Alert(key, level, category, title, detail)
            if len(self.alerts) > self.limit:
                oldest = min(self.alerts.values(), key=lambda x: x.last)
                self.alerts.pop(oldest.key, None)
        try:
            with self.log.open("a", encoding="utf-8") as f:
                f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')}  {level.upper():4}  {category:9}  {title}  {detail}\n")
        except OSError:
            pass

    def ack(self, key: str | None = None) -> None:
        with self.lock:
            for a in self.alerts.values():
                if key is None or a.key == key:
                    a.acked = True

    def snapshot(self) -> list[dict]:
        with self.lock:
            items = sorted(self.alerts.values(),
                           key=lambda a: (a.acked, -LEVELS[a.level], -a.last))
            return [asdict(a) for a in items]

    def alarm(self) -> str | None:
        with self.lock:
            levels = [a.level for a in self.alerts.values() if not a.acked]
        return "crit" if "crit" in levels else "warn" if "warn" in levels else None
