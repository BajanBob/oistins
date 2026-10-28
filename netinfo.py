"""Cross-platform helpers: gateway, ARP table, interfaces, public IP, HTTP."""

from __future__ import annotations

import ipaddress
import json
import platform
import re
import socket
import struct
import subprocess
import urllib.request

import psutil

OS = platform.system()
MAC_RE = re.compile(r"\b([0-9a-fA-F]{1,2}[:-]){5}[0-9a-fA-F]{1,2}\b")
IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
UA = {"User-Agent": "Oistins/1.0"}


def run(cmd: list[str], timeout: int = 20) -> str:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                              creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)).stdout
    except (OSError, subprocess.TimeoutExpired):
        return ""


def http_get(url: str, timeout: int = 10) -> bytes:
    with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=timeout) as r:
        return r.read()


def is_public(ip: str | None) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except (TypeError, ValueError):
        return False
    return not (a.is_private or a.is_loopback or a.is_link_local or a.is_multicast
                or a.is_reserved or a.is_unspecified)


def norm_mac(m: str) -> str:
    return ":".join(p.zfill(2) for p in re.split("[:-]", m.lower()))


def default_gateway() -> tuple[str | None, str | None]:
    """(gateway IP, interface) for the default IPv4 route."""
    if OS == "Linux":
        try:
            with open("/proc/net/route") as f:
                for line in f.read().splitlines()[1:]:
                    p = line.split()
                    if p[1] == "00000000" and int(p[3], 16) & 2:
                        return socket.inet_ntoa(struct.pack("<L", int(p[2], 16))), p[0]
        except OSError:
            pass
        m = re.search(r"via (\S+) dev (\S+)", run(["ip", "route", "show", "default"]))
        return (m.group(1), m.group(2)) if m else (None, None)
    if OS == "Darwin":
        out = run(["route", "-n", "get", "default"])
        gw, iface = re.search(r"gateway:\s*(\S+)", out), re.search(r"interface:\s*(\S+)", out)
        return (gw.group(1) if gw else None, iface.group(1) if iface else None)
    if OS == "Windows":
        for line in run(["route", "print", "-4", "0.0.0.0"]).splitlines():
            p = line.split()
            if len(p) >= 5 and p[0] == "0.0.0.0" and p[1] == "0.0.0.0" and IP_RE.match(p[2]):
                return p[2], p[3]
    return None, None


def arp_table() -> dict[str, str]:
    """IP → MAC for neighbours on the local network."""
    out = run(["arp", "-a"])
    if not out and OS == "Linux":
        out = run(["ip", "neigh"])
    table: dict[str, str] = {}
    for line in out.splitlines():
        ip, mac = IP_RE.search(line), MAC_RE.search(line)
        if not (ip and mac):
            continue
        m = norm_mac(mac.group(0))
        if m in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00") or m.startswith("01:00:5e"):
            continue
        table[ip.group(1)] = m
    return table


_KINDS = [
    ("vpn", re.compile(r"tun|tap|wg|utun|ppp|vpn|tailscale|zerotier|wireguard|nord|proton", re.I)),
    ("cellular", re.compile(r"wwan|cellular|mobile|rmnet|broadband|lte|5g", re.I)),
    ("wifi", re.compile(r"wi-?fi|wlan|wlp|airport|wireless", re.I)),
    ("ethernet", re.compile(r"eth|enp|eno|ethernet|en\d", re.I)),
]


def interfaces() -> list[dict]:
    stats, addrs = psutil.net_if_stats(), psutil.net_if_addrs()
    out = []
    for name, st in stats.items():
        ipv4 = [a.address for a in addrs.get(name, []) if a.family == socket.AF_INET]
        if not st.isup or not ipv4 or all(i.startswith("127.") for i in ipv4):
            continue
        kind = next((k for k, rx in _KINDS if rx.search(name)), "other")
        out.append({"name": name, "ipv4": ipv4, "kind": kind, "speed": st.speed})
    return out


def local_ips() -> set[str]:
    return {a.address for addrs in psutil.net_if_addrs().values() for a in addrs
            if a.family in (socket.AF_INET, socket.AF_INET6)}


def public_ip() -> str | None:
    try:
        return json.loads(http_get("https://api.ipify.org?format=json"))["ip"]
    except Exception:  # noqa: BLE001
        return None
