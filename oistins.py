#!/usr/bin/env python3
"""Oistins — internet link monitor and instrument panel.

    python oistins.py              start monitoring and open the panel
    python oistins.py --demo       show the panel with simulated data
    python oistins.py --port 9000 --no-browser

Run as administrator/root for the full picture (all processes' connections,
packet watch for pings and port scans).
"""

from __future__ import annotations

import argparse
import sys
import threading
import webbrowser


def main() -> int:
    p = argparse.ArgumentParser(description="Oistins internet link monitor")
    p.add_argument("--port", type=int, default=8787)
    p.add_argument("--no-browser", action="store_true")
    p.add_argument("--demo", action="store_true", help="Simulated data, to try the panel")
    args = p.parse_args()

    from server import serve
    if args.demo:
        from demo import DemoEngine
        engine = DemoEngine()
    else:
        from engine import Engine
        from store import Store
        engine = Engine(Store())
    engine.start()

    try:
        httpd = serve(engine, args.port)
    except OSError:
        print(f"Port {args.port} is busy. Is Oistins already running? Try --port 8788")
        return 1
    url = f"http://127.0.0.1:{args.port}/"
    print(f"\n  OISTINS is watching your connection{' (DEMO)' if args.demo else ''}.")
    print(f"  Instrument panel: {url}\n  Press Ctrl+C to stop.\n")
    if not args.no_browser:
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n  Oistins stopped.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
