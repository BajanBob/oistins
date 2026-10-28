# Oistins: Internet Link Monitor

Oistins watches your computer's internet connection and shows everything on a live **instrument panel**: gauges, threat lamps, every connection in and out with its country, the paths your traffic takes, open ports, and alerts with a **flashing red screen and a siren** when something looks wrong.

Everything runs on your own computer. The panel opens in your browser at `http://127.0.0.1:8787` and is never reachable from the network.

## What it watches

| Lamp | What Oistins checks | Raises an alarm when |
|---|---|---|
| **Router / ARP spoofing** | Your router's hardware (MAC) address | It changes, or another device claims it (classic man-in-the-middle) |
| **Encryption (MITM)** | Real HTTPS connections to Google, Cloudflare, GitHub and Wikipedia | A certificate isn't trusted, or is issued by an interception product or an unknown issuer |
| **DNS tampering** | Lookups of names with known answers, plus made-up names | Answers are wrong, or nonexistent sites resolve (hijack/redirect) |
| **Traffic injection** | Plain-HTTP test pages with known content | The content is modified or redirected |
| **New port openings** | Every port your computer listens on, compared with what it learned | A new port opens, especially one reachable from the network during **quiet hours** (default midnight–6 am) |
| **Vulnerable ports** | Services like Remote Desktop, SMB, Telnet, VNC, ADB, databases | One is reachable from the network |
| **Routing & diversions** | Traceroutes to 1.1.1.1 and 8.8.8.8 with the country of every hop | Traffic leaves through a different first hop, or starts passing through new countries |
| **Scans & intrusions** | Incoming pings and connection probes (optional packet watch) | Port scans, ping floods, risky inbound connections |
| **Fake cell towers** | See below | — |

Also on the panel:
- **Gauges:** download, upload, latency/jitter (Cloudflare speed test), plus live in/out traffic
- **Traffic table:** every incoming and outgoing connection with remote IP, country flag, network owner, ports, app and state. You can filter it.
- **Path map:** each hop to the internet, with its country and delay
- **Your link:** public IP, provider, router, interfaces

Oistins **learns what's normal** for each network it sees. Your home Wi-Fi and a café each get their own baseline, so moving between them doesn't set off alarms.

### About fake cell towers / stingrays
A computer can't see cell-tower signals; only a phone's modem can. So Oistins can't detect IMSI catchers, and the lamp says so instead of pretending. Dedicated tools for this:
- [EFF Rayhunter](https://github.com/EFForg/rayhunter), which runs on a cheap mobile hotspot
- SnoopSnitch on a rooted Android phone

## Run it

### Ready-made apps (Windows, macOS, Linux)
Push this repo to GitHub. The **Actions** tab builds the apps automatically; download them from the run's **Artifacts**. Push a tag (`git tag v1.0.0 && git push origin v1.0.0`) to publish them under **Releases**.

### From source
Requires Python 3.9+.
```bash
pip install -r requirements.txt
python oistins.py            # monitor this computer
python oistins.py --demo     # try the panel with simulated data
```

**Turning on the alarm sound:** click **Arm alarm sound** once after the panel opens. Browsers only allow sound after a click. It also asks to show desktop notifications.

### For the full picture
- **Run as administrator/root** so Oistins can see every app's connections (macOS especially).
- **Optional packet watch** (pings and port scans): `pip install scapy`, install [Npcap](https://npcap.com) on Windows, and run as administrator.
- **Linux:** install traceroute (`sudo apt install traceroute`).

## Android app (APK)
The `android/` folder holds a native Android version (Android 10 or newer) with the same instrument panel. GitHub Actions builds `Oistins-android.apk` alongside the desktop apps.

**Install:** download the APK on your phone, open it, and allow "Install unknown apps" for your browser or file manager when Android asks. On first launch, allow **location** (Android requires it to read cell-tower and Wi-Fi details), **phone** and **notifications**. For the app traffic table, tap **Grant usage access**.

**What it watches:**
| Lamp | Checks |
|---|---|
| **Cell towers / stingray** | Forced downgrades to 2G, towers hiding their identity, unfamiliar unusually strong towers whose area code doesn't match their neighbours, towers listing no neighbours. It learns the towers around you. |
| **Wi-Fi / evil twin** | New access points pretending to be a known network name, router address changes (rogue router or DHCP), open or WEP networks |
| **Encryption (MITM)** | Only Android's built-in certificate authorities are trusted, so interception certificates show up |
| **DNS tampering, traffic injection** | Same checks as the desktop version |
| **Routing & diversions** | Paths to 1.1.1.1 and 8.8.8.8 traced without root, with the country of each hop |
| **Open ports & debugging** | Remote-control ports open on the phone (ADB 5555, SSH, VNC…), USB and **wireless debugging** |
| **App traffic** | Data each app used in the last hour; alerts on large uploads during quiet hours |
| **VPN / private DNS** | Whether your browsing is hidden from your network provider |

Gauges show speed-test results and the phone's live traffic. Critical alerts sound a siren on the alarm channel, vibrate, flash the screen red and post a notification. Turn on **Watch in background** to keep checking with the app closed.

**Android limits:** without root, Android hides other apps' individual connections, the router's hardware (ARP) address and raw packets, so port-scan and ping detection aren't possible on the phone. Cell-tower warnings are heuristics: real networks sometimes do these things too, so a warning means "look closer", not "proven fake tower".

**Signing:** the APK is signed with `android/oistins-sideload.keystore`, whose password is in the build file, so each new version installs over the old one. That key is public. Before distributing Oistins to others or publishing it on Google Play, create your own private key and keep it secret.

**Build it yourself:** install Android Studio and open the `android/` folder, or run `gradle -p android assembleRelease` with the Android SDK installed.

## Settings
Settings live in `~/.oistins/config.json`. Alerts are logged to `~/.oistins/alerts.log`.

| Setting | Default | Meaning |
|---|---|---|
| `quiet_hours` | `[0, 6]` | Hours when new open ports and inbound connections are treated as more serious |
| `trusted_countries` | `[]` | e.g. `["BB","US"]`. Warn about traffic with any other country |
| `trusted_ports` | `[]` | Ports you've approved (the **Trust** button adds here) |
| `geo_mode` | `online` | `online` uses ip-api.com; `offline` uses a local `.mmdb` file; `off` disables lookups |
| `geo_db` | | Path to a [DB-IP Lite](https://db-ip.com/db/lite.php) or MaxMind GeoLite2 `.mmdb` (needs `pip install maxminddb`) |
| `trace_targets` | `1.1.1.1, 8.8.8.8` | Where to trace paths to |
| `trace_interval_min` / `speed_interval_min` | 10 / 30 | How often to trace and speed-test |
| `ping_threshold` / `scan_threshold` | 20 / 15 | Pings or distinct ports per minute from one source before alarming |

To relearn everything (for example, after replacing your router), delete `~/.oistins/baseline.json`.

## Privacy
- **Online country lookups** send the remote IP addresses you talk to (not your traffic) to ip-api.com over plain HTTP. For full privacy, use `offline` mode with a downloaded database.
- **Speed tests** use Cloudflare. **Checks** contact ipify.org, Google/Firefox connectivity pages, and the test sites listed above.
- The panel only listens on `127.0.0.1`. It rejects requests addressed to any other host name, and its buttons can't be triggered by other websites.

## Limits
These are warnings, not proof. Antivirus programs and work networks often inspect HTTPS traffic legitimately, and ISPs sometimes redirect DNS for ads. Routes also change naturally. Oistins tells you what changed so you can decide; check its explanation before acting.

## License
MIT
