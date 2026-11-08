# MedianBoxMonitor 3.0

**A local, defensive security monitoring application that watches every process, every connection, and every system event on your machine in real time — and shows its work.**

Single-file Python application (~44,800 lines, 62 classes). Windows-primary, Linux-partial. No offensive capability, no remote scanning, no phoning home.

```
python medianbox_monitor_v2.py
```

That's it — a Tkinter GUI opens with 18 tabs of live data, a background thread starts a web dashboard on `http://127.0.0.1:8470`, and the deductive engine starts reasoning about every process, connection, and signal-emitting device on your machine.

---

## Table of Contents

1. [What This Is](#what-this-is)
2. [Quick Start](#quick-start)
3. [Installation](#installation)
4. [CLI Reference](#cli-reference)
5. [What It Catches](#what-it-catches)
6. [Architecture at a Glance](#architecture-at-a-glance)
7. [Stats & Performance](#stats--performance)
8. [The GUI](#the-gui)
9. [The Web Dashboard](#the-web-dashboard)
10. [Data It Saves](#data-it-saves)
11. [Testing](#testing)
12. [Feature Completeness Ratings](#feature-completeness-ratings)
13. [Known Gaps — What's Missing](#known-gaps--whats-missing)
14. [Project Files](#project-files)
15. [Design Philosophy](#design-philosophy)
16. [Scope & Non-Goals](#scope--non-goals)
17. [Further Reading](#further-reading)

---

## What This Is

Modern attackers rarely drop a recognizable malware binary. They run `certutil.exe` to download a payload, `rundll32.exe` to execute it from memory, create a WMI subscription for persistence, dump LSASS with `comsvcs.dll,MiniDump`, and exfiltrate through a Discord webhook — all using tools that already ship with Windows. Meanwhile a VPN can leak DNS queries, a browser can expose your real IP via WebRTC, and a compromised service can beacon to a C2 server every 30 seconds without any of it looking like "a virus."

MedianBoxMonitor is a **digital witness**, not a scanner or a firewall. It sits inside your OS, watches everything every process and connection does, and reasons about whether that behavior is legitimate — producing an auditable evidence chain for every alert instead of a bare "suspicious" flag. Every deduction can be checked against the exact process name, PID, parent, command line, destination, and the specific rule that fired.

It is **local-only and defensive-only**. It does not attack remote systems, does not identify the people behind a VPN, and does not upload your data anywhere except the minimal IP-lookup calls needed for GeoIP enrichment (which can be disabled with `--no-geoip`, or redirected to a local MaxMind database with `--geoip-db`).

---

## Quick Start

```bash
# Clone / copy the project, then from the project directory:
python medianbox_monitor_v2.py
```

- Opens the GNA Tracer GUI (18 tabs, see below)
- Starts a web dashboard at `http://127.0.0.1:8470`
- Begins writing logs to `medianbox_structured.log`, `medianbox_full_actions.log`, `medianbox_deductions.log`
- Auto-saves a full session snapshot every 10 minutes to `sessions/YYYY-MM-DD/` and to your Desktop

**Run as Administrator** for full functionality — packet capture, the Windows Security event log, memory forensics (RWX-region scanning), and ARP-based device discovery all require elevation. Without admin, the monitor still runs and still catches most things; it just can't see packets on the wire or read the Security event log.

**Install Npcap** (in WinPcap-compatible mode) if you want packet-level detection — SNI extraction, JA4+ TLS fingerprinting, wire-level DNS-tunnel detection. Without it the monitor falls back to psutil/connection-based data only and logs a warning; it does not silently stop working, but a real slice of detection coverage goes dark. There is currently no in-app prompt telling you this plainly — see [Known Gaps](#known-gaps--whats-missing).

```bash
# Headless, no GUI, no dashboard — useful for a server or scripted deployment
python medianbox_monitor_v2.py --no-gui --no-dashboard

# Disable third-party GeoIP calls entirely (privacy-first mode)
python medianbox_monitor_v2.py --no-geoip

# Point at a local MaxMind GeoLite2-City.mmdb instead of the public API
python medianbox_monitor_v2.py --geoip-db "C:\GeoIP\GeoLite2-City.mmdb"

# Password-protect the web dashboard
python medianbox_monitor_v2.py --dashboard-password "correct horse battery staple"
```

---

## Installation

There is currently **no `requirements.txt` or `pyproject.toml`** in this project (see [Known Gaps](#known-gaps--whats-missing)) — dependencies must be installed manually from the import list below.

**Required:**

```bash
pip install psutil scapy
```

`tkinter` ships with most Python installs on Windows; on some Linux distributions it needs a separate OS package (`sudo apt install python3-tk`).

**Optional, but recommended:**

```bash
pip install fastapi uvicorn      # web dashboard — disabled without these
pip install pillow                # IP Map tile rendering — text-only without this
pip install manuf                 # MAC vendor lookup for device discovery
pip install geoip2                # local MaxMind DB support (needs a .mmdb file you supply)
```

**Platform:**
- Python 3.13+ (developed and tested on 3.13.14)
- Windows 10/11 is the primary, fully-supported platform
- Linux runs a real subset — process/connection/DNS/GeoIP/VPN-detection all work; the Windows-only anti-hack monitors (registry, WMI, services, scheduled tasks, security event log — see [Known Gaps](#known-gaps--whats-missing)) do not
- macOS is untested and has no dedicated monitoring code beyond a single "open this folder in Finder" call

**Packet capture (optional, Windows):**
Install [Npcap](https://npcap.com/) with "WinPcap API-compatible mode" checked during setup. Without it, `scapy`'s sniffer thread logs a retry warning every few seconds and the monitor continues on process/connection data alone.

---

## CLI Reference

```
python medianbox_monitor_v2.py [options]

  --config, -c PATH          Load a YAML config file (overrides CONFIG defaults)
  --no-dashboard             Disable the FastAPI web dashboard
  --no-geoip                 Disable GeoIP lookups entirely (privacy mode)
  --siem json|cef|syslog     Enable SIEM output in the given format
  --port PORT                Web dashboard port (default 8470)
  --workers N                Packet pipeline worker thread count (default 4)
  --dashboard-password PASS  Require this token to access the web dashboard
  --geoip-db PATH            Path to a local MaxMind GeoLite2-City.mmdb file
  --no-gui                   Run headless — no Tkinter window, terminal output only
```

There is no `--vt-api-key` flag; VirusTotal integration is opt-in via the `VT_API_KEY` environment variable only (see [Known Gaps](#known-gaps--whats-missing)).

---

## What It Catches

### Connected hackers (post-exploitation activity)
Network-spawned shells (sshd/w3wp spawning cmd/powershell) · listening-port anomalies (bind shells, C2 listeners) · credential dumping (mimikatz, `procdump -ma`, `reg save SAM`, LSASS MiniDump) · process hollowing · parent/child mismatch · 24+ LOLbin abuse patterns (`certutil`, `bitsadmin`, `mshta`, `regsvr32` Squiblydoo, `rundll32`, `wmic`, `msiexec`) · 12-indicator PowerShell obfuscation scoring (encoded commands, download cradles, AMSI bypass, reflective assembly load) · macro malware (Office spawning shells) · browser-exploit drive-bys · renamed system binaries · port forwarding/tunneling tools (chisel, ngrok, ligolo, plink) · data staging before exfiltration · backup tampering (`vssadmin delete shadows` — ransomware indicator) · admin-share lateral movement (`net use C$`, PsExec) · exfil channels (Discord/Telegram/Pastebin webhooks) · curl/wget upload detection

### System compromise
Windows Security event log (logon/failed-logon/process-creation/service-install/new-user/admin-escalation/Kerberos tickets) · hosts file hijack · DNS server changes · new suspicious services · Defender/Firewall disable · new user/admin accounts · WMI event-subscription persistence (stealthy APT technique) · new kernel driver loads · 10 known malware mutex names (Cobalt Strike, Meterpreter, etc.)

### Network threats
C2 beaconing (regular-interval connection detection) · DNS tunneling (entropy + label-length + query-rate heuristics) · exfiltration (I/O spike vs. baseline) · phantom connections (no owning process) · injection chains (known app spawning an unknown child with many connections) · mimicry (connecting to a look-alike of a trusted service) · foreign-country connections · high-risk-country flagging · DNS-over-HTTPS bypass detection · inbound port-scan detection · TLS certificate/MITM anomalies

### VPN & privacy leaks
DNS resolver leaks outside the tunnel · global IPv6 leaks bypassing an IPv4-only VPN · route leaks · WebRTC local-IP exposure · kill-switch verification

### Behavioral anomalies
Idle-time network activity · statistical Z-score deviation over a 24h per-process baseline · DLL injection (suspicious loaded modules) · registry/scheduled-task/startup persistence · clipboard access · USB device changes · file system changes in sensitive directories

### Non-IP & RF signal intelligence (Spectrum)
Wi-Fi AP/BSSID census with RSSI, band, channel, radio type, authentication and estimated distance (`netsh wlan`) · connected-radio state (SSID, BSSID, rates, signal %) · Bluetooth/BLE radios and devices (PnP registry + optional live `bleak` adverts) · WWAN/cellular interfaces (`netsh mbn`) · Wi-Fi Direct/P2P adapters · every local interface classified by medium · RF-capable USB hardware — SDR (RTL-SDR, HackRF, Airspy, ADALM-PLUTO, LimeSDR, SDRplay), Zigbee/802.15.4 (CC2531, ConBee), Z-Wave, NFC/RFID, Ubertooth, Flipper, proprietary 2.4 GHz receivers (Logitech Unifying, Razer, PixArt) · **Layer-2 wire census** — every source MAC on the wire becomes a traced emitter with its ethertypes, claimed IPs, announced discovery services (mDNS, SSDP, LLMNR, WS-Discovery, DHCP, NetBIOS, IPv6-ND), and derived roles (router, DHCP server, discovery-announcer, never-speaks-ip, raw-ethertype-channel) · RSSI→distance estimation via log-distance path loss (labeled approximate) · approach/recession trend detection (+dB/min slope) · weighted-least-squares **trilateration** when `rf_sensors` supplies 3+ positioned observers, or external sensors drop observations into `rf_obs_file` · evil-twin / rogue-AP suspicion (same SSID on new BSSIDs) · hidden-SSID beacons flagged as classic rogue cover · per-emitter lifecycle: first/last seen, active/lost, observation counts, per-sensor attribution

Every emitter lives in one unified registry across 11 media (`wifi-ap`, `wifi-radio`, `wifi-direct`, `bt-radio`, `bt-classic`, `ble`, `wwan-modem`, `local-radio`, `rf-hw`, `local-iface`, `l2-wire`), and a 12-row coverage matrix honestly reports which spectrums this host can physically hear (Zigbee/Z-Wave/NFC show as unavailable without matching hardware — nothing is fabricated). All of it renders in the SIGNALS tab with verbose field labels.

Every one of these produces a full `Deduction` — severity, category, process, PID, human-readable message, and a list of specific evidence strings — not a bare flag. See [`about.md`](about.md) for a worked example and the full design rationale.

---

## Architecture at a Glance

```
Main Thread (Tkinter GUI)
├── Connection-Mapper Thread     — psutil.net_connections() every 0.5s
├── Process-Watcher Thread       — psutil.process_iter() every 0.5s
│   └── 16 core deductions + 18 anti-hack checks per process
├── Connection-Inventory Thread  — enriches every connection with GeoIP/DNS/service
│   ├── GeoIP Worker Thread      — background ip-api.com / MaxMind calls
│   └── RDNS Worker Thread       — background reverse-DNS, bounded to a 3-5s timeout
├── MultiVerify Worker Pool (4)  — VPN/proxy/infra cross-verification (228 named
│                                   evidence methods), priority queue, covers
│                                   every public endpoint
├── Extended Monitor Thread      — ~19 monitors on 2-60s intervals (clipboard, USB,
│                                   scheduled tasks, named pipes, inbound scans,
│                                   Bluetooth, serial, proxy, VPN leak, + 8
│                                   Windows-only anti-hack background monitors)
├── Spectrum-Intel Thread        — SpectrumHub: Wi-Fi BSSID/RSSI sweeps (netsh),
│                                   BT/BLE census, WWAN, interface census, RF
│                                   hardware, external-sensor ingest, L2 wire
│                                   census, trilateration solves
├── Memory Forensics Thread      — RWX memory-region scan every 15s (admin)
├── Packet Pipeline (4 workers)  — SNI/DNS/JA4+/entropy extraction + per-MAC
│                                   L2 wire census (admin + Npcap)
├── ARP Scanner + Sniff Threads  — device discovery, raw packet capture (admin + Npcap)
├── FastAPI Dashboard Thread     — web server on port 8470
└── GUI Refresh                  — adaptive interval (~250ms target)
```

~20 persistent daemon threads at baseline, plus worker pools (4 MultiVerify, 4 packet-pipeline, GeoIP/RDNS/verify workers) — more with admin + Npcap. Every shared data structure either uses its own lock or is replaced atomically (never mutated in place) so the process watcher can read a reference without copying. Full detail in [`overview.md`](overview.md#thread-architecture).

**Data flow, simplified:**

```
psutil.net_connections()  →  Connection Mapper  →  conn_by_pid, conn_by_raddr
                                                          ↓
psutil.process_iter()  →  Process Watcher  →  ProcessProfile per PID
                              ↓                    ↓
                    16 core deductions      18 anti-hack checks
                              ↓                    ↓
                    Deduction evidence     Anti-hack pins (IP → categories)
                              ↓                    ↓
                          Merged payload  →  GUI (250ms) + Dashboard (3s WebSocket)
                              ↓
                    Session snapshot (every 10 min) + rotating logs + SQLite
```

---

## Stats & Performance

**Codebase**

| Metric | Value |
|--------|-------|
| Lines of code | ~44,800 (single file) |
| Top-level classes | 62 |
| Functions / methods | ~900 |
| GUI tabs | 18 (+ 5 dashboard tabs) |
| Persistent daemon threads | ~20, plus worker pools (4 MultiVerify + 4 packet-pipeline + GeoIP/RDNS/verify) |
| Core deductions / anti-hack checks / enhanced checks | 16 / 18 / 7 |
| Extended monitors | ~19 on 2–60s cadences |
| MultiVerifier named evidence methods | 228 |
| Spectrum/RF emitter media | 11 (wifi-ap, wifi-radio, wifi-direct, bt-radio, bt-classic, ble, wwan-modem, local-radio, rf-hw, local-iface, l2-wire) |
| Coverage-matrix media rows | 12 |
| RF-capable hardware VID&PID table | 30+ entries |
| Config keys | 71 (68 schema-validated) |
| ConnectionEntry fields | 54 |
| Save-file sections | 30+ |
| Test/audit scripts | 15 suites + 2 audits (~1,900 assertions) |

**Measured performance** (`_test_perf_profile.py` cProfile harness — ~400 processes, ~300 connections, 20k timeline rows):

| Path | Before | Now | How |
|------|--------|-----|-----|
| `_get_full_data` build | ~21.4 ms | ~0.14 ms | Per-section caches keyed on store mutation counters — rebuilds only on real change |
| `_get_dashboard_state` | ~11.1 ms | ~0.02 ms | Process-row payload memoized on `_proc_seq` |
| `_refresh_all` tick | ~4.7 ms | ~0.59 ms | Version-keyed `_render_skip` — tabs repaint only when their feed moved |
| `_refresh_status` | ~4.2 ms | ~0.59 ms | `_cfg()` diffs widget options; ~73 → ~13 Tcl calls per tick |
| `_refresh_trace` | ~3.8 ms | ~0.00 ms | Memoized trace-target list |
| Live tab render (250 expanded rows) | ~2,540 ms | ~34 ms | Embedded `tk.Button`s → clickable text spans + `_BufferedText` batch inserts (~9,000 → 1 Tk calls/row-set) |
| `get_timeline` (20k rows) | ~21 ms/build | ~0.00 ms | Cached on history version |

**Refresh cadences:** connection map 0.5s · process watcher 0.5s · status 5s · interface stats 1s · extended monitor 2s base · GUI 250ms (adaptive) · dashboard WebSocket 3s · spectrum tick 2s (Wi-Fi 15s / BT 30s / census 30s / WWAN 60s / RF-HW 120s / L2 flush 15s) · memory forensics 15s · session save 600s.

---

## The GUI

An 18-tab Tkinter interface (`GNATracerGUI`):

| Tab | What's in it |
|-----|---------------|
| Overview | Summary stats, anti-hack pin summary, high-risk processes, proxy list |
| Live Connections | Active/established connections only, collapsible rows, VPN/proxy badges inline |
| All Connections | Every connection, full detail (GeoIP, ASN, rDNS, timezone, MultiVerifier verdict, location proof) |
| Deductions | All alerts with severity, category, and full evidence chain |
| Processes | Every tracked process — risk score, CPU%, memory, I/O, command line, DNS domains, behavioral flags |
| Devices | ARP-discovered network devices — IP, MAC, vendor, hostname, OS guess |
| IP Map | Slippy-tile world map with geolocated, color-coded, risk-scored IP markers (needs Pillow) — plus a **spectrum-emitter layer**: every traced signal source is drawn as a map dot (solid marker + RMS ring for trilaterated fixes, dashed range-ring for single-receiver RSSI distance, golden-angle cluster around the receiver for wire talkers and un-ranged emitters) and a **MAP POINTS sidebar** listing every point with multi-toggle selection and a detail pane |
| Actions Log | Raw process action log |
| Terminal | Live color-coded terminal output, 10,000-line rolling buffer |
| Suspicious Activity | Out-of-norm events only |
| Blocked IPs | Manual firewall block/unblock management |
| Process Tree | Hierarchical parent/child process tree with risk scores |
| Net Stats | Per-interface bandwidth |
| Timeline | Connection lifecycle timeline (active + closed, with duration) |
| Config | Live-editable, type-validated configuration |
| Double Trace | VPN double-trace / full MultiVerifier verification view |
| System | Host/hardware detail — CPU, RAM, OS build, uptime, interfaces, power |
| Signals | Spectrum & RF intelligence — emitter census across 11 media, coverage matrix, RSSI/distance/trend, trilateration fixes, every scanner's raw feed, persistent event history |

As of the 2026-08-22 audit, every tab renders every field the backend actually collects (previously ~22 harvested fields — ASN, timezone, rDNS, RTT, TTL/OS, the full VPN/proxy verdict — were computed and then silently discarded before reaching the screen). The Live and All Connections tabs were also reworked for performance: embedded per-row `tk.Button` widgets (which Tk destroys and recreates on every refresh) were replaced with clickable text spans, cutting the Live tab's refresh time roughly 75x (~2,540ms → ~34ms at 250 expanded rows).

**The desktop GUI has no authentication of its own** — anyone with access to the desktop session sees everything while it's open.

---

## The Web Dashboard

FastAPI + WebSocket server on port 8470 (configurable via `--port`, disabled via `--no-dashboard`, optionally password-protected via `--dashboard-password`):

- `GET /` — full HTML dashboard, dark-themed, 5 tabs (Connection Map, All Connections, Deductions, Processes, Devices)
- `GET /api/state` — JSON snapshot of the complete dashboard state
- `WS /ws` — pushes the full state every 3 seconds for live updates

It's a lighter, browser-accessible subset of the desktop GUI's 18 tabs — served over plain HTTP (no TLS).

---

## Data It Saves

Every 10 minutes (and on close), a complete plain-text session snapshot is written to:
- `sessions/YYYY-MM-DD/session_HHMM_HHMM.txt` — organized by date and time segment
- `Desktop/GNA tracer data {N}.txt` — flat, numbered, backward-compatible

Each snapshot has 30+ sections: overview stats, every connection individually, every deduction with its full evidence chain, every process, every device, the complete raw action log, all IPs with geolocation, suspicious activity, the "sneakiest connections" (anti-hack-flagged endpoints), all 8 anti-hack monitors' events, VirusTotal results, file-system/clipboard/USB/scheduled-task/named-pipe/inbound-scan/DoH/TLS-cert events, the connection timeline, network bandwidth, Bluetooth/serial devices, the complete spectrum/RF emitter registry (per-medium census, every emitter's RSSI/distance/lifecycle and raw fields, trilateration fixes, spectrum events), the live processing-state dump, and the full terminal output.

**Structured logs** (rotating, 50MB × several backups): `medianbox_structured.log`, `medianbox_full_actions.log`, `medianbox_deductions.log`.

**SQLite** (`medianbox_ultimate.db`) persists only `deductions` and `devices` — connections, processes, and every Tier-5 monitor event exist only in the text logs above, not in a queryable database. See [Known Gaps](#known-gaps--whats-missing).

**SIEM output** (`--siem json|cef|syslog`) can additionally stream deductions to a file or UDP syslog endpoint for ingestion elsewhere.

---

## Testing

Fifteen test/verification scripts plus two static field-visibility audits — over 1,900 assertions total. Detection-logic suites verify the engine fires correctly; delivery-layer suites verify what it produces actually reaches the screen.

| Suite | Tests | Verifies |
|-------|-------|----------|
| `_test_antihack.py` | 41 | Every anti-hack detection path fires on a simulated attack technique, and does *not* fire on the matching benign case |
| `_test_vpn_leak.py` | ~30 | DNS/IPv6/route/WebRTC VPN leak detection |
| `_test_vpn_detection.py` | — | VPN/proxy detection across 1,100 synthetic endpoints: 100% detection rate, 0% false positives |
| `_test_location_accuracy.py` | — | MultiVerifier location accuracy (live GeoIP lookups) |
| `_test_gatecrasher.py` | 68 | IKE/PROX/TLSALT/BANNER/IPID/SRVLOC/VPN-gateway + GEOFEED/RPKI/TSRTT/H2FP/RDRCT verification methods |
| `_test_wireproof.py` | 1,560 | Silent-tunnel & non-IP-channel evidence rows — WireGuard/OpenVPN/DTLS/L3-tunnel/ICMP-tunnel/QUIC/encrypted-flow/TLS-weird/WS-tunnel/ECH/no-SNI/one-way signatures plus every tranche of protocol self-ID decoders, all fed to the pure classifiers |
| `_test_data_wiring.py` | ~20 | Runs the real monitor against live traffic; asserts every harvested field reaches the connection record for 100% of public IPs, and no payload key is built and never read |
| `_test_gui_render.py` | — | Builds the real Tkinter window offscreen, renders all tabs against live data, asserts zero exceptions and zero stale placeholders |
| `_test_ui_smoke.py` | ~180 | Full GUI smoke pass — every tab, sensor chips, search bars, inspector dossier, Signals tab field labels, raw feeds |
| `_test_click_actions.py` | ~10 | Fires real `<Button-1>` events at the GUI's clickable text spans |
| `_test_map_declutter.py` | 5 | Endpoint-map marker declustering logic |
| `_test_map_default_view.py` | 10 | Endpoint-map default viewport/zoom behavior |
| `_test_perf_profile.py` | — | cProfile harness (~400 procs / ~300 conns / 20k timeline rows) for the render pipeline |
| `_test_ui_shot.py`, `_test_ui_shot_sys.py` | — | Render the real GUI and screenshot each tab for visual review |
| `_audit_fields.py` | — | Static audit: every event-field key a feed produces is referenced by a renderer — nothing produced-but-invisible |
| `_audit_ui.py` | — | Static audit: every wire/protocol field name has a UI render path |

```bash
python _test_antihack.py
python _test_vpn_leak.py
python _test_vpn_detection.py
python _test_location_accuracy.py    # live GeoIP lookups — slow
python _test_gatecrasher.py
python _test_wireproof.py            # ~1,560 checks — several minutes
python _test_data_wiring.py          # ~90-120s — runs live threads
python _test_gui_render.py           # ~60-90s — builds a real Tk window
python _test_ui_smoke.py
python _test_click_actions.py
python _test_map_declutter.py
python _test_map_default_view.py
python _audit_fields.py
python _audit_ui.py
```

No CI is wired up to run these automatically — see [Known Gaps](#known-gaps--whats-missing).

---

## Feature Completeness Ratings

Every subsystem below was graded against the running code on 2026-08-22, not against its docstring or intent.

| Grade | Meaning |
|-------|---------|
| **A** | Fully implemented, cross-platform where relevant, verified against live data |
| **B** | Fully implemented on Windows, solid, but static rule lists or single-platform |
| **C** | Real structural limitation — opt-in, rate-capped, or degrades without an optional dependency |
| **D** | Present but materially incomplete relative to what the name implies |
| **F** | Not implemented |

| Subsystem | Grade |
|-----------|-------|
| Network & connection monitoring | **A-** |
| VPN/proxy detection | **A-** |
| GUI (18 tabs) | **A-** |
| GeoIP & MultiVerifier (228 evidence methods) | **B+** |
| Data export & session recording | **B+** |
| Core deductions + anti-hack process checks | **B** |
| Spectrum/RF & L2 signal intelligence | **B** (host-observable media only; hardware-limited bands show as unavailable) |
| Web dashboard | **C+** |
| Packet analysis / JA4+ / SNI | **C+** |
| Process profiling & forensics | **C+** |
| Behavioral & statistical/ML | **C+** |
| Anti-hack background monitors (8) | **C** (Windows-only) |
| System & persistence monitoring | **C** (Windows-only) |
| Hardware & peripheral monitoring | **C** (Windows-only) |
| Firewall & IP blocking | **C** |
| SIEM output | **C** |
| Database & logging | **D** (2 of ~15 tracked entity types persisted) |
| Threat-intel freshness | **D** (static hardcoded lists, no feed integration) |
| Cross-platform coverage | **D** (Linux ~9/33 detections; macOS unsupported) |
| Packaging / reproducibility | **D** (no requirements.txt / pinned versions) |
| Signature / YARA / code-signing detection | **F** (not implemented) |
| Automated response / containment | **F** (manual firewall block only) |
| Out-of-band alerting | **F** (no email/Slack/push/SMS) |

Full per-item rationale with code-line citations: [`overview.md`](overview.md#feature-completeness-ratings) and [`total_features.md`](total_features.md#42-completeness-ratings-by-category).

---

## Known Gaps — What's Missing

**Detection method gaps**
- No code-signing (Authenticode) verification anywhere — `ProcessLegitimacyChecker` checks only path and parent, never a certificate
- No YARA or byte-signature malware scanning
- Mutex scanner checks 10 hardcoded exact-name strings — trivially evaded by renaming
- DNS-tunneling/entropy thresholds are fixed constants, not adaptive
- No sandboxing or dynamic detonation — purely a passive observer
- Process-hollowing detection is path-based only, not actual PE/memory-image comparison
- Registry persistence watch list covers only the standard `Run`/`RunOnce` keys — no COM hijacking, service-DLL hijacking, or `AppInit_DLLs` coverage

**RF / spectrum boundaries**
- The monitor traces every emitter the host can **physically observe** — it cannot hear spectrums it has no receiver for. Zigbee/Z-Wave/NFC/sub-GHz traffic is only detectable with matching SDR or dongle hardware; the coverage matrix reports these as unavailable rather than fabricating data
- RSSI→distance is an approximation from a path-loss model (±tens of meters indoors is normal) — the UI labels it as estimated, and precise fixes require 3+ cooperating sensors in `rf_sensors` or an observation file feed
- Live BLE advert scanning needs the optional `bleak` library; wideband sweeps need external SDR tools (`rtl_power`, `hackrf_sweep`, etc.) — all are auto-detected and reported, none are bundled
- The L2 wire census (per-MAC emitter tracing) requires packet capture — without Npcap/admin, that medium sees nothing
- Wi-Fi BSSID scanning depends on `netsh wlan` — Windows-only; a wired-only or non-WLAN host reports the Wi-Fi rows honestly as unavailable

**Platform coverage**
- 8 of 8 anti-hack background monitors, and most of the 9 process checks that depend on Windows-specific data, are **Windows-only** (they shell out to `sc`, `wmic`, `schtasks`, `net user`, `netsh`, `wevtutil`, or use `winreg`/WinAPI directly)
- Linux gets process/connection/DNS/GeoIP/VPN-detection only — a real, useful subset, but roughly 24 of the ~33 named detections don't run
- macOS has no dedicated monitoring code at all

**Response & alerting**
- The only containment action is a manual "Block IP" firewall-rule button — no automatic process kill, quarantine, or network isolation
- No out-of-band alerting (email, Slack/Discord, push, SMS) — SIEM file/syslog output is the only notification path, and requires something else to be watching it
- VirusTotal integration is opt-in via the `VT_API_KEY` environment variable only, with no CLI flag or GUI field, and the free API tier (4 req/min) is far below real-time process-creation rates
- The desktop GUI has no authentication of its own

**Persistence & operations**
- The SQLite database has exactly 2 tables (`deductions`, `devices`) — connections, processes, and every Tier-5 monitor event live only in text logs, not in a queryable database
- Statistical behavioral baselines are in-memory only and reset on every restart
- No `requirements.txt`/`pyproject.toml` with pinned dependency versions
- No CI or automated test gate — the 7 suites must be run by hand
- Threat-intel lists (LOLbins, exfil domains, malware mutexes, VPN ASN markers) are hardcoded source constants with no update mechanism

**Boundaries by design, not gaps**
- TLS payload content is never decrypted — only SNI/JA4/certificate metadata is visible
- The monitor never attacks, scans, or de-anonymizes anything remote
- GeoIP defaults to free third-party HTTP APIs unless you supply a local MaxMind database

The exhaustive, code-cited version of every item above — with the exact evidence used to confirm it — is in [`total_features.md` §41-42](total_features.md#41-known-gaps-missing-features--platform-coverage).

---

## Project Files

| File | Purpose |
|------|---------|
| `medianbox_monitor_v2.py` | The application — everything lives in this one file |
| `_test_antihack.py` | 41-test anti-hack detection suite |
| `_test_vpn_leak.py` | 32-test VPN leak detection suite |
| `_test_vpn_detection.py` | VPN/proxy false-positive rate test |
| `_test_location_accuracy.py` | MultiVerifier location accuracy test |
| `_test_data_wiring.py` | Live-traffic test that harvested data reaches the connection record |
| `_test_gui_render.py` | Renders all 18 real Tk tabs against live data |
| `_test_ui_smoke.py` | ~180-check full GUI smoke pass (every tab, chips, Signals fields) |
| `_test_gatecrasher.py` | 68 checks — IKE/PROX/TLSALT/BANNER/IPID + gateway verification methods |
| `_test_wireproof.py` | 1,560 checks — silent-tunnel & non-IP-channel evidence rows |
| `_test_click_actions.py` | Fires real click events at the GUI's interactive controls |
| `_test_map_declutter.py` / `_test_map_default_view.py` | Map viewport + declustering tests |
| `_test_perf_profile.py` | cProfile harness for the render pipeline |
| `_test_ui_shot.py` / `_test_ui_shot_sys.py` | GUI screenshot tools |
| `_audit_fields.py` / `_audit_ui.py` | Static audits — no produced field lacks a render path |
| `README.md` | This file — entry point, quick start, ratings, gaps |
| `about.md` | The pitch — problem, philosophy, what it catches, full limitations |
| `overview.md` | Architecture — threads, data flow, GUI/dashboard detail, performance design |
| `total_features.md` | The exhaustive reference — every deduction, monitor, class, config key, and the full gap audit |
| `antihack.md` | Anti-hack feature gap analysis and integration map (earlier working doc) |
| `informational.md` | Original feature reference from an earlier version |
| `sessions/` | Auto-created, time-segmented save files |
| `medianbox_*.log` | Rotating structured/actions/deductions logs |
| `medianbox_ultimate.db` | SQLite database (deductions + devices only) |

---

## Design Philosophy

**Deductive, not just heuristic.** Every alert carries a full evidence chain — process name, PID, parent, command line, destination, domain, country, and the specific rule that fired — not a bare "suspicious" label.

**Defense in depth.** No single detection method is trusted. Process behavior, network connections, DNS, GeoIP, the registry, the filesystem, loaded DLLs, memory, Windows event logs, and 18 anti-hack heuristics are all cross-referenced. Evading one detection doesn't mean evading all of them.

**No single source of truth for location.** The MultiVerifier cross-checks IP geolocation with 11 core independent methods plus 200+ named wire-evidence checks (228 total today). Disagreement between them is *itself* reported as a VPN/proxy signal, with an honest confidence grade (A-F, or `UNVERIFIED` when the evidence doesn't support a grade) rather than a false-confidence single answer.

**Fails visibly, degrades gracefully.** Missing Npcap, missing admin rights, an unreachable GeoIP API, a missing optional library — none of these silently stop data collection. The monitor logs what's missing and continues with what it has.

Full philosophy and worked examples: [`about.md`](about.md).

---

## Scope & Non-Goals

This is a **local, defensive** security monitoring tool. It helps you detect a hacker who has gained access to your machine, fileless malware using living-off-the-land binaries, a leaking VPN, C2 beaconing, credential dumping, lateral movement, and installed persistence — and it records everything for later forensic review.

It is **not**: a network scanner, a firewall replacement, an antivirus replacement, a tool for de-anonymizing remote VPN users, or anything with an offensive capability. It watches your own machine and tells you, with evidence, what it sees.

---

## Further Reading

- **[`about.md`](about.md)** — the pitch: the problem, the design philosophy, what it catches, and the full limitations/ratings discussion in prose form
- **[`overview.md`](overview.md)** — the architecture: thread model, data flow, every GUI tab and dashboard endpoint in detail, performance design, ratings tables
- **[`total_features.md`](total_features.md)** — the exhaustive reference: every one of the 16 core deductions, 18 anti-hack checks, 8 background monitors, 7 enhanced checks, and the full spectrum/RF subsystem individually documented with technique, evidence, and score; every class; every config key; the full 42-section gap audit with code-line citations
