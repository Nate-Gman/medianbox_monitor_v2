# MedianBoxMonitor 3.0

**A local, defensive security monitoring application that watches every process, every connection, and every system event on your machine in real time — and shows its work.**

Single-file Python application (~17,150 lines). Windows-primary, Linux-partial. No offensive capability, no remote scanning, no phoning home.

```
python medianbox_monitor_v2.py
```

That's it — a Tkinter GUI opens with 16 tabs of live data, a background thread starts a web dashboard on `http://127.0.0.1:8470`, and the deductive engine starts reasoning about every process on your machine.

---

## Table of Contents

1. [What This Is](#what-this-is)
2. [Quick Start](#quick-start)
3. [Installation](#installation)
4. [CLI Reference](#cli-reference)
5. [What It Catches](#what-it-catches)
6. [Architecture at a Glance](#architecture-at-a-glance)
7. [The GUI](#the-gui)
8. [The Web Dashboard](#the-web-dashboard)
9. [Data It Saves](#data-it-saves)
10. [Testing](#testing)
11. [Feature Completeness Ratings](#feature-completeness-ratings)
12. [Known Gaps — What's Missing](#known-gaps--whats-missing)
13. [Project Files](#project-files)
14. [Design Philosophy](#design-philosophy)
15. [Scope & Non-Goals](#scope--non-goals)
16. [Further Reading](#further-reading)

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

- Opens the GNA Tracer GUI (16 tabs, see below)
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
├── MultiVerify Worker Pool (4)  — VPN/proxy/infra cross-verification (11 methods),
│                                   priority queue, covers every public endpoint
├── Extended Monitor Thread      — 16 monitors on 2-60s intervals (clipboard, USB,
│                                   scheduled tasks, named pipes, inbound scans,
│                                   Bluetooth, serial, proxy, VPN leak, + 8
│                                   Windows-only anti-hack background monitors)
├── Memory Forensics Thread      — RWX memory-region scan every 15s (admin)
├── Packet Pipeline (4 workers)  — SNI/DNS/JA4+/entropy extraction (admin + Npcap)
├── ARP Scanner + Sniff Threads  — device discovery, raw packet capture (admin + Npcap)
├── FastAPI Dashboard Thread     — web server on port 8470
└── GUI Refresh                  — adaptive interval (~250ms target)
```

11+ threads at baseline, more with admin + Npcap. Every shared data structure either uses its own lock or is replaced atomically (never mutated in place) so the process watcher can read a reference without copying. Full detail in [`overview.md`](overview.md#thread-architecture).

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

## The GUI

A 16-tab Tkinter interface (`GNATracerGUI`):

| Tab | What's in it |
|-----|---------------|
| Overview | Summary stats, anti-hack pin summary, high-risk processes, proxy list |
| Live Connections | Active/established connections only, collapsible rows, VPN/proxy badges inline |
| All Connections | Every connection, full detail (GeoIP, ASN, rDNS, timezone, MultiVerifier verdict, location proof) |
| Deductions | All alerts with severity, category, and full evidence chain |
| Processes | Every tracked process — risk score, CPU%, memory, I/O, command line, DNS domains, behavioral flags |
| Devices | ARP-discovered network devices — IP, MAC, vendor, hostname, OS guess |
| IP Map | Slippy-tile world map with geolocated, color-coded, risk-scored IP markers (needs Pillow) |
| Actions Log | Raw process action log |
| Terminal | Live color-coded terminal output, 10,000-line rolling buffer |
| Suspicious Activity | Out-of-norm events only |
| Blocked IPs | Manual firewall block/unblock management |
| Process Tree | Hierarchical parent/child process tree with risk scores |
| Net Stats | Per-interface bandwidth |
| Timeline | Connection lifecycle timeline (active + closed, with duration) |
| Config | Live-editable, type-validated configuration |
| Double Trace | VPN double-trace / full MultiVerifier verification view |

As of the 2026-08-22 audit, every tab renders every field the backend actually collects (previously ~22 harvested fields — ASN, timezone, rDNS, RTT, TTL/OS, the full VPN/proxy verdict — were computed and then silently discarded before reaching the screen). The Live and All Connections tabs were also reworked for performance: embedded per-row `tk.Button` widgets (which Tk destroys and recreates on every refresh) were replaced with clickable text spans, cutting the Live tab's refresh time roughly 75x (~2,540ms → ~34ms at 250 expanded rows).

**The desktop GUI has no authentication of its own** — anyone with access to the desktop session sees everything while it's open.

---

## The Web Dashboard

FastAPI + WebSocket server on port 8470 (configurable via `--port`, disabled via `--no-dashboard`, optionally password-protected via `--dashboard-password`):

- `GET /` — full HTML dashboard, dark-themed, 5 tabs (Connection Map, All Connections, Deductions, Processes, Devices)
- `GET /api/state` — JSON snapshot of the complete dashboard state
- `WS /ws` — pushes the full state every 3 seconds for live updates

It's a lighter, browser-accessible subset of the desktop GUI's 16 tabs — served over plain HTTP (no TLS).

---

## Data It Saves

Every 10 minutes (and on close), a complete plain-text session snapshot is written to:
- `sessions/YYYY-MM-DD/session_HHMM_HHMM.txt` — organized by date and time segment
- `Desktop/GNA tracer data {N}.txt` — flat, numbered, backward-compatible

Each snapshot has 25+ sections: overview stats, every connection individually, every deduction with its full evidence chain, every process, every device, the complete raw action log, all IPs with geolocation, suspicious activity, the "sneakiest connections" (anti-hack-flagged endpoints), all 8 anti-hack monitors' events, VirusTotal results, file-system/clipboard/USB/scheduled-task/named-pipe/inbound-scan/DoH/TLS-cert events, the connection timeline, network bandwidth, Bluetooth/serial devices, and the full terminal output.

**Structured logs** (rotating, 50MB × several backups): `medianbox_structured.log`, `medianbox_full_actions.log`, `medianbox_deductions.log`.

**SQLite** (`medianbox_ultimate.db`) persists only `deductions` and `devices` — connections, processes, and every Tier-5 monitor event exist only in the text logs above, not in a queryable database. See [Known Gaps](#known-gaps--whats-missing).

**SIEM output** (`--siem json|cef|syslog`) can additionally stream deductions to a file or UDP syslog endpoint for ingestion elsewhere.

---

## Testing

Seven test suites — four verify detection logic, three (added 2026-08-22) verify that what the detection logic produces actually reaches the user, which is a distinct and previously untested question.

| Suite | Tests | Verifies |
|-------|-------|----------|
| `_test_antihack.py` | 41 | Every anti-hack detection path fires on a simulated attack technique, and does *not* fire on the matching benign case |
| `_test_vpn_leak.py` | 32 | DNS/IPv6/route/WebRTC VPN leak detection |
| `_test_vpn_detection.py` | — | VPN/proxy detection across 1,100 synthetic endpoints: 100% detection rate, 0% false positives |
| `_test_location_accuracy.py` | — | MultiVerifier location accuracy across all 11 cross-verification methods: 100% country accuracy |
| `_test_data_wiring.py` *(new)* | 35 | Runs the real monitor against live traffic; asserts every harvested field (GeoIP, ASN, rDNS, RTT, VPN verdict) reaches the connection record for 100% of public IPs, and no payload key is built and never read |
| `_test_gui_render.py` *(new)* | — | Builds the real Tkinter window offscreen, renders all 16 tabs against live data, asserts zero exceptions and zero stale placeholders |
| `_test_click_actions.py` *(new)* | 9 | Fires real `<Button-1>` events at the GUI's interactive controls to verify the button→text-span performance rework didn't break interactivity |

```bash
python _test_antihack.py
python _test_vpn_leak.py
python _test_vpn_detection.py
python _test_location_accuracy.py
python _test_data_wiring.py          # takes ~90-120s — runs live threads
python _test_gui_render.py           # takes ~60-90s — builds a real Tk window
python _test_click_actions.py
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
| GUI (16 tabs) | **A-** |
| GeoIP & MultiVerifier | **B+** |
| Data export & session recording | **B+** |
| Core deductions + anti-hack process checks | **B** |
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
| `_test_data_wiring.py` | *(new)* Live-traffic test that harvested data reaches the connection record |
| `_test_gui_render.py` | *(new)* Renders all 16 real Tk tabs against live data |
| `_test_click_actions.py` | *(new)* Fires real click events at the GUI's interactive controls |
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

**No single source of truth for location.** The MultiVerifier cross-checks IP geolocation with 11 independent methods. Disagreement between them is *itself* reported as a VPN/proxy signal, with an honest confidence grade (A-F, or `UNVERIFIED` when the evidence doesn't support a grade) rather than a false-confidence single answer.

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
- **[`total_features.md`](total_features.md)** — the exhaustive reference: every one of the 16 core deductions, 18 anti-hack checks, 8 background monitors, and 7 enhanced checks individually documented with technique, evidence, and score; every class; every config key; the full 42-section gap audit with code-line citations
