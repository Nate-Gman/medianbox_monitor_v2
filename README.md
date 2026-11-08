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

It is **local-only and defensive-only**. It does not attack remote systems and does not upload your data anywhere except the minimal IP-lookup calls needed for GeoIP enrichment (which can be disabled with `--no-geoip`, or redirected to a local MaxMind database with `--geoip-db`).

On identifying parties behind VPN/Tor/CDN endpoints: the tool implements every channel that can legitimately produce the answer — endpoint self-disclosure, protocol leaks, induced leaks (canary/WebRTC/DNS/ETag), injected flow watermarks, second-vantage correlation ingest, and operator-records requests — and reports each channel's state honestly (`armed` / `REVEALED` / `BLOCKED` / `needs a second vantage`). It recovers the subscriber **whenever a channel produces evidence**; when none does, it says precisely why instead of guessing. See [Tracing Behind VPN/Tor/CDN](#tracing-behind-vpntorcdn--the-logic-proof) for the full argument.

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

`requirements.txt` pins the versions the test suites were run against: `pip install -r requirements.txt`. There is no `pyproject.toml` or hash-locked lockfile yet.

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
Install [Npcap](https://npcap.com/) with "WinPcap API-compatible mode" checked during setup. Without it the monitor prints a red startup notice ("Npcap is NOT installed - packet-level detection ... is DISABLED") and continues on process/connection data alone.

---

## CLI Reference

```
python medianbox_monitor_v2.py [options]

  --config, -c PATH          Load a YAML config file (overrides CONFIG defaults)
  --no-dashboard             Disable the FastAPI web dashboard
  --no-geoip                 Disable GeoIP lookups entirely (privacy mode)
  --siem json|cef|syslog|splunk_hec|elastic   Enable SIEM output (HTTP formats need --siem-url)
  --siem-url URL / --siem-token TOKEN         Endpoint and credential for splunk_hec / elastic
  --alert-webhook URL        Slack/Discord/Teams/generic webhook for CRITICAL findings
  --alert-min-severity S     INFO|WARNING|CRITICAL (default CRITICAL)
  --auto-response MODE       off (default) | dry_run | suspend — reversible containment
  --vt-key KEY               VirusTotal API key (else VT_API_KEY env var)
  --trace IP_OR_HOST         Reverse trace and exit: owner, ASN, abuse/legal contacts, TLS cert, AS-annotated path,
                             local owning process, and the same trace carried on to the operator (VPN/proxy/Tor/CDN/cloud)
  --trace-no-probe           With --trace: registry/DNS/BGP only, never connect to the target
  --trace-deep               With --trace: also run the full MultiVerifier (ACTIVE probes of the target)
  --trace-no-pivot           With --trace: stop at the endpoint, do not continue at the operator
  --trace-json / --trace-out FILE   Structured JSON output / also write the report to FILE
  --trace-draft FILE         With --trace: write a ready-to-send abuse-report / records-request e-mail to the
                             operator (RDAP + security.txt contacts, evidence packet) — the lawful route to the
                             party behind a VPN/proxy/Tor/CDN endpoint
  (every report also carries an OPERATOR-SIDE TRACE section: when this host is the operator — VPN
   listeners, tunnel interfaces, IP forwarding — the section resolves the pre-tunnel client from the
   socket table, NAT/conntrack table and DHCP leases; otherwise it says where the record lives,
   plus an ACTIVE REVERSE PROBE section: banner grab, HTTP disclosure headers, MSS/path tunnel
   detection, ICMP hop-distance/OS-class, neighbor-port posture, self-signed TLS cert identity)
  --canary PORT              Callback/de-mask HTTP listener: mints /c/<tok> (plain callback),
                             /d/<tok> (de-mask page — WebRTC ICE + fingerprint harvest, POSTs back),
                             /s/<tok> (ETag+cookie session-link pixel), /l/<tok> (leak intake),
                             /f/<tok> (second-vantage flow-correlation ingest). With --trace: every
                             traced endpoint gets all of them minted automatically
  --demask-dns ZONE          Authoritative DNS responder for ZONE on UDP :53 — the RESOLVER that
                             queries <tok>.ZONE is the client's real DNS egress; EDNS client-subnet
                             options name the client network itself
  --trace-matrix FILE        Trace every IP/host in FILE and print the per-channel
                             identity-recovery matrix (checked vs revealed per channel)
  --trace-fuzz N             Mutation-fuzz every wire parser N iterations (crash-proofing)
  --identify-probe SECONDS   Run the real pipeline for SECONDS, then report how many live public
                             connections remain unidentified — the measurable identification rate
  --port PORT                Web dashboard port (default 8470)
  --workers N                Packet pipeline worker thread count (default 4)
  --dashboard-password PASS  Require this token to access the web dashboard
  --geoip-db PATH            Path to a local MaxMind GeoLite2-City.mmdb file
  --no-gui                   Run headless — no Tkinter window, terminal output only
```

Email alerting (SMTP) and the finer alert/response thresholds are configured through the YAML config (`alert_*`, `auto_response_min_score`, `ml_baseline_file`, ...); see `total_features.md` section 43.

---

## Tracing Behind VPN/Tor/CDN — the logic proof

The question "can you find who is behind a VPN exit / Tor relay / CDN edge?" has a precise answer that the tool now encodes channel by channel:

**A masked endpoint is a trust boundary, not a math boundary.** A VPN or Tor exit emits only provider-side packets — you cannot send it a packet that returns the subscriber, because the exit does not have the subscriber to give. That is the negative half of the theorem. The positive half: **every working de-masking method in the published literature does one of exactly three things, and all three are implemented:**

1. **The client's own stack emits the answer.** Tunnels hide the route, not the client software. Implemented channels:
   - *Induced leak* — `--canary PORT` mints `/d/<tok>`, a page whose JavaScript runs WebRTC ICE gathering; on a misconfigured or leaking client the `srflx`/`host` candidate **is the pre-tunnel address**, POSTed back to `/l/<tok>` and recorded as a `webrtc/ice leak` origin. The plain `/c/<tok>` callback catches a fetcher that bypasses its tunnel entirely (torrents, direct-fetch apps, `curl`).
   - *DNS resolver egress* — `--demask-dns ZONE` binds an authoritative responder on UDP :53; the resolver that queries `<tok>.ZONE` is the client's real DNS path, and the EDNS client-subnet option (when forwarded) names the client network itself.
   - *Passive leaks already on the wire* — PROXY protocol, X-Forwarded-For/`Forwarded`, SIP Via/Contact/SDP, FTP PORT/EPRT embedded addresses, STUN reflexive addresses, tunnel-inner decapsulation (IPIP/GRE/GTP/VXLAN), IPv6-transition embedded IPv4, EDNS client subnet. Each leaked address is re-attributed through PTR+Cymru.
   - *Session-fingerprint linkage* — `/s/<tok>` sets an ETag+cookie; `SessionRegistry` hashes the browser fingerprint and links every egress it appears from. Same fingerprint at a VPN exit and a residential IP = one client, proven by the client's own entropy.

2. **A second vantage point closes the loop.** Tunnels preserve packet *shape* even though they hide content:
   - *Injected watermark* — `/d/` responses are chunked on a deterministic pacing schedule (`_wm_gaps(token)`); the rhythm survives the tunnel.
   - *Local-wire correlation* — the sniffer continuously feeds every observed per-flow gap series (`_flowstats`) into `FLOWCORR`; a shape match ≥ 0.72 marks the flow as the watermarked one — the two observation points are joined.
   - *External vantage ingest* — `POST /f/<tok>` accepts `{gaps:[ms…]}` from a cooperating vantage (ISP NetFlow, a second monitor, an accomplice at the entry side) and returns the correlation score. This is the DeepCorr/DREAMER-class method, implemented as data-in/match-out.
   - *Operator records* — the exit operator's connection logs are the one record that always exists; `--trace-draft` writes the evidence packet + records request citing IP, port and timestamp.

3. **We own a second point in the path.** Where infrastructure is legitimately ours:
   - *Local relay observation* — `_tor_relay_observe()` detects a tor process on this host and lists inbound OR-port clients: a relay we run sees the entering client directly.
   - *Sybil census* — `our_tor_relays[]` fingerprints are matched against live Onionoo data; when we cover both entry and exit of a circuit, the correlation is ours alone (the method guard-pinning was designed to resist — documented, not automated).
   - *Guard population model* — `tor_guard_census()` fetches the consensus weights: a client known to enter through guard G is narrowed to G's share of ~2M daily clients — real probabilistic localization.
   - *Operator-side trace* — run on the VPN provider's own host, the tool resolves the pre-tunnel client directly from the socket table, NAT/conntrack and DHCP leases.

**What is deliberately not implemented:** server compromise, client compromise, and protocol-subversion attacks appear in every report as `BLOCKED` channels naming the lawful substitute — present as documented boundaries, never executed.

**The honest remainder.** When the subscriber never touches anything you control, never leaks, and you hold no vantage and no relay, the subscriber record exists only at the operator — and the report says exactly that per channel rather than guessing. That residue is a protocol boundary, not a missing feature: it is the only part of the space where the information provably does not exist on your side of the wire.


---


## Fighting trafficking, drug markets & dark-web infrastructure

The de-masking engine exists because hidden services hide *addresses*, not *physics*. Its channels map onto real investigative workflows against criminal infrastructure:

- **Attributing hidden-service infrastructure.** A dark-web market or trafficking forum that reaches the clearnet through a Cloudflare edge, a bulletproof hoster, or a VPN gateway is still a sequence of traceable operators. `--trace` names each one concretely — relay fingerprint and operator contact for Tor nodes, ISP/ASN/holder for gateways, provider feed + verified origin for CDN tenants — and `--trace-draft` produces the evidence packet a records request or takedown notice needs (endpoint, port, timestamp, operator contacts). This is the workflow analysts run manually, automated.
- **Finding the real server behind the CDN front.** Criminal storefronts park behind Cloudflare/Akamai for exactly this reason — the edge IP is a dead end. The origin hunt cross-references passive-DNS history, certificate-transparency names, MX/SPF records and subdomain tables, then *verifies* candidates against the origin's own certificate and served content — candidate → strong → verified → confirmed tiers, never a guess.
- **Unmasking operators and buyers at controlled endpoints.** When investigators lawfully control an endpoint the suspect touches — a seized market's login page, an undercover listing, a honeypot drop site — the de-mask suite does the rest: a `/d/<tok>` page whose WebRTC harvest returns the pre-tunnel address on a leaking client, a canary URL that reports the fetcher's real egress, an ETag session link that joins the same fingerprint across different exits, and a DNS authority (`--demask-dns`) that captures the suspect's real resolver path including EDNS client-subnet.
- **Correlating flows across the tunnel.** Tunnels hide payloads, not packet *shape*. Responses served to a suspect carry an injected pacing watermark; the sniffer continuously scores every observed flow against it, and `POST /f/<tok>` accepts observations from a cooperating vantage (an ISP's NetFlow under legal process, a second sensor). A ≥0.72 match joins the entry side and exit side — the technique published as flow watermarking / DeepCorr, run as a feature.
- **Narrowing a suspect inside the Tor user population.** `tor_guard_census()` computes each guard's share of the ~2M-user client population from consensus weights; knowing a suspect's guard preference narrows them to that share. Investigators running their own relays (`our_tor_relays[]`, verified against Onionoo) gain the entry-side view directly; a local relay's inbound OR-port clients are listed by `_tor_relay_observe()`.
- **The lawful floor, built in.** Where the wire genuinely cannot produce the answer — a disciplined suspect who never touches a controlled endpoint — the report says so per channel and pivots to the one record that always exists: the operator's connection logs, reached through the drafted records request. And the channels it refuses to implement (server compromise, client compromise, protocol subversion) appear in every report as `BLOCKED` with the lawful substitute named — the tool is built for the evidence chain, not around it.


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
| `_test_unmask_v2.py` | 38 | Full de-mask engine: widened real-client headers, generic DNS records, IKE/OpenVPN/TURN gate probes, CDN origin hunt + verification tiers, open-proxy relay egress, self-naming battery, coverage matrix, parser fuzz harness, watermark codec (`_wm_gaps`/`wm_correlate`), FlowCorrelator inject/match/reject, SessionRegistry cross-egress linkage, de-mask page binding, all-8-tier channel presence, WebRTC-leak→origin, Tor channels, guard-census parse, sybil census, relay observe |
| `_test_attribution.py` / `_test_attribution_v2.py` | 30 | Identification chain, address decoding, fake-resolver DNS/Cymru, provider ranges, socket-owner recovery, LAN/loopback naming, operator-pivot trace |
| `_test_identify_v3.py` | — | Live identification chain incl. pDNS first-call queueing |
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
python -m pytest _test_unmask_v2.py   # 38 de-masking-engine tests — offline
python medianbox_monitor_v2.py --trace-fuzz 300000   # parser crash-proof
python medianbox_monitor_v2.py --identify-probe 60   # live unresolved count
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
| **A+** | Grade A, and every remaining limit is an OS/protocol boundary (not missing code) that is measured live and stated |
| **A** | Fully implemented, cross-platform where relevant, verified against live data |
| **B** | Fully implemented on Windows, solid, but static rule lists or single-platform |
| **C** | Real structural limitation — opt-in, rate-capped, or degrades without an optional dependency |
| **D** | Present but materially incomplete relative to what the name implies |
| **F** | Not implemented |

| Subsystem | Grade |
|-----------|-------|
| Network & connection monitoring | **A+** (every peer named by an evidenced chain: DNS/SNI, rDNS, TLS cert, VPN-provider feeds, provider-published ranges, RDAP/Cymru owner, loopback/LAN peer process, ownerless sockets traced back to their owner; live run 2026-11-08 on the dev host: of 260 connections not generated by the monitor's own probes, 0 public peers unresolved, every loopback/LAN peer named, and ownerless TIME_WAIT sockets cut from 196 to 6 (the 6 are public sockets that closed between 0.5 s mapper ticks; their remote service is still named)) |
| Reverse tracing / attribution (`--trace`) | **A+** (owner, ASN, contacts, annotated path, local owner, operator pivot, evidence packet; **disclosure surface**: CHAOS DNS self-ID + resolver-egress echo, NTP readvar, page title/meta, co-tenant vhosts, CT names, DB history; **client de-masking**: every channel to the party behind a relay — XFF/PROXY-protocol/SIP/FTP/STUN/tunnel-inner/EDNS leaks, shared-state alias links, optional `--canary` callback — is checked live and its result stated; verified live on 1.1.1.1 and a Tor exit; the only residue is the operator-held client record — a protocol boundary the report itself measures and states) |
| VPN/proxy detection | **A-** |
| GUI (18 tabs) | **A-** |
| GeoIP & MultiVerifier (228 evidence methods) | **B+** |
| Data export & session recording | **B+** |
| Core deductions + anti-hack process checks | **B** |
| Spectrum/RF & L2 signal intelligence | **B** (host-observable media only; hardware-limited bands show as unavailable) |
| Web dashboard | **C+** |
| Packet analysis / JA4+ / SNI | **B-** (explicit startup notice when Npcap/libpcap is missing; still needs the driver) |
| Process profiling & forensics | **B-** (Authenticode verdicts, `--vt-key`) |
| Behavioral & statistical/ML | **B-** (baseline persisted across restarts) |
| Anti-hack background monitors (8) | **C** (Windows-only) |
| System & persistence monitoring | **C** (Windows-only) |
| Hardware & peripheral monitoring | **C** (Windows-only) |
| Firewall & IP blocking | **C** |
| SIEM output | **B-** (JSON/CEF/syslog + Splunk HEC + Elastic; connectors not yet live-verified) |
| Database & logging | **C** (deductions, devices, connections persisted) |
| Threat-intel freshness | **C+** (provider ranges, VPN exit lists and Tor relay data now refresh from the operators' own feeds; LOLbin/mutex/exfil lists are still static source constants) |
| Cross-platform coverage | **D** (Linux ~9/33 detections; macOS unsupported) |
| Packaging / reproducibility | **B-** (pinned requirements.txt + CI workflow, not yet run on GitHub) |
| Signature / YARA / code-signing detection | **C** (Authenticode on Windows; YARA not implemented) |
| Automated response / containment | **B** (opt-in reversible suspend; no isolation) |
| Out-of-band alerting | **B+** (webhook + email; no push/SMS) |

Full per-item rationale with code-line citations: [`overview.md`](overview.md#feature-completeness-ratings) and [`total_features.md`](total_features.md#42-completeness-ratings-by-category).

---

## Known Gaps — What's Missing

**Detection method gaps**
- Authenticode verification is Windows-only and covers processes using public IPs; `ProcessLegitimacyChecker` itself still checks only path and parent
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
- Automatic containment is opt-in and limited to reversible process suspend — no quarantine or network isolation; "Block IP" stays manual
- Alerting covers webhook and email only (no push/SMS), and has not yet been exercised against live Slack/Discord/SMTP endpoints
- VirusTotal takes `--vt-key` or `VT_API_KEY` but has no GUI field, and the free API tier (4 req/min) is far below real-time process-creation rates
- The desktop GUI has no authentication of its own

**Persistence & operations**
- The SQLite database has 3 tables (`deductions`, `devices`, `connections`) — processes, RF emitters and Tier-5 monitor events still live only in text logs
- No `pyproject.toml` / hash-locked lockfile; the GitHub Actions workflow is written but has not been run on GitHub yet
- Threat-intel lists (LOLbins, exfil domains, malware mutexes, VPN ASN markers) are hardcoded source constants with no update mechanism (address-range, VPN-exit and Tor data do refresh: `ProviderRangeDB`, exit feeds, Onionoo)
- A socket that opens and closes between two 0.5 s connection-mapper ticks is reported by Windows as an ownerless TIME_WAIT entry; the owner is recovered from socket history, from the live listener it was accepted on, or (marked *inferred*) from the last owner of that remote endpoint. What none of those catch stays labelled `owner exited before it was observed`

**Boundaries by design, not gaps**
- TLS payload content is never decrypted — only SNI/JA4/certificate metadata is visible
- The monitor never attacks or de-anonymizes anything remote. `--trace` attributes an endpoint to its registered operator and then **continues at the operator** (its domains, security.txt, announced prefixes, BGP neighbours, Tor relay family, an infrastructure trace of its own servers, and an evidence packet to cite in an abuse report or lawful request). For VPN/proxy/Tor/CDN endpoints that is where public data ends: the client behind the endpoint exists only in the operator's records
- GeoIP defaults to free third-party HTTP APIs unless you supply a local MaxMind database

The exhaustive, code-cited version of every item above — with the exact evidence used to confirm it — is in [`total_features.md` §41-42](total_features.md#41-known-gaps-missing-features--platform-coverage).

---

## Project Files

| File | Purpose |
|------|---------|
| `medianbox_monitor_v2.py` | The application — everything lives in this one file |
| `_test_antihack.py` | 41-test anti-hack detection suite |
| `_test_vpn_leak.py` | 32-test VPN leak detection suite |
| `_test_attribution.py` / `_test_attribution_v2.py` | 30 offline tests: identification chain, address decoding, pure-Python DNS/Cymru against a fake resolver, provider ranges, socket-owner recovery, LAN/loopback naming, operator-pivot trace |
| `_live_identify_probe.py` | Live coverage check: how many real connections remain unidentified (`--dump file.json`) |
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
