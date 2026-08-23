# MedianBoxMonitor 3.0 — Overview

**File:** `medianbox_monitor_v2.py` — single-file Python security monitoring application (~16,500 lines)
**Platform:** Windows (primary), Linux (partial)
**Python:** 3.13+
**Dependencies:** psutil, scapy, tkinter, FastAPI/Uvicorn (optional), Pillow (optional), manuf (optional), geoip2 (optional)

---

## What It Is

MedianBoxMonitor 3.0 is a **real-time network security monitoring application** that runs on your local machine and watches every process, every network connection, and every system event to detect hackers, malware, intruders, and anomalous behavior — as it happens.

It is not a network scanner. It is not a firewall. It is a **digital witness** that sits inside your operating system, observes everything that processes do, and reasons about whether those actions are legitimate or malicious — using a deductive evidence engine that produces auditable proof chains for every alert.

---

## What It Does

### 1. Watches Every Process

The monitor enumerates all running processes every 0.5 seconds via `psutil.process_iter()`. For each process it builds a `ProcessProfile` containing:

- Process name, PID, executable path, parent process name and PID
- CPU usage samples (60-sample rolling window)
- Network connection count and destination set
- DNS domains queried by the process
- SNI domains from TLS handshakes
- GeoIP countries contacted
- Loaded DLLs (scanned every 30s)
- I/O byte counters and transfer rates
- Risk score (0-100+, decays at 0.3%/cycle)
- ML anomaly score (Z-score over 24h baseline)
- Memory forensics flags (RWX regions, injected modules)
- Start time and last network activity timestamp

### 2. Watches Every Connection

A dedicated connection mapper thread calls `psutil.net_connections(kind='all')` every 0.5 seconds and builds two indexes:

- **`conn_by_pid`** — maps every PID to its list of connections
- **`conn_by_raddr`** — maps every remote IP to the owning PID and connection object

A `ConnectionInventory` thread enriches each connection with:
- Service identification (via `ServiceResolver` — reverse DNS, port heuristics, domain matching)
- GeoIP data (country, city, coordinates, ISP, organization — via background worker to avoid blocking)
- Proxy detection (TCP fingerprinting, known proxy port patterns)
- Domain resolution (via `DNSCache` — tracks every DNS query-to-IP mapping)
- First-seen / last-seen timestamps
- Connection duration and bandwidth usage
- Location verification proof chain

### 3. Watches Every DNS Query

A `DNSCache` tracks every DNS query and response, building a bidirectional map:
- Domain → resolved IPs
- IP → domains that resolved to it

This lets the monitor attribute a connection to `discord.com` even when the connection itself only shows a raw IP address. A `DNSTunnelingDetector` watches for DNS exfiltration (high-entropy subdomains, long labels, high query rates). A `DoHDetector` flags connections to known DNS-over-HTTPS servers (Cloudflare 1.1.1.1, Google 8.8.8.8, etc.) which bypass local DNS monitoring.

### 4. Watches Every Packet (When Admin)

When run with administrator privileges, a packet sniffer thread uses Scapy to capture layer-2 traffic. Packets flow through a `PacketPipeline` with 4 worker threads that:
- Extract SNI (Server Name Indication) from TLS ClientHello
- Extract DNS queries from UDP port 53
- Compute JA4+ TLS fingerprints
- Measure entropy of packet payloads
- Feed extracted metadata back to the process profiles

When Npcap/WinPcap is not installed, the monitor continues operating on process and connection data alone — packet capture is an enhancement, not a dependency.

### 5. Reasons About Everything

The deductive chess engine runs 16 core deductions every process-watcher cycle (0.5s), each producing an evidence chain:

| Deduction | What It Detects |
|-----------|----------------|
| Mimic | Process connecting to IPs that mimic a known legitimate service |
| Foreign | Process connecting to an unexpected foreign country |
| Behavioral Anomaly | Process behavior deviating from its own baseline |
| Beacon | Regular interval connections (C2 beaconing) |
| Impersonation | Process running from a non-legitimate path or with wrong parent |
| Phantoms | ESTABLISHED connections with no owning process |
| Injection Chain | Known app spawning unknown children with many connections |
| DNS Tunneling | DNS queries with exfiltration signatures |
| Exfiltration | I/O byte spike exceeding 10x baseline |
| DLL Injection | Suspicious modules loaded into process memory |
| Persistence | Registry run keys, scheduled tasks, startup folder changes |
| Idle Anomaly | Network activity while user is idle |
| ML Anomaly | Statistical Z-score deviation over 24h window |
| GeoIP Risk | Connection to high-risk country (CN, RU, KP, IR) |
| Watchlist | Connection to user-defined watched IP or process |
| Verification | MultiVerifier cross-check disagreement on location |

### 6. Catches Hackers (18 Anti-Hack Features)

Eight background monitors run in a dedicated thread at varying intervals:

| Monitor | Interval | What It Catches |
|---------|----------|----------------|
| SecurityEventMonitor | 15s | Windows Security event log (4624/4625/4688/7045/4720/4728/4732/4768/4769) |
| HostsFileMonitor | 30s | Hosts file modification, DNS server changes |
| ServiceMonitor | 60s | New Windows services, suspicious binary paths |
| SecurityToolMonitor | 30s | Defender disable, firewall disable |
| UserAccountMonitor | 60s | New user accounts, admin group changes |
| WMISubscriptionMonitor | 60s | WMI event filter/consumer creation (stealth persistence) |
| DriverLoadMonitor | 60s | New kernel drivers, new .sys files |
| MutexScanner | 30s | Known malware mutex names (Cobalt Strike, Meterpreter, etc.) |

Nine per-process checks run in the process watcher every 0.5s:

| Check | What It Catches |
|-------|----------------|
| Network-Spawned Process | Network-facing process (sshd, w3wp) spawning a shell |
| Listening Port Anomaly | Non-system process opening unexpected listening port |
| Credential Dumping | mimikatz, procdump -ma, reg save, ntdsutil, comsvcs.dll MiniDump |
| Port Forwarding | chisel, ngrok, ligolo, plink, SSH -L/-R/-D |
| Data Staging | 7z/winrar/tar compressing user document directories |
| PowerShell Abuse | -enc, -ExecutionPolicy Bypass, -w hidden, IEX, AMSI bypass |
| Backup Tampering | vssadmin delete, wbadmin delete, bcdedit recoveryenabled no |
| Admin Share Access | net use C$/ADMIN$, PsExec on port 445 |
| Process Hollowing | System-named process running from non-System32 path |

Seven enhanced checks catch the sneakiest hackers:

| Check | What It Catches |
|-------|----------------|
| LOLbin Abuse | certutil/bitsadmin/mshta/regsvr32/rundll32/wmic/msiexec with suspicious args |
| Suspicious Exec Path | Exe running from Temp/AppData/Downloads/Desktop |
| Parent-Child Mismatch | svchost.exe spawned by cmd.exe, lsass.exe by explorer.exe |
| LSASS Access | comsvcs.dll MiniDump, taskmgr dump targeting LSASS |
| PowerShell Obfuscation | XOR/base64/reversed strings/download cradles/Reflection.Assembly/stealth combos |
| Suspicious Child | Office apps spawning shells (macro malware), browsers spawning shells (drive-by) |
| Renamed System Binary | cmd.exe/powershell.exe from non-standard path |

Plus exfil channel detection (Discord/Telegram/Pastebin/webhook.site) and curl/wget upload detection.

### 7. Verifies Locations

A `MultiVerifier` cross-checks every public IP using 11 independent methods:

1. Primary GeoIP (MaxMind DB or ip-api.com)
2. Alternate GeoIP (ipwho.is)
3. Reverse DNS (IATA/city codes, ccTLD analysis)
4. RDAP registry country
5. RTT latency band (active ping)
6. TTL/OS fingerprint (active ping)
7. VPN/proxy TCP port fingerprint (active probe)
8. Infrastructure classification (org/ASN/CDN/hosting)
9. DNS leak / resolver mismatch (rDNS TLD)
10. TLS JA3 fingerprint (active, port 443)
11. ASN correlation (known VPN/proxy ASNs)

Results are fused into a consensus country/city with a confidence grade (A-F) and any disagreements are surfaced as conflicts — disagreement itself is a VPN/proxy indicator.

### 8. Detects VPN Leaks

A `VPNLeakDetector` checks for:
- VPN interface detection (WireGuard, OpenVPN, TAP adapters)
- DNS resolver leaks (DNS going outside the VPN tunnel)
- Global IPv6 leaks (IPv6 traffic bypassing IPv4-only VPN)
- Route leaks (traffic not going through the VPN interface)
- WebRTC local IP leaks (JavaScript-based detection)

### 9. Provides a Full GUI

A Tkinter GUI (`GNATracerGUI`) with 16 tabs:

| Tab | Content |
|-----|---------|
| Overview | Summary stats, proxy info, anti-hack pins, high-risk processes |
| Live Connections | Active/established connections only, collapsible detail rows |
| All Connections | Every connection with full detail (GeoIP, domains, proxy, verification) |
| Deductions | All deductions with severity, category, evidence chains |
| Processes | All processes with risk scores, connection counts, countries |
| Devices | Network devices (ARP scan, MAC vendor lookup, OS guess) |
| IP Map | Slippy tile map with geolocated IP markers (requires Pillow) |
| Actions Log | Raw process action log (NETWORK_FLOW, STARTED, etc.) |
| Terminal | Live terminal output with color-coded severity |
| Suspicious Activity | Out-of-norm events only |
| Blocked IPs | IP blocklist management with block/unblock buttons |
| Process Tree | Hierarchical parent-child process tree |
| Net Stats | Network interface bandwidth statistics |
| Timeline | Connection timeline with durations |
| Config | Live-editable configuration with validation |
| Double Trace | VPN double-trace verification view |

### 10. Serves a Web Dashboard

A FastAPI web server on port 8470 provides:
- `GET /` — Full HTML dashboard with live-updating widgets
- `GET /api/state` — JSON API returning the complete dashboard state
- `WS /ws` — WebSocket for real-time push updates

### 11. Saves Everything

Every 10 minutes, the monitor writes a complete operations log to:
- `Desktop/GNA tracer data {N}.txt` — backward-compatible desktop file
- `sessions/YYYY-MM-DD/session_HHMM_HHMM.txt` — organized by date and 10-minute time segment

Each save file contains 25+ sections including:
- Overview stats, all connections (individually), all deductions with evidence, all processes, all devices, complete raw actions log, all IPs with geolocation, suspicious activity, **sneakiest connections (anti-hack flagged)**, **anti-hack deductions**, **anti-hack monitor events**, VirusTotal results, file system events, clipboard events, USB events, scheduled task changes, named pipe events, inbound scan detections, DoH detections, TLS certificate events, connection timeline, network bandwidth, Bluetooth devices/events, serial ports, and full terminal output.

---

## How It Works — Architecture

### Thread Architecture

```
Main Thread (GUI)
├── Connection-Mapper Thread     — psutil.net_connections() every 0.5s
│                                   (interface auto-selected by actual route, not
│                                    first-found adapter — fixed 2026-08-22)
├── Process-Watcher Thread       — psutil.process_iter() every 0.5s
│   └── 16 core deductions + 18 anti-hack checks per process
├── Status-Reporter Thread       — status line every 5s
├── Connection-Inventory Thread  — enriches connections with GeoIP/DNS/service
│   ├── GeoIP Worker Thread      — background ip-api.com calls
│   └── RDNS Worker Thread       — background reverse DNS calls (bounded — was
│                                   able to stall the whole queue for 30s on one
│                                   unreachable host; fixed 2026-08-22)
├── MultiVerify Worker Pool (4)  — VPN/proxy/infra cross-verification, priority
│                                   queue (was 1 worker gated to a minority of
│                                   IPs; now covers every public endpoint)
├── DNS Cache Poll Thread        — DNS cache maintenance every 5s
├── Memory Forensics Thread      — RWX region scan every 15s (admin)
├── Extended Monitor Thread      — 16 monitors every 2-60s
│   ├── Clipboard, USB, Scheduled Tasks, Named Pipes
│   ├── Inbound Scan, Bluetooth, Serial, Proxy, VPN Leak
│   └── 8 Anti-Hack Monitors (SecurityEvent, HostsFile, Service, etc.)
│       — all 8 are Windows-only (see Known Gaps)
├── Interface Stats Thread       — bandwidth tracking every 1s
├── Packet Pipeline (4 workers)  — Scapy packet processing (admin + Npcap)
├── ARP Scanner Thread           — network device discovery (admin + Npcap)
├── Sniff Thread                 — Scapy packet capture (admin + Npcap)
├── FastAPI Dashboard Thread     — web server on port 8470
└── GUI Refresh (Tkinter after)  — adaptive interval (target 250ms, backs off
                                    under load); Live/AllConn tabs render via
                                    tagged text spans, not embedded widgets
                                    (~20x faster after 2026-08-22 perf rework)
```

### Data Flow

```
psutil.net_connections()  →  Connection Mapper  →  conn_by_pid, conn_by_raddr
                                                        ↓
psutil.process_iter()   →  Process Watcher  →  ProcessProfile per PID
                              ↓                    ↓
                         16 deductions      18 anti-hack checks
                              ↓                    ↓
                         Deduction log      Anti-hack pins (IP → categories)
                              ↓                    ↓
                         Dashboard state  ←  Merge  →  GUI refresh (250ms)
                              ↓
                         Save file (every 10 min)
```

### Performance Design

- Connection inventory uses background workers for GeoIP and reverse DNS to avoid blocking scans on network I/O
- Process watcher grabs a reference (not a copy) to the connection cache — the mapper replaces the dict atomically
- GUI refresh only rebuilds the active tab immediately; background tabs refresh periodically
- Deduction formatting happens outside the monitor lock
- Status thread merges lock acquisitions into a single critical section
- Service resolver caches results and uses background rDNS queue
- GeoIP cache has direct fast paths for cached entries
- Token bucket rate-limits external API calls

---

## Files

| File | Purpose |
|------|---------|
| `medianbox_monitor_v2.py` | Main application (single file, ~17,150 lines) |
| `_test_antihack.py` | 41-test anti-hack detection suite |
| `_test_vpn_leak.py` | 32-test VPN leak detection suite |
| `_test_vpn_detection.py` | VPN detection false-positive test (target: <5% FP) |
| `_test_location_accuracy.py` | Location verification accuracy test |
| `_test_data_wiring.py` | *(new)* Live-traffic test that harvested data actually reaches the connection record |
| `_test_gui_render.py` | *(new)* Drives all 16 real Tk tabs against live data, asserts zero exceptions/placeholders |
| `_test_click_actions.py` | *(new)* Fires real click events at the GUI's interactive controls |
| `informational.md` | Original feature reference (from earlier version) |
| `antihack.md` | Anti-hack gap analysis and integration map |
| `sessions/` | Time-segmented save files (auto-created) |
| `medianbox_structured.log` | Rotating structured log (50MB, 5 backups) |
| `medianbox_full_actions.log` | Rotating actions log (50MB, 3 backups) |
| `medianbox_deductions.log` | Rotating deductions log (50MB, 3 backups) |
| `medianbox_ultimate.db` | SQLite database for persistent data |

---

## CLI Usage

```
python medianbox_monitor_v2.py [options]

  --config, -c PATH          Load YAML config file
  --no-dashboard             Disable FastAPI web dashboard
  --no-geoip                 Disable GeoIP lookups
  --siem json|cef|syslog     SIEM output format
  --port PORT                Dashboard port (default 8470)
  --workers N                Packet pipeline workers (default 4)
  --dashboard-password PASS  Protect dashboard with password
  --geoip-db PATH            Path to MaxMind GeoIP2 database
  --no-gui                   Run without Tkinter GUI (headless)
```

---

## Auto-Flag Action System

Every process action (`NETWORK_FLOW`, `STARTED`, etc.) is checked against 33 suspicious keyword patterns via `_auto_flag_action()`. When a match is found, the action is automatically flagged as suspicious with a category:

| Keyword | Category | Description |
|---------|----------|-------------|
| `cookie` | COOKIE_TRACKING | Process sending/receiving tracking cookies |
| `upload` | DATA_UPLOAD | Process uploading data |
| `exfil` | DATA_EXFIL | Potential data exfiltration |
| `credential` | CREDENTIAL_ACCESS | Process accessing credentials |
| `password` | CREDENTIAL_ACCESS | Process accessing password data |
| `token` | TOKEN_ACCESS | Process accessing authentication tokens |
| `clipboard` | CLIPBOARD_ACCESS | Process accessing clipboard |
| `keylog` | KEYLOGGER | Possible keylogger behavior |
| `screenshot` | SCREEN_CAPTURE | Process performing screen capture |
| `inject` | CODE_INJECTION | Process injection activity |
| `hook` | API_HOOK | Process hooking system APIs |
| `encrypt` | ENCRYPTION | Process performing encryption (possible ransomware) |
| `decrypt` | ENCRYPTION | Process performing decryption |
| `powershell` | SCRIPT_EXEC | PowerShell execution |
| `cmd.exe` | SCRIPT_EXEC | Command shell execution |
| `wscript`/`cscript` | SCRIPT_EXEC | Windows Script Host |
| `regsvr` | DLL_REGISTER | DLL registration |
| `schtask` | SCHEDULED_TASK | Scheduled task manipulation |
| `rdp`/`vnc`/`ssh`/`telnet` | REMOTE_ACCESS | Remote access protocol |
| `wake-on-lan`/`shutdown`/`restart` | REMOTE_POWER | Remote power control |
| `microphone`/`camera`/`webcam`/`audiodg` | HARDWARE_ACCESS | Hardware device access |
| `temp\` | TEMP_EXECUTION | Process running from temp |
| `appdata` | SUSPICIOUS_PATH | Process running from AppData |
| `downloads\` | SUSPICIOUS_PATH | Process running from Downloads |

---

## Known Service IP Ranges

The monitor includes CIDR ranges for known services to validate that connections are legitimate:

| Service | Example Ranges |
|---------|---------------|
| Google | 142.250.0.0/15, 172.217.0.0/16, 216.58.192.0/19, 74.125.0.0/16 |
| Cloudflare | 104.16.0.0/13, 172.64.0.0/13, 1.1.1.0/24 |
| Microsoft | 13.64.0.0/11, 20.33.0.0/16, 52.96.0.0/12 |
| Discord | 162.159.128.0/17, 66.22.196.0/22 |
| Zoom | 3.7.35.0/25, 170.114.0.0/16, 206.247.0.0/16 |
| Riot Games | 104.160.128.0/17, 185.40.64.0/22 |

---

## Expected Executable Paths

The monitor knows where legitimate processes should run from:

| Process | Expected Path |
|---------|--------------|
| chrome.exe | `google\chrome\application` |
| firefox.exe | `mozilla firefox` |
| msedge.exe | `microsoft\edge\application` |
| zoom.exe | `zoom\bin` |
| discord.exe | `discord\app` |
| teams.exe | `microsoft teams` |
| svchost.exe | `windows\system32` |
| lsass.exe | `windows\system32` |
| services.exe | `windows\system32` |
| explorer.exe | `windows` |

A process running from a different path triggers an impersonation deduction.

---

## Expected Parent Processes

| Process | Expected Parent |
|---------|----------------|
| svchost.exe | services.exe |
| lsass.exe | wininit.exe |
| services.exe | wininit.exe |
| smss.exe | System / smss.exe |
| winlogon.exe | smss.exe |
| wininit.exe | smss.exe |
| csrss.exe | smss.exe / wininit.exe / winlogon.exe |
| taskhostw.exe | svchost.exe |

A process with the wrong parent triggers a parent-child mismatch deduction.

---

## Web Dashboard Details

The FastAPI dashboard on port 8470 provides a full-screen dark-themed web interface with:

- **Header bar** — live stats: connections, services, unique IPs, processes, deductions, devices, idle time
- **5 tabs:**
  - Connection Map — Leaflet.js map with geolocated IP markers + active services panel
  - All Connections — sortable table with process, IP, GeoIP, org
  - Deductions — severity-colored deduction log
  - Processes — process table with risk scores
  - Devices — discovered network devices
- **WebSocket** — pushes full state every 3 seconds for real-time updates
- **Authentication** — optional token-based via `--dashboard-password`
- **Styling** — dark theme (#0a0a0f background), monospace font, color-coded severity badges

---

## Database Schema

SQLite database (`medianbox_ultimate.db`) with WAL journal mode:

**deductions table:**
| Column | Type |
|--------|------|
| id | INTEGER PRIMARY KEY AUTOINCREMENT |
| timestamp | TEXT (ISO format) |
| severity | TEXT |
| category | TEXT |
| process | TEXT |
| pid | INTEGER |
| message | TEXT |
| evidence | TEXT (JSON array) |
| score | REAL |

**devices table:**
| Column | Type |
|--------|------|
| key | TEXT PRIMARY KEY |
| mac | TEXT |
| ip | TEXT |
| vendor | TEXT |
| hostname | TEXT |
| os_guess | TEXT |
| first_seen | TEXT |
| last_seen | TEXT |
| confidence | REAL |

---

## RDAP/WHOIS Lookup

The `WhoisLookup` class queries `rdap.org/ip/{ip}` for IP ownership information:
- Organization name, handle, entity type
- Country, start/end address range
- Up to 3 entity contacts with roles
- Rate-limited via TokenBucket (10 requests/sec)
- Cached per IP

---

## Connection Entry Fields

Each tracked connection (`ConnectionEntry` with `__slots__` for memory efficiency) contains **53 fields** (expanded from 31 in the 2026-08-22 audit — the collectors were already harvesting ASN, timezone, rDNS, RTT, TTL/OS, and the full VPN/proxy verdict, but the data model discarded it before it ever reached the GUI):

**Identity / process:** `pid`, `process_name`, `exe_path`, `parent_name`, `parent_pid`, `cmdline`, `website_tag`
**Network:** `remote_ip`, `remote_port`, `local_ip`, `local_port`, `protocol`, `status`
**Service / domain:** `service`, `category`, `icon`, `domain`, `all_domains`, `via`
**Geo:** `country`, `country_code`, `city`, `region`, `org`, `isp`, `lat`, `lon`, `timezone`, `geo_source`
**Timing:** `first_seen`, `last_seen`
**Location verification (`LocationVerifier`):** `loc_confidence`, `loc_grade`, `loc_proof`
**Proxy (`ProxyDetector`):** `proxy_type`, `proxy_detail`
**Infrastructure identity:** `asn`, `asn_org`, `rdns`
**VPN/proxy verdict (`MultiVerifier` — new):** `is_vpn`, `is_proxy`, `is_hosting`, `is_cdn`, `vpn_score`, `vpn_provider`, `vpn_labels`, `verify_grade`, `verify_summary`, `verify_conflicts`
**Active-probe evidence (new):** `rtt_ms`, `ttl_os`, `hop_distance`, `open_ports`

Every field above is now populated for effectively 100% of public IPs — verified by `_test_data_wiring.py`, which measures per-unique-public-IP coverage against live traffic rather than trusting that a field exists in the dataclass.

---

## Test Results

| Suite | Result |
|-------|--------|
| `_test_antihack.py` | 41/41 passed — all sneaky hacker techniques detected |
| `_test_vpn_leak.py` | 32/32 passed |
| `_test_vpn_detection.py` | 0% false positive rate (target: <5%), 100% detection rate across 1,100 synthetic endpoints |
| `_test_location_accuracy.py` | PASS — 100% country accuracy, 100% fixed-location within 200km |
| `_test_data_wiring.py` *(new)* | 35/35 passed — every harvested field reaches the connection record for 100% of public IPs |
| `_test_gui_render.py` *(new)* | PASS — all 16 tabs render with zero exceptions, zero stale placeholders |
| `_test_click_actions.py` *(new)* | 9/9 passed — clickable-span interactivity verified after the button→text-tag perf rework |
| `py_compile` | OK |

---

## Performance Optimizations

The monitor is designed to stay responsive even with hundreds of processes and connections:

### Caching
- `_is_public_ip_cached()` — LRU cache (4096 entries) for IP validation
- `GeoIPCache` — TTL-based cache (3600s) with direct fast paths
- `ServiceResolver` — reverse DNS + service cache
- `WhoisLookup` — per-IP cache
- `VirusTotalChecker` — per-PID cache

### Background Workers
- GeoIP worker — processes queue of IPs needing ip-api.com lookup
- RDNS worker — processes queue of IPs needing `socket.gethostbyaddr()`
- Both prevent the connection inventory scan from blocking on network I/O

### Atomic Replacement
- Connection mapper replaces `conn_by_pid` and `conn_by_raddr` dicts atomically
- Process watcher grabs a reference (not a copy) — safe because the mapper replaces rather than mutates

### Rate Limiting
- `TokenBucket` — used by GeoIPCache, WhoisLookup, VirusTotalChecker
- Prevents API bans and rate-limit errors

### Memory Efficiency
- `ConnectionEntry` uses `__slots__` (53 fields, no `__dict__`)
- `ProcessProfile` uses bounded deques for CPU samples (60), packet timestamps (500)
- `StatisticalBaseline` uses bounded deques (500 per metric)
- `AlertEscalation` cleans up dead PIDs at 5000+ entries
- Suspicious events deque capped at 10,000
- Terminal buffer deque capped at 10,000

### Hoisted Constants
- `_PORT_NAMES`, `_PORT_SERVICES` — module-level, not recreated per call
- `_SUSPICIOUS_EXTRA_KW` — class-level, not recreated per action
- `_LOLBIN_PATTERNS`, `_EXPECTED_PARENTS`, `_SYSTEM_PROCESSES` — class-level

### Lock Contention Reduction
- Deduction formatting happens outside the monitor lock
- Status thread merges lock acquisitions into a single critical section
- `deque.append()` is thread-safe in CPython — no lock needed for append-only suspicious events

---

## Graceful Degradation

The monitor degrades gracefully when optional components are unavailable:

| Missing Component | Behavior |
|-------------------|----------|
| Npcap/WinPcap | Packet capture disabled; SNI/DNS/JA4 from packets unavailable; process/connection monitoring continues |
| Admin rights | Memory forensics, Security event log, ARP scan disabled; other monitors continue |
| FastAPI/Uvicorn | Web dashboard disabled; GUI continues |
| Pillow (PIL) | IP Map tab shows text-only; other tabs unaffected |
| manuf library | MAC vendor lookup returns "Unknown"; device discovery continues |
| geoip2 + MaxMind DB | Falls back to ip-api.com HTTP API |
| ip-api.com unreachable | GeoIP shows "Unknown"; connections still tracked |
| ipwho.is unreachable | MultiVerifier alternate GeoIP method skipped; other methods continue |
| rdap.org unreachable | RDAP verification method skipped; other methods continue |
| VirusTotal API key | VirusTotal checks skipped |
| win32evtlog | Falls back to `wevtutil qe Security` command |
| winreg (non-Windows) | Registry monitor disabled |

The monitor never silently stops collecting data. If a component fails, it logs the error and continues with the remaining monitors.

---

## Feature Completeness Ratings

Audited against the running code on 2026-08-22 — grades reflect verified behavior, not intent. Rubric:

| Grade | Meaning |
|-------|---------|
| **A** | Fully implemented, cross-platform where relevant, verified against live data |
| **B** | Fully implemented on Windows, solid, but static rule lists or single-platform |
| **C** | Implemented with a real structural limitation (opt-in, rate-capped, degrades without an optional dependency) |
| **D** | Present but materially incomplete relative to what the name implies |
| **F** | Not implemented |

| # | Subsystem | Grade | Basis |
|---|-----------|-------|-------|
| 5 | Network & Connection Monitoring | **A-** | Every public IP now gets full enrichment + verification (was a minority before 2026-08-22); interface auto-detection now picks the routed adapter, not the first one enumerated. |
| 6 | DNS Monitoring | **B** | Bidirectional DNS map and DoH detection work well from psutil/registry alone; tunneling detection and SNI extraction need Npcap for full function. Entropy/rate thresholds are static constants. |
| 7 | GeoIP & Location Verification | **B+** | The 11-method MultiVerifier design is genuinely rigorous and honest about confidence — but the default data sources are free third-party HTTP APIs with no bundled local database. |
| 8 | VPN & Proxy Detection | **A-** | 100% detection / 0% false positives across 1,100 synthetic endpoints; now runs on every public connection instead of a filtered subset. |
| 1–4 | Core Deductions + Anti-Hack Checks (16+18+7) | **B** | Thorough, auditable evidence chains — but 100% heuristic (path/parent/keyword/static-list). No code-signing verification anywhere. |
| 3 | Anti-Hack Background Monitors (8) | **C** | Fully functional but 100% Windows-only (`sc`, `wmic`, `schtasks`, `net user`, `netsh`, `wevtutil`, `winreg`). Inert on Linux/macOS. |
| 12 | Packet Analysis & TLS Fingerprinting | **C+** | Well-engineered JA4+/SNI/entropy pipeline, but entirely dependent on Npcap being installed — and the monitor never prompts the user that it's missing. |
| 9 | Process Profiling & Forensics | **C+** | Broad data collection, but memory forensics is RWX-region-only (no code-signing check), and VirusTotal is opt-in via an undocumented-in-CLI env var, rate-capped at 4 req/min on the free tier. |
| 10 | System & Persistence Monitoring | **C** | Windows-only; the registry watch list covers the standard Run keys but not every known persistence technique (no COM hijack detection, no service-DLL-hijack detection). |
| 11 | Hardware & Peripheral Monitoring | **C** | Windows-only (registry/WMI enumeration). |
| 13 | Behavioral & Statistical/ML | **C+** | Real Z-score baselining, but entirely in-memory — the learned baseline resets every restart; nothing is persisted across sessions. |
| 14 | Firewall & IP Blocking | **C** | Functional manual block/unblock via Windows Firewall; no Linux iptables equivalent, and no automatic response of any kind. |
| 15 | GUI (16 tabs) | **A-** | Now fully wired (53/53 ConnectionEntry fields render, 0 stale placeholders) and fast (Live tab refresh cut from ~2.5s to ~30ms) — but has no authentication of its own. |
| 16 | Web Dashboard | **C+** | Functional 5-tab view with optional password, but exposes a subset of the GUI's 16 tabs and has no HTTPS. |
| 17 | Data Export & Session Recording | **B+** | Very thorough plain-text export (25+ sections); not queryable — see Database below. |
| 18 | Database & Logging | **D** | SQLite has exactly 2 tables (`deductions`, `devices`). Connections, processes, and every Tier-5 monitor event are absent from the database entirely. |
| 19 | SIEM Output | **C** | File (JSON/CEF) or UDP syslog only — no direct Splunk HEC, Elastic, or Sentinel connector. |
| — | Automated response/containment | **F** | Manual firewall block is the only containment action that exists. |
| — | Out-of-band alerting | **F** | No email/Slack/Discord/push/SMS. SIEM output is the only notification path, and it requires something else to be watching the file or syslog stream. |
| — | Signature / YARA detection | **F** | Zero Authenticode verification, zero byte-signature scanning, anywhere in the codebase. |
| — | Cross-platform coverage | **D** | Linux gets process/connection/DNS/GeoIP/VPN detection only (~9 of ~33 named detections). macOS has no dedicated support beyond one `open`-a-folder call. |
| — | Packaging / reproducibility | **D** | No `requirements.txt`, `pyproject.toml`, or pinned versions anywhere. |
| — | Test coverage of the delivery layer | **B** *(was F)* | Detection-logic tests existed and passed (73+ cases); nothing verified the data actually rendered until `_test_data_wiring.py` / `_test_gui_render.py` / `_test_click_actions.py` were added 2026-08-22. |

## Known Gaps — Not Implemented

Grouped by kind, so it's clear which gaps are "add a feature" vs. "this is a boundary by design":

**Not implemented — closeable with more code**
- Code-signing (Authenticode) verification for any process
- YARA or other byte-signature malware scanning
- Automatic response (process kill, quarantine, network isolation) beyond a manual firewall-rule block
- Out-of-band alerting (email, Slack/Discord webhook, push, SMS) — SIEM file/syslog output only
- Persisted connection/process history in the database (only deductions and devices are stored; everything else is text-log-only)
- Auto-updating threat-intel lists (LOLbin patterns, exfil domains, malware mutex names, VPN ASN markers are all static source constants)
- Linux equivalents for the 8 Windows-only anti-hack background monitors (registry, WMI, services, scheduled tasks, security event log, hosts/DNS hijack, driver loads, new user accounts)
- macOS-specific monitoring of any kind
- A `requirements.txt`/`pyproject.toml` with pinned dependency versions
- A startup check that tells the user plainly "Npcap is not installed, packet-level detection is disabled" rather than a log-line warning
- CLI flag / GUI field for the VirusTotal API key (currently `VT_API_KEY` env var only)
- CI / automated test gate (7 suites exist; none run automatically on a change)

**Boundaries by design — not gaps to close, but worth stating plainly**
- The monitor never decrypts TLS payloads; it sees SNI/JA4/certificate metadata only
- It is defensive-only — it does not identify remote VPN users or perform any offensive action
- It watches only the local machine, not the network at large

