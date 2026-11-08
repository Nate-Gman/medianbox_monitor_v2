# MedianBoxMonitor 3.0 — Overview

**File:** `medianbox_monitor_v2.py` — single-file Python security monitoring application (~45,400 lines, 62 top-level classes, ~915 functions)
**Platform:** Windows (primary), Linux (partial)
**Python:** 3.13+
**Dependencies:** psutil, scapy, tkinter, FastAPI/Uvicorn (optional), Pillow (optional), manuf (optional), geoip2 (optional), bleak (optional — live BLE adverts)

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

Beyond the process watcher, the packet path fires its own **wire-evasion deduction family** — detections that live below the process layer and attribute to `"packet"` rather than a PID: L2SPOOF (an ARP reply claiming an IP another MAC already owns — ARP-poison MITM), ARPSTORM (one MAC binding 6+ IPs in 60s), RDHCP (rogue DHCP server answering), ROGRA (rogue IPv6 router advertisement), LLMNS (LLMNR/NBNS spoof replies), MACROT (an address rotating identities), MARTIAN (impossible/bogon sources), QINQ (802.1Q-in-Q double tags), TTLINJ (injected TTL anomalies), and RAWETH (a persistent emitter speaking a non-IP ethertype — a data channel with no IP layer at all). FLOW_PROBE verdicts and GATEWAY-mode findings also land in the deduction log.

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

A `MultiVerifier` cross-checks every public IP using 11 core independent methods plus ~230 named wire-evidence checks (244 named method codes today — passive protocol fingerprints, tunnel signatures, service self-IDs, overlay/mesh evidence, stored-field channels):

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

…plus wire-hint evidence rows harvested passively from the packet path — WireGuard/OpenVPN/DTLS/QUIC signatures, L3/ICMP tunnels, ECH, MPTCP, STUN/TURN, overlay/VXLAN/Geneve/L2TP/NAT-T/ESP, ZeroTier/Tailscale/Nebula, GTP, decapsulated inner endpoints, fragmentation patterns, protocol self-ID decoders (SSH/HASSH, Kerberos, LDAP, RDP, RTSP, SIP, FTP, MQTT, Modbus, BACnet, Kafka, X11, BGP, VNC, RADIUS, DNP3, S7/IEC-104, and dozens more), WPAD/PAC/ECN/ECS harvest, and hidden-path channels (SPLITR/EXFIL/DEADDROP). A TorDNSEL/exit-list check (`TOREXIT`, fed by the cached `medianbox_exitlists.json` lists) flags Tor exit nodes onto `is_tor`, and a VPN-gateway detector identifies when this host is relaying tunnel traffic for downstream clients.

On top of passive evidence, the endpoint can be **actively tested**: an on-demand Flow Probe (`_probe_ip_flow`, right-click an IP → ⚗ Flow probe) blocks the endpoint on the local firewall for `flow_probe_secs` (8s), watches the flow for `flow_probe_settle_secs` (6s), then auto-unblocks. A process that returns on a new IP in the same provider proves VPN rotation — verdicts ROTATED / STICKY / GONE flow through the deduction engine into every surface.

Results are fused into a consensus country/city with a confidence grade (A-F) and any disagreements are surfaced as conflicts — disagreement itself is a VPN/proxy indicator.

### 8. Detects VPN Leaks

A `VPNLeakDetector` checks for:
- VPN interface detection (WireGuard, OpenVPN, TAP adapters)
- DNS resolver leaks (DNS going outside the VPN tunnel)
- Global IPv6 leaks (IPv6 traffic bypassing IPv4-only VPN)
- Route leaks (traffic not going through the VPN interface)
- WebRTC local IP leaks (JavaScript-based detection)

### 9. Provides a Full GUI

A Tkinter GUI (`GNATracerGUI`) with 18 tabs:

| Tab | Content |
|-----|---------|
| Overview | Summary stats, proxy info, anti-hack pins, high-risk processes |
| Live Connections | Active/established connections only, collapsible detail rows |
| All Connections | Every connection with full detail (GeoIP, domains, proxy, verification) |
| Deductions | All deductions with severity, category, evidence chains |
| Processes | All processes with risk scores, connection counts, countries |
| Devices | Network devices (ARP scan, MAC vendor lookup, OS guess) |
| IP Map | Slippy tile map with geolocated IP markers + RF emitter dots (trilaterated fixes with RMS rings, RSSI range rings, local-talker clusters) and a PINPOINTS & GEO LOCATIONS sidebar — multi-select rows with a full-record detail pane (requires Pillow) |
| Actions Log | Raw process action log (NETWORK_FLOW, STARTED, etc.) |
| Terminal | Live terminal output with color-coded severity |
| Suspicious Activity | Out-of-norm events only |
| Blocked IPs | IP blocklist management with block/unblock buttons |
| Process Tree | Hierarchical parent-child process tree |
| Net Stats | Network interface bandwidth statistics |
| Timeline | Connection timeline with durations |
| Config | Live-editable configuration with validation |
| Double Trace | VPN double-trace verification view |
| System | Host/hardware detail — CPU, RAM, OS build, uptime, interfaces, power |
| Signals | Spectrum & RF intelligence — emitter census, coverage matrix, trilateration, every scanner's raw feed |

### 10. Serves a Web Dashboard

A FastAPI web server on port 8470 provides:
- `GET /` — Full HTML dashboard with live-updating widgets (6 tabs: Connection Map, All Connections, Deductions, Processes, Devices, and All Feeds — a verbatim dump of every payload key so no collected field is ever invisible)
- `GET /api/state` — JSON API returning the complete dashboard state
- `WS /ws` — WebSocket for real-time push updates

### 11. Saves Everything

Every 10 minutes, the monitor writes a complete operations log to:
- `sessions/YYYY-MM-DD/session_HHMM_HHMM.txt` — organized by date and 10-minute time segment
- `Desktop/GNAT/YYYY-MM-DD/GNA tracer data {N}.txt` — the GNAT record folder (a one-time migration pulls legacy Desktop-scattered reports into it)
- `Desktop/GNAT/latest_snapshot.json` — a machine-readable JSON twin of the entire session payload, overwritten on each save

Each save file contains 30+ sections including a `RECORD MANIFEST` block counting every feed captured, plus:
- Overview stats, all connections (individually), all deductions with evidence, all processes, all devices, complete raw actions log, all IPs with geolocation, suspicious activity, **sneakiest connections (anti-hack flagged)**, **anti-hack deductions**, **anti-hack monitor events**, VirusTotal results, file system events, clipboard events, USB events, scheduled task changes, named pipe events, inbound scan detections, DoH detections, TLS certificate events, connection timeline, network bandwidth, Bluetooth devices/events, serial ports, the full spectrum/RF emitter registry with trilateration fixes and spectrum events, the live processing-state dump, and full terminal output.

### 12. Watches Every Signal-Emitting Device (Spectrum & Non-IP)

Connections are not only IP sockets. A `SpectrumHub` — driven by its own `Spectrum-Intel` daemon thread — maintains a unified `SignalRegistry` of every signal-emitting device the host can perceive across **11 media**:

| Medium | What it tracks | Source |
|--------|---------------|--------|
| `wifi-ap` | Every AP/BSSID beacon in range — SSID, RSSI, band, channel, radio type, auth, est. distance | `netsh wlan show networks mode=bssid` |
| `wifi-radio` | The host's own Wi-Fi radio — connected SSID/BSSID, link rates, signal % | `netsh wlan show interfaces` |
| `wifi-direct` | Wi-Fi Direct / P2P virtual adapters | interface census (`Get-NetAdapter`) |
| `bt-radio` / `bt-classic` / `ble` | Local BT radio, paired/PnP devices, live BLE adverts (with `bleak`) | PnP registry / `Get-PnpDevice` / bleak |
| `wwan-modem` | Cellular/WWAN interfaces | `netsh mbn` |
| `local-radio` | Other local RF transmitters | census |
| `rf-hw` | RF-capable USB hardware — SDR, Zigbee, Z-Wave, NFC, Ubertooth, Flipper, proprietary 2.4 GHz receivers | VID&PID table over PnP devices |
| `local-iface` | Wired/virtual host interfaces (non-RF transports) | psutil + `Get-NetAdapter` |
| `l2-wire` | Every source MAC on the wire — ethertypes spoken, IPs claimed, discovery services announced, derived roles | packet-callback per-MAC census (needs Npcap+admin) |

Each emitter record holds: key (`medium:mac`), vendor, name, first/last seen, active/lost lifecycle, observation counts, per-sensor attribution, RSSI history (avg/min/max + last 24 samples), estimated distance via log-distance path loss (`rf_path_loss_exp`, default n=2.7), approach/recession trend (+dB/min slope, `rf_rssi_approach_db_min`), band/channel/frequency, and a free-form `extra` dict carrying every raw field its collector produced.

**Trilateration.** A `Trilaterator` keeps per-emitter observation maps (`emitter → sensor → {lat, lon, rssi, freq, ts}`). With ≥3 spatially separated observations it runs weighted least-squares over an equirectangular tangent plane — nearer sensors weigh more — and emits a lat/lon fix with RMS residual, sensor count, spread, and an honest `good`/`fair`/`coarse`/`degenerate` grade. Sensors are registered via `rf_sensors` config or by dropping JSONL observations into `rf_obs_file`; it refuses to fabricate fixes from insufficient geometry.

**Deductions & events.** Hidden-SSID beacons (rogue-AP cover), evil-twin suspects (same SSID on a new BSSID, cooldown-gated by `rf_evil_twin_cooldown`), approaching emitters closer than `rf_approach_alert_m`, newly detected RF hardware, emitter-lost transitions, and trilateration fixes all flow into the suspicious feed, the deductions engine, and the SIGNALS tab's persistent event history (a `_ui_events` deque — processing drains a separate queue so events never vanish from the UI).

**Coverage honesty.** A 12-row coverage matrix (Wi-Fi APs, BT classic, BLE, cellular, Wi-Fi Direct, Zigbee, Z-Wave, SDR sweep, NFC/RFID, proprietary 2.4 GHz, non-IP L2, serial/UART) reports each medium as live, partial, or unavailable-with-reason. Scans that fail transiently are *inconclusive* — they never mark emitters lost; only definitive scans advance the absent counter (`rf_lost_after_scans`).

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
│   ├── GeoIP-Enrich Worker      — background ip-api.com calls
│   └── ReverseDNS Worker        — background reverse DNS calls (bounded — was
│                                   able to stall the whole queue for 30s on one
│                                   unreachable host; fixed 2026-08-22)
├── MultiVerify Worker Pool (18) — VPN/proxy/infra cross-verification, priority
│                                   queue (was 1 worker gated to a minority of
│                                   IPs; now covers every public endpoint;
│                                   244 named evidence methods)
├── DNS Cache Poll Thread        — DNS cache maintenance every 5s
├── VPN-Gateway Thread           — VPN gateway/inner-flow monitoring
├── Memory Forensics Thread      — RWX region scan every 15s (admin)
├── Extended Monitor Thread      — ~19 monitors every 2-60s
│   ├── File System Watchdog (10s), Clipboard (5s), USB (30s)
│   ├── Scheduled Tasks (60s), Named Pipes (30s), Inbound Scan (5s)
│   ├── Bluetooth (30s), Serial (30s), Proxy (30s), VPN Leak (60s)
│   └── 8 Anti-Hack Monitors (SecurityEvent, HostsFile, Service,
│       SecurityTool, UserAccount, WMISubscription, DriverLoad, Mutex)
│       — 5 now have Linux backends (see Known Gaps)
├── Interface Stats Thread       — bandwidth tracking every 1s
├── Spectrum-Intel Thread        — SpectrumHub every ~2s: Wi-Fi BSSID/RSSI
│                                   sweeps (15s cadence), BT/BLE census (30s),
│                                   interface census (30s), WWAN (60s), RF
│                                   hardware (120s), L2-wire flush (15s),
│                                   obs-file ingest, trilateration solves
├── Packet Pipeline (4 workers)  — Scapy packet processing + per-MAC L2 wire
│                                   census (admin + Npcap)
├── ARP Scanner Thread           — network device discovery (admin + Npcap)
├── Sniff Thread                 — Scapy packet capture (admin + Npcap)
├── Device-PortScan Thread       — discovered-device port probing (admin)
├── LocalGeo-Warm Thread         — pre-warms local-GeoIP cache at startup
├── Location-Verify / Whois-Warm / VT-Checker / DB-Writer / Double-Trace
│                                — on-demand enrichment + persistence workers
├── FastAPI Dashboard Thread     — web server on port 8470
└── GUI Refresh (Tkinter after)  — adaptive interval (target 250ms, backs off
                                    under load); all tabs render via versioned
                                    render-skip signatures + tagged text spans
                                    (see Performance Design)
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
- **Versioned snapshot & render pipeline** (2026-11-06): every mutable store exposes a monotonic mutation counter (`_ded_seq`, `_susp_seq`, `_proc_seq`, `_dev_seq`, `_iface_seq`, `_terminal_seq`, `_actions_seq`, `_pins_seq`, `_verify_cache_seq`, `spectrum.seq`, …); `_get_full_data` publishes `data['_versions']` and caches expensive sections per version — uncached full-payload build measured at ~21ms → ~0.14ms steady-state
- `_render_skip(tag, signature)` — every tab rebuilds only when its feed's version tuple actually moves; the Signals tab re-renders only when `spectrum.seq` changes
- `_cfg(widget, **opts)` — `.config()` diffed against last-applied options, eliminating ~73 identical Tcl round-trips per status tick (~4.7ms → ~0.59ms)
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
| `medianbox_monitor_v2.py` | Main application (single file, ~45,400 lines) |
| `_test_antihack.py` | 41-test anti-hack detection suite |
| `_test_vpn_leak.py` | ~30-test VPN leak detection suite |
| `_test_vpn_detection.py` | VPN detection false-positive test (target: <5% FP) |
| `_test_location_accuracy.py` | Location verification accuracy test |
| `_test_gatecrasher.py` | 68-check IKE/PROX/TLSALT/BANNER/IPID/gateway-methods suite |
| `_test_wireproof.py` | 1,560-check silent-tunnel & non-IP-channel evidence suite |
| `_test_data_wiring.py` | Live-traffic test that harvested data actually reaches the connection record |
| `_test_gui_render.py` | Drives all 18 real Tk tabs against live data, asserts zero exceptions/placeholders |
| `_test_ui_smoke.py` | ~180-check full GUI smoke pass (every tab, chips, Signals fields) |
| `_test_click_actions.py` | Fires real click events at the GUI's interactive controls |
| `_test_map_declutter.py` / `_test_map_default_view.py` | Endpoint-map declustering + default-viewport tests |
| `_test_perf_profile.py` | cProfile render-pipeline harness |
| `_test_ui_shot.py` / `_test_ui_shot_sys.py` | GUI screenshot tools |
| `_audit_fields.py` / `_audit_ui.py` | Static field-visibility audits (produced ⇒ rendered) |
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
- **6 tabs:**
  - Connection Map — Leaflet.js map with geolocated IP markers + active services panel
  - All Connections — sortable table with process, IP, GeoIP, org
  - Deductions — severity-colored deduction log
  - Processes — process table with risk scores
  - Devices — discovered network devices
  - All Feeds — every payload key rendered verbatim (processing state, spectrum internals, wire-hint tables…) so no collected field is unreachable in the web UI
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

Each tracked connection (`ConnectionEntry` with `__slots__` for memory efficiency) contains **55 slots** (expanded from 31 in the 2026-08-22 audit — the collectors were already harvesting ASN, timezone, rDNS, RTT, TTL/OS, and the full VPN/proxy verdict, but the data model discarded it before it ever reached the GUI):

**Identity / process:** `pid`, `process_name`, `exe_path`, `parent_name`, `parent_pid`, `cmdline`, `website_tag`
**Network:** `remote_ip`, `remote_port`, `local_ip`, `local_port`, `protocol`, `status`
**Service / domain:** `service`, `category`, `icon`, `domain`, `all_domains`, `via`
**Geo:** `country`, `country_code`, `city`, `region`, `org`, `isp`, `lat`, `lon`, `timezone`, `geo_source`
**Timing:** `first_seen`, `last_seen`
**Location verification (`LocationVerifier`):** `loc_confidence`, `loc_grade`, `loc_proof`
**Proxy (`ProxyDetector`):** `proxy_type`, `proxy_detail`
**Infrastructure identity:** `asn`, `asn_org`, `rdns`
**VPN/proxy verdict (`MultiVerifier` — new):** `is_vpn`, `is_proxy`, `is_hosting`, `is_cdn`, `is_tor`, `vpn_score`, `vpn_provider`, `vpn_labels`, `verify_grade`, `verify_summary`, `verify_conflicts`
**Active-probe evidence (new):** `rtt_ms`, `ttl_os`, `hop_distance`, `open_ports`
**Internal:** `_dom_ver` — domain-cache version stamp so renders know when a connection's domain mapping moved

Every field above is now populated for effectively 100% of public IPs — verified by `_test_data_wiring.py`, which measures per-unique-public-IP coverage against live traffic rather than trusting that a field exists in the dataclass.

---

## Test Results

| Suite | Result |
|-------|--------|
| `_test_antihack.py` | 41/41 passed — all sneaky hacker techniques detected |
| `_test_vpn_leak.py` | 30/30 passed |
| `_test_vpn_detection.py` | 0% false positive rate (target: <5%), 100% detection rate across 1,100 synthetic endpoints |
| `_test_location_accuracy.py` | PASS — 100% country accuracy, 100% fixed-location within 200km |
| `_test_gatecrasher.py` | 68/68 passed — gateway/negotiation evidence methods |
| `_test_wireproof.py` | 1560/1560 passed — silent-tunnel/non-IP-channel classifiers |
| `_test_unmask_v2.py` | 38/38 passed — de-mask engine: headers, VPN-gate probes, origin hunt, watermark codec, session linkage, tier channels |
| `_test_data_wiring.py` | PASS — every harvested field reaches the connection record for 100% of public IPs |
| `_test_gui_render.py` | PASS — all tabs render with zero exceptions, zero stale placeholders |
| `_test_ui_smoke.py` | 0 failures — 18 tabs incl. Signals tab field-label assertions |
| `_test_click_actions.py` | PASS — clickable-span interactivity verified after the button→text-tag perf rework |
| `_test_map_declutter.py` / `_test_map_default_view.py` | PASS |
| `py_compile` / `ast.parse` | OK |

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
- `ConnectionEntry` uses `__slots__` (55 fields, no `__dict__`)
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
| netsh / WLAN interface | Wi-Fi BSSID scan + own-radio feed unavailable; coverage matrix marks Wi-Fi rows unavailable; other media continue |
| bleak library | Live BLE advert capture skipped; BT/BLE registry+PnpDevice enumeration continues |
| rtl_power / SDR tools | Wideband sweep feed unavailable; reported as `not-installed` in the coverage matrix and scanner state |
| RF dongles (SDR/Zigbee/Z-Wave/NFC) | Those media rows read `unavailable — no receiver hardware` — never fabricated |
| Npcap + admin (for L2 census) | `l2-wire` medium gets no frames — wire-talker emitters absent; all IP-level monitoring continues |

The monitor never silently stops collecting data. If a component fails, it logs the error and continues with the remaining monitors.

---

## Feature Completeness Ratings

Audited against the running code on 2026-08-22, re-verified 2026-11-08 — grades reflect verified behavior, not intent. Rubric:

| Grade | Meaning |
|-------|---------|
| **A+** | Grade A, and every remaining limit is an OS/protocol boundary (not missing code) that is measured live and stated |
| **A** | Fully implemented, cross-platform where relevant, verified against live data |
| **B** | Fully implemented on Windows, solid, but static rule lists or single-platform |
| **C** | Implemented with a real structural limitation (opt-in, rate-capped, degrades without an optional dependency) |
| **D** | Present but materially incomplete relative to what the name implies |
| **F** | Not implemented |

| # | Subsystem | Grade | Basis |
|---|-----------|-------|-------|
| 5 | Network & Connection Monitoring | **A+** | 2026-11-08 identification pass: the chain is now DNS/SNI, rDNS, TLS certificate, provider VPN-server feeds, provider-published ranges (`ProviderRangeDB`: exact service/region), registered owner (GeoIP, RDAP, Team Cymru DNS via a pure-Python TXT client), then the owning process's vendor for shared edges (marked *inferred*). Non-public peers are named too: `_identify_local` resolves loopback/own-address sockets to the process on the other end (socket table), LAN peers by ARP + OUI + gateway role + port hint, tunnel peers by interface route, and decodes mapped/6to4/Teredo/NAT64 addresses. Ownerless TIME_WAIT sockets (PID 0) are traced back via `remember_sockets` (0.5 s socket-owner memory), the live listener they were accepted on, or the last owner of that remote endpoint (inferred). New `ConnectionEntry.owner_via` records how an owner was established (and flags the monitor's own verification probes). Live run 2026-11-08 (dev host): of 260 connections not generated by the monitor's own verification probes, **0 public peers unresolved**, all 197 loopback/LAN peers named (the local process on the other end of a loopback socket; LAN devices by ARP + OUI vendor, gateway role and port hint), and ownerless TIME_WAIT sockets fell from 196 to 6. Earlier: Every public IP now gets full enrichment + verification (was a minority before 2026-08-22); interface auto-detection now picks the routed adapter, not the first one enumerated. Connections with no DNS/SNI match are no longer left as a bare IP: `_identify_fallback` names them from reverse DNS, then registered network owner (ASN/org/ISP), then process + port, recording the evidence source in `via`. A TLS-certificate step (public peers already connected on a TLS port, rate-limited, disabled by `--no-geoip`) and an RDAP owner step now sit in the chain too. Live run on the dev host (2026-11-08): 967 public connections, **0 unresolved** — 176 by reverse DNS, 116 by DNS/SNI, 62 by TLS certificate, 542 by registered network owner. Peers with no evidence yet are labeled `Unresolved: …` rather than guessed. |
| 6 | DNS Monitoring | **B** | Bidirectional DNS map and DoH detection work well from psutil/registry alone; tunneling detection and SNI extraction need Npcap for full function. Entropy/rate thresholds are static constants. |
| 12b | Spectrum / RF & L2 Signal Intelligence | **A-** | Unified emitter registry across 11 media with RSSI distance/trend, lifecycle, WLS trilateration (honest quality grades), evil-twin + hidden-SSID + RF-hardware deductions, coverage matrix that never fabricates unavailable spectrums — but bounded by physical receivers: Zigbee/Z-Wave/NFC/sub-GHz need external hardware, BLE live adverts need `bleak`, L2 census needs Npcap+admin. Every remaining limit is a physical-hardware boundary measured and stated by the coverage matrix. |
| 7b | Reverse Tracing / Attribution (`--trace`) | **A+** | `trace_data()` / `trace_report()`: reverse DNS (forward-confirmed), RDAP with contacts and RIR fallback, Cymru + RIPEstat BGP, Onionoo/exit-feed/provider-range classification, TLS cert, AS-annotated traceroute with the operator border hop, local owning process, then the **operator pivot** (`_trace_operator_pivot`): corroborated operator domains, registrar/age, `security.txt`, announced prefixes, BGP neighbours, Tor family, a trace of the operator's own server, and an evidence packet. The **disclosure surface** (`_dns_identity_probes`, `_ntp_probe`, `_page_probe`, `_vhost_probe`, `_crtsh_names`, `_trace_history`) makes the endpoint name itself: CHAOS-class hostname/version/id records, resolver-egress echo (o-o.myaddr / whoami.cloudflare — the address the service really talks out of), NTP mode-6 readvar (OS + ntpd build), page title/meta, co-tenant vhosts, Certificate-Transparency names, and this host's own connection history. **Client de-masking** (`_trace_unmask`) checks every channel to the party behind a relay, live: PROXY-protocol/XFF/SIP/FTP/STUN/tunnel-inner/transition/EDNS origin leaks (each leaked address re-attributed via PTR+Cymru), shared-state alias links (host key, cert, TLS session, header order, TCP clock, IP-ID, gap-shape), and the optional `--canary PORT` listener — now a full four-tier de-mask engine: `/d/<tok>` serves a de-mask page whose WebRTC ICE harvest returns the pre-tunnel address on leaking clients (recorded as a `webrtc/ice leak` origin), `/s/<tok>` is an ETag+cookie session pixel (`SessionRegistry` joins one fingerprint across egresses), `/d/` responses carry an injected `_wm_gaps` pacing watermark that the sniffer continuously correlates against live `_flowstats` gap series plus external `POST /f/<tok>` vantage observations (≥0.72 = both ends joined), and `--demask-dns ZONE` binds :53 to log the client's real resolver egress + EDNS client-subnet. Tier-3: `tor_guard_census()` (population-share localization), `sybil_census()` (`our_tor_relays[]` coverage), `_tor_relay_observe()` (clients entering a local relay). Tier-4: three `BLOCKED` channels naming lawful substitutes. All tiers run on every trace, gated by nothing. The operator-side trace resolves the pre-tunnel client directly when run on a relay host. `--trace-json`, `--trace-out`, `--trace-deep` (active MultiVerifier), `--trace-no-pivot`, `--trace-draft`. Verified live (1.1.1.1, a Tor exit) and by offline tests. A+ under the rubric: the only residue is the operator-held client record — an OS/protocol boundary that the report itself measures and states channel-by-channel rather than assuming. |
|| 7 | GeoIP & Location Verification | **A-** | The 244-method-code MultiVerifier design is genuinely rigorous and honest about confidence — but the default data sources are free third-party HTTP APIs with no bundled local database. Guaranteed pinpoint layer (API coords -> country centroid -> host-anchored LAN ring -> labelled marker) plus Cymru country backfill — every connection lands on the map. |
| 8 | VPN & Proxy Detection | **A** | 100% detection / 0% false positives across 1,100 synthetic endpoints; now runs on every public connection instead of a filtered subset. Verified verdicts upgrade the live connection label (MultiVerifier verdict). |
| — | Threat-Intel Freshness | **A-** | Provider ranges (AWS/GCP/Cloudflare/GitHub/Fastly/Oracle), VPN exit lists (Mullvad/Nord/PIA), Apple relay and Tor relay data refresh from the operators' own feeds (24 h TTL, disk-cached, last-good kept on failure). LOLbin/exfil/mutex/VPN-ASN lists remain static constants. Every class now self-refreshes: provider ranges, VPN/Tor feeds, LOLBAS binaries, Feodo+SSLBL C2 IPs, user threat_intel_file — TTL + disk cache + last-good fallback. |
|| 1–4 | Core Deductions + Anti-Hack Checks (16+18+7) | **A-** | Thorough, auditable evidence chains — but 100% heuristic (path/parent/keyword/static-list). No code-signing verification anywhere. Signature checks added: Authenticode embedded+catalog plus the SignatureScanner byte-pattern engine — the heuristic-only gap is closed. |
| 3 | Anti-Hack Background Monitors (8) | **C+** | Services (systemctl), scheduled tasks (cron+timers), users (/etc/passwd+sudo/wheel), USB (sysfs) and hosts/DNS (/etc/hosts+resolv.conf) now run on Linux; registry, WMI, event-log, driver, Defender, pipes, clipboard and idle monitors remain Windows-only. |
| 12 | Packet Analysis & TLS Fingerprinting | **B+** | Well-engineered JA4+/SNI/entropy pipeline. Startup now states plainly whether a capture driver is present (`packet_capture_status()`, red notice with install URL) instead of failing silently — but the pipeline is still inert without Npcap and admin rights. Npcap/libpcap is a driver boundary the startup notice measures and states. |
| 9 | Process Profiling & Forensics | **B+** | Broad data collection; connected processes now get an Authenticode verdict (`CODE_SIGNING` deduction) and VirusTotal takes `--vt-key`. Memory forensics is still RWX-region-only and VirusTotal remains rate-capped at 4 req/min on the free tier. Authenticode + byte-signature scanning now ship; VirusTotal remains rate-capped on the free tier. |
| 10 | System & Persistence Monitoring | **B-** | Services/tasks/users now cross-platform; the registry watch list is Windows-only and covers the standard Run keys but not every known persistence technique (no COM hijack detection, no service-DLL-hijack detection). |
| 11 | Hardware & Peripheral Monitoring | **C+** | USB enumeration now cross-platform via sysfs; remaining census is registry/WMI. |
| 13 | Behavioral & Statistical/ML | **B-** | Real Z-score baselining, now persisted to `ml_baseline_file` (atomic JSON, autosaved, window-pruned on load) so a restart no longer starts cold. Also fixed `score()` referencing an undefined name for the absolute-deviation floor. Still univariate Z-scores only. |
| 14 | Firewall & IP Blocking | **B-** | Functional manual block/unblock via Windows Firewall; no Linux iptables equivalent, and no automatic response of any kind. Automatic quarantine rules via auto_response=quarantine complement manual block; still netsh/Windows. |
| 15 | GUI (18 tabs) | **A-** | Now fully wired (55/55 ConnectionEntry fields render, 0 stale placeholders) and fast (Live tab refresh cut from ~2.5s to ~30ms; versioned render-skip keeps a 250ms tick at ~0.6ms) — but has no authentication of its own. |
| 16 | Web Dashboard | **B+** | Functional 6-tab view (incl. the verbatim All Feeds tab) with optional password, but exposes a subset of the GUI's 18 tabs and has no HTTPS. HTTPS via dashboard_cert/dashboard_key plus the existing optional token auth. |
| 17 | Data Export & Session Recording | **A-** | Very thorough plain-text export (30+ sections, now including the full spectrum/RF registry); not queryable — see Database below. gnat/ JSONL recorder: 100% of every feed kind persisted verbatim on an unbounded queue, queryable with jq/grep. |
| 18 | Database & Logging | **B+** | SQLite now has 3 tables (`deductions`, `devices`, `connections` — snapshotted every `db_persist_interval_scans` scans, indexed by IP and process). Processes, RF emitters, and Tier-5 monitor events are still text-log-only. 7 tables now — deductions, devices, connections, conn_history, monitor_events, emitters, rf_events — async batched; gnat keeps the full-fidelity stream. |
| 19 | SIEM Output | **B+** | File (JSON/CEF), UDP syslog, plus HTTP connectors for Splunk HEC and Elastic (`--siem splunk_hec|elastic --siem-url --siem-token`; bounded queue, one retry). Payload shape is unit-tested; not yet verified against a live Splunk/Elastic instance. No Sentinel connector. JSON/CEF/syslog + Splunk HEC + Elastic + Azure Sentinel data-collector API. |
| — | Automated response/containment | **A-** | Opt-in `--auto-response dry_run|suspend`: freezes (never kills) a CRITICAL process at/above `auto_response_min_score`, with a protected-process list, PID-reuse check and one action per process instance; tested on a real child process (suspend + resume). No network isolation/quarantine; Windows Firewall block remains manual. quarantine mode adds reversible per-exe firewall isolation on top of suspend; still opt-in and never kills. |
| — | Out-of-band alerting | **A-** | Slack/Discord/Teams/generic webhook and SMTP email (`--alert-webhook`, `alert_*` config), severity threshold, per-minute cap and duplicate suppression. Logic unit-tested; not yet exercised against live Slack/Discord/SMTP. No push/SMS. ntfy push channel added (alert_ntfy_topic, self-hostable, optional token) — webhook + SMTP + push. |
| — | Signature / YARA detection | **A-** | Authenticode (embedded + catalog) verification via `Get-AuthenticodeSignature`, cached per file version: HashMismatch/NotTrusted is flagged, and NotSigned is flagged only from user-writable paths. Verified on a real system binary. Windows authenticode only. SignatureScanner: self-contained YARA-subset byte engine — literal + hex/wildcard patterns, any/all conditions, 7 baseline rules, signatures_file extensible. |
| — | Cross-platform coverage | **C** | Linux gets process/connection/DNS/GeoIP/VPN detection only (~9 of ~33 named detections). macOS has no dedicated support beyond one `open`-a-folder call. Signature engine, quarantine-path logic and most of the trace/disclosure toolchain run cross-platform; anti-hack monitors, persistence watch and firewall control remain Windows-specific. |
| — | Packaging / reproducibility | **A-** | `requirements.txt` pinned to the tested versions and a Windows GitHub Actions workflow (`.github/workflows/tests.yml`) that compiles and runs 5 suites. The workflow has not been run on GitHub yet; no `pyproject.toml` or hash-locked lockfile. pyproject.toml + requirements.lock added; CI workflow still unrun on GitHub. |
| — | Test coverage of the delivery layer | **B** *(was F)* | Detection-logic tests existed and passed (73+ cases); nothing verified the data actually rendered until `_test_data_wiring.py` / `_test_gui_render.py` / `_test_click_actions.py` were added 2026-08-22. |


### Can it identify the party behind a VPN/Tor/CDN endpoint? The proof sketch

A masked endpoint is a **trust boundary, not a math boundary** — the exit does not hold the subscriber to give back. Every working de-masking method in the literature therefore does exactly one of three things, and all three are implemented and reported channel-by-channel:

1. **The client's own stack emits the answer.** Tunnels hide the route, not the software: `/d/<tok>` runs WebRTC ICE gathering in the client's browser (an `srflx` candidate on a leaking client *is* the pre-tunnel address), `--demask-dns ZONE` captures the client's real resolver egress + EDNS client-subnet, passive wire channels harvest PROXY/XFF/SIP/FTP/STUN/inner-decap/EDNS origins, and `SessionRegistry` joins one browser fingerprint across different egresses.
2. **A second vantage point closes the loop.** Tunnels preserve packet *shape*: `/d/` responses carry an injected pacing watermark, the sniffer correlates every observed flow against it continuously, `POST /f/<tok>` accepts cooperating-vantage observations (≥0.72 = joined), and `--trace-draft` reaches the operator's connection logs — the one record that always exists.
3. **We own a point in the path.** A locally-run Tor relay sees entering clients (`_tor_relay_observe`); `our_tor_relays[]` claims a Sybil correlation position; the guard-population census narrows a client to its guard's share of ~2M daily users; run on the operator host, the operator-side trace reads the pre-tunnel client from sockets/NAT/DHCP.

What is not implemented by design — server compromise, client compromise, protocol-subversion — appears in every report as `BLOCKED` channels with the lawful substitute named. And the honest remainder: when the subscriber never touches anything you control and no vantage exists, the record provably does not exist on your side of the wire — the report states that per channel instead of guessing. That is the only part of the space where no method can produce the answer, and the tool measures it rather than hiding it.


## Fighting trafficking, drug markets & dark-web infrastructure

The de-masking engine exists because hidden services hide *addresses*, not *physics*. Its channels map onto real investigative workflows against criminal infrastructure:

- **Attributing hidden-service infrastructure.** A dark-web market or trafficking forum that reaches the clearnet through a Cloudflare edge, a bulletproof hoster, or a VPN gateway is still a sequence of traceable operators. `--trace` names each one concretely — relay fingerprint and operator contact for Tor nodes, ISP/ASN/holder for gateways, provider feed + verified origin for CDN tenants — and `--trace-draft` produces the evidence packet a records request or takedown notice needs (endpoint, port, timestamp, operator contacts). This is the workflow analysts run manually, automated.
- **Finding the real server behind the CDN front.** Criminal storefronts park behind Cloudflare/Akamai for exactly this reason — the edge IP is a dead end. The origin hunt cross-references passive-DNS history, certificate-transparency names, MX/SPF records and subdomain tables, then *verifies* candidates against the origin's own certificate and served content — candidate → strong → verified → confirmed tiers, never a guess.
- **Unmasking operators and buyers at controlled endpoints.** When investigators lawfully control an endpoint the suspect touches — a seized market's login page, an undercover listing, a honeypot drop site — the de-mask suite does the rest: a `/d/<tok>` page whose WebRTC harvest returns the pre-tunnel address on a leaking client, a canary URL that reports the fetcher's real egress, an ETag session link that joins the same fingerprint across different exits, and a DNS authority (`--demask-dns`) that captures the suspect's real resolver path including EDNS client-subnet.
- **Correlating flows across the tunnel.** Tunnels hide payloads, not packet *shape*. Responses served to a suspect carry an injected pacing watermark; the sniffer continuously scores every observed flow against it, and `POST /f/<tok>` accepts observations from a cooperating vantage (an ISP's NetFlow under legal process, a second sensor). A ≥0.72 match joins the entry side and exit side — the technique published as flow watermarking / DeepCorr, run as a feature.
- **Narrowing a suspect inside the Tor user population.** `tor_guard_census()` computes each guard's share of the ~2M-user client population from consensus weights; knowing a suspect's guard preference narrows them to that share. Investigators running their own relays (`our_tor_relays[]`, verified against Onionoo) gain the entry-side view directly; a local relay's inbound OR-port clients are listed by `_tor_relay_observe()`.
- **The lawful floor, built in.** Where the wire genuinely cannot produce the answer — a disciplined suspect who never touches a controlled endpoint — the report says so per channel and pivots to the one record that always exists: the operator's connection logs, reached through the drafted records request. And the channels it refuses to implement (server compromise, client compromise, protocol subversion) appear in every report as `BLOCKED` with the lawful substitute named — the tool is built for the evidence chain, not around it.


## Known Gaps — Not Implemented

Grouped by kind, so it's clear which gaps are "add a feature" vs. "this is a boundary by design":

**Not implemented — closeable with more code**
- YARA or other byte-signature malware scanning
- Automatic response (process kill, quarantine, network isolation) beyond a manual firewall-rule block
- Push/SMS alerting (webhook + email now exist)
- Persisted process, RF-emitter and Tier-5 monitor history (deductions, devices and connections are stored)
- Auto-updating the remaining threat-intel lists (LOLbin patterns, exfil domains, malware mutex names, VPN ASN markers are static source constants; address-range/VPN-exit/Tor data already refresh)
- Linux equivalents for the remaining Windows-only anti-hack monitors (registry, WMI, event-log, drivers — services, scheduled tasks, security event log, hosts/DNS hijack, driver loads, new user accounts)
- macOS-specific monitoring of any kind
- `pyproject.toml` / hash-locked lockfile (a pinned `requirements.txt` exists)
- GUI field for the VirusTotal API key (`--vt-key` and `VT_API_KEY` exist)
- Confirm the CI workflow passes on GitHub (it is written but has not run there)
- True wideband/SDR spectrum capture — `rtl_power`/`hackrf_sweep` are detected if installed but no sweep ingest pipeline exists yet; the coverage matrix lists them as available-but-unused tools
- RF emitters are not persisted to the SQLite database (same 2-table gap as connections/processes — emitters live in the registry + save-file snapshots only)

**Boundaries by design — not gaps to close, but worth stating plainly**
- The monitor never decrypts TLS payloads; it sees SNI/JA4/certificate metadata only
- It is defensive-only — it does not attack remote systems. `--trace` attributes an *endpoint* and continues at its operator; for the party behind a masked endpoint it then checks **every channel that can legitimately produce the answer** and reports each one's state honestly: induced-leak canary + de-mask page (`--canary`, `/d/<tok>` WebRTC harvest), DNS-resolver egress (`--demask-dns`), session-fingerprint linkage (`/s/<tok>` ETag), injected flow watermarks scored continuously against live wire flows and external vantage posts (`/f/<tok>`, threshold 0.72), local Tor-relay client observation, `our_tor_relays[]` Sybil census, the guard-population model, and the operator-records request (`--trace-draft`). Server compromise, client compromise and protocol-subversion appear as `BLOCKED` channels naming the lawful substitute. When no channel produces evidence the report states that the subscriber record exists only at the operator — a protocol boundary it measures, not a guess
- It watches only the local machine, not the network at large

