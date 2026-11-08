# MedianBoxMonitor 3.0 — Total Features Reference

**Complete enumeration of every feature, detection, monitor, class, and capability.**

---

## Table of Contents

1. [Core Deductions (16)](#1-core-deductions-16)
2. [Anti-Hack Process Checks (18)](#2-anti-hack-process-checks-18)
3. [Anti-Hack Background Monitors (8)](#3-anti-hack-background-monitors-8)
4. [Enhanced Sneaky-Hacker Checks (7)](#4-enhanced-sneaky-hacker-checks-7)
5. [Network & Connection Monitoring](#5-network--connection-monitoring)
6. [DNS Monitoring](#6-dns-monitoring)
7. [GeoIP & Location Verification](#7-geoip--location-verification)
8. [VPN & Proxy Detection](#8-vpn--proxy-detection)
9. [Process Profiling & Forensics](#9-process-profiling--forensics)
10. [System & Persistence Monitoring](#10-system--persistence-monitoring)
11. [Hardware & Peripheral Monitoring](#11-hardware--peripheral-monitoring)
12. [Packet Analysis & TLS Fingerprinting](#12-packet-analysis--tls-fingerprinting)
13. [Behavioral & Statistical / ML](#13-behavioral--statistical--ml)
14. [Firewall & IP Blocking](#14-firewall--ip-blocking)
15. [GUI (18 Tabs)](#15-gui-18-tabs)
16. [Web Dashboard (FastAPI)](#16-web-dashboard-fastapi)
17. [Data Export & Session Recording](#17-data-export--session-recording)
18. [Database & Logging](#18-database--logging)
19. [SIEM Output](#19-siem-output)
20. [Alert Escalation](#20-alert-escalation)
21. [Configuration System](#21-configuration-system)
22. [Thread Architecture](#22-thread-architecture)
23. [Class Reference (62 Classes)](#23-class-reference-62-classes)
24. [Test Suite](#24-test-suite)
25. [CLI Options](#25-cli-options)
26. [Auto-Flag Action System (33 Keywords)](#26-auto-flag-action-system-33-keywords)
27. [Known Service IP Ranges (CIDR Validation)](#27-known-service-ip-ranges-cidr-validation)
28. [Expected Executable Paths (20+ Processes)](#28-expected-executable-paths-20-processes)
29. [Expected Parent Processes](#29-expected-parent-processes)
30. [Mimic Keywords (Service Fingerprinting)](#30-mimic-keywords-service-fingerprinting)
31. [Allowed Apps (User-Configurable Trust)](#31-allowed-apps-user-configurable-trust)
32. [Hardware Keywords](#32-hardware-keywords)
33. [Persistence Registry Keys](#33-persistence-registry-keys)
34. [Suspicious DLL Paths](#34-suspicious-dll-paths)
35. [Port-to-Service Maps](#35-port-to-service-maps)
36. [Connection Entry Fields (55 Fields)](#36-connection-entry-fields-55-fields)
37. [Database Schema](#37-database-schema)
38. [RDAP/WHOIS Lookup](#38-rdapwhois-lookup)
39. [Web Dashboard Details](#39-web-dashboard-details)
40. [Performance Optimizations](#40-performance-optimizations)
41. [Known Gaps, Missing Features & Platform Coverage](#41-known-gaps-missing-features--platform-coverage)
42. [Completeness Ratings by Category](#42-completeness-ratings-by-category)

---

## 1. Core Deductions (16)

These run in the process watcher thread every 0.5 seconds for every process.

### 1.1 Mimic Detection (`_check_mimic`)
- **What:** Detects a process connecting to an IP that mimics a known legitimate service
- **How:** Cross-references the destination IP's reverse DNS domain against the process's expected service. If `chrome.exe` connects to an IP whose rDNS resolves to `google.com`, that is normal. If `chrome.exe` connects to an IP whose rDNS resolves to a look-alike domain or no domain, it is flagged.
- **Evidence:** Process name, PID, destination IP, domains, expected vs. actual service
- **Score:** 35.0

### 1.2 Foreign Connection (`_check_foreign`)
- **What:** Detects a process connecting to an unexpected foreign country
- **How:** Tracks which countries each process has contacted historically. If a process that has only ever connected to US/UK suddenly connects to Russia or China, it is flagged.
- **Evidence:** Process name, PID, destination IP, country, historical countries
- **Score:** 30.0

### 1.3 Behavioral Anomaly (`_check_behavioral_anomaly`)
- **What:** Detects process behavior deviating from its own baseline
- **How:** Compares current connection rate, destination count, and byte rate against the process's own historical baseline. Uses the `StatisticalBaseline` class.
- **Evidence:** Process name, PID, current vs. baseline metrics
- **Score:** Variable based on deviation

### 1.4 Beacon Detection (`_check_beacon`)
- **What:** Detects regular-interval connections (C2 beaconing)
- **How:** Tracks timestamps of each connection for a process. If connections occur at regular intervals (low variance in inter-arrival time) with at least `beacon_min_samples` (20) samples, it is flagged as a beacon.
- **Evidence:** Process name, PID, connection count, interval statistics
- **Score:** 45.0

### 1.5 Impersonation (`_check_impersonation`)
- **What:** Detects a process running from a non-legitimate path or with wrong parent
- **How:** `ProcessLegitimacyChecker.check_all()` verifies the executable path, parent process, and digital signature against known-good values. A `svchost.exe` running from `C:\Temp\` is flagged.
- **Evidence:** Process name, PID, exe path, parent name, legitimacy reasons
- **Score:** 45.0

### 1.6 Phantom Connections (`_check_phantoms`)
- **What:** Detects ESTABLISHED connections with no owning process
- **How:** Cross-references the connection snapshot against the active PID list. If a connection has `pid=None`, `pid=0`, or a PID that is not in the process list, it is flagged as a phantom.
- **Evidence:** Connection details, PID (or NONE), domains
- **Score:** 50.0

### 1.7 Injection Chain (`_check_injection_chain`)
- **What:** Detects known apps spawning unknown children with many connections
- **How:** If a known app (Chrome, Firefox, Edge, Explorer, Zoom, Teams, Discord, Slack) spawns a child process that is not in the known apps set and that child has >2 network connections, it is flagged as a possible injection chain.
- **Evidence:** Parent process, child process, connection list with services and domains
- **Score:** 40.0

### 1.8 DNS Tunneling (`_check_dns_tunnel`)
- **What:** Detects DNS exfiltration via high-entropy subdomains
- **How:** `DNSTunnelingDetector` checks each DNS query for: label length > 50 chars, entropy > 3.5 bits/char, query rate > 30 queries/sec. These indicate data encoded in DNS subdomains.
- **Evidence:** Query name, source IP, entropy, label length
- **Score:** 50.0

### 1.9 Exfiltration (`_check_exfil`)
- **What:** Detects I/O byte spike exceeding 10x baseline
- **How:** Tracks per-process I/O counters (`proc.io_read_bytes`, `proc.io_write_bytes`). If the current rate exceeds `exfil_bytes_spike_factor` (10x) the baseline and exceeds `exfil_min_bytes` (1MB), it is flagged.
- **Evidence:** Process name, PID, byte rate, baseline rate, spike factor
- **Score:** 55.0

### 1.10 DLL Injection (`_check_dlls`)
- **What:** Detects suspicious modules loaded into process memory
- **How:** `DLLInspector` enumerates loaded modules via `proc.memory_maps()`. Flags DLLs loaded from non-standard paths (Temp, AppData, Downloads), unsigned DLLs, and known injection DLLs.
- **Evidence:** Process name, PID, suspicious module paths, module count
- **Score:** 40.0
- **Scan interval:** Every 30s per process

### 1.11 Persistence (`_check_persistence`)
- **What:** Detects registry run keys, scheduled tasks, startup folder changes
- **How:** `RegistryMonitor` watches `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`, `HKCU\...\Run`, `StartupFolder`, and Winlogon shell keys. Compares against baseline.
- **Evidence:** Registry key, value, change type
- **Score:** 35.0
- **Scan interval:** Every 60s

### 1.12 Idle Anomaly (`_check_idle_anomaly`)
- **What:** Detects network activity while user is idle
- **How:** `UserIdleMonitor` uses Windows `GetLastInputInfo()` to detect idle time. If the user has been idle > `user_idle_threshold` (300s) and a process is making network connections, it is flagged.
- **Evidence:** Process name, PID, idle duration, connection details
- **Score:** 30.0

### 1.13 ML Anomaly (`_check_ml_anomaly`)
- **What:** Statistical Z-score deviation over 24h baseline window
- **How:** `StatisticalBaseline` maintains per-process-name deques of connection rate, destination count, byte rate, and CPU mean. Computes Z-score for each metric. If Z > `ml_zscore_threshold` (3.0), it is flagged.
- **Evidence:** Process name, PID, anomalous metrics with Z-scores
- **Score:** `min(100, total_z * 10)`
- **Baseline window:** 86400s (24h)
- **Minimum samples:** 50

### 1.14 GeoIP Risk (`_check_geoip`)
- **What:** Detects connections to high-risk countries
- **How:** Looks up the destination IP's country via `GeoIPCache`. If the country code is in `high_risk_countries` ({CN, RU, KP, IR}), it is flagged.
- **Evidence:** Process name, PID, destination IP, country, domains
- **Score:** 40.0

### 1.15 Watchlist (`_check_watchlist`)
- **What:** Detects connections to user-defined watched IPs or processes
- **How:** Compares destination IP against `_watchlist_ips` and process name against `_watchlist_procs`. Watchlists are managed via GUI context menus and persisted between sessions.
- **Evidence:** Process name, PID, destination IP, watchlist match
- **Score:** 50.0

### 1.16 Verification (`_check_verification`)
- **What:** MultiVerifier cross-check disagreement on location
- **How:** Queues public IPs for `MultiVerifier.verify()` which runs 38 independent location verification methods. If methods disagree on country/city, the conflict is flagged.
- **Evidence:** Process name, PID, destination IP, verification report, conflicts
- **Score:** Variable based on confidence grade

---

## 2. Anti-Hack Process Checks (18)

These run in the process watcher thread every 0.5 seconds.

### 2.1 Network-Spawned Process (`_check_network_spawned`)
- **Catches:** Network-facing process (sshd, w3wp, sqlservr, winrm, termsrv, nginx, httpd) spawning a shell (cmd, powershell, whoami, net, systeminfo, wmic, certutil, bitsadmin, etc.)
- **Technique:** Checks `profile.parent_name` against `_NETWORK_PARENTS` set and `profile.name` against `_SUSPICIOUS_CHILDREN` set
- **Severity:** CRITICAL, Score: 55.0
- **Pin category:** `NET_SPAWN`

### 2.2 Listening Port Anomaly (`_check_listening_ports`)
- **Catches:** Non-system process opening unexpected listening port (bind shell, C2 listener)
- **Technique:** Calls `psutil.Process(pid).connections(kind='inet')`, checks for LISTEN status. Flags if port > 1024 and not in `_EXPECTED_LISTEN_PORTS` ({80, 443, 3389, 22, 21, 25, 53, 110, 143, 445, 139, 5985, 5986, 8080, 8443, 5900, 5938, 135, 137, 138, 161, 162, 389, 636, 464, 1433, 1521, 3306, 5432, 6379, 27017, 9200}) and process name not in `_SYSTEM_PROCESSES`
- **Severity:** CRITICAL, Score: 50.0
- **Pin category:** `LISTEN_ANOMALY`

### 2.3 Credential Dumping (`_check_credential_access`)
- **Catches:** mimikatz, procdump -ma, reg save HKLM\SAM, ntdsutil, sekurlsa, laZagne, sharpkatz, pypykatz, nanodump
- **Technique:** Checks process name against `cred_tools` set. Checks `reg.exe` command line for "save" + "sam"/"security"/"system". Checks `procdump.exe` for "-ma" flag. Checks `ntdsutil.exe` presence.
- **Severity:** CRITICAL, Score: 60-70.0
- **Pin category:** `CREDENTIAL_DUMP`

### 2.4 Port Forwarding / Tunnel (`_check_port_forward`)
- **Catches:** chisel, ngrok, ligolo, plink, socat, stunnel, iodine, dnscat2, rathole, frpc, frps, SSH with -L/-R/-D
- **Technique:** Checks process name against `tunnel_tools` set. Checks `ssh.exe` command line for " -l ", " -r ", " -d " flags.
- **Severity:** CRITICAL (tunnel tools) / WARNING (SSH forwarding), Score: 35-50.0
- **Pin category:** `PORT_FORWARD`

### 2.5 Data Staging (`_check_data_staging`)
- **Catches:** 7z, winrar, rar, tar, 7za, bandizip compressing user document directories; PowerShell Compress-Archive
- **Technique:** Checks process name against `archive_tools` set and command line for user directories (`\documents\`, `\desktop\`, `\downloads\`, `\pictures\`, `\users\`). Checks PowerShell for "compress-archive".
- **Severity:** WARNING, Score: 35.0
- **Pin category:** `DATA_STAGING`

### 2.6 PowerShell Abuse (`_check_powershell_abuse`)
- **Catches:** -enc, -EncodedCommand, -e, -ExecutionPolicy Bypass, -w hidden, -WindowStyle hidden, IEX(, DownloadString, Invoke-Expression, FromBase64String, Invoke-WebRequest, Invoke-RestMethod, -nop, -NonInteractive, amsiInitFailed, AMSI bypass, Reflection.Assembly
- **Technique:** Inspects command line of powershell.exe and pwsh.exe against 17 abuse indicators
- **Severity:** CRITICAL (enc/amsi/iex/download/frombase64/reflection) / WARNING (others)
- **Score:** 30-45.0
- **Pin category:** `PS_ABUSE`

### 2.7 Backup Tampering (`_check_backup_tampering`)
- **Catches:** vssadmin delete/resize, wbadmin delete, bcdedit recoveryenabled no
- **Technique:** Checks process name and command line for delete/resize/recoveryenabled keywords
- **Severity:** CRITICAL, Score: 55-60.0
- **Pin category:** `BACKUP_TAMPER`

### 2.8 Admin Share Access (`_check_admin_share`)
- **Catches:** net use \\host\C$/ADMIN$/IPC$, PsExec, PsExecSvc on port 445
- **Technique:** Checks if `dst_port == 445` and process is `net.exe` with "use" and "$" in command line, or process is `psexec.exe`/`psexesvc.exe`
- **Severity:** CRITICAL, Score: 50.0
- **Pin category:** `ADMIN_SHARE`

### 2.9 Exfil Channel (`_check_exfil_channel`)
- **Catches:** Connections to Discord, Telegram, Slack, Pastebin, transfer.sh, gofile.io, file.io, mega.nz, webhook.site, requestbin.com, ngrok, trycloudflare, etc.
- **Technique:** Checks connection domains against `_EXFIL_CHANNELS` set (25 known exfil/C2 domains)
- **Severity:** WARNING, Score: 40.0
- **Pin category:** `EXFIL_CHANNEL`

### 2.10 Process Hollowing (`_check_process_hollow`)
- **Catches:** System-named process (svchost, lsass, csrss, etc.) running from non-System32/SysWOW64 path
- **Technique:** Checks if `profile.name` is in `_SYSTEM_PROCESSES` and `exe_path` does not contain "system32" or "syswow64"
- **Severity:** CRITICAL, Score: 55.0
- **Pin category:** `PROCESS_HOLLOW`

### 2.11 LSASS Access (`_check_lsass_access`)
- **Catches:** comsvcs.dll MiniDump via rundll32, taskmgr.exe creating dump files
- **Technique:** Finds LSASS PID, checks non-system processes for comsvcs.dll+MiniDump in command line or taskmgr with dump flags
- **Severity:** CRITICAL, Score: 70.0
- **Pin category:** `CREDENTIAL_DUMP`

### 2.12 Exfil Upload (`_check_exfil_upload`)
- **Catches:** curl/wget with --upload-file, -T, --form, -d, --data, --data-binary uploading to external servers
- **Technique:** Checks curl.exe/wget.exe command line for upload flags
- **Severity:** CRITICAL, Score: 50.0
- **Pin category:** `EXFIL_CHANNEL`

### 2.13-2.18: See Enhanced Checks below (features 4.1-4.7)

---

## 3. Anti-Hack Background Monitors (8)

These run in the `_extended_monitor_thread` at varying intervals.

### 3.1 Security Event Log Monitor (`SecurityEventMonitor`)
- **Interval:** Every 15s (cycle % 3 == 0, base cycle 5s)
- **Catches:** Windows Security event log entries 4624 (logon), 4625 (failed logon), 4688 (process creation), 7045 (service install), 4720 (user created), 4728 (admin group add), 4732 (local group member add), 4768 (Kerberos TGT), 4769 (Kerberos service ticket)
- **How:** Uses `win32evtlog.OpenEventLog('Security')` with backwards sequential read. Falls back to `wevtutil qe Security` if win32evtlog is not available.
- **Severity:** CRITICAL for 4625/7045/4720/4728/4732, WARNING for others

### 3.2 Hosts File / DNS Hijack Monitor (`HostsFileMonitor`)
- **Interval:** Every 30s
- **Catches:** Modification to `C:\Windows\System32\drivers\etc\hosts`, DNS server changes
- **How:** MD5 hash of hosts file compared each cycle. DNS servers extracted from `ipconfig /all` output. First run establishes baseline.
- **Severity:** CRITICAL for hosts file change, WARNING for DNS server change

### 3.3 Service Creation Monitor (`ServiceMonitor`)
- **Interval:** Every 60s
- **Catches:** New Windows services, services with binary paths in Temp/Downloads/AppData/Desktop/Public/ProgramData
- **How:** Runs `sc query type= service state= all`, parses service names. New services compared against baseline. Binary path retrieved via `sc qc {service}`.
- **Severity:** CRITICAL

### 3.4 Security Tool Monitor (`SecurityToolMonitor`)
- **Interval:** Every 30s
- **Catches:** Windows Defender real-time protection disabled, Windows Firewall disabled
- **How:** Defender status via `Get-MpComputerStatus | Select RealTimeProtectionEnabled` (PowerShell). Firewall status via `netsh advfirewall show allprofiles state`.
- **Severity:** CRITICAL when disabled, WARNING when re-enabled

### 3.5 User Account Monitor (`UserAccountMonitor`)
- **Interval:** Every 60s
- **Catches:** New user accounts, new admin group members
- **How:** Runs `net user` and `net localgroup administrators`, parses output, compares against baseline.
- **Severity:** CRITICAL

### 3.6 WMI Subscription Monitor (`WMISubscriptionMonitor`)
- **Interval:** Every 60s
- **Catches:** New WMI EventFilter or CommandLineEventConsumer (stealthy persistence)
- **How:** Runs `wmic /namespace:\\root\subscription path __EventFilter get Name` and `__CommandLineEventConsumer get Name`, compares against baseline.
- **Severity:** CRITICAL

### 3.7 Driver Load Monitor (`DriverLoadMonitor`)
- **Interval:** Every 60s
- **Catches:** New kernel driver loads, new .sys files in `C:\Windows\System32\drivers\`
- **How:** Runs `sc query type= driver state= active` and lists `.sys` files in drivers directory. Compares both against baselines.
- **Severity:** WARNING

### 3.8 Mutex Scanner (`MutexScanner`)
- **Interval:** Every 30s
- **Catches:** Known malware mutex names
- **How:** Uses `ctypes.windll.kernel32.OpenMutexW()` to test for known mutex names: Synaptics, avira_gui_lock, OneOneMutex, WinInitMutex, Global\__DDAInterface, Global\D3DWindow, B0184A2A-1F90-4D55-A6B0-13A8B5C0E6B2 (Cobalt Strike), Global\MSEdgeRedirector, Global\ChromeExtPipe, MUTEX_UUID (Meterpreter).
- **Severity:** CRITICAL

---

## 4. Enhanced Sneaky-Hacker Checks (7)

These run in the process watcher every 0.5 seconds and catch the most evasive techniques.

### 4.1 LOLbin Abuse (`_check_lolbin_abuse`)
- **Catches:** Living-off-the-land binary abuse — certutil, bitsadmin, mshta, regsvr32, rundll32, wmic, msiexec, msbuild, installutil, forfiles, cmstp, and 12 more
- **How:** Maintains `_LOLBIN_PATTERNS` dict mapping each LOLbin to suspicious argument patterns:
  - `certutil.exe`: -urlcache, -split, -decode, -encode
  - `bitsadmin.exe`: /transfer, /create, /addfile
  - `mshta.exe`: http, javascript:, vbscript:
  - `regsvr32.exe`: /i:http, /i:https, /u, scrobj.dll (Squiblydoo attack)
  - `rundll32.exe`: javascript:, shell32.dll,ShellExec, comsvcs.dll,MiniDump, \temp\, \downloads\
  - `wmic.exe`: process call create, process create, /node: (lateral movement)
  - `msiexec.exe`: /i http, /quiet
  - `forfiles.exe`: /c, cmd.exe (LOLbin bypass)
  - `cmstp.exe`: /s, /ns
- **Severity:** CRITICAL for remote/script/dump patterns, WARNING for others
- **Score:** 30-50.0
- **Pin category:** `LOLBIN_ABUSE`

### 4.2 Suspicious Execution Path (`_check_suspicious_exec_path`)
- **Catches:** Executable running from Temp, AppData\Local\Temp, AppData\Roaming, Downloads, Desktop, Public, ProgramData, $Recycle.Bin, Windows\Temp, PerfLogs
- **How:** Checks `profile.exe_path` against `_SUSPICIOUS_EXEC_DIRS` tuple. Exempts system processes and known safe directories (System32, SysWOW64, Program Files, WinSxS, Servicing, Assembly).
- **Severity:** CRITICAL, Score: 45.0
- **Pin category:** `SUSPICIOUS_PATH`

### 4.3 Parent-Child Mismatch (`_check_parent_child_mismatch`)
- **Catches:** System processes spawned by unexpected parents (process hollowing/injection indicator)
- **How:** Maintains `_EXPECTED_PARENTS` dict:
  - `svchost.exe` should be spawned by `services.exe`
  - `lsass.exe` should be spawned by `wininit.exe`
  - `smss.exe` should be spawned by `smss.exe` or `System`
  - `wininit.exe` should be spawned by `smss.exe`
  - `winlogon.exe` should be spawned by `smss.exe`
  - `csrss.exe` should be spawned by `smss.exe`/`wininit.exe`/`winlogon.exe`
  - `services.exe` should be spawned by `wininit.exe`
  - `spoolsv.exe` should be spawned by `services.exe`
  - `explorer.exe` should be spawned by `userinit.exe`/`explorer.exe`
  - `conhost.exe` should be spawned by cmd/powershell/terminal/explorer/svchost
  - And 4 more
- **Severity:** CRITICAL, Score: 55.0
- **Pin category:** `PARENT_MISMATCH`

### 4.4 LSASS Handle Access (`_check_lsass_access`)
- **Catches:** Non-system processes accessing LSASS memory via comsvcs.dll MiniDump or taskmgr dump
- **How:** Finds LSASS PID via `psutil.process_iter()`. Checks non-system process command lines for "comsvcs.dll" + "minidump" or taskmgr.exe with ".dmp"/"dump" in command line.
- **Severity:** CRITICAL, Score: 70.0
- **Pin category:** `CREDENTIAL_DUMP`

### 4.5 PowerShell Obfuscation (`_check_powershell_obfuscation`)
- **Catches:** Advanced PowerShell obfuscation that evades simple pattern matching
- **How:** 12 obfuscation indicators:
  1. High special-character ratio (>15% non-alphanumeric in commands >50 chars)
  2. Reversed string patterns (e.g., `}he\``, `noisseuqxe-ekovni`)
  3. String concatenation with char codes (>10 `+` signs + "char")
  4. XOR encoding (`-bxor` or `^` + "char")
  5. Base64 decode with type accelerator (`FromBase64String` + `::`)
  6. Long encoded command (`-enc` with >100 char blob)
  7. `-Command` with IEX/Invoke-Expression
  8. Stealth flag combo (3+ of: -w hidden, -nop, -noninteractive, -sta)
  9. WebClient download cradle (`Net.WebClient` + `download`)
  10. Reflective assembly load (`Reflection.Assembly` or `[Assembly]`)
  11. Add-Type with network access (in-memory C# compile)
  12. AMSI bypass (`amsiInitFailed` or `amsi bypass`)
- **Severity:** CRITICAL (2+ indicators) / WARNING (1 indicator)
- **Score:** 35-55.0
- **Pin category:** `PS_OBFUSCATION`

### 4.6 Suspicious Child Process (`_check_suspicious_child`)
- **Catches:** Office apps spawning shells (macro malware), browsers spawning shells (exploit drive-by)
- **How:** Two parent sets:
  - `_OFFICE_PARENTS`: winword, excel, powerpnt, outlook, onenote, msaccess → spawning cmd/powershell/etc = MACRO_MALWARE
  - `_BROWSER_PARENTS`: chrome, firefox, msedge, iexplore, brave, opera, vivaldi → spawning cmd/powershell/wscript/mshta/rundll32/regsvr32 = BROWSER_EXPLOIT
- **Severity:** CRITICAL, Score: 60.0
- **Pin categories:** `MACRO_MALWARE`, `BROWSER_EXPLOIT`

### 4.7 Renamed System Binary (`_check_renamed_system_binary`)
- **Catches:** System binaries (cmd, powershell, reg, regedit, sc, net, taskmgr, wmic, netsh, certutil, bitsadmin, mshta) running from non-standard paths
- **How:** Checks if process name is in `_SYSTEM_BINARIES` set and exe_path does not contain "system32", "syswow64", or "WindowsPowerShell"
- **Severity:** CRITICAL, Score: 50.0
- **Pin category:** `RENAMED_BINARY`

---

## 5. Network & Connection Monitoring

### 5.1 Connection Mapper (`_connection_mapper`)
- **Interval:** Every 0.5s
- **Source:** `psutil.net_connections(kind='all')`
- **Outputs:**
  - `_conn_snapshot` — raw connection list (for ConnectionInventory)
  - `conn_by_pid` — defaultdict mapping PID → list of connections
  - `conn_by_raddr` — dict mapping remote IP → (pid, conn)
- **Thread safety:** Replaces dicts atomically; process watcher grabs reference (not copy)

### 5.2 Connection Inventory (`ConnectionInventory`)
- **Class:** `ConnectionInventory` (line 21822)
- **Interval:** Configurable via `scan_interval_min`/`scan_interval_max` (2-10s)
- **What it does:** Enriches each connection with:
  - Service identification (via `ServiceResolver`)
  - GeoIP data (via `GeoIPCache` — background worker for API calls)
  - Domain resolution (via `DNSCache`)
  - Proxy detection (via `ProxyDetector`)
  - First-seen / last-seen timestamps
  - Connection duration and bandwidth
  - Location verification proof chain
- **Background workers:**
  - `_geoip_worker` — processes GeoIP queue, calls ip-api.com, enriches existing entries
  - `_rdns_worker` — processes reverse DNS queue, calls `socket.gethostbyaddr()`, updates cache

### 5.3 Connection History (`ConnectionHistory`)
- **Class:** `ConnectionHistory` (line 4309)
- **What:** Tracks connection lifecycles (active → closed) with durations
- **Outputs:** Timeline, active connections, closed connections, bandwidth data

### 5.4 Inbound Scan Detector (`InboundScanDetector`)
- **Class:** `InboundScanDetector` (line 3692)
- **What:** Detects external IPs probing multiple ports
- **How:** Tracks unique source IPs and the ports they probe. Flags when an IP probes >N ports in a time window.

### 5.5 Interface Statistics (`_iface_stats_thread`)
- **Interval:** Every 1s
- **What:** Tracks per-interface bandwidth via `psutil.net_io_counters(pernic=True)`
- **Outputs:** Total sent/recv, packets, errors per interface

---

## 6. DNS Monitoring

### 6.1 DNS Cache (`DNSCache`)
- **Class:** `DNSCache` (line 2368)
- **What:** Bidirectional DNS mapping — domain → IPs and IP → domains
- **How:** Populated from sniffed DNS responses (UDP port 53) and from `socket.gethostbyaddr()` background worker
- **Features:**
  - `get_domains(ip)` — returns domains that resolved to this IP
  - `get_ips(domain)` — returns IPs that this domain resolved to
  - `recent_queries(window)` — returns recent DNS queries with timestamps
  - TTL-based aging

### 6.2 DNS Tunneling Detector (`DNSTunnelingDetector`)
- **Class:** `DNSTunnelingDetector` (line 2647)
- **What:** Detects data exfiltration via DNS queries
- **Thresholds:**
  - `dns_tunnel_max_label_len`: 50 chars
  - `dns_tunnel_entropy_threshold`: 3.5 bits/char
  - `dns_tunnel_query_rate_threshold`: 30 queries/sec

### 6.3 DoH Detector (`DoHDetector`)
- **Class:** `DoHDetector` (line 4223)
- **What:** Detects DNS-over-HTTPS connections that bypass local DNS monitoring
- **Known DoH servers:** Cloudflare (1.1.1.1, 1.0.0.1), Google (8.8.8.8, 8.8.4.4), Quad9 (9.9.9.9), OpenDNS (208.67.222.222), AdGuard (94.140.14.14), CleanBrowsing (185.228.168.9)

### 6.4 SNI Extractor (`SNIExtractor`)
- **Class:** `SNIExtractor` (line 2730)
- **What:** Extracts Server Name Indication from TLS ClientHello packets
- **How:** Parses TLS ClientHello extension to get the requested hostname

---

## 7. GeoIP & Location Verification

### 7.1 GeoIP Cache (`GeoIPCache`)
- **Class:** `GeoIPCache` (line 6776)
- **What:** Caches GeoIP lookups with TTL-based expiration
- **Sources:**
  - Primary: MaxMind GeoIP2 database (if `geoip2` installed and DB path configured)
  - Fallback: ip-api.com HTTP API (free, rate-limited via `TokenBucket`)
- **Cache TTL:** 3600s (1 hour)
- **Background enrichment:** New public IPs are queued for background GeoIP lookup to avoid blocking scans
- **Fast paths:** `get_cached()` returns cached data only (no network), `get_country()` and `get_org()` have direct cache check

### 7.2 Location Verifier (`LocationVerifier`)
- **Class:** `LocationVerifier` (line 7406)
- **What:** Single-IP location verification with 4 methods:
  1. Reverse DNS check (IATA/city codes, ccTLD)
  2. RDAP registry country
  3. RTT latency band (active ping)
  4. Alternate GeoIP source (ipwho.is)

### 7.3 MultiVerifier (`MultiVerifier`)
- **Class:** `MultiVerifier` (line 7746)
- **What:** Cross-verifies IP location and identity using **244 named evidence methods** — an 11-method core battery (run as a parallel probe wave inside `verify()`, ~1–4s total instead of ~15s serial) plus a passive wire-evidence battery harvested from traffic the sniffer already sees
- **Core / active-lite methods:**
  1. GeoIP primary (MaxMind DB or ip-api.com) → country/city vote
  2. GeoIP alternate (ipwho.is) → independent vote
  3. Reverse DNS (IATA/city codes, ccTLD) → independent vote
  4. RDAP registry country → independent vote
  5. RIPE/BGP + Cymru DNS-ASN (`RIPE`/`BGP`/`ASNDNS`, `ASNX` conflict on disagreement) → third geolocation vote + announced prefix/origin AS
  6. RTT latency band + jitter (active ping) → physical plausibility
  7. TCP-RTT vs ICMP-RTT divergence (`TCPRTT`) → relay-edge / port-forward evidence
  8. TTL / OS fingerprint (active ping) → OS + hop distance
  9. VPN/proxy TCP port fingerprint (`PortFP`, active) → service evidence
  10. Infrastructure classification (org/ASN/CDN/hosting) → VPN/proxy/hosting flag
  11. DNS leak / resolver mismatch (`DNSLeak`, rDNS TLD) → VPN DNS-leak signal
  12. TLS JA3 + peer cert decode (`JA3`/`CERT`, :443) → client software ID + cert SAN city votes
  13. ASN correlation (known VPN/proxy ASNs) → VPN provider match
  14. `PATH` / `HOPDIST` — claimed distance vs RTT ceiling / per-hop span → the "IP is lying about its location" proof
  15. `PEER` — RTT coherence sweep within a claimed city → relabeled-sibling detection
  16. `MSS`/`PMTU`/`TUNX` — advertised MSS clamp vs measured path-MTU → localizes tunnel overhead (endpoint link vs near path vs end-to-end)
  17. `TCPFP`/`TTLX`/`HOPS`/`LAND` — passive TCP fingerprint, path-split check, last-mile pings, path-landing geolocation
  18. `EDGE`/`VIA`/`HTTP`/`RDRCT`/`XFF` — HTTP response headers (CF-RAY/x-amz-cf-pop/Via/Server, redirects, forwarded-for chains)
  19. `GEOFEED`/`RPKI`/`H2FP`/`TSRTT`/`TSCLK` — geofeed files, RPKI validation, HTTP/2 fingerprints, passive handshake RTT/clock-skew
  20. `TOREXIT`/`EXITLIST`/`ONIONOO` — Tor exit-node detection (cached `medianbox_exitlists.json` + TorDNSEL/Onionoo lookups) → `is_tor` on the connection
  21. `IKE`/`IKEV2`/`WGWIRE`/`OVPNOP`/`DTLSOP`/`QUICV`/`STUN`/`NATT` — tunnel-protocol negotiation signatures (VPN proto tranche)
- **Passive wire-evidence battery:** ~200 additional named rows — L3/ICMP tunnels, ECH, MPTCP, overlay/VXLAN/Geneve/L2TP/ESP, ZeroTier/Tailscale/Nebula/mesh overlays, GTP, decapsulated inner endpoints, fragmentation/IPID/flow-label analysis, protocol self-ID decoders (SSH/HASSH, Kerberos, LDAP, RDP, RTSP, SIP, FTP, MQTT, Modbus, BACnet, Kafka, X11, BGP, VNC, RADIUS, DNP3, S7/IEC-104, DB2, ClickHouse, OPC-UA, iSCSI, NUT, Prometheus, Docker, DICOM, Cassandra, TS3, SVN, AMQP, Zabbix, CheckMK, AFP, IDENT, GIT, WS-Discovery, ENIP, NAT-PMP, Mumble, SrcDS, VMware, DIAMETER, NATS, Q3, Minecraft-Bedrock, TINC, CoAP, and dozens more), WPAD/PAC/ECN/ECS harvest, session-link/correlation rows (SCTPMH, EUI64, ALIAS, CRTSH, FLOWCORR, TLS session resumption), and hidden-path channels (SPLITR/EXFIL/DEADDROP/PORTAL/KNOCK)
- **Output:** Consensus country/city, confidence grade (A-F), conflict list, VPN score, labels, `is_tor` flag — every row renders in the LIVE/CONN method tables, Inspector dossier, SYS verification table, the All Feeds dashboard tab, and the .txt exports
- **Design:** No single source trusted; disagreement is itself a VPN/proxy indicator; `verify_workers` pool (default 18) keeps pace with every public endpoint

---

## 8. VPN & Proxy Detection

### 8.1 VPN Leak Detector (`VPNLeakDetector`)
- **Class:** `VPNLeakDetector` (line 20366)
- **What:** Detects VPN privacy leaks
- **Checks:**
  1. `_detect_vpn_interfaces()` — detects WireGuard, OpenVPN, TAP adapters
  2. `_detect_dns_resolvers()` — checks if DNS goes outside VPN tunnel
  3. `_detect_global_ipv6()` — detects global IPv6 traffic bypassing IPv4-only VPN
  4. `_detect_route_leaks()` — checks if traffic routes through VPN interface
  5. `_detect_webrtc_local_ip()` — detects WebRTC exposing real local IP

### 8.2 Proxy Detector (`ProxyDetector`)
- **Class:** `ProxyDetector` (line 20173)
- **What:** Detects proxy/VPN connections via TCP fingerprinting and port patterns
- **How:** Checks connections against known proxy ports (1080, 3128, 8080, 8443, 9050/Tor). Identifies proxy processes. Detects system proxy settings (PAC file, env vars, WinHTTP proxy).

---

## 9. Process Profiling & Forensics

### 9.1 Process Profile (`ProcessProfile`)
- **Class:** `ProcessProfile` (line 2288)
- **Fields:** pid, name, exe_path, parent_pid, parent_name, start_time, destinations, dns_domains, sni_domains, connection_count, seen_conn_keys, cpu_samples (60-sample deque), packet_timestamps (500-sample deque), bytes_sent, bytes_recv, risk_score, risk_reasons, last_network_ts, checked_legitimacy, checked_dlls, dll_scan_time, io_baseline_sent, io_baseline_recv, io_snapshot_time, io_send_rate, io_rate_samples (60-sample deque), geo_countries, loaded_dlls, escalation_hits, ml_anomaly_score

### 9.2 Process Legitimacy Checker (`ProcessLegitimacyChecker`)
- **Class:** `ProcessLegitimacyChecker` (line 2825)
- **What:** Verifies process legitimacy via path, parent, and signature
- **How:** `check_all(proc)` returns list of reasons why a process is suspicious

### 9.3 DLL Inspector (`DLLInspector`)
- **Class:** `DLLInspector` (line 2870)
- **What:** Enumerates loaded modules and flags suspicious DLLs
- **How:** Uses `proc.memory_maps()` to list loaded modules. Flags DLLs from Temp/AppData/Downloads, unsigned DLLs, and known injection DLLs.
- **Scan interval:** Every 30s per process

### 9.4 Memory Forensics (`_memory_forensics_thread`)
- **Interval:** Every 15s (admin only)
- **What:** Scans process memory for RWX (read-write-execute) regions
- **How:** Uses `proc.memory_maps()` to find regions with RWX permissions, which indicate injected code

### 9.5 VirusTotal Checker (`VirusTotalChecker`)
- **Class:** `VirusTotalChecker` (line 3124)
- **What:** Checks executable hashes against VirusTotal
- **How:** Computes SHA256 of `profile.exe_path`, queries VirusTotal API (if API key configured). Rate-limited, cached per PID.
- **Output:** Malicious/suspicious/harmless/undetected counts, AV engine detections

---

## 10. System & Persistence Monitoring

### 10.1 Registry Monitor (`RegistryMonitor`)
- **Class:** `RegistryMonitor` (line 2894)
- **Interval:** Every 60s
- **Watches:** `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`, `HKCU\...\Run`, `StartupFolder`, Winlogon shell keys
- **How:** Reads registry values via `winreg`, compares against baseline

### 10.2 File System Watchdog (`FileSystemWatchdog`)
- **Class:** `FileSystemWatchdog` (line 3242)
- **Interval:** Every 10s
- **Watches:** Sensitive directories (System32, Program Files, user directories, temp)
- **How:** Tracks file creation, modification, deletion in watched directories

### 10.3 Scheduled Task Monitor (`ScheduledTaskMonitor`)
- **Class:** `ScheduledTaskMonitor` (line 3480)
- **Interval:** Every 60s
- **How:** Enumerates scheduled tasks via `schtasks /query /fo LIST /v`, compares against baseline

### 10.4 Named Pipe Monitor (`NamedPipeMonitor`)
- **Class:** `NamedPipeMonitor` (line 3536)
- **Interval:** Every 30s
- **How:** Enumerates named pipes via `\\.\pipe\` on Windows. Flags pipes with suspicious names or created by non-system processes.

### 10.5 Clipboard Monitor (`ClipboardMonitor`)
- **Class:** `ClipboardMonitor` (line 3331)
- **Interval:** Every 5s
- **What:** Detects processes reading the clipboard
- **How:** Monitors clipboard content changes and attributes access to processes

### 10.6 User Idle Monitor (`UserIdleMonitor`)
- **Class:** `UserIdleMonitor` (line 2933)
- **What:** Detects user idle time via Windows `GetLastInputInfo()`
- **Threshold:** 300s (configurable)

---

## 11. Hardware & Peripheral Monitoring

### 11.1 USB Monitor (`USBMonitor`)
- **Class:** `USBMonitor` (line 3421)
- **Interval:** Every 30s
- **What:** Detects USB device connections and removals

### 11.2 Bluetooth Scanner (`BluetoothScanner`)
- **Class:** `BluetoothScanner` (line 4432)
- **Interval:** Every 30s
- **What:** Enumerates Bluetooth devices and detects new connections

### 11.3 Serial Port Scanner (`SerialPortScanner`)
- **Class:** `SerialPortScanner` (line 4536)
- **Interval:** Every 30s
- **What:** Enumerates COM ports and serial devices

### 11.4 ARP Scanner (`_arp_thread`)
- **Admin only**
- **What:** Discovers network devices via ARP scan using Scapy `srp()`
- **Output:** IP, MAC, vendor (via `manuf` library or OUI lookup), hostname, OS guess

### 11.5 Spectrum Hub (`SpectrumHub`)
- **Class:** `SpectrumHub` (line 5555) — `Spectrum-Intel` daemon thread, ~2s tick
- **Function:** Orchestrates every non-IP signal collector on its own cadences — Wi-Fi BSSID sweep (`rf_wifi_interval`, 15s), BT/BLE census (30s), interface census (30s), WWAN (60s), RF hardware (120s), L2-wire flush (`rf_l2_flush_interval`, 15s), obs-file ingest, trilateration solves — and drains a labeled event queue into deductions/suspicious feed.
- **Cadence correctness:** scan results are classified `ok` / `inconclusive` / `unavailable`; only `ok` sweeps advance the per-medium absent counter — a transient `netsh`/PowerShell failure never marks emitters lost.
- **Events:** `RF_NEW_EMITTER`, `RF_EMITTER_LOST`, `RF_APPROACH`, `RF_EVIL_TWIN`, `RF_HIDDEN_SSID`, `RF_HARDWARE`, `RF_FIX` — appended to both a processing deque (drained by the monitor thread) and a persistent `_ui_events` deque (maxlen 400) so the UI feed is never emptied by processing.

### 11.6 Signal Registry (`SignalRegistry`)
- **Class:** `SignalRegistry` (line 4830)
- **Function:** Unified emitter registry — one record per `medium:mac` across **11 media**: `wifi-ap`, `wifi-radio`, `wifi-direct`, `bt-radio`, `bt-classic`, `ble`, `wwan-modem`, `local-radio`, `rf-hw`, `local-iface`, `l2-wire`.
- **Record fields:** key, medium, address (MAC normalized across `-`/`:`/case so one physical radio is one emitter), name, vendor (OUI), first_seen, last_seen, seen_count, scans_absent, status (active/lost), sensors, notes, rssi_dbm, rssi_hist (90-sample deque), rssi_avg/min/max, rssi_trend_db_min, dist_m, dist_trend, freq_mhz, band, channel, extra (free-form raw fields per collector).
- **Distance:** `_rssi_to_distance_m` — log-distance path loss `d = 10^((RSSI_1m − rssi)/(10·n))` with `rssi_1m` derived from free-space loss at 1 m plus ~15 dBm assumed beacon EIRP; `n = rf_path_loss_exp` (2.7 indoor default). Always labeled approximate.
- **Trend:** least-squares RSSI slope over a 90 s window; ≥ `rf_rssi_approach_db_min` (6 dB/min) → `approaching`, ≤ −threshold → `receding`.
- **Lifecycle:** `mark_scan(medium, seen)` increments `scans_absent`; ≥ `rf_lost_after_scans` (3) → `lost` + `RF_EMITTER_LOST` event. Called only on definitive sweeps.

### 11.7 Trilaterator (`Trilaterator`)
- **Class:** `Trilaterator` (line 4688)
- **Function:** Weighted least-squares 2D trilateration over RSSI-derived ranges projected onto a local equirectangular tangent plane (valid for the short baselines RSSI surveys cover).
- **Inputs:** per-emitter observation map `emitter → sensor → {lat, lon, rssi_dbm, freq_mhz, ts}`; sensors registered from `rf_sensors` config (`[{name,lat,lon}]`) or `rf_obs_file` JSONL drops (external/cooperating sensors).
- **Solve:** ≥3 spatially separated observations → linearized intersection, weight `1/(1+d)` per sensor; rejects co-located/collinear geometry as `degenerate`; output = lat, lon, `rms_m`, `n_sensors`, `spread_m`, `quality` (`good` rms<3m & spread≥20m / `fair` / `coarse`), method string, per-sensor `ranges_m`. Verified exact (0.0 m error) on consistent synthetic data.
- **Under 3 sensors:** no fix is fabricated — emitters still carry per-sensor distance rings.

### 11.8 Wi-Fi Spectrum Scanner (`WiFiSpectrumScanner`)
- **Class:** `WiFiSpectrumScanner` (line 4988)
- **Method:** `netsh wlan show networks mode=bssid` (driver beacon survey) + `netsh wlan show interfaces` (own radio: SSID, BSSID, band, channel, radio type, TX/RX rates, signal %).
- **Fields per AP:** BSSID, SSID (empty = hidden), signal %, RSSI dBm (`signal→dBm` mapping), band, channel, radio type (802.11be/ax/n/…), authentication, encryption, BSS load/QoS where present.

### 11.9 Bluetooth RF Scanner (`BluetoothRFScanner`)
- **Class:** `BluetoothRFScanner` (line 5135)
- **Method:** `Get-PnpDevice -Class Bluetooth` + registry enumeration (paired devices, local radio), plus optional live BLE advert rounds via `bleak` (`rf_ble_live_scan`, `rf_ble_scan_secs`=6s) when the package is installed.
- **Empty ≠ absent:** an empty PowerShell result is treated as inconclusive (transient API failure), not a definitive empty spectrum.

### 11.10 WWAN Scanner / Interface Census (`WWANScanner`, `InterfaceCensus`)
- **Classes:** `WWANScanner` (line 5277), `InterfaceCensus` (line 5330)
- **WWAN:** `netsh mbn` interfaces/state — cellular medium registration.
- **Census:** `psutil.net_if_addrs`/`net_if_stats` + `Get-NetAdapter -IncludeHidden` for real descriptions — classifies every interface (Ethernet, Wi-Fi, loopback, virtual, Wi-Fi Direct) into the right medium so local adapters are themselves traced emitters.

### 11.11 RF Hardware Detector (`RFHardwareDetector`)
- **Class:** `RFHardwareDetector` (line 5469)
- **Method:** PnP device enumeration matched against a VID&PID table of RF-capable hardware: RTL-SDR (2832/2834/2838), HackRF, Airspy, Yard Stick One, Ubertooth, GreatFET, ADALM-PLUTO, LimeSDR, SDRplay (RSP1/RSPdx/duo/1A), Flipper Zero, CC2531, ConBee, Aeotec Z-Stick, CP210x, ACR122U/ACS NFC readers, Intel/Broadcom/Marvell Bluetooth radios, Logitech Unifying/LightSpeed, Razer HyperSpeed, Roccat, PixArt, generic NRF24 receivers.
- **Also detects:** installed SDR tooling (`rtl_power`, `rtl_sdr`, `hackrf_sweep`, `SoapySDRUtil`, `sdrpp`, `gqrx`, …) reported in the coverage matrix.
- **Deduction:** `RF_HARDWARE` events feed an "RF-capable hardware detected" deduction — a new receiver is an attack surface.

### 11.12 L2 Wire Census (`_l2_wire` → `_process_wire`)
- **Method:** the packet callback keeps a bounded per-source-MAC table (`rf_l2_wire_max`=4096) — ethertypes spoken (`_ETHERTYPE_NAMES` human labels: IPv4/IPv6/ARP/VLAN/LLDP/EAPoL/PPPoE/MACsec/PTP/HomePlug/MPLS/FCoE/GOOSE/…), claimed L3 identities (src IP, ARP, ND targets), and discovery services announced (`_L2_DISCOVERY_PORTS`: NetBIOS, SSDP, WS-Discovery, mDNS, LLMNR, DHCPv4/v6, Dropbox LAN).
- **Derived roles:** ipv6-router, dhcp-server, discovery-announcer, arp-speaker, ipv6-nd-speaker, raw-ethertype-channel, gateway/forwarder, never-speaks-ip, ip-endpoint, l2-only.
- **Flush:** SpectrumHub folds the table into `l2-wire` emitters every `rf_l2_flush_interval` (15 s); talkers silent > `rf_l2_active_s` (120 s) stop counting as seen; > `rf_l2_drop_s` (3600 s) prunes the row. Requires packet capture — without Npcap+admin the medium is empty.

---

## 12. Packet Analysis & TLS Fingerprinting

### 12.1 Packet Pipeline (`PacketPipeline`)
- **Class:** `PacketPipeline` (line 21299)
- **Workers:** 4 (configurable via `pipeline_workers`)
- **Queue size:** 10,000 (configurable)
- **What:** Multi-threaded packet processing pipeline
- **Processing:**
  - SNI extraction from TLS ClientHello
  - DNS query extraction from UDP port 53
  - JA4+ fingerprint computation
  - Entropy analysis of payloads
  - Feed metadata back to process profiles

### 12.2 JA4+ Fingerprinting (`JA4Plus`)
- **Class:** `JA4Plus` (line 3032)
- **What:** Extended JA4 TLS fingerprinting
- **Methods:**
  - `ja4(pkt)` — ClientHello fingerprint (TLS version, cipher count, extension count, ALPN)
  - `ja4s(pkt)` — ServerHello fingerprint (TLS version, cipher)
  - `ja4h(pkt)` — HTTP fingerprint
  - `ja4x(pkt)` — X.509 certificate fingerprint

### 12.3 Entropy Analyzer (`EntropyAnalyzer`)
- **Class:** `EntropyAnalyzer` (line 2802)
- **What:** Computes Shannon entropy of packet payloads
- **Threshold:** 7.2 bits/byte (suspicious — indicates encrypted/compressed data)

### 12.4 Beacon Detector (`BeaconDetector`)
- **Class:** `BeaconDetector` (line 2696)
- **What:** Detects regular-interval connections (C2 beaconing)
- **Minimum samples:** 20

### 12.5 TLS Certificate Detector (`TLSCertDetector`)
- **Class:** `TLSCertDetector` (line 4261)
- **What:** Detects TLS certificate anomalies (MITM indicators)
- **How:** Examines certificate issuer, validity, subject for anomalies

### 12.6 Wire-Evasion Deductions (packet path)
- **Method:** `_packet_callback` fires its own deduction family attributed to `"packet"` (no owning PID) — detections that live below the process layer:
- **Categories:**
  - `L2SPOOF` (CRITICAL) — an ARP reply claiming an IP a different MAC already owns → ARP-poison MITM on the LAN (hourly cooldown)
  - `ARPSTORM` (CRITICAL) — one MAC binding ≥6 IPs in 60s → gratuitous-ARP poison flood
  - `RDHCP` — a rogue DHCP server answering on the LAN
  - `ROGRA` — a rogue IPv6 router advertisement
  - `LLMNS` — LLMNR/NBNS spoof replies (credential-relay vector)
  - `MACROT` — a MAC address rotating through identities (moving-L2 unmask)
  - `MARTIAN` — impossible/bogon source addresses on the wire
  - `QINQ` — 802.1Q-in-Q double-tag encapsulation
  - `TTLINJ` — injected TTL anomalies / RST-injection evidence
  - `RAWETH` (WARNING, bounded alerts) — a persistent emitter speaking a non-IP ethertype (legit ethertypes ARP/VLAN/LLDP/EAPoL/PPPoE/MPLS/IS-IS exempted) → a data channel with no IP layer at all
- **Also lands here:** `FLOW_PROBE` verdicts (ROTATED/STICKY/GONE), `GATEWAY` (this host is relaying tunnel traffic for downstream clients — VPN-gateway mode with a separate inner-flow meter), `VIRUSTOTAL` hits, `ENTROPY`/`TUNNEL`/`HOSTING`/`VPN_PROXY` classifications
- **Honest boundary (unchanged):** these prove a mask/tunnel/spoofer is on the path; they cannot name the human behind a remote exit node — the tunnel terminates there and no client-side signal recovers the pre-tunnel source. For pre/post-tunnel visibility the deployment note stands: run a second instance on the VPN gateway/exit host's LAN side.

---

## 13. Behavioral & Statistical / ML

### 13.1 Statistical Baseline (`StatisticalBaseline`)
- **Class:** `StatisticalBaseline` (line 2957)
- **What:** Z-score anomaly detection per process name
- **Metrics:** connection_rate, destination_count, bytes_rate, cpu_mean
- **Window:** 86400s (24h), 500 samples max per metric
- **Threshold:** Z-score > 3.0
- **Minimum samples:** 50

### 13.2 Alert Escalation (`AlertEscalation`)
- **Class:** `AlertEscalation` (line 21172)
- **What:** Compounds risk when same process triggers multiple deductions in a window
- **Window:** 300s (5 min)
- **Multiplier:** 1.5^(N-1) where N = recent deduction count, capped at 5.0x

### 13.3 Token Bucket (`TokenBucket`)
- **Class:** `TokenBucket` (line 6297)
- **What:** Rate-limits external API calls (ip-api.com, ipwho.is, VirusTotal)
- **How:** Classic token bucket algorithm — tokens refill at configured rate, calls consume tokens

---

## 14. Firewall & IP Blocking

### 14.1 IP Blocking (`_block_ip`)
- **What:** Blocks an IP address via Windows Firewall
- **How:** Creates two `netsh advfirewall firewall add rule` entries — one outbound, one inbound — with `action=block protocol=any remoteip={ip}`
- **Rule naming:** `GNA_Tracer_Block_{IP}` prefix (both directions)

### 14.2 IP Unblocking (`_unblock_ip`)
- **What:** Removes firewall rules for an IP
- **How:** `netsh advfirewall firewall delete rule name="GNA_Tracer_Block_{IP}"` (both directions)

### 14.3 Block Check (`_is_blocked`)
- **What:** Checks if a firewall rule exists for an IP
- **How:** `netsh advfirewall firewall show rule name="GNA_Tracer_Block_{IP}"`

### 14.4 Clear All Blocks (`_clear_all_blocks`)
- **What:** Removes all firewall rules created by this session

### 14.5 Flow Probe (`_probe_ip_flow`)
- **What:** On-demand active verification that an endpoint is a rotating VPN exit — the honest substitute for "see through the tunnel"
- **How:** Right-click an IP → `⚗ Flow probe` (or Inspector → `[⚗ Flow probe]`). Blocks the endpoint on the **local** firewall for `flow_probe_secs` (8s), watches the flow for `flow_probe_settle_secs` (6s), then auto-unblocks — the rule always self-terminates; non-admin path is a single elevated batch (one UAC prompt)
- **Verdicts:** `ROTATED` (same process returns on a new exit IP in the same provider → VPN rotation proven), `STICKY` (same IP → persistent endpoint), `GONE` (flow died). Verdicts go through `_add_deduction` (`FLOW_PROBE` category) so they land in the Deductions tab, actions log, structured log, deductions log, DB, SIEM, suspicious events, and the .txt exports
- **Surface:** `PRB` sensor chip counts probes run; verdicts visible in the Inspector IP dossier

---

## 15. GUI (18 Tabs)

### Tab 1: Overview (`_overview_frame`)
- Summary statistics: active connections, unique services, unique IPs, tracked processes, total deductions, network devices, suspicious events, terminal lines, DNS cache, GeoIP cache, pipeline stats, proxy connections
- Anti-hack pin summary with flagged IPs and categories
- High-risk processes (risk >= 40)
- Proxy process list

### Tab 2: Live Connections (`_live_frame`)
- Active/established connections only
- Collapsible detail rows with expand/collapse buttons
- Inline anti-hack pin tags
- Block/unblock buttons per connection

### Tab 3: All Connections (`_conn_frame`)
- Every connection with full detail
- Searchable and filterable
- Per-connection detail: process, remote address, local port, protocol, status, domain, country, city, region, org, ISP, coordinates, location verification, proxy info, first/last seen
- Anti-hack pin tags in header and detail
- Block/unblock buttons

### Tab 4: Deductions (`_ded_frame`)
- All deductions with severity, category, time, process, PID, score, message, full evidence chain
- Color-coded by severity (CRITICAL=red, WARNING=yellow)
- Category emoji icons for all 40+ categories

### Tab 5: Processes (`_proc_frame`)
- All processes with risk scores, connection counts, destinations, ML anomaly scores, countries contacted
- Sortable columns

### Tab 6: Devices (`_dev_frame`)
- Network devices from ARP scan
- IP, MAC, vendor (OUI lookup), hostname, OS guess, confidence

### Tab 7: IP Map (`_map_frame`)
- Slippy tile map (requires Pillow)
- Geolocated IP markers with color-coded risk
- Click to see connection detail
- Uses OpenStreetMap tiles via `TileManager`
- **RF emitter dots** — every traced emitter is positioned honestly in three tiers: SOLVED trilaterated fixes (solid medium-colored dot + crosshair + dashed RMS-error ring), RANGED single-receiver emitters (dashed distance ring with a stable-derived tick — tooltip states bearing is not measurable), LOCAL un-ranged talkers (clustered around the receiver marker). Medium colors: Wi-Fi cyan, BT/BLE violet, WWAN amber, l2-wire green, interfaces slate, RF hardware white; lost emitters render hollow
- **PINPOINTS & GEO LOCATIONS sidebar** (`_build_map_sidebar`) — scrollable list of every mapped point: local marker, connection dots, trace hops, RF sensors, and emitters (◉ solved / ● active / ○ lost). Click = multi-toggle selection with selection rings + ⌖ center-on-selection; last-clicked row gets the full-record detail pane; ✖ DESELECT ALL resets

### Tab 8: Actions Log (`_actions_frame`)
- Raw process action log (NETWORK_FLOW, STARTED, etc.)
- Action type counts

### Tab 9: Terminal (`_terminal_frame`)
- Live terminal output with color-coded severity
- 10,000-line rolling buffer
- Searchable

### Tab 10: Suspicious Activity (`_suspicious_frame`)
- Out-of-norm events only
- Severity, category, time, description, process, details

### Tab 11: Blocked IPs (`_blocked_frame`)
- IP blocklist management
- Block/unblock buttons
- Bulk clear all blocks

### Tab 12: Process Tree (`_ptree_frame`)
- Hierarchical parent-child process tree
- Risk scores shown inline

### Tab 13: Net Stats (`_netstats_frame`)
- Network interface bandwidth statistics
- Per-interface: bytes sent/recv, packets, errors

### Tab 14: Timeline (`_timeline_frame`)
- Connection timeline with durations
- Active vs. closed state
- Start time, duration, remote IP:port, PID

### Tab 15: Config (`_config_frame`)
- Live-editable configuration
- All CONFIG keys with type validation
- Apply/reset buttons

### Tab 16: Double Trace (`_trace_frame`)
- VPN double-trace verification view
- MultiVerifier results with all named evidence methods

### Tab 17: System (`_sys_frame`)
- Host/hardware detail — OS build, CPU, RAM, uptime, power, interface inventory
- Live host-clock row (render signature bucketed to 5s)
- **LIVE PROCESSING STATE** (`_PS_GROUPS`) — verbatim internal-store dumps: packet-pipeline backlog/drops, verification-pipeline queue + in-flight, passive wire-hint harvest, evasion/decap tables, spectrum-intel internals (sensors, obs ingested, trilat stats, registry/scanners/ble_live/l2_wire maps)
- **VPN GATEWAY MODE** — whether this host is forwarding tunnel traffic for downstream clients (or is itself a tunnel client) plus the inner-flow meter
- **VPN LEAK STATUS** — resolver cross-check, STUN, WebRTC, kill-switch findings
- **MULTI-VERIFICATION** — every cached MultiVerifier report with per-method flags

### Tab 18: Signals (`_sig_frame`)
- **SPECTRUM & SIGNAL INTELLIGENCE** — everything §11.5–11.12 collects, rendered with verbose labels:
  - Coverage matrix — 12 media rows (Wi-Fi APs, BT classic, BLE, cellular, Wi-Fi Direct, Zigbee, Z-Wave, SDR sweep, NFC/RFID, proprietary 2.4 GHz, non-IP L2, serial/UART) each marked live / partial / unavailable-with-reason
  - Emitter census — every tracked emitter grouped by medium: address, vendor, name/SSID, status (active/lost), RSSI dBm, estimated distance, approach/recession trend, band/channel, observation count, per-sensor attribution, first/last seen, and the full `extra` raw-field dump
  - Trilateration — solved fixes (lat/lon, RMS m, quality, sensor spread, per-sensor ranges) plus pending emitters that still need observers
  - Sensors & obs-file state — configured `rf_sensors`, ingested observation count, obs-file errors
  - Processing feeds — every scanner's internal status (`ok`/`inconclusive`/`unavailable` + detail) so a dead feed is visibly dead
  - Persistent spectrum event stream — `RF_*` events survive processing drains (`_ui_events`)
- Sensor chip in the status bar counts live emitters and solved fixes (`N+fix`)

---

## 16. Web Dashboard (FastAPI)

- **Port:** 8470 (configurable)
- **Endpoints:**
  - `GET /` — Full HTML dashboard with live-updating widgets (6 tabs: Connection Map, All Connections, Deductions, Processes, Devices, All Feeds)
  - `GET /api/state` — JSON API returning complete dashboard state
  - `WS /ws` — WebSocket for real-time push updates
- **All Feeds tab:** generic completeness tail — every payload key not curated by another tab rendered verbatim in `<details>` blocks (processing state, spectrum internals, wire-hint tables), so a newly-added feed is never invisible in the web UI
- **Authentication:** Optional password protection via `--dashboard-password`
- **Dependencies:** FastAPI, Uvicorn (optional — dashboard disabled if not installed)

---

## 17. Data Export & Session Recording

### 17.1 Auto-Save
- **Interval:** Every 10 minutes (600,000ms)
- **Trigger:** Tkinter `after()` callback + on close
- **Locations:**
  1. `sessions/YYYY-MM-DD/session_HHMM_HHMM.txt` — organized by date and 10-minute time segment
  2. `Desktop/GNAT/YYYY-MM-DD/GNA tracer data {N}.txt` — the GNAT record folder: every rolling report lands in a dated subfolder so the record stays organized and the Desktop stays clean. A one-time migration on first save pulls legacy `GNA tracer data *.txt` files, `GNA_Report_*.html` files, and the old `GNA_Double_Trace_Logs/` directory into the record tree (dated subfolders, `reports/`, `trace_logs/` respectively)
  3. `Desktop/GNAT/latest_snapshot.json` — machine-readable JSON twin of the complete session payload, overwritten on each save
- **Record header** carries export time, session start, runtime, save #, time segment, `Session Dir`, and `Record Dir`; every file ends with a **RECORD MANIFEST** section counting what each feed captured (connection rows, deduction counts, per-monitor events, processing-state groups, …)

### 17.2 Save File Sections (30+)
1. Header (export time, session start, runtime, save #, time segment, session dir)
2. Overview (connection/process/deduction/device counts, DNS/GeoIP cache, pipeline, proxy)
3. All Connections (each individually — process, remote, local, protocol, domain, country, city, org, ISP, coordinates, location verification, proxy, first/last seen)
4. All Deductions (full evidence chains)
5. All Processes (PID, name, exe, parent, risk, connections, destinations, ML anomaly, countries)
6. All Devices (IP, MAC, vendor, hostname, OS guess, confidence)
7. Complete Raw Actions Log (ALL, no caps)
8. All IPs with Geolocation
9. Suspicious Activity (out-of-norm only)
10. **Sneakiest Connections (Anti-Hack Flagged)** — every flagged IP with pin categories, process, service, domain, country, org, status, first/last seen, all pin details
11. **Anti-Hack Deductions** — all deductions from 24 anti-hack categories with full evidence
12. **Anti-Hack Monitor Events** — events from 8 background monitors
13. VirusTotal Scan Results
14. File System Watchdog Events
15. Clipboard Monitor Events
16. USB Device Events
17. Scheduled Task Changes
18. Named Pipe / IPC Events
19. Inbound Port Scan Detections
20. DNS-over-HTTPS (DoH) Detections
21. TLS Certificate / MITM Events
22. Connection Timeline (Active + Closed, with Duration)
23. Network Interface Bandwidth
24. Bluetooth Devices + Events
25. Serial / COM Ports + Events
26. Raw Monitor Events (verbatim dump of every extended-monitor feed)
27. Services Seen, Connection Counts, Per-IP Bandwidth, Watchlist, Recent DNS, JA4X fingerprints, Local Proxy State, VPN Leak Status, Local GeoIP
28. **Spectrum / RF Signal Intelligence** — per-medium emitter census, every emitter's address/name/status/RSSI/distance/seen-count/sensors plus its raw `extra` fields, trilateration fixes, spectrum events
29. **Live Processing State** — internal stores verbatim (queue backlogs, wire-hint harvest, fingerprints, baselines)
30. Full Terminal Output (100%)

---

## 18. Database & Logging

### 18.1 Database (`DatabaseManager`)
- **Class:** `DatabaseManager` (line 21199)
- **Engine:** SQLite with WAL journal mode
- **File:** `medianbox_ultimate.db`
- **Tables:** deductions, devices
- **Thread safety:** Connection-per-operation (no shared connections across threads)

### 18.2 Structured Logging
- **Main logger:** `medianbox` → `medianbox_structured.log` (50MB rotating, 5 backups)
- **Actions logger:** `medianbox.actions` → `medianbox_full_actions.log` (50MB rotating, 3 backups)
- **Deductions logger:** `medianbox.deductions` → `medianbox_deductions.log` (50MB rotating, 3 backups)
- **Format:** `%(asctime)s [%(levelname)s] %(message)s`

---

## 19. SIEM Output

### 19.1 SIEM Output (`SIEMOutput`)
- **Class:** `SIEMOutput` (line 21099)
- **Formats:**
  - `json` — JSON-formatted events to `medianbox_siem.json`
  - `cef` — Common Event Format to `medianbox_siem.cef`
  - `syslog` — UDP syslog to configured host:port (default 127.0.0.1:514)
- **Configuration:** `--siem json|cef|syslog`

---

## 20. Alert Escalation

- **Class:** `AlertEscalation` (line 21172)
- **What:** Compounds risk score when same process triggers multiple deductions within a 5-minute window
- **Multiplier:** 1.5^(N-1), capped at 5.0x
- **Example:** If a process triggers 3 deductions in 5 minutes, the 3rd deduction's score is multiplied by 1.5^2 = 2.25x

---

## 21. Configuration System

### 21.1 CONFIG Dictionary
All configuration is in a single `CONFIG` dict with type validation:

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `remote_ports` | set | {22, 3389, 5900, 5938, 445, 139, 5985, 5986} | Remote access ports |
| `probe_alert_ports` | set | {21, 23, 80, 443, 445, 22, 3389, 5900} | Ports that trigger probe alerts |
| `alert_cooldown` | int | 75 | Alert cooldown in seconds |
| `deduction_cooldown` | int | 120 | Deduction cooldown in seconds |
| `process_scan_interval` | float | 0.5 | Process scan interval (seconds) |
| `conn_map_interval` | float | 0.5 | Connection mapper interval (seconds) |
| `status_interval` | int | 5 | Status thread interval (seconds) |
| `gui_refresh_ms` | int | 250 | GUI refresh interval (milliseconds) |
| `baseline_min_samples` | int | 50 | Minimum samples for baseline |
| `beacon_min_samples` | int | 20 | Minimum samples for beacon detection |
| `risk_critical` | int | 70 | Critical risk threshold |
| `risk_warning` | int | 40 | Warning risk threshold |
| `entropy_suspicious_threshold` | float | 7.2 | Entropy threshold (bits/byte) |
| `exfil_bytes_spike_factor` | int | 10 | Exfil spike factor (x baseline) |
| `exfil_min_bytes` | int | 1,000,000 | Minimum bytes for exfil flag |
| `dns_tunnel_max_label_len` | int | 50 | Max DNS label length |
| `dns_tunnel_entropy_threshold` | float | 3.5 | DNS tunnel entropy threshold |
| `dns_tunnel_query_rate_threshold` | int | 30 | DNS query rate threshold |
| `geoip_cache_ttl` | int | 3600 | GeoIP cache TTL (seconds) |
| `high_risk_countries` | set | {CN, RU, KP, IR} | High-risk country codes |
| `user_idle_threshold` | int | 300 | User idle threshold (seconds) |
| `ml_baseline_window` | int | 86400 | ML baseline window (seconds) |
| `ml_zscore_threshold` | float | 3.0 | ML Z-score threshold |
| `pipeline_workers` | int | 4 | Packet pipeline worker count |
| `pipeline_queue_size` | int | 10000 | Pipeline queue size |
| `verify_workers` | int | 18 | MultiVerify cross-verification pool size |
| `flow_probe_secs` | int | 8 | Flow-probe local block duration (s) |
| `flow_probe_settle_secs` | int | 6 | Flow-probe post-block watch window (s) |
| `dashboard_port` | int | 8470 | Dashboard port |
| `siem_output` | str | None | SIEM output format |

**Spectrum / RF keys (16 — all `rf_*`):**

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `rf_monitor_enabled` | bool | True | Master switch for the SpectrumHub |
| `rf_wifi_interval` | int | 15 | `netsh wlan` BSSID scan cadence (s) |
| `rf_bt_interval` | int | 30 | BT/BLE PnP enumeration cadence (s) |
| `rf_iface_interval` | int | 30 | Interface/medium census cadence (s) |
| `rf_wwan_interval` | int | 60 | `netsh mbn` cellular cadence (s) |
| `rf_hw_interval` | int | 120 | RF-capable USB hardware re-detect (s) |
| `rf_ble_live_scan` | bool | True | Live BLE adverts via bleak when installed |
| `rf_ble_scan_secs` | int | 6 | bleak discovery window per round (s) |
| `rf_lost_after_scans` | int | 3 | Consecutive absent scans → emitter `lost` |
| `rf_path_loss_exp` | float | 2.7 | Indoor path-loss exponent (2.0 = free space) |
| `rf_rssi_approach_db_min` | float | 6.0 | +dB/min slope that flags `approaching` |
| `rf_approach_alert_m` | float | 8.0 | Approaching emitters closer than this alert |
| `rf_obs_file` | str | `medianbox_rf_observations.json` | External sensor observation drop (JSONL) |
| `rf_evil_twin_cooldown` | int | 600 | Per-SSID twin-suspect alert cooldown (s) |
| `rf_sensors` | list | [] | Cooperating sensor nodes `[{name,lat,lon}]` |
| `rf_l2_flush_interval` | int | 15 | L2 wire-talker table → registry cadence (s) |
| `rf_l2_wire_max` | int | 4096 | Max distinct src MACs tracked on the wire |
| `rf_l2_active_s` | int | 120 | Silent this long → emitter drops to `lost` |
| `rf_l2_drop_s` | int | 3600 | Silent this long → table row pruned |

**Total CONFIG keys: 71** (68 have schema-validation entries in `CONFIG_SCHEMA`).

### 21.2 Config Validation
Every tunable CONFIG key has a validation spec in `CONFIG_SCHEMA` with type, min, max, and element type constraints. The GUI Config tab validates changes before applying.

### 21.3 YAML Config File
External config can be loaded via `--config path/to/config.yaml`. YAML keys override CONFIG defaults.

---

## 22. Thread Architecture

```
Main Thread (GUI/Tkinter)
├── Connection-Mapper Thread          — psutil.net_connections() every 0.5s
├── Process-Watcher Thread            — psutil.process_iter() every 0.5s
│   └── 16 core deductions + 18 anti-hack checks per process
├── Status-Reporter Thread            — status line every 5s
├── Connection-Inventory Thread       — enriches connections every 2-10s
│   ├── GeoIP Worker Thread           — background ip-api.com calls
│   └── RDNS Worker Thread            — background reverse DNS calls
├── DNS Cache Poll Thread             — DNS cache maintenance every 5s
├── VPN-Gateway Thread                — VPN gateway/inner-flow monitoring
├── Memory Forensics Thread           — RWX region scan every 15s (admin)
├── Extended Monitor Thread           — ~19 monitors every 2-60s
│   ├── File System Watchdog (10s)
│   ├── Clipboard Monitor (5s)
│   ├── USB Monitor (30s)
│   ├── Scheduled Task Monitor (60s)
│   ├── Named Pipe Monitor (30s)
│   ├── Inbound Scan Detector (5s)
│   ├── Bluetooth Scanner (30s)
│   ├── Serial Port Scanner (30s)
│   ├── Proxy Detector (30s)
│   ├── VPN Leak Detector (60s)
│   ├── Security Event Monitor (15s)
│   ├── Hosts File Monitor (30s)
│   ├── Service Monitor (60s)
│   ├── Security Tool Monitor (30s)
│   ├── User Account Monitor (60s)
│   ├── WMI Subscription Monitor (60s)
│   ├── Driver Load Monitor (60s)
│   └── Mutex Scanner (30s)
├── Interface Stats Thread            — bandwidth tracking every 1s
├── Spectrum-Intel Thread             — SpectrumHub every ~2s: Wi-Fi BSSID/RSSI
│                                       sweep (15s), BT/BLE census (30s), interface
│                                       census (30s), WWAN (60s), RF hardware (120s),
│                                       L2-wire flush (15s), obs-file ingest,
│                                       trilateration solves
├── Packet Pipeline (4 workers)       — Scapy packet processing + per-MAC L2
│                                       wire census (admin + Npcap)
├── ARP Scanner Thread                — network device discovery (admin)
├── Sniff Thread                      — Scapy packet capture (admin)
├── Device-PortScan Thread            — discovered-device port probing (admin)
├── LocalGeo-Warm Thread              — pre-warms local-GeoIP cache at startup
├── Location-Verify / Whois-Warm / VT-Checker / DB-Writer / Double-Trace
│                                     — on-demand enrichment + persistence workers
├── MultiVerify Worker Pool (18)      — endpoint cross-verification queue
│                                       (`verify_workers`; parallel probe wave
│                                       inside verify() ≈ max(probe) not sum)
├── FastAPI Dashboard Thread          — web server on port 8470
└── GUI Refresh (Tkinter after)       — 250ms active tab refresh
```

**Total: ~20 persistent daemon threads** plus worker pools (18 MultiVerify, 4 packet-pipeline, GeoIP/RDNS/verify bounded workers) — more when admin mode enables packet capture, ARP scanning, and device port-scanning.

---

## 23. Class Reference (62 Classes)

| # | Class | Line | Purpose |
|---|-------|------|---------|
| 1 | `Colors` | 2141 | ANSI color codes for terminal output |
| 2 | `ProcessProfile` | 2288 | Per-process data structure (dataclass) |
| 3 | `Deduction` | 2328 | Alert with evidence chain (dataclass) |
| 4 | `DNSCache` | 2368 | Bidirectional DNS domain↔IP mapping |
| 5 | `DNSTunnelingDetector` | 2647 | DNS exfiltration detection |
| 6 | `BeaconDetector` | 2696 | C2 beaconing detection |
| 7 | `SNIExtractor` | 2730 | TLS Server Name Indication extraction |
| 8 | `EntropyAnalyzer` | 2802 | Shannon entropy computation |
| 9 | `ProcessLegitimacyChecker` | 2825 | Process path/parent verification |
| 10 | `DLLInspector` | 2870 | Loaded module enumeration and flagging |
| 11 | `RegistryMonitor` | 2894 | Registry run key monitoring |
| 12 | `UserIdleMonitor` | 2933 | Windows idle time detection |
| 13 | `StatisticalBaseline` | 2957 | Z-score ML anomaly detection |
| 14 | `JA4Plus` | 3032 | TLS JA4/JA4S/JA4H/JA4X fingerprinting |
| 15 | `VirusTotalChecker` | 3124 | VirusTotal hash lookup |
| 16 | `FileSystemWatchdog` | 3242 | File system change monitoring |
| 17 | `ClipboardMonitor` | 3331 | Clipboard access monitoring |
| 18 | `USBMonitor` | 3421 | USB device monitoring |
| 19 | `ScheduledTaskMonitor` | 3480 | Scheduled task monitoring |
| 20 | `NamedPipeMonitor` | 3536 | Named pipe monitoring |
| 21 | `WhoisLookup` | 3600 | WHOIS/RDAP IP lookup |
| 22 | `InboundScanDetector` | 3692 | Inbound port scan detection |
| 23 | `SecurityEventMonitor` | 3740 | Windows Security event log monitor |
| 24 | `HostsFileMonitor` | 3809 | Hosts file / DNS hijack monitor |
| 25 | `ServiceMonitor` | 3868 | Windows service creation monitor |
| 26 | `SecurityToolMonitor` | 3931 | Defender/Firewall disable monitor |
| 27 | `UserAccountMonitor` | 3984 | New user/admin account monitor |
| 28 | `WMISubscriptionMonitor` | 4057 | WMI persistence monitor |
| 29 | `DriverLoadMonitor` | 4113 | Kernel driver load monitor |
| 30 | `MutexScanner` | 4174 | Malware mutex name scanner |
| 31 | `DoHDetector` | 4223 | DNS-over-HTTPS detection |
| 32 | `TLSCertDetector` | 4261 | TLS certificate anomaly detection |
| 33 | `ConnectionHistory` | 4309 | Connection lifecycle tracking |
| 34 | `BluetoothScanner` | 4432 | Bluetooth device scanning |
| 35 | `SerialPortScanner` | 4536 | Serial/COM port scanning |
| 36 | `Trilaterator` | 4688 | WLS trilateration over RSSI-derived ranges |
| 37 | `SignalRegistry` | 4830 | Unified multi-medium emitter registry (11 media) |
| 38 | `WiFiSpectrumScanner` | 4988 | `netsh wlan` AP/BSSID + own-radio survey |
| 39 | `BluetoothRFScanner` | 5135 | BT/BLE enumeration + optional bleak adverts |
| 40 | `WWANScanner` | 5277 | `netsh mbn` cellular/WWAN probing |
| 41 | `InterfaceCensus` | 5330 | Full interface classification by medium |
| 42 | `RFHardwareDetector` | 5469 | RF-capable USB hardware (SDR/Zigbee/NFC/2.4 GHz) |
| 43 | `SpectrumHub` | 5555 | Signal-collector orchestrator + event queue |
| 44 | `TokenBucket` | 6297 | API rate limiting |
| 45 | `GeoIPCache` | 6776 | GeoIP lookup caching with background worker |
| 46 | `LocationVerifier` | 7406 | Single-IP location verification (4 methods) |
| 47 | `MultiVerifier` | 7746 | Multi-method IP verification (244 named evidence methods) |
| 48 | `ProxyDetector` | 20173 | Proxy/VPN detection |
| 49 | `VPNLeakDetector` | 20366 | VPN leak detection (DNS/IPv6/route/WebRTC) |
| 50 | `SIEMOutput` | 21099 | CEF/JSON/Syslog SIEM output |
| 51 | `AlertEscalation` | 21172 | Risk score compounding |
| 52 | `DatabaseManager` | 21199 | SQLite database management |
| 53 | `PacketPipeline` | 21299 | Multi-threaded packet processing |
| 54 | `ServiceResolver` | 21462 | Service identification from IP/port/domain |
| 55 | `ConnectionEntry` | 21713 | Per-connection data structure |
| 56 | `ConnectionInventory` | 21822 | Connection enrichment and tracking |
| 57 | `TileManager` | 22982 | OSM tile management for IP map |
| 58 | `_BufferedText` | 23372 | Batches ~40 `insert()` calls into one Tk call per render |
| 59 | `WidgetTooltip` | 23397 | GUI tooltip widget |
| 60 | `GNATracerGUI` | 23544 | Main Tkinter GUI (18 tabs) |
| 61 | `_MvSeen` | 38630 | dict wrapper recording which report keys a renderer consumed |
| 62 | `MedianBoxMonitor` | 38804 | Main orchestrator class |

---

## 24. Test Suite

### 24.1 `_test_antihack.py` (41 tests)
Simulates sneaky hacker techniques and verifies each detection path fires:

**LOLbin Abuse (8 tests):**
- certutil -urlcache download
- mshta remote HTA (Squiblydoo variant)
- regsvr32 Squiblydoo attack
- rundll32 from temp directory
- rundll32 LSASS minidump via comsvcs.dll
- wmic process call create (lateral movement)
- bitsadmin file download
- msiexec remote install

**Suspicious Execution Paths (4 tests):**
- exe from Temp directory
- exe from AppData\Local\Temp
- exe from Downloads
- System32 exe should NOT trigger (negative test)

**Parent-Child Mismatch (3 tests):**
- svchost.exe spawned by cmd.exe
- lsass.exe spawned by explorer.exe
- svchost <- services.exe should NOT trigger (negative test)

**PowerShell Obfuscation (5 tests):**
- -enc with long base64 blob
- WebClient download cradle
- Stealth combo (-nop -w hidden -noninteractive + IEX)
- Reflection.Assembly load (fileless .NET)
- Benign Get-Process should NOT trigger (negative test)

**Macro Malware (2 tests):**
- Word spawned cmd.exe
- Excel spawned powershell.exe

**Browser Exploit (2 tests):**
- Chrome spawned powershell.exe
- Edge spawned mshta.exe

**Renamed Binary (3 tests):**
- cmd.exe from Temp directory
- powershell.exe from Downloads
- cmd.exe from System32 should NOT trigger (negative test)

**Other Anti-Hack (14 tests):**
- Network spawned: sshd spawned cmd.exe
- Credential dump: mimikatz.exe detected
- Credential dump: reg.exe save SAM hive
- Process hollowing: svchost.exe from Temp
- Process hollowing: svchost.exe from System32 should NOT trigger
- Exfil channel: Discord webhook
- Exfil channel: Telegram bot API
- Exfil upload: curl --upload-file
- Data staging: 7z compressing user documents
- Port forward: chisel.exe tunnel
- Backup tamper: vssadmin delete shadows
- Admin share: net use C$ (lateral movement)
- PS abuse: AMSI bypass attempt
- Pin system: end-to-end pin verification

### 24.2 `_test_vpn_leak.py` (~30 tests)
Tests VPN leak detection for DNS, IPv6, route, and WebRTC leaks.

### 24.3 `_test_vpn_detection.py`
Tests VPN/proxy detection false-positive rate. Target: <5%, achieved: 0%.

### 24.4 `_test_location_accuracy.py`
Tests MultiVerifier location accuracy across the verification method battery (244 named evidence methods today — growing per tranche).

### 24.5 `_test_data_wiring.py` (35 checks) — *new, 2026-08-22*
Answers a different question from 24.1-24.4: not "does the detection logic fire correctly" but "does what it produces actually reach the user." Starts the real monitor threads against live traffic for a warm-up window, then asserts:
- The interface auto-detection picked a live, routable adapter (not APIPA/loopback)
- Per-unique-public-IP field coverage — country, city, org, isp, lat, website_tag, verify_grade all resolve for (allowing a small tail-latency margin for IPs discovered in the final seconds of the window) every public endpoint, not a filtered subset
- Every public endpoint gets a MultiVerifier VPN/proxy cross-check
- Connections carry `is_vpn`/`is_proxy`/`is_hosting`/`is_cdn`/`vpn_score`
- No process is silently dropped from the export
- The process export carries CPU%, memory, cmdline, DNS domains, bytes sent/recv, behavioral flags, and risk reasons
- No payload key is built by the backend and never read anywhere in the GUI (a static-analysis check against the actual source)
- The full payload build completes well inside the GUI's refresh interval (median ~7-9ms vs a 250ms budget)

### 24.6 `_test_gui_render.py` — *new, 2026-08-22*
Builds the **real Tkinter window** (not a mock) offscreen, drives a full refresh of every one of the 18 tabs against live monitor data, and asserts:
- Zero exceptions across all 18 tabs
- Every newly-wired connection field (timezone, ASN, rDNS, MULTIVERIFIER block, VPN score, verify grade, RTT, TTL/OS, geo source, command line, numeric parent PID) is present in the actual rendered widget text
- Zero stale `?` placeholders remain where a real value should now appear
- Reports warm (first-render) and steady-state (repeat-render) timing per tab

### 24.7 `_test_click_actions.py` (9 checks) — *new, 2026-08-22*
Verifies the GUI performance rework (embedded `tk.Button` widgets replaced with clickable text-tag spans, see §40) didn't silently break interactivity. Fires real `<Button-1>` events at the actual Tk widget — not a call to the underlying Python function — and asserts:
- The toggle-arrow span expands a collapsed row
- Clicking again collapses it back
- The block/unblock span calls `_toggle_block_ip` with the correct IP
- Both the Live and All Connections tabs register click spans correctly

### 24.8 `_test_gatecrasher.py` (68 checks)
GATE-CRASHER verification methods — IKE, PROX, TLSALT, BANNER, IPID, SRVLOC and VPN-gateway mode, plus the round-2 methods GEOFEED, RPKI, TSRTT, H2FP, RDRCT and the gateway inner-flow meter. Synthetic packets/replies feed the pure parsers; loopback listeners exercise the negotiation paths — no external targets needed.

### 24.9 `_test_wireproof.py` (1,560 checks)
The silent-tunnel / non-IP-channel suite — evidence rows for tunnels that answer no probe: WireGuard black-holes, OpenVPN hard-resets, DTLS, ESP/GRE L3 tunnels, ICMP tunnels, QUIC, encrypted-flow, TLS-weird, WS tunnels, ECH, no-SNI, one-way channels — plus dozens of protocol self-ID decoders (SSH/HASSH, Kerberos, LDAP, RDP, RTSP, SIP, FTP, MQTT, Modbus, BACnet, Kafka, X11, BGP, VNC, RADIUS, SCADA S7/IEC-104, DNP3, gopher-class services, game/mesh/db/OT protocols). Synthetic packets and wire_hint dicts feed the pure classifiers and `verify()` — no external targets needed. **1560/1560 passing.**

### 24.10 `_test_ui_smoke.py` (~180 checks)
Full GUI smoke pass built on a fabricated state: every tab renders, sensor chips show correct counts, search bars filter, the inspector dossier expands/collapses, flash keeps numbering, and the Signals tab asserts coverage-matrix rows, emitter fields (RSSI/distance/trend), trilateration fix blocks, processing-feed rows, and raw `RF_*` events all render with detailed labels.

### 24.11 `_test_map_declutter.py` (5 checks) / `_test_map_default_view.py` (10 checks)
Endpoint-map marker declustering (zoom-bucketed co-location merging) and default viewport/zoom behavior.

### 24.12 `_test_perf_profile.py`
cProfile harness (~400 procs / ~300 conns / 20k timeline rows) that drove the versioned-snapshot/render pipeline in §40 — measures `_get_full_data`, `_get_dashboard_state`, `_refresh_all`, `_refresh_status`, `_refresh_trace` cost.

### 24.13 `_test_ui_shot.py` / `_test_ui_shot_sys.py`
Render the real GUI against fabricated/live state and screenshot each tab for visual review.

### 24.14 `_audit_fields.py` / `_audit_ui.py`
Static field-visibility audits answering "is anything collected but never displayed?": `_audit_fields` extracts every event-field key a feed produces and asserts a renderer references it; `_audit_ui` asserts every wire/protocol field name has a UI render path.

---

## 25. CLI Options

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

## 26. Auto-Flag Action System (33 Keywords)

Every process action (`NETWORK_FLOW`, `STARTED`, etc.) written via `_write_action()` is screened against 33 suspicious keyword patterns in `_auto_flag_action()`. Matching actions are flagged via `_flag_suspicious()` and appear in the Suspicious Activity tab and save file.

| Keyword | Category | Description |
|---------|----------|-------------|
| `cookie` | COOKIE_TRACKING | Process sending/receiving tracking cookies |
| `upload` | DATA_UPLOAD | Process uploading data |
| `exfil` | DATA_EXFIL | Potential data exfiltration |
| `credential` | CREDENTIAL_ACCESS | Process accessing credentials |
| `password` | CREDENTIAL_ACCESS | Process accessing password data |
| `token` | TOKEN_ACCESS | Process accessing authentication tokens |
| `clipboard` | CLIPBOARD_ACCESS | Process accessing clipboard data |
| `keylog` | KEYLOGGER | Possible keylogger behavior |
| `screenshot` | SCREEN_CAPTURE | Process performing screen capture |
| `inject` | CODE_INJECTION | Process injection activity |
| `hook` | API_HOOK | Process hooking system APIs |
| `encrypt` | ENCRYPTION | Process performing encryption (possible ransomware) |
| `decrypt` | ENCRYPTION | Process performing decryption |
| `powershell` | SCRIPT_EXEC | PowerShell execution detected |
| `cmd.exe` | SCRIPT_EXEC | Command shell execution detected |
| `wscript` | SCRIPT_EXEC | Windows Script Host execution |
| `cscript` | SCRIPT_EXEC | Console Script Host execution |
| `regsvr` | DLL_REGISTER | DLL registration activity |
| `schtask` | SCHEDULED_TASK | Scheduled task manipulation |
| `rdp` | REMOTE_ACCESS | Remote Desktop Protocol activity |
| `vnc` | REMOTE_ACCESS | VNC remote access activity |
| `ssh` | REMOTE_ACCESS | SSH remote access activity |
| `telnet` | REMOTE_ACCESS | Telnet remote access activity |
| `wake-on-lan` | REMOTE_POWER | Wake-on-LAN (remote power on) |
| `shutdown` | REMOTE_POWER | Remote shutdown command detected |
| `restart` | REMOTE_POWER | Remote restart command detected |
| `microphone` | HARDWARE_ACCESS | Microphone access detected |
| `camera` | HARDWARE_ACCESS | Camera access detected |
| `webcam` | HARDWARE_ACCESS | Webcam access detected |
| `audiodg` | HARDWARE_ACCESS | Audio device graph isolation active |
| `temp\` | TEMP_EXECUTION | Process running from temp directory |
| `appdata` | SUSPICIOUS_PATH | Process running from AppData |
| `downloads\` | SUSPICIOUS_PATH | Process running from Downloads |

**Implementation:** `_SUSPICIOUS_EXTRA_KW` list at line 13816. Each entry is `(keyword, category, description)`. The combined `action + extra` string is lowercased and checked once per keyword. First match wins.

---

## 27. Known Service IP Ranges (CIDR Validation)

The monitor includes `KNOWN_SERVICE_RANGES` (line 171) for validating that connections are legitimate:

| Service | CIDR Ranges |
|---------|-------------|
| Riot Games | 104.160.128.0/17, 185.40.64.0/22, 162.249.72.0/21, 103.10.8.0/22, 45.7.36.0/22 |
| Google | 142.250.0.0/15, 172.217.0.0/16, 216.58.192.0/19, 209.85.128.0/17, 74.125.0.0/16, 64.233.160.0/19, 173.194.0.0/16, 108.177.0.0/17, 35.190.0.0/17 |
| Cloudflare | 104.16.0.0/13, 172.64.0.0/13, 131.0.72.0/22, 1.1.1.0/24, 1.0.0.0/24 |
| Microsoft | 13.64.0.0/11, 20.33.0.0/16, 20.40.0.0/13, 40.64.0.0/10, 52.96.0.0/12, 52.112.0.0/14 |
| Discord | 162.159.128.0/17, 66.22.196.0/22 |
| Zoom | 3.7.35.0/25, 3.21.137.128/25, 3.22.11.0/24, 8.5.128.0/23, 64.125.62.0/24, 64.211.144.0/24, 65.39.152.0/24, 69.174.57.0/24, 147.124.96.0/19, 170.114.0.0/16, 206.247.0.0/16, 209.9.211.0/24 |

**Usage:** A `chrome.exe` connecting to a Google IP range is legitimate. A `chrome.exe` connecting to an unknown IP triggers a Mimic deduction.

---

## 28. Expected Executable Paths (20+ Processes)

`EXPECTED_EXE_PATHS` (line 135) maps process names to their legitimate install paths:

| Process | Expected Path Substring |
|---------|------------------------|
| chrome.exe | `google\chrome\application` |
| firefox.exe | `mozilla firefox` |
| msedge.exe | `microsoft\edge\application` |
| zoom.exe | `zoom\bin`, `zoom` |
| discord.exe | `discord\app` |
| teams.exe | `microsoft teams`, `teams` |
| slack.exe | `slack\app` |
| riotclientservices.exe | `riot games` |
| leagueclient.exe | `riot games\league of legends` |
| league of legends.exe | `riot games\league of legends` |
| svchost.exe | `windows\system32` |
| csrss.exe | `windows\system32` |
| lsass.exe | `windows\system32` |
| services.exe | `windows\system32` |
| smss.exe | `windows\system32` |
| winlogon.exe | `windows\system32` |
| explorer.exe | `windows` |
| taskhostw.exe | `windows\system32` |
| conhost.exe | `windows\system32` |
| dllhost.exe | `windows\system32` |
| wininit.exe | `windows\system32` |
| spoolsv.exe | `windows\system32` |

**Usage:** `ProcessLegitimacyChecker.check_all()` verifies the process's actual exe path against this map. A mismatch triggers an Impersonation deduction.

---

## 29. Expected Parent Processes

`EXPECTED_PARENTS` (line 160) maps system process names to their expected parent:

| Process | Expected Parent(s) |
|---------|-------------------|
| svchost.exe | services.exe |
| csrss.exe | smss.exe |
| lsass.exe | wininit.exe |
| services.exe | wininit.exe |
| smss.exe | System |
| winlogon.exe | smss.exe |
| wininit.exe | smss.exe |
| taskhostw.exe | svchost.exe |

**Usage:** `_check_parent_child_mismatch()` compares `profile.parent_name` against this map. A mismatch triggers a PARENT_MISMATCH pin (score: 55.0, CRITICAL).

---

## 30. Mimic Keywords (Service Fingerprinting)

`MIMIC_KEYWORDS` (line 121) maps service names to their known domain keywords:

| Service | Keywords |
|---------|----------|
| zoom | zoom, zmeet, zoomus, zoom.us |
| google | google, gstatic, googlevideo, googleapis, goog |
| cloudflare | cloudflare, cf-, warp, one.one |
| teams | teams, microsoftonline, microsoft365, office365 |
| slack | slack, slack-edge |
| discord | discord, discordapp, dis.gd |
| riot | riot, riotgames, leagueoflegends |
| league | league, lol, lolesports |
| chrome | chrome, chromium |
| firefox | firefox, mozilla |
| edge | msedge, microsoftedge |

**Usage:** `_check_mimic()` compares a process's destination domain against its expected service keywords. If `chrome.exe` connects to a domain with none of the chrome/firefox/edge keywords, it is flagged as a mimic (score: 35.0).

---

## 31. Allowed Apps (User-Configurable Trust)

`ALLOWED_APPS` (line 116) is a user-configurable dict of services that are trusted:

```python
ALLOWED_APPS = {
    "zoom": False, "google": True, "cloudflare": False, "teams": False,
    "slack": False, "discord": False, "riot": True, "league": True,
}
```

**Usage:** When `True`, the service is exempt from certain deductions. When `False`, the service is monitored normally.

---

## 32. Hardware Keywords

`HARDWARE_KEYWORDS` (line 188) maps hardware categories to process names that legitimately access them:

| Category | Process Names |
|----------|--------------|
| audio | audiodg, audioservice, pulseaudio, pipewire, rtkaudioservice |
| camera | camerabrokersvc, frameworkservice, webcam, camerahelper |

**Usage:** Prevents false positives when system audio/camera services trigger HARDWARE_ACCESS flags.

---

## 33. Persistence Registry Keys

`PERSISTENCE_KEYS` (line 193) on Windows:

| Hive | Key |
|------|-----|
| HKEY_CURRENT_USER | `Software\Microsoft\Windows\CurrentVersion\Run` |
| HKEY_LOCAL_MACHINE | `Software\Microsoft\Windows\CurrentVersion\Run` |
| HKEY_CURRENT_USER | `Software\Microsoft\Windows\CurrentVersion\RunOnce` |

**Usage:** `RegistryMonitor` reads these keys every 60s and compares against baseline. New entries trigger a Persistence deduction (score: 35.0).

---

## 34. Suspicious DLL Paths

`SUSPICIOUS_DLL_PATHS` (line 201):

- `\temp\`, `\tmp\`, `\appdata\local\temp`, `\downloads\`, `\desktop\`, `\public\`, `\programdata\`, `\users\public`

**Usage:** `DLLInspector` flags any loaded module whose path contains one of these substrings.

---

## 35. Port-to-Service Maps

### `_PORT_NAMES` (Remote Access Ports) — line 242

| Port | Service |
|------|---------|
| 22 | SSH |
| 3389 | RDP |
| 5900 | VNC |
| 5938 | TeamViewer |
| 445 | SMB |
| 139 | NetBIOS |
| 5985 | WinRM |
| 5986 | WinRM-S |

### `_PORT_SERVICES` (Common Ports) — line 247

| Port | Service | Port | Service |
|------|---------|------|---------|
| 80 | HTTP | 443 | HTTPS |
| 22 | SSH | 21 | FTP |
| 25 | SMTP | 53 | DNS |
| 110 | POP3 | 143 | IMAP |
| 993 | IMAPS | 995 | POP3S |
| 3389 | RDP | 5900 | VNC |
| 8080 | HTTP-Alt | 8443 | HTTPS-Alt |
| 445 | SMB | 139 | NetBIOS |
| 123 | NTP | 161 | SNMP |
| 5228 | FCM-Google | 5222 | XMPP |
| 5060 | SIP | | |

---

## 36. Connection Entry Fields (55 Fields)

`ConnectionEntry` (line 21713) uses `__slots__` for memory efficiency. **Expanded from 31 to 54 fields in the 2026-08-22 audit** — the collector layer (GeoIP, MultiVerifier, active RTT/TTL/port probes) was already producing this data on every scan; the dataclass simply discarded it before it reached `to_dict()`, so it never appeared anywhere in the GUI, the web dashboard, or the save files. All 22 new fields are now populated and verified by `_test_data_wiring.py` against live traffic (100% coverage across every public IP tested). A 55th field — `is_tor` — was added with the Tor-exit detection (TOREXIT/EXITLIST methods), plus an internal `_dom_ver` domain-version stamp slot.

| Field | Type | Description | Status |
|-------|------|-------------|--------|
| pid | int | Process ID | original |
| process_name | str | Process executable name | original |
| exe_path | str | Full executable path | original |
| parent_name | str | Parent process name | original |
| parent_pid | int | Parent process ID | **new** — was read by the GUI (`c.get('parent_pid')`) but never provided; rendered as a literal `?` |
| cmdline | str | Process command line | original |
| website_tag | str | Website/service tag | original |
| remote_ip | str | Remote IP address | original |
| remote_port | int | Remote port | original |
| local_ip | str | Local IP address | **new** — same "requested but never provided" gap as parent_pid |
| local_port | int | Local port | original |
| protocol | str | Protocol (TCP/UDP) | original |
| status | str | Connection status (ESTABLISHED, LISTEN, etc.) | original |
| service | str | Resolved service name | original |
| category | str | Service category | original |
| icon | str | Service icon (emoji) | original |
| domain | str | Primary domain | original |
| all_domains | list | All domains resolving to this IP | original |
| via | str | Connection path info | original |
| country | str | Country name | original |
| country_code | str | 2-letter country code | original |
| city | str | City name | original |
| region | str | Region/state | original |
| org | str | Organization | original |
| isp | str | ISP name | original |
| lat | float | Latitude | original |
| lon | float | Longitude | original |
| timezone | str | Timezone from GeoIP | **new** — GeoIPCache and MaxMind lookups return this; it was thrown away |
| geo_source | str | Which GeoIP source resolved this (`hardcoded`/`local`/`api`) | **new** |
| asn | str | Autonomous System Number | **new** |
| asn_org | str | ASN-registered organization name | **new** |
| rdns | str | Reverse-DNS PTR hostname | **new** |
| first_seen | float | First-seen timestamp | original |
| last_seen | float | Last-seen timestamp | original |
| loc_confidence | int | Location confidence (0-100) | original |
| loc_grade | str | Confidence grade (A-F, UNVERIFIED) | original |
| loc_proof | list | Location verification proof chain | original |
| proxy_type | str | Proxy type (if detected) | original |
| proxy_detail | str | Proxy detection details | original |
| is_vpn | bool | MultiVerifier VPN verdict | **new** — MultiVerifier computed this on every call; only reached a separate side-cache dict the GUI mostly didn't read, not the connection itself |
| is_proxy | bool | MultiVerifier proxy verdict | **new** |
| is_hosting | bool | Datacenter/hosting-provider verdict | **new** |
| is_cdn | bool | CDN infrastructure verdict | **new** |
| is_tor | bool | Tor exit-node verdict (TOREXIT/EXITLIST/ONIONOO methods) | **new (2026-11)** |
| _dom_ver | int | Internal domain-cache version stamp — render caches know when this connection's domain mapping moved | internal |
| vpn_score | int | 0-100 VPN likelihood score | **new** |
| vpn_provider | str | Named VPN/proxy provider label if one matched | **new** |
| vpn_labels | list | All infrastructure labels from MultiVerifier | **new** |
| verify_grade | str | MultiVerifier's own confidence grade | **new** |
| verify_summary | str | One-line MultiVerifier narrative summary | **new** |
| verify_conflicts | list | Disagreements between the verification methods | **new** |
| rtt_ms | float | Active-ping round-trip time | **new** |
| ttl_os | str | OS fingerprint inferred from TTL | **new** |
| hop_distance | int | Estimated network hop distance | **new** |
| open_ports | list | Open VPN/proxy fingerprint ports found by active probe | **new** |

**What this fixed, concretely:** before the audit, the connection detail panel's "MULTIVERIFIER" section only populated for the minority of connections that had been queued for verification under the old gating logic (high-risk country / watchlisted / remote-access port / risk>30). Every other connection — the overwhelming majority of ordinary traffic — showed nothing there, and fields like ASN, rDNS, timezone, and RTT were entirely absent from the UI regardless of whether they had been computed.

---

## 37. Database Schema

### `deductions` table

| Column | Type |
|--------|------|
| id | INTEGER PRIMARY KEY AUTOINCREMENT |
| timestamp | TEXT (ISO format) |
| severity | TEXT (CRITICAL/WARNING) |
| category | TEXT (MIMIC, FOREIGN, BEACON, etc.) |
| process | TEXT |
| pid | INTEGER |
| message | TEXT |
| evidence | TEXT (JSON array of strings) |
| score | REAL |

### `devices` table

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

**Engine:** SQLite with WAL journal mode, connection-per-operation for thread safety.

---

## 38. RDAP/WHOIS Lookup (`WhoisLookup`)

- **Class:** `WhoisLookup` (line 3600)
- **Endpoint:** `https://rdap.org/ip/{ip}`
- **Rate limit:** 10 requests/sec via `TokenBucket`
- **Timeout:** 8 seconds
- **Returns:**
  - `name` — organization name
  - `handle` — registry handle
  - `type` — entity type
  - `country` — registered country
  - `start_address` / `end_address` — IP range
  - `entities` — up to 3 contacts with roles
- **Caching:** Per-IP, cached indefinitely
- **Error handling:** Failed lookups cached with `error: True` to avoid retry storms

---

## 39. Web Dashboard Details

### HTML Dashboard (`DASHBOARD_HTML` — line 22528)

A full-screen dark-themed web interface with:

**Header bar:**
- MedianBoxMonitor 3.0 title
- Live stat counters: Connections, Services, Unique IPs, Processes, Deductions, Devices, Idle (s)

**6 tabs:**
1. **Connection Map** — Leaflet.js map (OpenStreetMap tiles) with geolocated IP markers + active services panel
2. **All Connections** — sortable table with process, IP, GeoIP, org
3. **Deductions** — severity-colored deduction log (CRITICAL=red, WARNING=yellow)
4. **Processes** — process table with risk scores
5. **Devices** — discovered network devices
6. **All Feeds** — verbatim rendering of every payload key not curated by another tab (processing state, spectrum internals, wire-hint tables) — the generic completeness tail so no collected field is unreachable

**Styling:**
- Background: `#0a0a0f` (near-black)
- Panels: `#12121a` with `#1a1a2e` borders
- Accent: `#e94560` (red-pink for titles/critical)
- Secondary: `#00d4ff` (cyan for services)
- Warning: `#f5a623` (orange)
- Font: Consolas/Fira Code monospace, 13px

**WebSocket:** Pushes full state every 3 seconds via `/ws`

**Authentication:** Optional token via `--dashboard-password`. Token checked via `?token=` query param or WebSocket query param.

---

## 40. Performance Optimizations

### Caching
- `_is_public_ip_cached()` — LRU cache (4096 entries) for `ipaddress.ip_address().is_global`
- `GeoIPCache` — TTL-based cache (3600s) with direct fast paths
- `ServiceResolver` — reverse DNS cache + service cache
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
- `TokenBucket` — used by GeoIPCache (ip-api.com), WhoisLookup (rdap.org), VirusTotalChecker
- Prevents API bans and rate-limit errors

### Memory Efficiency
- `ConnectionEntry` uses `__slots__` (55 fields, no `__dict__`)
- `ProcessProfile` uses `deque(maxlen=60)` for CPU samples, `deque(maxlen=500)` for packet timestamps
- `StatisticalBaseline` uses `deque(maxlen=500)` per metric
- `AlertEscalation` uses `deque(maxlen=50)` per PID, cleans up dead PIDs at 5000+ entries
- Suspicious events use `deque(maxlen=10000)`
- Terminal buffer uses `deque(maxlen=10000)`
- Process export cap raised from a hard 200 (silently dropped anything beyond insertion order) to 2000, ranked by risk score descending — a high-risk process starting after the old cap filled was previously invisible to the GUI and every export
- Anti-hack pin detail lists per IP bounded to 50 entries with de-duplication against the last 10, so a repeatedly-re-flagged process no longer grows the list unbounded for the whole session
- `_rdns_bounded()` wraps every reverse-DNS lookup in a 3-5s wall-clock timeout on a throwaway thread — `socket.gethostbyaddr()` has no native timeout and was observed stalling a worker (and everything queued behind it) for 30+ seconds on an unreachable host

### Hoisted Constants
- `_PORT_NAMES`, `_PORT_SERVICES` — module-level, not recreated per call
- `_SUSPICIOUS_EXTRA_KW` — class-level, not recreated per action
- `_LOLBIN_PATTERNS`, `_EXPECTED_PARENTS`, `_SYSTEM_PROCESSES` — class-level

### Lock Contention Reduction
- Deduction formatting happens outside the monitor lock
- Status thread merges lock acquisitions into a single critical section
- `deque.append()` is thread-safe in CPython — no lock needed for append-only suspicious events

### GUI Rendering (2026-08-22 rework)
Profiling the Live Connections and All Connections tabs with real Tk widgets (not a mock) found that embedded `tk.Button` widgets — one per connection row, for the expand/collapse arrow and the block/unblock control — accounted for ~78% of refresh time. `Text.delete()` destroys every embedded widget it contains, so clearing and repainting the tab meant creating and destroying several hundred `tk.Button` objects on every refresh cycle.

- Embedded buttons replaced with tagged, clickable text spans (`_click_text()`), dispatched through one shared `<Button-1>`/`<Motion>` binding per widget instead of 2-3 bindings per row
- The connection-detail renderer's ~40 `Text.insert()` calls per expanded row are now buffered (`_BufferedText`) and flushed as a single batched insert
- The IP Map no longer redraws every tile and grid line on every refresh cycle when its tab isn't visible — it marks itself dirty and repaints once when the user switches back to it
- **Measured result:** Live tab refresh (250 connections, all expanded) dropped from ~2,540ms to ~34ms; All Connections dropped from ~466ms to ~76ms. Verified functionally intact by `_test_click_actions.py`, which fires real `<Button-1>` events at the new spans and asserts the correct callback fires — not just that render time improved.

### Versioned Snapshot & Render Pipeline (2026-11-06 pass)

A `cProfile` harness (`_test_perf_profile.py`, ~400 procs / ~300 conns / 20k timeline rows) found the remaining costs were *rebuild-everything* work rather than slow primitives: `_get_full_data` ≈21ms/build dominated by `ConnectionHistory.get_timeline()` running `heapq.nlargest` over 20k rows, and `_refresh_all` ≈4.7ms/tick dominated by ~73 identical `widget.config()` Tcl round-trips. Every mutable store now exposes a monotonic mutation counter; snapshots and render signatures key on those instead of object identity, so a new dict built over unchanged feeds no longer triggers any re-derivation or repaint.

- **Mutation counters** — `conn_history.version`/`bw_seq`, `dns_cache.q_seq`/`map_seq`, `conn_inventory.mut_seq` (bumped at scan AND at async enrichment writes: `apply_verification`, GeoIP worker, location-verify worker), and monitor-side `_ded_seq`, `_susp_seq` (atomic under `self.lock` — appended from many threads), `_verify_cache_seq`, `_pins_seq`, `_iface_seq`, `_proc_seq`, `_dev_seq`, `_terminal_seq`, `_actions_seq`.
- **Section caches in `_get_full_data`** — publishes `data['_versions']`; each expensive section (actions, deductions, terminal lines, suspicious events, DNS recents, bandwidth, verify reports, anti-hack pins) rebuilds only when its source counter moved. Version is captured inside the same lock as the data it describes (no torn read).
- **`get_timeline` cache** — active+closed merge + `nlargest`+sort ran per build; now cached on history version (20k rows → 0.00ms on hit).
- **Inventory getter caches** — `get_all()`, `get_map_points()`, `get_services_summary()`, `get_stats()` memoized on `mut_seq`.
- **Process payload cache** — `_get_dashboard_state` process rows (~400 dicts × 30 fields) keyed on `_proc_seq`; worst-case added staleness is one watcher pass (~0.5s), same granularity the feeds already had.
- **`_cfg(widget, **opts)`** — `.config()` that diffs against the last-applied options kept on the widget and no-ops on identical values; applied to all ~73 status-tick widgets (chips, flow strip, toggle chips, clock, threat spark, inspector header).
- **`_ver(data, key)` render signatures** — every tab's `_render_skip` signature keys on its feed's version + local UI state (search, expanded set, blocked set) instead of `id(data)`; 'dev' adds a 30s bucket for the time-derived NEW badge, 'sys' a 5s bucket for its live clock. Inspector dossier guard converted the same way.
- **Remaining embedded buttons → click spans** — Live tab's Expand/Collapse-All and per-category toggles were the last per-render `tk.Button` creates; now `_click_text` spans.
- **Derived-value memoization** — `_hud_counts` (severity/risk tallies), flow-strip socket mix, iface rate sums, trace-target list all keyed on their feed versions; trace combobox `["values"]` only assigned on change.
- **Packet path** — `len(pkt)` (full serialization per packet) → `pkt.wirelen`; dead `haslayer(ARP)` check (unreachable behind the IP early-return) replaced with a working MAC↔IP claim-conflict check that also maintains the MAC history map.

**Measured result (same harness):** `_get_full_data` uncached 21.4→0.14ms (rebuilds only on real mutation), `_get_dashboard_state` 11.1→0.02ms steady-state, `_refresh_status` ~4.2→0.59ms, `_refresh_all` 4.7→0.59ms, `_refresh_trace` 3.8→0.00ms, Tcl calls per refresh ~73→~13. Cache-invalidation verified synthetically: susp/verify/conn writes all move their versions and surface in the next build.

---

## Summary

| Metric | Count |
|--------|-------|
| Total classes | 62 |
| Core deductions | 16 |
| Anti-hack process checks | 18 |
| Anti-hack background monitors | 8 |
| Enhanced sneaky-hacker checks | 7 |
| Auto-flag keywords | 33 |
| GUI tabs | 18 |
| Dashboard tabs | 6 (incl. All Feeds verbatim tab) |
| Background threads | ~20 persistent + worker pools |
| MultiVerifier named evidence methods | 244 |
| Spectrum/RF emitter media | 11 (wifi-ap, wifi-radio, wifi-direct, bt-radio, bt-classic, ble, wwan-modem, local-radio, rf-hw, local-iface, l2-wire) |
| Coverage-matrix media rows | 12 |
| RF-capable hardware VID&PID table | 30+ entries (SDR, Zigbee, Z-Wave, NFC, Flipper, Ubertooth, 2.4 GHz receivers) |
| SDR tools detected | 9 (rtl_power, rtl_sdr, hackrf_sweep, hackrf_info, SoapySDRUtil, sdrpp, CubicSDR, gqrx, osmocom_fft) |
| Save file sections | 30+ |
| Test cases | ~1,900+ assertions across all suites |
| Test/audit scripts | 15 test suites + 2 field-visibility audits |
| Configuration keys | 71 (68 schema-validated) |
| Known LOLbins | 24 |
| Known exfil channels | 25 |
| Known malware mutexes | 10 |
| Known DoH servers | 12 |
| Known service CIDR ranges | 30+ |
| Expected exe paths | 22 |
| Expected parent relationships | 8 |
| Mimic keyword sets | 11 |
| Port-to-service mappings | 20 |
| ConnectionEntry fields | 55 (was 31 — 22 collected-but-discarded fields wired up 2026-08-22, +is_tor 2026-11) |
| Database tables | 2 (of ~15 tracked entity types — see §41) |
| Process export cap | 2,000 by risk rank (was a hard 200 by insertion order) |
| MultiVerify worker pool | 18 (was 1, gated to a minority of IPs; now covers every public endpoint) |
| Sensor-strip chips | 31 |
| Wire-evasion deduction categories | 10 (L2SPOOF, ARPSTORM, RDHCP, ROGRA, LLMNS, MACROT, MARTIAN, QINQ, TTLINJ, RAWETH) |
| Total lines of code | ~45,400 |


---

## 41. Known Gaps, Missing Features & Platform Coverage

Every item below was verified directly against the running source on 2026-08-22 (grep/read of `medianbox_monitor_v2.py`, plus live-traffic testing) — not inferred from documentation or intent. Where a claim needed evidence, the evidence is stated. Re-verified 2026-11-08: the capability set grew (wire-evasion deduction family, Flow Probe, Tor-exit detection, map emitter dots + pinpoints sidebar, GNAT record folder + JSON snapshot, All Feeds dashboard tab) but the structural gaps below are unchanged.

### 41.1 Detection method gaps

| Gap | Evidence | Impact |
|-----|----------|--------|
| **No code-signing (Authenticode) verification anywhere** | `ProcessLegitimacyChecker.check_all()` (line 2846) checks only exe path substring and parent process name — no call to `WinVerifyTrust`, no `signtool`, no certificate chain validation exists in the codebase | A binary that is correctly named, correctly pathed, and correctly parented is invisible to every check, whether or not it is actually signed by the vendor it claims to be. This is the single largest structural gap in the process-integrity layer. |
| **No YARA or byte-signature scanning** | Zero references to `yara`, signature matching, or hash-based static detection anywhere in the file (the only hash use is SHA256-for-VirusTotal, which requires an opt-in API key — see 41.3) | Detection is 100% behavioral: path, parent, command-line keyword, static mutex name, port pattern. A known-malicious binary with none of those specific tells will not be flagged by static means. |
| **Mutex scanner checks 10 hardcoded names** (`MutexScanner`, line 4174) | Cobalt Strike, Meterpreter, and 8 others — an exact-string `OpenMutexW()` probe, no pattern/heuristic matching | Renaming a mutex — a one-line change on the attacker's side — evades this check completely. |
| **DNS-tunneling / entropy thresholds are fixed constants**, not adaptive | `dns_tunnel_entropy_threshold` (3.5 bits/char), `dns_tunnel_max_label_len` (50), `entropy_suspicious_threshold` (7.2 bits/byte) — all static CONFIG values, no per-network or per-baseline calibration | A slow, low-and-slow tunnel under threshold evades detection. Legitimately high-entropy traffic (some already-compressed uploads) can produce a warning needing manual dismissal. |
| **No sandboxing or dynamic detonation** | The monitor is a passive observer — it never executes, unpacks, or triggers anything | A payload that waits for a specific external trigger and never manifests suspicious behavior while being watched will not be caught, however long the monitor runs. |
| **No process-hollowing detection via actual memory inspection** — only path checking | `_check_process_hollow` and `ProcessLegitimacyChecker` both test whether `exe_path` contains `system32`/`syswow64`; neither inspects the PE header, entry point, or module base against what was mapped at process creation | The more rigorous form of hollowing detection (comparing the on-disk image to the in-memory image) is not implemented — only the coarser "wrong folder" signal is. |
| **Registry persistence watch list is narrow** | `PERSISTENCE_KEYS` (line 193) covers only the standard `Run`/`RunOnce` keys in HKCU/HKLM | No coverage for COM hijacking, service-DLL hijacking (`ServiceDll` under a legitimate service), `AppInit_DLLs`, IFEO debugger hijacking, or the dozens of other documented Windows persistence techniques (ATT&CK T1547 has 20+ sub-techniques; this covers roughly 2). |

### 41.2 Platform coverage gaps

| Component | Windows | Linux | macOS |
|-----------|---------|-------|-------|
| Process/connection tracking (psutil-based) | Yes | Yes | Yes (untested) |
| DNS cache, GeoIP, MultiVerifier, VPN leak detection | Yes | Yes | Yes (untested) |
| Packet capture (SNI, JA4+, DNS-tunnel from wire) | Yes (needs Npcap) | Yes (needs libpcap) | Yes (needs libpcap, untested) |
| Security Event Log Monitor | Yes (`win32evtlog`/`wevtutil`) | No | No |
| Hosts File / DNS Hijack Monitor | Yes | No (Windows hosts path hardcoded) | No |
| Service Creation Monitor | Yes (`sc query`) | No | No |
| Security Tool Monitor (Defender/Firewall) | Yes (PowerShell, `netsh`) | No | No |
| User Account Monitor | Yes (`net user`) | No | No |
| WMI Subscription Monitor | Yes (`wmic`) | No (no WMI) | No |
| Driver Load Monitor | Yes (`sc query type=driver`) | No | No |
| Registry Monitor | Yes (`winreg`) | No (no registry) | No |
| Scheduled Task Monitor | Yes (`schtasks`) | No (no cron/systemd-timer equivalent) | No |
| Memory Forensics (RWX region scan) | Yes (admin) | No | No |
| ARP Scanner / device discovery | Yes (admin + Npcap) | Yes (admin + libpcap) | Yes (untested) |
| Firewall block/unblock | Yes (`netsh advfirewall`) | No (no iptables/nftables equivalent) | No |
| Bluetooth / USB / Serial scanners | Yes (registry/WMI) | No | No |
| User idle detection | Yes (`GetLastInputInfo`) | No | No |
| Wi-Fi spectrum scan (`netsh wlan`) | Yes | No (`nmcli`/`iw` path not implemented) | No |
| WWAN probing (`netsh mbn`) | Yes | No | No |
| Interface census (descriptions via `Get-NetAdapter`) | Yes | Partial (psutil only, no descriptions) | No |
| RF hardware VID&PID detection | Yes (PnP) | Partial (sysfs path not implemented) | No |
| Live BLE adverts | Yes (needs `bleak`) | Yes (needs `bleak`) | Yes (needs `bleak`, untested) |
| L2 wire census | Yes (Npcap + admin) | Yes (libpcap + root) | Yes (untested) |

**Net effect:** the "18 anti-hack process checks" and "8 anti-hack background monitors" headline figures are real and fully functional — **on Windows**. On Linux, roughly 9 of the ~33 named detections still run (the psutil/network/DNS/GeoIP-based ones); the other ~24, everything touching the registry, WMI, services, scheduled tasks, the security event log, or a Windows-only WinAPI call, are silent no-ops. macOS has no code path exercised in testing and no macOS-specific monitor of any kind — the only macOS-aware line in the file is a single `subprocess.Popen(["open", ...])` call used to open a folder in Finder from the Double Trace tab.

### 41.3 Response, alerting & operational gaps

| Gap | Evidence | Impact |
|-----|----------|--------|
| **No automatic response of any kind** | Grep for `.kill()`/`.terminate()` on a *process* (not the traceroute subprocess) returns nothing — the only 3 `.terminate()` call sites in the file all stop the Double Trace subprocess, not a suspicious user process | The ceiling of automated containment is a manual "Block IP" button that adds two Windows Firewall rules. No auto-kill, no quarantine, no session lockout, no network isolation triggers automatically on a CRITICAL finding. |
| **No out-of-band alerting** | Grep for `smtp`, `slack`, `webhook`, `pushover`, `twilio` (as an outbound notification, not as a detection target) returns nothing | SIEM output (JSON/CEF file or UDP syslog) is the only mechanism to get an event out of the process. If nothing is tailing that file/socket, and you aren't looking at the GUI or web dashboard, a CRITICAL deduction produces no notification anywhere. |
| **VirusTotal is opt-in via an env var with no CLI/GUI surface** | `self.api_key = api_key or os.environ.get('VT_API_KEY', '')` (line 3129); `main()`'s `argparse` setup has no `--vt-api-key` flag; the only in-GUI mention is a hint string ("Or set VT_API_KEY environment variable") | Even when a key is configured, the free-tier VirusTotal API is rate-limited to 4 requests/minute — far below the process-creation rate of an active machine — so only a small fraction of executables are ever actually checked. |
| **Tkinter GUI has no authentication of its own** | Only the FastAPI web dashboard supports `--dashboard-password`; the desktop GUI window has no PIN/lock | Anyone with physical/RDP access to the desktop session while the GUI is open sees the complete forensic picture — every process, connection, and evidence chain — with no additional gate. |
| **Threat-intel lists are static source constants** | LOLbin patterns (`_LOLBIN_PATTERNS`), 25 exfil-channel domains (`_EXFIL_CHANNELS`), 10 malware mutex names, VPN/proxy ASN markers, 12 known DoH servers, high-risk country codes — all literal Python dicts/sets/tuples in the source | No feed integration (no MISP, no live threat-intel API, no auto-update mechanism of any kind). The lists are exactly as current as the last time someone hand-edited the script. |

### 41.4 Persistence & data-model gaps

| Gap | Evidence | Impact |
|-----|----------|--------|
| **SQLite database has exactly 2 tables** | `DatabaseManager._init_db()` (line 21219) creates only `deductions` and `devices` — confirmed by reading the full `CREATE TABLE` statements | Connections, processes, VPN-leak events, the RF emitter registry, and all 11 Tier-5 monitor event feeds (filesystem, certs, DoH, scheduled tasks, named pipes, inbound scans, USB, Bluetooth, serial, spectrum events) exist only in rotating text logs and 10-minute session `.txt` snapshots — there is no SQL-queryable connection or process history. Answering "what did this IP connect to last Tuesday" means grepping text files, not running a query. |
| **Statistical baselines are in-memory only** | `StatisticalBaseline` (line 2957) holds its 24h Z-score window in `deque`s on the live object, with no persistence to disk or DB | The learned "normal" behavior for every process resets on every restart. A machine restarted daily never accumulates more than a few hours of baseline before the anomaly detector is starting cold again. |
| **No packaging manifest** | No `requirements.txt`, `pyproject.toml`, `setup.py`, or `Pipfile` anywhere in the project directory | Dependencies (psutil, scapy, tkinter, fastapi, uvicorn, pillow, manuf, geoip2) must be inferred by reading imports; no pinned versions exist, so `pip install` on a fresh machine has no authoritative list to run against. |
| **No CI / automated test gate** | No `.github/` directory; the project is not a git repository at all as of this audit | The 15 test suites + 2 field-visibility audits (~1,900+ assertions) must be run manually. Nothing enforces that they pass before a change ships. |

### 41.5 Boundaries by design (not gaps — stated for completeness)

These are deliberate, correct design choices, not missing features:

- **TLS payload content is never decrypted.** The monitor sees SNI, JA3/JA4, and certificate metadata only. This is the correct privacy boundary for a defensive tool, but it means genuinely malicious activity conducted entirely inside an otherwise-normal-looking encrypted session (e.g., abuse of a stolen legitimate API token to a legitimate SaaS endpoint) is outside what packet inspection here can ever see.
- **The monitor never attacks, scans, or de-anonymizes anything remote.** It watches only the local machine. VPN exit-node locations are reported (with a clear "this is the exit node, not the real user" disclaimer); the real person behind a VPN is never targeted or inferred.
- **GeoIP defaults to free third-party HTTP APIs** (ip-api.com, ipwho.is) unless the user supplies a local MaxMind database — a documented, intentional trade-off (no bundled proprietary database), but every enriched public IP is sent to a third party over plain HTTP by default.
- **The emitter census is bounded by physics, not by the code.** "Every device that sends a signal" means every signal this host's radios and interfaces can actually receive — Wi-Fi/BLE in range, local adapters, wire frames. Media with no local receiver (Zigbee, Z-Wave, NFC, sub-GHz ISM) are reported as `unavailable — no receiver hardware` in the coverage matrix, never fabricated. This is the honest boundary of host-based RF monitoring.
- **RSSI-derived distance is approximate by design.** The log-distance model carries ±tens-of-meters error indoors; the trilaterator will not fabricate a fix from <3 sensors or degenerate geometry — it reports quality grades (`good`/`fair`/`coarse`/`degenerate`) rather than false precision.
- **Failed scans never mark emitters lost.** `ok`/`inconclusive`/`unavailable` scan classification means transient `netsh`/PowerShell errors are silent gaps, not false absences — lifecycle transitions only advance on definitive sweeps.

---

## 42. Completeness Ratings by Category

Grades assigned 2026-08-22 against the live, running code — not the docstrings or the section headers above; figures re-verified 2026-11-08. Rubric:

- **A** — Fully implemented, cross-platform where the feature name implies it should be, verified against live data
- **B** — Fully implemented on the primary platform (Windows), solid design, but static rule lists or single-platform
- **C** — Implemented with a real structural limitation (opt-in, rate-capped, degrades silently without an optional dependency, static thresholds)
- **D** — Present but covers a minority of what the section name implies
- **F** — Not implemented

| Section | Category | Grade | Rationale |
|---------|----------|-------|-----------|
| 1 | Core Deductions (16) | B | Auditable evidence chains, solid coverage — but every rule is heuristic (keyword/path/statistics), no signature or signing check backs any of them |
| 2 | Anti-Hack Process Checks (18) | B | Same strengths/limits as §1; runs cross-platform where the underlying data (psutil, command lines) is available |
| 3 | Anti-Hack Background Monitors (8) | C | Fully correct on Windows; 100% inert on Linux/macOS — see §41.2 |
| 4 | Enhanced Sneaky-Hacker Checks (7) | B | Genuinely sophisticated (12-indicator PowerShell obfuscation scoring, parent/child mismatch tables) — still zero code-signing backing |
| 5 | Network & Connection Monitoring | A- | Fixed 2026-08-22: every public IP now gets full enrichment (was gated to a minority); interface auto-detection now picks the actually-routed adapter instead of the first one enumerated (was silently selecting a disconnected APIPA link in testing) |
| 6 | DNS Monitoring | B | Bidirectional DNS map and DoH detection are solid from psutil/registry data alone; SNI extraction and full tunneling detection need Npcap; entropy/rate thresholds are static |
| 7 | GeoIP & Location Verification | B+ | 244-method-code MultiVerifier design is rigorous and honestly graded — but defaults to free third-party APIs with no bundled local database, and is rate-limited via TokenBucket under sustained load |
| 8 | VPN & Proxy Detection | A- | 100% detection rate / 0% false positives across 1,100 synthetic endpoints; now cross-verifies every public connection, not a filtered subset |
| 9 | Process Profiling & Forensics | C+ | Broad, genuinely useful data collection (I/O counters, DLL enumeration, CPU/memory now exported) — but memory forensics is RWX-region-only (no signing check), and VirusTotal is opt-in/undiscoverable/rate-capped |
| 10 | System & Persistence Monitoring | C | Windows-only; covers the standard Run-key persistence path but not COM hijacking, service-DLL hijacking, or `AppInit_DLLs` |
| 11 | Hardware & Peripheral Monitoring + Spectrum/RF | B | Windows-side collectors are real and verified live (Wi-Fi BSSID census, BT/BLE, WWAN, RF hardware, interface census, L2 wire talkers) with honest unavailable-not-fabricated coverage reporting; bounded by receivers — Zigbee/Z-Wave/NFC/sub-GHz need external hardware, BLE live-scan needs `bleak`, L2 census needs Npcap+admin, and `netsh` paths are Windows-only |
| 12 | Packet Analysis & TLS Fingerprinting | C+ | Well-engineered JA4+/SNI/entropy pipeline — entirely dependent on Npcap/libpcap, with no startup check that tells the user plainly when it's missing (only a log-line warning) |
| 13 | Behavioral & Statistical/ML | C+ | Real Z-score baselining across 4 metrics — but purely in-memory, resets to cold on every restart |
| 14 | Firewall & IP Blocking | C | Functional manual block/unblock on Windows via `netsh` plus the self-terminating Flow Probe (block→observe→auto-unblock with ROTATED/STICKY/GONE verdicts); no Linux equivalent; no automatic triggering |
| 15 | GUI (18 Tabs) | A- | Fixed 2026-08-22: all 55 ConnectionEntry fields now render, zero stale placeholders, Live tab refresh cut roughly 75x (2,540ms to 34ms); 2026-11-07: Signals tab surfaces the full spectrum registry with verbose labels; 2026-11-08: IP map plots every traced emitter (solved/ranged/local tiers) + PINPOINTS & GEO LOCATIONS sidebar — but the window itself has no authentication |
| 16 | Web Dashboard | C+ | Functional 6-tab live view (incl. the verbatim All Feeds completeness tail) with optional token auth — but a subset of the desktop GUI's 18 tabs, and served over plain HTTP (no TLS) |
| 17 | Data Export & Session Recording | B+ | Extremely thorough plain-text export (30+ sections including the spectrum/RF registry, effectively complete) — but not queryable; see §18 |
| 18 | Database & Logging | D | 2 of roughly 15 tracked entity types (deductions, devices) actually persisted to SQL; everything else is text-log-only |
| 19 | SIEM Output | C | File (JSON/CEF) or UDP syslog only — no direct connector for Splunk HEC, Elastic, Sentinel, or any SIEM's native ingestion API |
| 20 | Alert Escalation | B | Solid, well-reasoned compounding logic (1.5^(N-1), capped at 5x within a 5-minute window) — but escalation only changes a score, it doesn't trigger any external notification |
| 21 | Configuration System | B | Full type/range validation per key, live-editable in the GUI — but some values (thread intervals, dashboard port) only take effect on restart, and this isn't surfaced in the Config tab |
| n/a | Automated response/containment | F | Manual firewall block is the entire ceiling — see §41.3 |
| n/a | Out-of-band alerting | F | No email/Slack/Discord/push/SMS — see §41.3 |
| n/a | Signature/YARA detection | F | Not implemented anywhere — see §41.1 |
| n/a | Code-signing verification | F | Not implemented anywhere — see §41.1 |
| n/a | Cross-platform coverage | D | Linux: roughly 9/33 detections functional. macOS: effectively 0 — see §41.2 |
| n/a | Packaging/reproducibility | D | No dependency manifest, no pinned versions, no CI — see §41.4 |
| n/a | Delivery-layer test coverage | B (was F) | Detection logic was always well-tested (73+ cases); nothing verified harvested data actually reached the screen until `_test_data_wiring.py`/`_test_gui_render.py`/`_test_click_actions.py` were added 2026-08-22 |

**Overall assessment:** the detection engine (deduction logic, anti-hack heuristics, VPN/proxy/GeoIP cross-verification) is the strongest and most mature part of the system — rigorously designed, honestly graded (it says "UNVERIFIED" rather than guessing), and now, after the 2026-08-22 audit, fully wired end-to-end so what it computes actually reaches the screen. The weakest areas are consistently the same three: cross-platform coverage (Windows-first by a wide margin), response automation (detection-only, no containment), and operational maturity (no persisted history beyond two tables, no external alerting, no packaging/CI hygiene). None of these are secret — they're now stated plainly here rather than left implicit.
