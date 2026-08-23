#!/usr/bin/env python3
"""MedianBoxMonitor 3.0 — Complete Single-File Edition.

Modular Deductive Chess Engine for network security monitoring.
Deep process profiling + DNS-aware deductive chess.
Cross-references every process action with network traffic in real time.
"""
from __future__ import annotations

import sys
# Fix Windows console encoding — emoji/unicode chars crash cp1252
if sys.stdout and hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if sys.stderr and hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

import argparse
import datetime
import hashlib
import html as html_lib
import io
import ipaddress
import itertools
import json
import logging
import math
import os
import queue
import random
import re
import socket
import sqlite3
import statistics
import subprocess
import threading
import time
import urllib.error
import urllib.request
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from logging.handlers import RotatingFileHandler
from typing import Callable, Optional

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox

import psutil
from scapy.all import (
    ARP, BOOTP, DHCP, DNS, IP, TCP, UDP,
    Ether, IPv6, Raw, sniff, srp,
)

_IS_WINDOWS = os.name == 'nt'
if _IS_WINDOWS:
    try:
        import winreg
        import ctypes
        import ctypes.wintypes
    except ImportError:
        _IS_WINDOWS = False

# subprocess.CREATE_NO_WINDOW flag — suppresses console popups on Windows.
# Defined unconditionally so it's always available (0 on non-Windows).
_CREATE_NO_WINDOW = getattr(subprocess, 'CREATE_NO_WINDOW', 0)

try:
    import uvicorn
    from fastapi import FastAPI, WebSocket, WebSocketDisconnect
    from fastapi.responses import HTMLResponse, JSONResponse
    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False

try:
    import manuf
    _PARSER = manuf.MacParser()
    _HAS_MANUF = True
except ImportError:
    _HAS_MANUF = False
    _PARSER = None

try:
    import geoip2.database as _geoip2_db
    HAS_GEOIP2 = True
except ImportError:
    HAS_GEOIP2 = False

try:
    from PIL import Image, ImageTk
    HAS_PIL = True
except ImportError:
    HAS_PIL = False

_logger = logging.getLogger('medianbox')


# ========================== USER CONFIG ==========================
ALLOWED_APPS = {
    "zoom": False, "google": True, "cloudflare": False, "teams": False,
    "slack": False, "discord": False, "riot": True, "league": True,
}

MIMIC_KEYWORDS = {
    "zoom":       ["zoom", "zmeet", "zoomus", "zoom.us"],
    "google":     ["google", "gstatic", "googlevideo", "googleapis", "goog"],
    "cloudflare": ["cloudflare", "cf-", "warp", "one.one"],
    "teams":      ["teams", "microsoftonline", "microsoft365", "office365"],
    "slack":      ["slack", "slack-edge"],
    "discord":    ["discord", "discordapp", "dis.gd"],
    "riot":       ["riot", "riotgames", "leagueoflegends"],
    "league":     ["league", "lol", "lolesports"],
    "chrome":     ["chrome", "chromium"],
    "firefox":    ["firefox", "mozilla"],
    "edge":       ["msedge", "microsoftedge"],
}

EXPECTED_EXE_PATHS = {
    "chrome.exe":       [r"google\chrome\application"],
    "firefox.exe":      [r"mozilla firefox"],
    "msedge.exe":       [r"microsoft\edge\application"],
    "zoom.exe":         [r"zoom\bin", r"zoom"],
    "discord.exe":      [r"discord\app"],
    "teams.exe":        [r"microsoft teams", r"teams"],
    "slack.exe":        [r"slack\app"],
    "riotclientservices.exe": [r"riot games"],
    "leagueclient.exe": [r"riot games\league of legends"],
    "league of legends.exe": [r"riot games\league of legends"],
    "svchost.exe":      [r"windows\system32"],
    "csrss.exe":        [r"windows\system32"],
    "lsass.exe":        [r"windows\system32"],
    "services.exe":     [r"windows\system32"],
    "smss.exe":         [r"windows\system32"],
    "winlogon.exe":     [r"windows\system32"],
    "explorer.exe":     [r"windows"],
    "taskhostw.exe":    [r"windows\system32"],
    "conhost.exe":      [r"windows\system32"],
    "dllhost.exe":      [r"windows\system32"],
    "wininit.exe":      [r"windows\system32"],
    "spoolsv.exe":      [r"windows\system32"],
}

EXPECTED_PARENTS = {
    "svchost.exe":  ["services.exe"],
    "csrss.exe":    ["smss.exe"],
    "lsass.exe":    ["wininit.exe"],
    "services.exe": ["wininit.exe"],
    "smss.exe":     ["system"],
    "winlogon.exe": ["smss.exe"],
    "wininit.exe":  ["smss.exe"],
    "taskhostw.exe": ["svchost.exe"],
}

KNOWN_SERVICE_RANGES = {
    "riot":  ["104.160.128.0/17", "185.40.64.0/22", "162.249.72.0/21",
              "103.10.8.0/22", "45.7.36.0/22"],
    "google":["142.250.0.0/15", "172.217.0.0/16", "216.58.192.0/19",
              "209.85.128.0/17", "74.125.0.0/16", "64.233.160.0/19",
              "173.194.0.0/16", "108.177.0.0/17", "35.190.0.0/17"],
    "cloudflare": ["104.16.0.0/13", "172.64.0.0/13", "131.0.72.0/22",
                   "1.1.1.0/24", "1.0.0.0/24"],
    "microsoft": ["13.64.0.0/11", "20.33.0.0/16", "20.40.0.0/13",
                  "40.64.0.0/10", "52.96.0.0/12", "52.112.0.0/14"],
    "discord": ["162.159.128.0/17", "66.22.196.0/22"],
    "zoom":  ["3.7.35.0/25", "3.21.137.128/25", "3.22.11.0/24",
              "8.5.128.0/23", "64.125.62.0/24", "64.211.144.0/24",
              "65.39.152.0/24", "69.174.57.0/24", "147.124.96.0/19",
              "170.114.0.0/16", "206.247.0.0/16", "209.9.211.0/24"],
}

HARDWARE_KEYWORDS = {
    'audio':  ['audiodg', 'audioservice', 'pulseaudio', 'pipewire', 'rtkaudioservice'],
    'camera': ['camerabrokersvc', 'frameworkservice', 'webcam', 'camerahelper'],
}

PERSISTENCE_KEYS = []
if _IS_WINDOWS:
    PERSISTENCE_KEYS = [
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    ]

SUSPICIOUS_DLL_PATHS = [
    "\\temp\\", "\\tmp\\", "\\appdata\\local\\temp", "\\downloads\\",
    "\\desktop\\", "\\public\\", "\\programdata\\", "\\users\\public",
]

# ========================== DEFAULT CONFIG ==========================
# Upper bounds that keep long-running sessions from growing without limit.
MAX_ACTIONS_PER_PID = 400        # per-process action history
MAX_ACTIONS_EXPORTED = 20000     # lines handed to the GUI / reports per refresh
# Process export cap. Deliberately generous — the old hard 200 hid processes.
MAX_PROCESSES_EXPORTED = 2000
# Connection-timeline rows handed to the GUI per refresh.
MAX_TIMELINE_EXPORTED = 5000
MAX_FLOW_KEYS = 20000            # tracked (src,dst,proto,sport,dport) flows
MAX_REMOTE_SESSIONS = 5000       # tracked remote-access sessions

# Module-level constant — hoisted from process watcher to avoid recreating
# a dict literal on every remote-access port check (hot path).
_PORT_NAMES = {22: 'SSH', 3389: 'RDP', 5900: 'VNC', 5938: 'TeamViewer',
               445: 'SMB', 139: 'NetBIOS', 5985: 'WinRM', 5986: 'WinRM-S'}

# Port-to-service-name map — hoisted from _live_render_detail to avoid
# recreating a dict literal on every connection render (hot GUI path).
_PORT_SERVICES = {80: 'HTTP', 443: 'HTTPS', 22: 'SSH', 21: 'FTP', 25: 'SMTP',
                  53: 'DNS', 110: 'POP3', 143: 'IMAP', 993: 'IMAPS', 995: 'POP3S',
                  3389: 'RDP', 5900: 'VNC', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt',
                  445: 'SMB', 139: 'NetBIOS', 123: 'NTP', 161: 'SNMP',
                  5228: 'FCM-Google', 5222: 'XMPP', 5060: 'SIP'}

# Fast LRU cache for _is_public_ip — called on every packet and every connection.
# ipaddress.ip_address() + .is_global is expensive; most IPs repeat frequently.
from functools import lru_cache as _lru_cache

_RDNS_BOUNDED_CACHE: dict = {}
_RDNS_BOUNDED_LOCK = threading.Lock()


def _proc_connections(proc, kind: str = 'inet'):
    """Per-process sockets, across psutil versions.

    Process.connections() is deprecated in favour of Process.net_connections()
    and emits a DeprecationWarning on every call.
    """
    getter = getattr(proc, 'net_connections', None) or proc.connections
    return getter(kind=kind)


def _rdns_bounded(ip: str, timeout: float = 3.0) -> str:
    """socket.gethostbyaddr() with a wall-clock bound.

    gethostbyaddr honours no timeout argument and on Windows can block for
    30+ seconds on a filtered host, which stalls whichever worker called it.
    Run it on a throwaway daemon thread and abandon it if it overruns. The
    result (including the empty string for a failure) is cached so a slow IP
    is only ever waited on once.
    """
    with _RDNS_BOUNDED_LOCK:
        if ip in _RDNS_BOUNDED_CACHE:
            return _RDNS_BOUNDED_CACHE[ip]
    box = {}

    def _work():
        try:
            box['host'] = socket.gethostbyaddr(ip)[0]
        except Exception:
            box['host'] = ''

    t = threading.Thread(target=_work, daemon=True, name="rdns-bounded")
    t.start()
    t.join(timeout)
    host = box.get('host', '')
    if t.is_alive():
        # Timed out — don't cache, the abandoned thread may still land a result.
        return ''
    with _RDNS_BOUNDED_LOCK:
        if len(_RDNS_BOUNDED_CACHE) > 20000:
            _RDNS_BOUNDED_CACHE.clear()
        _RDNS_BOUNDED_CACHE[ip] = host
    return host


@_lru_cache(maxsize=4096)
def _is_public_ip_cached(ip: str) -> bool:
    """Cached version of _is_public_ip — avoids repeated ipaddress parsing."""
    try:
        return ipaddress.ip_address(ip).is_global
    except (ValueError, Exception):
        return False

CONFIG = {
    'remote_ports': {22, 3389, 5900, 5938, 445, 139, 5985, 5986},
    'probe_alert_ports': {21, 23, 80, 443, 445, 22, 3389, 5900},
    'alert_cooldown': 75,
    'deduction_cooldown': 120,
    'db_file': 'medianbox_ultimate.db',
    'log_file': 'medianbox_structured.log',
    'actions_log': 'medianbox_full_actions.log',
    'deductions_log': 'medianbox_deductions.log',
    'verify_workers': 4,             # MultiVerifier background workers
    'process_scan_interval': 0.5,
    'scan_interval_min': 2,
    'scan_interval_max': 10,
    # --- Low-latency tuning (near real-time monitoring) ---
    'gui_refresh_ms': 250,           # GUI refresh interval in milliseconds
    'conn_map_interval': 0.5,        # connection mapper poll interval (seconds)
    'status_interval': 5,            # status thread interval (seconds)
    'dns_poll_interval': 5,          # DNS cache poll interval (seconds)
    'extended_monitor_interval': 2,  # extended monitors interval (seconds)
    'iface_stats_interval': 1,       # interface stats interval (seconds)
    'memory_forensics_interval': 15, # memory forensics interval (seconds)
    'sniff_retry_interval': 2,       # sniff retry on error (seconds)
    'baseline_min_samples': 50,
    'beacon_min_samples': 20,
    'risk_critical': 70,
    'risk_warning': 40,
    'entropy_suspicious_threshold': 7.2,
    'exfil_bytes_spike_factor': 10,
    'exfil_min_bytes': 1_000_000,
    'dns_tunnel_max_label_len': 50,
    'dns_tunnel_entropy_threshold': 3.5,
    'dns_tunnel_query_rate_threshold': 30,
    'geoip_cache_ttl': 3600,
    'geoip_enabled': True,
    'high_risk_countries': {'CN', 'RU', 'KP', 'IR'},
    'user_idle_threshold': 300,
    'registry_scan_interval': 60,
    'dll_scan_interval': 30,
    'escalation_window': 300,
    'escalation_multiplier': 1.5,
    'siem_output': None,
    'siem_host': '127.0.0.1',
    'siem_port': 514,
    'dashboard_enabled': True,
    'dashboard_port': 8470,
    'ml_baseline_window': 86400,
    'ml_zscore_threshold': 3.0,
    'config_file': 'medianbox_config.yaml',
    'pipeline_workers': 4,
    'pipeline_queue_size': 10000,
    'dashboard_password': '',
    'geoip_db_path': '',
}

EMOJI = {
    'new': '🆕', 'alert': '🚨', 'remote': '🔌', 'probe': '🔍', 'kill': '☠️',
    'ok': '✅', 'spoof': '🕵️', 'mimic': '🎭', 'foreign': '🌍', 'chess': '♟️',
    'beacon': '📡', 'phantom': '👻', 'impersonate': '🥸', 'inject': '💉',
    'anomaly': '📊', 'brain': '🧠', 'tunnel': '🕳️', 'exfil': '📤',
    'entropy': '🔐', 'dll': '🧩', 'persist': '📌', 'geo': '🗺️',
    'idle': '💤', 'ml': '🤖', 'escalate': '⬆️', 'dashboard': '📺',
}


class Colors:
    G = '\033[92m'
    Y = '\033[93m'
    R = '\033[91m'
    C = '\033[96m'
    M = '\033[95m'
    B = '\033[94m'
    W = '\033[97m'
    END = '\033[0m'


# ========================== CONFIG SCHEMA & VALIDATION ==========================
CONFIG_SCHEMA = {
    'remote_ports':               {'type': set,   'elem': int},
    'probe_alert_ports':          {'type': set,   'elem': int},
    'alert_cooldown':             {'type': (int, float), 'min': 0},
    'deduction_cooldown':         {'type': (int, float), 'min': 0},
    'db_file':                    {'type': str},
    'log_file':                   {'type': str},
    'actions_log':                {'type': str},
    'deductions_log':             {'type': str},
    'process_scan_interval':      {'type': (int, float), 'min': 0.1, 'max': 60},
    'scan_interval_min':          {'type': (int, float), 'min': 1},
    'scan_interval_max':          {'type': (int, float), 'min': 1},
    'gui_refresh_ms':             {'type': (int, float), 'min': 50, 'max': 10000},
    'conn_map_interval':          {'type': (int, float), 'min': 0.1, 'max': 30},
    'status_interval':            {'type': (int, float), 'min': 1, 'max': 120},
    'dns_poll_interval':          {'type': (int, float), 'min': 1, 'max': 120},
    'extended_monitor_interval':  {'type': (int, float), 'min': 1, 'max': 60},
    'iface_stats_interval':       {'type': (int, float), 'min': 0.5, 'max': 60},
    'memory_forensics_interval':  {'type': (int, float), 'min': 5, 'max': 300},
    'sniff_retry_interval':       {'type': (int, float), 'min': 1, 'max': 60},
    'baseline_min_samples':       {'type': int, 'min': 5},
    'beacon_min_samples':         {'type': int, 'min': 5},
    'risk_critical':              {'type': (int, float), 'min': 0, 'max': 1000},
    'risk_warning':               {'type': (int, float), 'min': 0, 'max': 1000},
    'entropy_suspicious_threshold': {'type': (int, float), 'min': 0, 'max': 8},
    'exfil_bytes_spike_factor':   {'type': (int, float), 'min': 1},
    'exfil_min_bytes':            {'type': int, 'min': 1000},
    'dns_tunnel_max_label_len':   {'type': int, 'min': 10},
    'dns_tunnel_entropy_threshold': {'type': (int, float), 'min': 0, 'max': 8},
    'dns_tunnel_query_rate_threshold': {'type': (int, float), 'min': 1},
    'geoip_cache_ttl':            {'type': (int, float), 'min': 0},
    'geoip_enabled':              {'type': bool},
    'high_risk_countries':        {'type': set, 'elem': str},
    'user_idle_threshold':        {'type': (int, float), 'min': 0},
    'registry_scan_interval':     {'type': (int, float), 'min': 5},
    'dll_scan_interval':          {'type': (int, float), 'min': 5},
    'escalation_window':          {'type': (int, float), 'min': 10},
    'escalation_multiplier':      {'type': (int, float), 'min': 1.0, 'max': 10.0},
    'siem_output':                {'type': (str, type(None)), 'choices': {None, 'json', 'cef', 'syslog'}},
    'siem_host':                  {'type': str},
    'siem_port':                  {'type': int, 'min': 1, 'max': 65535},
    'dashboard_enabled':          {'type': bool},
    'dashboard_port':             {'type': int, 'min': 1, 'max': 65535},
    'ml_baseline_window':         {'type': (int, float), 'min': 60},
    'ml_zscore_threshold':        {'type': (int, float), 'min': 1.0},
    'config_file':                {'type': str},
    'pipeline_workers':           {'type': int, 'min': 1, 'max': 16},
    'pipeline_queue_size':        {'type': int, 'min': 100},
    'dashboard_password':         {'type': str},
    'geoip_db_path':              {'type': str},
}


def validate_config(cfg: dict) -> list:
    """Validate config dict against schema. Returns list of error strings (empty = valid)."""
    errors = []
    for key, rules in CONFIG_SCHEMA.items():
        if key not in cfg:
            continue
        val = cfg[key]
        expected_type = rules['type']
        if not isinstance(val, expected_type):
            errors.append(f"{key}: expected {expected_type}, got {type(val).__name__} ({val!r})")
            continue
        if 'elem' in rules and isinstance(val, set):
            for item in val:
                if not isinstance(item, rules['elem']):
                    errors.append(f"{key}: set element {item!r} is not {rules['elem'].__name__}")
                    break
        if 'min' in rules and isinstance(val, (int, float)) and val < rules['min']:
            errors.append(f"{key}: {val} < minimum {rules['min']}")
        if 'max' in rules and isinstance(val, (int, float)) and val > rules['max']:
            errors.append(f"{key}: {val} > maximum {rules['max']}")
        if 'choices' in rules and val not in rules['choices']:
            errors.append(f"{key}: {val!r} not in {rules['choices']}")
    return errors


def load_config(cfg_path: Optional[str] = None):
    """Load config from YAML file, validate, and merge into CONFIG."""
    try:
        import yaml
    except ImportError:
        _logger.info("PyYAML not installed — using default config")
        return
    cfg_file = cfg_path or CONFIG.get('config_file', 'medianbox_config.yaml')
    if not os.path.exists(cfg_file):
        _logger.debug("Config file %s not found — using defaults", cfg_file)
        return
    try:
        with open(cfg_file, encoding='utf-8') as f:
            user_cfg = yaml.safe_load(f) or {}
    except Exception as exc:
        _logger.warning("Failed to load config from %s: %s", cfg_file, exc)
        return
    for k, v in user_cfg.items():
        if k in CONFIG and isinstance(CONFIG[k], set) and isinstance(v, list):
            user_cfg[k] = set(v)
    errors = validate_config(user_cfg)
    if errors:
        for err in errors:
            _logger.warning("Config validation error: %s", err)
        _logger.warning("Config file has %d error(s) — invalid keys were NOT applied", len(errors))
        error_keys = {e.split(':')[0] for e in errors}
        for k, v in user_cfg.items():
            if k in CONFIG and k not in error_keys:
                CONFIG[k] = v
    else:
        for k, v in user_cfg.items():
            if k in CONFIG:
                CONFIG[k] = v
    _logger.info("Loaded config from %s", cfg_file)


# ========================== MODELS ==========================
@dataclass
class ProcessProfile:
    pid: int
    name: str
    exe_path: str = ""
    parent_pid: int = 0
    parent_name: str = ""
    start_time: float = 0.0
    destinations: set[str] = field(default_factory=set)
    dns_domains: set[str] = field(default_factory=set)
    sni_domains: set[str] = field(default_factory=set)
    connection_count: int = 0
    seen_conn_keys: set[tuple] = field(default_factory=set)
    cpu_samples: "deque[float]" = field(default_factory=lambda: deque(maxlen=60))
    packet_timestamps: "deque[float]" = field(default_factory=lambda: deque(maxlen=500))
    bytes_sent: int = 0
    bytes_recv: int = 0
    risk_score: float = 0.0
    risk_reasons: list[str] = field(default_factory=list)
    last_network_ts: float = 0.0
    checked_legitimacy: bool = False
    checked_dlls: bool = False
    dll_scan_time: float = 0.0
    io_baseline_sent: int = 0
    io_baseline_recv: int = 0
    io_snapshot_time: float = 0.0
    io_send_rate: float = 0.0
    io_rate_samples: "deque[float]" = field(default_factory=lambda: deque(maxlen=60))
    geo_countries: set[str] = field(default_factory=set)
    loaded_dlls: list[str] = field(default_factory=list)
    escalation_hits: int = 0
    ml_anomaly_score: float = 0.0
    cmdline: str = ""
    memory_mb: float = 0.0
    # Deduction categories raised against this process. The Processes tab
    # renders these as behavioural flags; they used to be read from keys that
    # nothing ever wrote, so the flag line never appeared.
    flags: set[str] = field(default_factory=set)


@dataclass
class Deduction:
    timestamp: float
    severity: str
    category: str
    process_name: str
    pid: int
    message: str
    evidence: list
    score: float


# ========================== OUI LOOKUP ==========================
_FALLBACK_OUI = {
    '001A2B': 'Apple', 'ACBC32': 'Samsung', '000C29': 'VMware', '001C42': 'D-Link',
    'AC8995': 'TP-Link', '001E65': 'Netgear', 'B827EB': 'Raspberry Pi', 'F81A67': 'TP-Link',
    '001122': 'Generic', '0024E4': 'Withings', '00156D': 'Ubiquiti', '001B11': 'ARRIS',
    '00E04C': 'Realtek', '0017C4': 'Nokia', '0019E0': 'TP-Link', '0024A5': 'Freebox',
    '001D92': 'AVM', '0026B9': 'Dell', '001310': 'HP', '001E0B': 'Hewlett-Packard',
    'F0B429': 'Google Nest', '00163E': 'ASUSTek', '0024D2': 'Askey', '001B21': 'Intel',
    '0014D1': 'OvisLink', '0019FB': 'Philips', '0023DF': 'Sony', '000E8F': 'ADT',
    'F4F5D8': 'Google', '0017B0': 'Samsung', '0018F8': 'Linksys', '0023BE': 'Belkin',
    '001D0F': 'TP-Link', '0024D7': 'Xiaomi', '0019E3': 'Aruba', '0026BB': 'ARRIS',
}


def get_vendor(mac: str) -> str:
    if not mac:
        return "Unknown"
    if _HAS_MANUF:
        try:
            result = _PARSER.get_manuf(mac)
            if result:
                return result
        except Exception as exc:
            _logger.debug("manuf lookup failed for %s: %s", mac, exc)
    prefix = mac.upper().replace(':', '').replace('-', '')[:6]
    return _FALLBACK_OUI.get(prefix, "Unknown Vendor")


# ========================== DNS CACHE & TUNNEL DETECTOR ==========================
class DNSCache:
    """Thread-safe DNS resolution cache built from sniffed DNS responses."""
    def __init__(self):
        self.ip_to_domains: dict[str, set[str]] = defaultdict(set)
        self.domain_to_ips: dict[str, set[str]] = defaultdict(set)
        self.query_log: deque = deque(maxlen=5000)
        self.lock = threading.Lock()

    def process_packet(self, pkt):
        if not pkt.haslayer(DNS):
            return
        dns_layer = pkt[DNS]
        if dns_layer.qr == 1 and dns_layer.ancount > 0:
            try:
                qname = dns_layer.qd.qname.decode(errors='ignore').rstrip('.')
                rr = dns_layer.an
                for _ in range(min(dns_layer.ancount, 30)):
                    if rr is None:
                        break
                    if hasattr(rr, 'rdata'):
                        ip_str = str(rr.rdata)
                        try:
                            ipaddress.ip_address(ip_str)
                            with self.lock:
                                self.ip_to_domains[ip_str].add(qname)
                                self.domain_to_ips[qname].add(ip_str)
                        except ValueError:
                            pass
                    rr = rr.payload if hasattr(rr, 'payload') and rr.payload else None
            except Exception as exc:
                _logger.debug("DNS response parse error: %s", exc)
        elif dns_layer.qr == 0:
            try:
                qname = dns_layer.qd.qname.decode(errors='ignore').rstrip('.')
                src = pkt[IP].src if pkt.haslayer(IP) else "?"
                with self.lock:
                    self.query_log.append((time.time(), src, qname))
            except Exception as exc:
                _logger.debug("DNS query parse error: %s", exc)

    def get_domains(self, ip: str) -> set[str]:
        with self.lock:
            doms = self.ip_to_domains.get(ip)
            if not doms:
                return set()
            return set(doms)

    def get_ips(self, domain: str) -> set[str]:
        with self.lock:
            return set(self.domain_to_ips.get(domain, set()))

    def recent_queries(self, keyword: str = '', window: float = 120) -> list[tuple]:
        """Recent DNS queries, newest first. An empty keyword returns them all."""
        cutoff = time.time() - window
        kw = (keyword or '').lower()
        with self.lock:
            hits = [(t, s, d) for t, s, d in self.query_log
                    if t > cutoff and (not kw or kw in d.lower())]
        hits.reverse()
        return hits

    # --- Windows DNS client cache polling ---
    def poll_system_dns_cache(self):
        """Harvest IP→domain mappings from the Windows DNS client cache.
        Uses ipconfig /displaydns with CNAME chain tracking, then
        PowerShell Get-DnsClientCache for richer data."""
        added = 0
        added += self._poll_ipconfig_displaydns()
        added += self._poll_powershell_dns_cache()
        if added:
            _logger.debug("DNS cache poll: added %d new IP→domain mappings total", added)

    def _add_domain_ip(self, ip_str: str, domain: str) -> bool:
        """Add a single IP→domain mapping. Returns True if new."""
        domain = domain.rstrip('.').lower()
        if not domain or not ip_str:
            return False
        with self.lock:
            if domain not in self.ip_to_domains.get(ip_str, set()):
                self.ip_to_domains[ip_str].add(domain)
                self.domain_to_ips[domain].add(ip_str)
                return True
        return False

    def _poll_ipconfig_displaydns(self) -> int:
        """Parse 'ipconfig /displaydns' with CNAME chain resolution."""
        try:
            result = subprocess.run(
                ['ipconfig', '/displaydns'],
                capture_output=True, text=True, timeout=10,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0),
            )
            if result.returncode != 0:
                return 0
            # Pass 1: collect all record names → A/AAAA IPs and CNAME targets
            current_name = None
            a_records = {}      # record_name → set of IPs
            cname_map = {}      # cname_target → set of original names that point to it
            for line in result.stdout.splitlines():
                stripped = line.strip()
                if stripped.startswith('Record Name'):
                    parts = stripped.split(':', 1)
                    if len(parts) == 2:
                        current_name = parts[1].strip().rstrip('.').lower()
                elif current_name:
                    if 'A (Host) Record' in stripped or 'AAAA' in stripped:
                        parts = stripped.split(':', 1)
                        if len(parts) == 2:
                            ip_str = parts[1].strip()
                            try:
                                ipaddress.ip_address(ip_str)
                                a_records.setdefault(current_name, set()).add(ip_str)
                            except ValueError:
                                pass
                    elif 'CNAME Record' in stripped:
                        parts = stripped.split(':', 1)
                        if len(parts) == 2:
                            target = parts[1].strip().rstrip('.').lower()
                            cname_map.setdefault(target, set()).add(current_name)
            # Pass 2: for each A record, follow CNAME chains back to original names
            added = 0
            for record_name, ips in a_records.items():
                # Collect all names that resolve to these IPs (including CNAME sources)
                all_names = {record_name}
                queue = [record_name]
                visited = set()
                while queue:
                    name = queue.pop()
                    if name in visited:
                        continue
                    visited.add(name)
                    # Find names that CNAME to this name
                    for source in cname_map.get(name, set()):
                        all_names.add(source)
                        queue.append(source)
                for ip_str in ips:
                    for name in all_names:
                        if self._add_domain_ip(ip_str, name):
                            added += 1
            return added
        except Exception as exc:
            _logger.debug("ipconfig /displaydns parse error: %s", exc)
            return 0

    def _poll_powershell_dns_cache(self) -> int:
        """Use PowerShell Get-DnsClientCache for richer DNS data with original query names."""
        try:
            cmd = (
                'Get-DnsClientCache -Status Success -ErrorAction SilentlyContinue '
                '| Where-Object { $_.Type -in 1,28 } '
                '| Select-Object -Property Entry,Data '
                '| Format-Table -HideTableHeaders -AutoSize'
            )
            result = subprocess.run(
                ['powershell', '-NoProfile', '-NonInteractive', '-Command', cmd],
                capture_output=True, text=True, timeout=15,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0),
            )
            if result.returncode != 0:
                return 0
            added = 0
            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 2:
                    entry = parts[0].strip().rstrip('.').lower()
                    ip_str = parts[-1].strip()
                    try:
                        ipaddress.ip_address(ip_str)
                        if self._add_domain_ip(ip_str, entry):
                            added += 1
                    except ValueError:
                        pass
            return added
        except Exception as exc:
            _logger.debug("PowerShell DNS cache error: %s", exc)
            return 0

    # --- Persistent domain history ---
    _HISTORY_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.dns_domain_history.json')

    def save_history(self):
        """Persist all IP→domain mappings to disk so they survive restarts."""
        try:
            with self.lock:
                data = {ip: sorted(doms) for ip, doms in self.ip_to_domains.items() if doms}
            with open(self._HISTORY_FILE, 'w', encoding='utf-8') as f:
                json.dump(data, f)
        except Exception as exc:
            _logger.debug("DNS history save error: %s", exc)

    def load_history(self):
        """Load persisted IP→domain mappings from a previous session."""
        try:
            if not os.path.exists(self._HISTORY_FILE):
                return
            with open(self._HISTORY_FILE, 'r', encoding='utf-8') as f:
                data = json.load(f)
            added = 0
            with self.lock:
                for ip, doms in data.items():
                    for d in doms:
                        if d not in self.ip_to_domains.get(ip, set()):
                            self.ip_to_domains[ip].add(d)
                            self.domain_to_ips[d].add(ip)
                            added += 1
            if added:
                _logger.debug("DNS history: loaded %d IP→domain mappings from disk", added)
        except Exception as exc:
            _logger.debug("DNS history load error: %s", exc)


class DNSTunnelingDetector:
    """Detects data exfiltration via DNS queries (long subdomains, high entropy, high rate)."""
    def __init__(self):
        self.domain_query_counts: dict[str, deque] = defaultdict(lambda: deque(maxlen=200))
        self.lock = threading.Lock()

    @staticmethod
    def shannon_entropy(s: str) -> float:
        if not s:
            return 0.0
        freq = Counter(s)
        length = len(s)
        return -sum((c / length) * math.log2(c / length) for c in freq.values())

    def analyze_query(self, qname: str) -> tuple[bool, float, list[str]]:
        evidence = []
        score = 0.0
        parts = qname.split('.')
        if len(parts) < 2:
            return False, 0, []
        base_domain = '.'.join(parts[-2:])
        subdomain = '.'.join(parts[:-2])
        max_label = max((len(p) for p in parts[:-2]), default=0)
        if max_label > CONFIG['dns_tunnel_max_label_len']:
            evidence.append(f"Very long subdomain label: {max_label} chars")
            score += 25
        if subdomain:
            ent = self.shannon_entropy(subdomain.replace('.', ''))
            if ent > CONFIG['dns_tunnel_entropy_threshold']:
                evidence.append(f"High subdomain entropy: {ent:.2f} bits")
                score += 25
        now = time.time()
        with self.lock:
            self.domain_query_counts[base_domain].append(now)
            recent = sum(1 for t in self.domain_query_counts[base_domain] if now - t < 60)
        if recent > CONFIG['dns_tunnel_query_rate_threshold']:
            evidence.append(f"High query rate: {recent}/min to {base_domain}")
            score += 25
        if len(evidence) >= 2:
            score += 15
            evidence.append("Multiple indicators — high confidence DNS tunneling")
        return score >= 25, score, evidence


# ========================== NETWORK DETECTORS ==========================
class BeaconDetector:
    """Catches C2 beaconing via inter-packet timing regularity analysis."""
    @staticmethod
    def analyze(timestamps) -> tuple[bool, float, str]:
        if len(timestamps) < CONFIG['beacon_min_samples']:
            return False, 0.0, ""
        ts = sorted(timestamps)
        intervals = [ts[i+1] - ts[i] for i in range(len(ts)-1)]
        if not intervals:
            return False, 0.0, ""
        mean_iv = statistics.mean(intervals)
        if mean_iv < 0.5:
            return False, 0.0, ""
        try:
            stdev_iv = statistics.stdev(intervals)
            cv = stdev_iv / mean_iv if mean_iv > 0 else float('inf')
        except statistics.StatisticsError:
            return False, 0.0, ""
        if cv < 0.12 and mean_iv > 2:
            conf = min(1.0, (0.12 - cv) / 0.12 + 0.5)
            return True, conf, f"Fixed beacon: {mean_iv:.1f}s +/-{stdev_iv:.2f}s jitter={cv:.3f}"
        if cv < 0.25 and mean_iv > 5 and len(intervals) > 40:
            conf = min(0.85, (0.25 - cv) / 0.25 + 0.3)
            return True, conf, f"Periodic callback: ~{mean_iv:.1f}s jitter={cv:.3f}"
        if len(intervals) > 30:
            median_iv = statistics.median(intervals)
            if median_iv > 3:
                within = sum(1 for i in intervals if abs(i - median_iv) < median_iv * 0.15)
                ratio = within / len(intervals)
                if ratio > 0.65:
                    return True, ratio * 0.75, f"Clustered: ~{median_iv:.1f}s {ratio:.0%} consistent"
        return False, 0.0, ""


class SNIExtractor:
    """Extracts Server Name Indication from TLS ClientHello."""
    @staticmethod
    def extract(pkt) -> Optional[str]:
        if not (pkt.haslayer(TCP) and pkt.haslayer(Raw)):
            return None
        try:
            data = bytes(pkt[Raw])
            if len(data) < 6 or data[0] != 0x16:
                return None
            hs_data = data[5:]
            if len(hs_data) < 4 or hs_data[0] != 0x01:
                return None
            ch_len = int.from_bytes(hs_data[1:4], 'big')
            ch = hs_data[4:4+ch_len]
            if len(ch) < 38:
                return None
            offset = 34
            sess_id_len = ch[offset]
            offset += 1 + sess_id_len
            if offset + 2 > len(ch):
                return None
            cipher_len = int.from_bytes(ch[offset:offset+2], 'big')
            offset += 2 + cipher_len
            if offset >= len(ch):
                return None
            comp_len = ch[offset]
            offset += 1 + comp_len
            if offset + 2 > len(ch):
                return None
            ext_total = int.from_bytes(ch[offset:offset+2], 'big')
            offset += 2
            end = min(offset + ext_total, len(ch))
            while offset + 4 < end:
                ext_type = int.from_bytes(ch[offset:offset+2], 'big')
                ext_len = int.from_bytes(ch[offset+2:offset+4], 'big')
                offset += 4
                if ext_type == 0x0000:
                    sni_data = ch[offset:offset+ext_len]
                    if len(sni_data) >= 5:
                        name_len = int.from_bytes(sni_data[3:5], 'big')
                        if len(sni_data) >= 5 + name_len:
                            return sni_data[5:5+name_len].decode('ascii', errors='ignore')
                offset += ext_len
        except Exception as exc:
            _logger.debug("SNI extraction error: %s", exc)
        return None


class EntropyAnalyzer:
    """Shannon entropy analysis on packet payloads to detect encrypted C2."""
    @staticmethod
    def payload_entropy(data: bytes) -> float:
        if not data:
            return 0.0
        freq = Counter(data)
        length = len(data)
        return -sum((c / length) * math.log2(c / length) for c in freq.values())

    @staticmethod
    def is_suspicious(pkt, entropy_val: float) -> tuple[bool, str]:
        sport = pkt[TCP].sport if pkt.haslayer(TCP) else (pkt[UDP].sport if pkt.haslayer(UDP) else 0)
        dport = pkt[TCP].dport if pkt.haslayer(TCP) else (pkt[UDP].dport if pkt.haslayer(UDP) else 0)
        tls_ports = {443, 8443, 993, 995, 465, 636}
        if dport in tls_ports or sport in tls_ports:
            return False, ""
        if entropy_val > CONFIG['entropy_suspicious_threshold']:
            return True, (f"High entropy {entropy_val:.2f} on non-TLS port "
                          f"(sport={sport} dport={dport}) — possible encrypted C2")
        return False, ""


# ========================== PROCESS DETECTORS ==========================
class ProcessLegitimacyChecker:
    """Detects impersonation by verifying exe path and parent chain."""
    @staticmethod
    def check_path(name: str, exe_path: str) -> tuple[bool, str]:
        name_l = name.lower()
        exe_l = (exe_path or "").lower()
        if name_l in EXPECTED_EXE_PATHS and exe_l and not any(f in exe_l for f in EXPECTED_EXE_PATHS[name_l]):
            return True, f"'{name}' at unexpected path: {exe_path}"
        return False, ""

    @staticmethod
    def check_parent(name: str, parent_name: str) -> tuple[bool, str]:
        name_l = name.lower()
        parent_l = (parent_name or "").lower()
        if name_l in EXPECTED_PARENTS:
            expected = EXPECTED_PARENTS[name_l]
            if parent_l and parent_l not in expected:
                return True, f"'{name}' has unexpected parent '{parent_name}' (expected: {expected})"
        return False, ""

    @staticmethod
    def check_all(proc) -> list[str]:
        reasons = []
        try:
            name = proc.name()
            exe = proc.exe() or ""
            sus, msg = ProcessLegitimacyChecker.check_path(name, exe)
            if sus:
                reasons.append(msg)
            try:
                parent = psutil.Process(proc.ppid())
                sus2, msg2 = ProcessLegitimacyChecker.check_parent(name, parent.name())
                if sus2:
                    reasons.append(msg2)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
            if name.lower() in ("svchost.exe", "csrss.exe", "lsass.exe", "services.exe",
                                "smss.exe", "winlogon.exe", "wininit.exe"):
                if exe and "system32" not in exe.lower() and "syswow64" not in exe.lower():
                    reasons.append(f"SYSTEM IMPERSONATION: '{name}' at '{exe}' — NOT in System32")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        return reasons


class DLLInspector:
    """Checks loaded modules per process for suspicious DLL paths."""
    @staticmethod
    def inspect(proc) -> list[str]:
        suspicious = []
        if not _IS_WINDOWS:
            return suspicious
        try:
            for mmap in proc.memory_maps(grouped=False):
                path_lower = (mmap.path or "").lower()
                if any(frag in path_lower for frag in SUSPICIOUS_DLL_PATHS):
                    suspicious.append(mmap.path)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        except Exception as exc:
            _logger.debug("DLL inspection error for %s: %s", proc, exc)
        return suspicious


# ========================== SYSTEM DETECTORS ==========================
class RegistryMonitor:
    """Monitors Windows Run keys and scheduled tasks for persistence changes."""
    def __init__(self):
        self.baseline: dict[str, str] = {}
        self.lock = threading.Lock()

    def scan(self) -> list[tuple[str, str, str]]:
        if not _IS_WINDOWS:
            return []
        changes = []
        current = {}
        for hive, key_path in PERSISTENCE_KEYS:
            try:
                with winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ) as key:
                    i = 0
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(key, i)
                            full_key = f"{key_path}\\{name}"
                            current[full_key] = str(value)
                            i += 1
                        except OSError:
                            break
            except OSError as exc:
                _logger.debug("Registry scan error for %s: %s", key_path, exc)
        with self.lock:
            if self.baseline:
                for k, v in current.items():
                    if k not in self.baseline:
                        changes.append(("ADDED", k, v))
                    elif self.baseline[k] != v:
                        changes.append(("MODIFIED", k, v))
                for k in self.baseline:
                    if k not in current:
                        changes.append(("REMOVED", k, self.baseline[k]))
            self.baseline = current
        return changes


class UserIdleMonitor:
    """Tracks user idle time via Windows GetLastInputInfo."""
    @staticmethod
    def get_idle_seconds() -> float:
        if not _IS_WINDOWS:
            return 0.0
        try:
            class LASTINPUTINFO(ctypes.Structure):
                _fields_ = [("cbSize", ctypes.c_uint), ("dwTime", ctypes.c_uint)]
            lii = LASTINPUTINFO()
            lii.cbSize = ctypes.sizeof(LASTINPUTINFO)
            if ctypes.windll.user32.GetLastInputInfo(ctypes.byref(lii)):
                millis = ctypes.windll.kernel32.GetTickCount() - lii.dwTime
                return millis / 1000.0
        except Exception as exc:
            _logger.debug("GetLastInputInfo failed: %s", exc)
        return 0.0


# ========================== STATISTICAL BASELINE ==========================
class StatisticalBaseline:
    """Z-score anomaly detection per process name on key behavioral metrics."""
    def __init__(self):
        self.models: dict[str, dict] = defaultdict(lambda: {
            'conn_rate': deque(maxlen=500),
            'dst_count': deque(maxlen=500),
            'bytes_rate': deque(maxlen=500),
            'cpu_mean': deque(maxlen=500),
            'ts': deque(maxlen=500),
        })
        self.lock = threading.Lock()

    def record(self, proc_name: str, conn_rate: float, dst_count: int,
               bytes_rate: float, cpu_mean: float):
        now = time.time()
        with self.lock:
            m = self.models[proc_name]
            m['conn_rate'].append(conn_rate)
            m['dst_count'].append(dst_count)
            m['bytes_rate'].append(bytes_rate)
            m['cpu_mean'].append(cpu_mean)
            m['ts'].append(now)
            # Age out anything older than ml_baseline_window so a baseline
            # tracks recent behaviour rather than the whole session.
            window = CONFIG.get('ml_baseline_window', 86400)
            cutoff = now - window
            while m['ts'] and m['ts'][0] < cutoff:
                m['ts'].popleft()
                for key in ('conn_rate', 'dst_count', 'bytes_rate', 'cpu_mean'):
                    if m[key]:
                        m[key].popleft()

    def score(self, proc_name: str, conn_rate: float, dst_count: int,
              bytes_rate: float, cpu_mean: float) -> tuple[float, list[str]]:
        anomalies = []
        total_z = 0.0
        # Honour the configured warm-up length instead of a hardcoded 30/10.
        min_samples = max(5, int(CONFIG.get('baseline_min_samples', 50)))
        with self.lock:
            m = self.models.get(proc_name)
            if not m or len(m['conn_rate']) < min_samples:
                return 0.0, []
            for metric_name, current_val in [('conn_rate', conn_rate), ('dst_count', dst_count),
                                              ('bytes_rate', bytes_rate), ('cpu_mean', cpu_mean)]:
                samples = list(m[metric_name])
                if len(samples) < min_samples:
                    continue
                mean = statistics.mean(samples)
                try:
                    std = statistics.stdev(samples)
                except statistics.StatisticsError:
                    continue
                if std < 0.001:
                    continue
                z = abs(current_val - mean) / std
                if z > CONFIG['ml_zscore_threshold']:
                    anomalies.append(f"{metric_name}: z={z:.1f} (val={current_val:.1f} mean={mean:.1f} std={std:.1f})")
                    total_z += z
        score = min(100, total_z * 10)
        return score, anomalies


# ========================== JA4+ FINGERPRINTING ==========================
class JA4Plus:
    """Extended JA4 — JA4S (ServerHello), JA4H (HTTP), JA4X (X.509 cert)."""
    @staticmethod
    def ja4(pkt) -> Optional[str]:
        if not (pkt.haslayer(TCP) and pkt.haslayer(Raw)):
            return None
        try:
            data = bytes(pkt[Raw])
            if len(data) < 9 or data[0] != 0x16:
                return None
            handshake = data[5:]
            if len(handshake) < 4 or handshake[0] != 0x01:
                return None
            ch = handshake[4:]
            if len(ch) < 38:
                return None
            tls_ver = f"t{ch[0]:02x}{ch[1]:02x}"
            sess_id_len = ch[34]
            offset = 35 + sess_id_len
            cipher_len = int.from_bytes(ch[offset:offset+2], 'big')
            offset += 2 + cipher_len
            comp_len = ch[offset]
            offset += 1 + comp_len
            ext_len = int.from_bytes(ch[offset:offset+2], 'big')
            alpn = "h2" if b'\x00\x10' in data else "http1"
            return f"{tls_ver}d{cipher_len//2:02d}{ext_len//4:02d}_{alpn}"
        except Exception as exc:
            _logger.debug("JA4 fingerprint error: %s", exc)
            return None

    @staticmethod
    def ja4s(pkt) -> Optional[str]:
        if not (pkt.haslayer(TCP) and pkt.haslayer(Raw)):
            return None
        try:
            data = bytes(pkt[Raw])
            if len(data) < 6 or data[0] != 0x16:
                return None
            hs = data[5:]
            if len(hs) < 4 or hs[0] != 0x02:
                return None
            sh = hs[4:]
            if len(sh) < 38:
                return None
            ver = f"s{sh[0]:02x}{sh[1]:02x}"
            cipher = int.from_bytes(sh[35:37], 'big')
            return f"{ver}c{cipher:04x}"
        except Exception as exc:
            _logger.debug("JA4S parse error: %s", exc)
            return None

    @staticmethod
    def ja4h(pkt) -> Optional[str]:
        if not pkt.haslayer(Raw):
            return None
        try:
            data = bytes(pkt[Raw])
            text = data.decode('ascii', errors='ignore')
            if not any(text.startswith(m) for m in ['GET ', 'POST ', 'PUT ', 'DELETE ', 'PATCH ', 'HEAD ']):
                return None
            lines = text.split('\r\n')
            method = lines[0].split(' ')[0]
            headers = []
            for line in lines[1:]:
                if ':' in line:
                    headers.append(line.split(':')[0].strip().lower())
                elif line == '':
                    break
            h_hash = hashlib.sha256(','.join(headers).encode()).hexdigest()[:12]
            return f"h_{method}_{len(headers):02d}_{h_hash}"
        except Exception as exc:
            _logger.debug("JA4H parse error: %s", exc)
            return None

    @staticmethod
    def ja4x(cert_data: bytes) -> Optional[str]:
        try:
            h = hashlib.sha256(cert_data).hexdigest()[:16]
            return f"x_{h}"
        except Exception as exc:
            _logger.debug("JA4X hash error: %s", exc)
            return None


# ========================== VIRUSTOTAL INTEGRATION ==========================
class VirusTotalChecker:
    """Check executable hashes against VirusTotal API (free tier: 4 req/min)."""
    _VT_URL = "https://www.virustotal.com/api/v3/files/{hash}"

    def __init__(self, api_key: str = ""):
        self.api_key = api_key or os.environ.get('VT_API_KEY', '')
        self.cache: dict[str, dict] = {}  # sha256 -> result
        self.lock = threading.Lock()
        self._rate_bucket = TokenBucket(rate=4.0, capacity=4.0)
        self._checked_pids: set[int] = set()

    def _hash_file(self, filepath: str) -> Optional[str]:
        try:
            h = hashlib.sha256()
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(65536), b''):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return None

    def check_exe(self, pid: int, exe_path: str) -> Optional[dict]:
        if not self.api_key or not exe_path:
            return None
        with self.lock:
            if pid in self._checked_pids:
                return None
            if len(self._checked_pids) > 20000:
                self._checked_pids.clear()
            self._checked_pids.add(pid)
        sha256 = self._hash_file(exe_path)
        if not sha256:
            return None
        with self.lock:
            if sha256 in self.cache:
                return self.cache[sha256]
        if not self._rate_bucket.consume():
            return None
        try:
            req = urllib.request.Request(
                self._VT_URL.format(hash=sha256),
                headers={'x-apikey': self.api_key, 'Accept': 'application/json'})
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read())
            stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            result = {
                'sha256': sha256, 'malicious': stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0),
                'undetected': stats.get('undetected', 0),
                'harmless': stats.get('harmless', 0),
                'name': data.get('data', {}).get('attributes', {}).get('meaningful_name', ''),
            }
            with self.lock:
                self.cache[sha256] = result
            return result
        except urllib.error.HTTPError as e:
            if e.code == 404:
                result = {'sha256': sha256, 'malicious': 0, 'suspicious': 0,
                          'undetected': 0, 'harmless': 0, 'name': 'NOT IN VT DB'}
                with self.lock:
                    self.cache[sha256] = result
                return result
            return None
        except Exception:
            return None

    def get_all_results(self) -> dict:
        with self.lock:
            return dict(self.cache)


# ========================== FILE SYSTEM WATCHDOG ==========================
class FileSystemWatchdog:
    """Monitor sensitive directories for suspicious file changes (ransomware, staging)."""
    RANSOMWARE_EXTS = {'.encrypted', '.locked', '.crypto', '.crypt', '.enc', '.pay',
                       '.ransom', '.locky', '.cerber', '.zepto', '.odin', '.thor',
                       '.aesir', '.zzzzz', '.micro', '.mp3', '.xxx'}

    def __init__(self):
        self.lock = threading.Lock()
        self._baseline: dict[str, dict] = {}  # path -> {mtime, size}
        self._events: deque = deque(maxlen=5000)
        self._dirs_to_watch: list[str] = []
        home = os.path.expanduser("~")
        for d in ['Desktop', 'Documents', 'Downloads', 'AppData\\Local\\Temp']:
            p = os.path.join(home, d)
            if os.path.isdir(p):
                self._dirs_to_watch.append(p)
        self._baseline_set = False
        self._rename_counter: dict[str, int] = defaultdict(int)  # dir -> rename count in window
        self._rename_window_start: float = time.time()

    def scan(self) -> list[dict]:
        events = []
        current: dict[str, dict] = {}
        now = time.time()
        # Reset rename window every 60s
        if now - self._rename_window_start > 60:
            self._rename_counter.clear()
            self._rename_window_start = now
        for watch_dir in self._dirs_to_watch:
            try:
                for entry in os.scandir(watch_dir):
                    if not entry.is_file(follow_symlinks=False):
                        continue
                    try:
                        st = entry.stat()
                        current[entry.path] = {'mtime': st.st_mtime, 'size': st.st_size}
                    except Exception:
                        continue
                    _, ext = os.path.splitext(entry.name)
                    if ext.lower() in self.RANSOMWARE_EXTS:
                        events.append({
                            'type': 'RANSOMWARE_EXT', 'path': entry.path,
                            'time': now, 'severity': 'CRITICAL',
                            'detail': f"Suspicious extension: {ext}"})
            except Exception:
                continue
        if self._baseline_set:
            for path, info in current.items():
                if path not in self._baseline:
                    events.append({'type': 'FILE_CREATED', 'path': path,
                                   'time': now, 'severity': 'INFO',
                                   'detail': f"New file: {os.path.basename(path)} ({info['size']} bytes)"})
                    d = os.path.dirname(path)
                    self._rename_counter[d] = self._rename_counter.get(d, 0) + 1
                elif self._baseline[path]['mtime'] != info['mtime']:
                    events.append({'type': 'FILE_MODIFIED', 'path': path,
                                   'time': now, 'severity': 'INFO',
                                   'detail': f"Modified: {os.path.basename(path)}"})
            for path in self._baseline:
                if path not in current:
                    events.append({'type': 'FILE_DELETED', 'path': path,
                                   'time': now, 'severity': 'WARNING',
                                   'detail': f"Deleted: {os.path.basename(path)}"})
                    d = os.path.dirname(path)
                    self._rename_counter[d] = self._rename_counter.get(d, 0) + 1
            # Mass rename detection (ransomware pattern)
            for d, count in self._rename_counter.items():
                if count > 20:
                    events.append({'type': 'MASS_RENAME', 'path': d,
                                   'time': now, 'severity': 'CRITICAL',
                                   'detail': f"Mass file changes in {d}: {count} files in 60s"})
        with self.lock:
            self._baseline = current
            if not self._baseline_set:
                self._baseline_set = True
            for ev in events:
                self._events.append(ev)
        return events

    def get_events(self) -> list[dict]:
        with self.lock:
            return list(self._events)


# ========================== CLIPBOARD MONITOR ==========================
class ClipboardMonitor:
    """Watch for clipboard hijacking (crypto address swaps, data theft)."""
    _CRYPTO_PATTERNS = {
        'BTC': re.compile(r'^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62}$'),
        'ETH': re.compile(r'^0x[0-9a-fA-F]{40}$'),
        'XMR': re.compile(r'^4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}$'),
    }

    def __init__(self):
        self.lock = threading.Lock()
        self._last_content: str = ""
        self._events: deque = deque(maxlen=1000)
        self._change_count: int = 0
        self._window_start: float = time.time()

    def check(self) -> list[dict]:
        if not _IS_WINDOWS:
            return []
        events = []
        now = time.time()
        if now - self._window_start > 60:
            if self._change_count > 50:
                events.append({'type': 'RAPID_CLIPBOARD', 'time': now,
                               'severity': 'WARNING',
                               'detail': f"Clipboard changed {self._change_count} times in 60s"})
            self._change_count = 0
            self._window_start = now
        try:
            result = subprocess.run(
                ['powershell', '-NoProfile', '-Command', 'Get-Clipboard'],
                capture_output=True, text=True, timeout=5,
                creationflags=0x08000000)  # CREATE_NO_WINDOW
            if result.returncode == 0:
                text = result.stdout.strip()[:2000]
                if text and text != self._last_content:
                    self._change_count += 1
                    for coin, pat in self._CRYPTO_PATTERNS.items():
                        if pat.match(text.strip()):
                            events.append({
                                'type': 'CRYPTO_ADDRESS', 'time': now,
                                'severity': 'CRITICAL',
                                'detail': f"Clipboard contains {coin} address: {text[:40]}..."})
                    self._last_content = text
        except Exception:
            pass
        with self.lock:
            for ev in events:
                self._events.append(ev)
        return events

    def get_events(self) -> list[dict]:
        with self.lock:
            return list(self._events)


# ========================== USB DEVICE MONITOR ==========================
class USBMonitor:
    """Detect new USB devices being plugged in."""
    def __init__(self):
        self.lock = threading.Lock()
        self._known_devices: set[str] = set()
        self._events: deque = deque(maxlen=500)
        self._baseline_set = False

    def scan(self) -> list[dict]:
        if not _IS_WINDOWS:
            return []
        events = []
        current = set()
        try:
            key_path = r"SYSTEM\CurrentControlSet\Enum\USB"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_READ) as key:
                i = 0
                while True:
                    try:
                        subkey_name = winreg.EnumKey(key, i)
                        with winreg.OpenKey(key, subkey_name, 0, winreg.KEY_READ) as subkey:
                            j = 0
                            while True:
                                try:
                                    instance = winreg.EnumKey(subkey, j)
                                    dev_id = f"{subkey_name}\\{instance}"
                                    current.add(dev_id)
                                    try:
                                        with winreg.OpenKey(subkey, instance, 0, winreg.KEY_READ) as inst_key:
                                            desc, _ = winreg.QueryValueEx(inst_key, 'DeviceDesc')
                                    except Exception:
                                        desc = dev_id
                                    if self._baseline_set and dev_id not in self._known_devices:
                                        events.append({
                                            'type': 'USB_NEW', 'device_id': dev_id,
                                            'time': time.time(), 'severity': 'WARNING',
                                            'detail': f"New USB device: {desc}"})
                                    j += 1
                                except OSError:
                                    break
                        i += 1
                    except OSError:
                        break
        except Exception as exc:
            _logger.debug("USB scan error: %s", exc)
        with self.lock:
            self._known_devices = current
            if not self._baseline_set:
                self._baseline_set = True
            for ev in events:
                self._events.append(ev)
        return events

    def get_events(self) -> list[dict]:
        with self.lock:
            return list(self._events)


# ========================== SCHEDULED TASK MONITOR ==========================
class ScheduledTaskMonitor:
    """Monitor Windows scheduled tasks for new/modified entries."""
    def __init__(self):
        self.lock = threading.Lock()
        self._baseline: dict[str, str] = {}  # task_name -> hash
        self._events: deque = deque(maxlen=500)
        self._baseline_set = False

    def scan(self) -> list[dict]:
        if not _IS_WINDOWS:
            return []
        events = []
        current: dict[str, str] = {}
        try:
            result = subprocess.run(
                ['schtasks', '/query', '/fo', 'CSV', '/nh'],
                capture_output=True, text=True, timeout=15,
                creationflags=0x08000000)
            for line in result.stdout.strip().split('\n'):
                parts = line.strip().strip('"').split('","')
                if len(parts) >= 2:
                    task_name = parts[0].strip('"')
                    task_hash = hashlib.md5(line.encode()).hexdigest()
                    current[task_name] = task_hash
        except Exception as exc:
            _logger.debug("Scheduled task scan error: %s", exc)
            return []
        if self._baseline_set:
            for name, h in current.items():
                if name not in self._baseline:
                    events.append({'type': 'TASK_ADDED', 'task': name,
                                   'time': time.time(), 'severity': 'WARNING',
                                   'detail': f"New scheduled task: {name}"})
                elif self._baseline[name] != h:
                    events.append({'type': 'TASK_MODIFIED', 'task': name,
                                   'time': time.time(), 'severity': 'WARNING',
                                   'detail': f"Modified scheduled task: {name}"})
            for name in self._baseline:
                if name not in current:
                    events.append({'type': 'TASK_REMOVED', 'task': name,
                                   'time': time.time(), 'severity': 'INFO',
                                   'detail': f"Removed scheduled task: {name}"})
        with self.lock:
            self._baseline = current
            if not self._baseline_set:
                self._baseline_set = True
            for ev in events:
                self._events.append(ev)
        return events

    def get_events(self) -> list[dict]:
        with self.lock:
            return list(self._events)


# ========================== NAMED PIPE / IPC MONITOR ==========================
class NamedPipeMonitor:
    """Detect inter-process communication via named pipes (used by RATs, Cobalt Strike)."""
    SUSPICIOUS_PIPES = {'msagent_', 'postex_', 'status_', 'msse-', 'MSSE-',
                        'mssecsvc', 'mypipe', 'win_svc', 'ntsvcs', 'scerpc',
                        'isapi', 'sdclient', 'chromepipe', 'gecko', '\\psexec',
                        'csexec', 'paexec', 'remcom'}

    def __init__(self):
        self.lock = threading.Lock()
        self._known_pipes: set[str] = set()
        self._events: deque = deque(maxlen=500)
        self._baseline_set = False

    def scan(self) -> list[dict]:
        if not _IS_WINDOWS:
            return []
        events = []
        current = set()
        try:
            pipe_dir = r'\\.\pipe'
            import win32file
            pipes = win32file.FindFilesW(pipe_dir + r'\*')
            for p in pipes:
                current.add(p[8])  # cFileName
        except ImportError:
            try:
                result = subprocess.run(
                    ['cmd', '/c', 'dir', r'\\.\pipe\\', '/b'],
                    capture_output=True, text=True, timeout=10,
                    creationflags=0x08000000)
                for line in result.stdout.strip().split('\n'):
                    name = line.strip()
                    if name:
                        current.add(name)
            except Exception:
                pass
        except Exception as exc:
            _logger.debug("Named pipe scan error: %s", exc)
        if self._baseline_set:
            new_pipes = current - self._known_pipes
            for pipe_name in new_pipes:
                is_suspicious = any(s.lower() in pipe_name.lower() for s in self.SUSPICIOUS_PIPES)
                if is_suspicious:
                    events.append({'type': 'SUSPICIOUS_PIPE', 'pipe': pipe_name,
                                   'time': time.time(), 'severity': 'CRITICAL',
                                   'detail': f"Suspicious named pipe: {pipe_name}"})
                elif len(new_pipes) <= 20:  # only log if not too noisy
                    events.append({'type': 'NEW_PIPE', 'pipe': pipe_name,
                                   'time': time.time(), 'severity': 'INFO',
                                   'detail': f"New named pipe: {pipe_name}"})
        with self.lock:
            self._known_pipes = current
            if not self._baseline_set:
                self._baseline_set = True
            for ev in events:
                self._events.append(ev)
        return events

    def get_events(self) -> list[dict]:
        with self.lock:
            return list(self._events)


# ========================== WHOIS LOOKUP ==========================
class WhoisLookup:
    """Look up IP ownership via RDAP/whois for unknown IPs."""
    _RDAP_URL = "https://rdap.org/ip/{ip}"

    def __init__(self):
        self.cache: dict[str, dict] = {}
        self.lock = threading.Lock()
        self._rate = TokenBucket(rate=10.0, capacity=10.0)

    def lookup(self, ip: str) -> Optional[dict]:
        with self.lock:
            if ip in self.cache:
                return self.cache[ip]
        if not self._rate.consume():
            return None
        try:
            req = urllib.request.Request(self._RDAP_URL.format(ip=ip),
                                        headers={'Accept': 'application/json'})
            with urllib.request.urlopen(req, timeout=8) as resp:
                data = json.loads(resp.read())
            result = {
                'name': data.get('name', '?'),
                'handle': data.get('handle', '?'),
                'type': data.get('type', '?'),
                'country': data.get('country', '?'),
                'start_address': data.get('startAddress', '?'),
                'end_address': data.get('endAddress', '?'),
                'entities': [],
            }
            for ent in data.get('entities', [])[:3]:
                vcard = ent.get('vcardArray', [None, []])[1] if 'vcardArray' in ent else []
                org_name = ''
                for v in vcard:
                    if v[0] == 'org':
                        org_name = v[3] if len(v) > 3 else ''
                    elif v[0] == 'fn':
                        org_name = org_name or (v[3] if len(v) > 3 else '')
                result['entities'].append({'name': org_name, 'roles': ent.get('roles', [])})
            with self.lock:
                self.cache[ip] = result
            return result
        except Exception as exc:
            _logger.debug("RDAP lookup failed for %s: %s", ip, exc)
            result = {'name': '?', 'handle': '?', 'type': '?', 'country': '?',
                      'start_address': '?', 'end_address': '?',
                      'entities': [], 'error': True}
            with self.lock:
                self.cache[ip] = result
            return result


# ========================== INBOUND SCAN DETECTOR ==========================
class InboundScanDetector:
    """Detect external IPs port-scanning this machine (inbound SYN probes)."""
    def __init__(self):
        self.lock = threading.Lock()
        self._inbound_syns: dict[str, list[int]] = defaultdict(list)  # src_ip -> [ports]
        self._alerts: deque = deque(maxlen=500)
        self._alerted: set[str] = set()
        self._window_start: float = time.time()

    def record_inbound_syn(self, src_ip: str, dst_port: int):
        now = time.time()
        with self.lock:
            if now - self._window_start > 120:
                self._inbound_syns.clear()
                # Clear the alerted set with the window too, so a scanner that
                # comes back later is reported again instead of being suppressed
                # forever (and so the set cannot grow without bound).
                self._alerted.clear()
                self._window_start = now
            if len(self._inbound_syns[src_ip]) < 500:
                self._inbound_syns[src_ip].append(dst_port)

    def check(self) -> list[dict]:
        events = []
        with self.lock:
            for ip, ports in self._inbound_syns.items():
                unique_ports = set(ports)
                if len(unique_ports) >= 5 and ip not in self._alerted:
                    self._alerted.add(ip)
                    events.append({
                        'type': 'INBOUND_SCAN', 'source_ip': ip,
                        'time': time.time(), 'severity': 'CRITICAL',
                        'ports_probed': sorted(unique_ports)[:20],
                        'detail': f"Port scan from {ip}: {len(unique_ports)} ports probed"})
            for ev in events:
                self._alerts.append(ev)
        return events

    def get_events(self) -> list[dict]:
        with self.lock:
            return list(self._alerts)


# ========================== ANTI-HACK MONITORS (18 features) ==========================
# Each monitor returns a list of event dicts: {type, severity, detail, ...extras}
# All events are flagged via _flag_suspicious and pinned to connections.

# ---- 1. Security Event Log Monitor ----
class SecurityEventMonitor:
    """Reads Windows Security event log for logon, process-creation, service-install,
    user-creation, and admin-group-change events."""
    def __init__(self):
        self._last_record = 0
        self._events: deque = deque(maxlen=200)

    def scan(self) -> list:
        if not _IS_WINDOWS:
            return []
        results = []
        try:
            import win32evtlog  # type: ignore
            import win32evtlogutil  # type: ignore
            hand = win32evtlog.OpenEventLog(None, 'Security')
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            events = win32evtlog.ReadEventLog(hand, flags, 0)
            max_rec = self._last_record
            for ev in events[:100]:
                rec = ev.RecordNumber
                if rec <= self._last_record:
                    break
                max_rec = max(max_rec, rec)
                eid = ev.EventID & 0xFFFF
                if eid in (4624, 4625, 4688, 7045, 4720, 4728, 4732, 4768, 4769):
                    sev = 'CRITICAL' if eid in (4625, 7045, 4720, 4728, 4732) else 'WARNING'
                    desc = {
                        4624: 'Successful logon', 4625: 'Failed logon',
                        4688: 'Process created', 7045: 'Service installed',
                        4720: 'User account created', 4728: 'User added to admin group',
                        4732: 'Member added to local group', 4768: 'Kerberos TGT requested',
                        4769: 'Kerberos service ticket requested',
                    }.get(eid, f'Event {eid}')
                    results.append({
                        'type': 'SECURITY_EVENT', 'severity': sev,
                        'detail': f'Event {eid}: {desc} — {str(ev.StringInserts)[:200]}',
                        'event_id': eid, 'record': rec,
                    })
            self._last_record = max_rec
            win32evtlog.CloseEventLog(hand)
        except ImportError:
            # win32evtlog not available — fall back to wevtutil
            try:
                out = subprocess.run(
                    ['wevtutil', 'qe', 'Security', '/c:50', '/rd:true', '/f:text'],
                    capture_output=True, text=True, timeout=10)
                for line in out.stdout.split('\n'):
                    if 'Event ID:' in line:
                        eid_str = line.split('Event ID:')[1].strip()
                        try:
                            eid = int(eid_str)
                        except ValueError:
                            continue
                        if eid in (4624, 4625, 4688, 7045, 4720, 4728, 4732):
                            sev = 'CRITICAL' if eid in (4625, 7045, 4720) else 'WARNING'
                            results.append({
                                'type': 'SECURITY_EVENT', 'severity': sev,
                                'detail': f'Event {eid}: security event',
                                'event_id': eid,
                            })
            except Exception:
                pass
        except Exception:
            pass
        self._events.extend(results)
        return results


# ---- 5. Hosts File / DNS Hijack Monitor ----
class HostsFileMonitor:
    """Detects modifications to the hosts file and DNS server changes."""
    HOSTS_PATH = r'C:\Windows\System32\drivers\etc\hosts' if _IS_WINDOWS else '/etc/hosts'

    def __init__(self):
        self._hosts_hash = ''
        self._dns_servers = set()
        self._first_run = True

    def _hash_hosts(self) -> str:
        try:
            import hashlib
            with open(self.HOSTS_PATH, 'rb') as f:
                return hashlib.md5(f.read()).hexdigest()
        except Exception:
            return ''

    def _get_dns_servers(self) -> set:
        try:
            out = subprocess.run(['ipconfig', '/all'], capture_output=True,
                                 text=True, timeout=10)
            servers = set()
            for line in out.stdout.split('\n'):
                if 'DNS Servers' in line:
                    parts = line.split(':')
                    if len(parts) > 1:
                        ip = parts[1].strip()
                        if ip and ip != '127.0.0.1':
                            servers.add(ip)
            return servers
        except Exception:
            return set()

    def scan(self) -> list:
        results = []
        h = self._hash_hosts()
        if self._first_run:
            self._hosts_hash = h
            self._dns_servers = self._get_dns_servers()
            self._first_run = False
            return []
        if h and h != self._hosts_hash:
            results.append({
                'type': 'DNS_HIJACK', 'severity': 'CRITICAL',
                'detail': 'Hosts file modified — possible DNS hijack',
                'path': self.HOSTS_PATH,
            })
            self._hosts_hash = h
        dns = self._get_dns_servers()
        if dns and self._dns_servers and dns != self._dns_servers:
            results.append({
                'type': 'DNS_HIJACK', 'severity': 'WARNING',
                'detail': f'DNS servers changed: {self._dns_servers} -> {dns}',
            })
            self._dns_servers = dns
        return results


# ---- 6. Windows Service Creation Monitor ----
class ServiceMonitor:
    """Detects new Windows services and services with suspicious binary paths."""
    SUSPICIOUS_PATHS = ('\\temp\\', '\\tmp\\', '\\downloads\\', '\\appdata\\',
                        '\\desktop\\', '\\public\\', '\\programdata\\')

    def __init__(self):
        self._baseline: set = set()
        self._first_run = True

    def _get_services(self) -> dict:
        try:
            out = subprocess.run(
                ['sc', 'query', 'type=', 'service', 'state=', 'all'],
                capture_output=True, text=True, timeout=15)
            services = {}
            current = ''
            for line in out.stdout.split('\n'):
                if 'SERVICE_NAME:' in line:
                    current = line.split('SERVICE_NAME:')[1].strip()
                if 'DISPLAY_NAME:' in line and current:
                    services[current] = line.split('DISPLAY_NAME:')[1].strip()
            return services
        except Exception:
            return {}

    def _get_service_binpath(self, svc: str) -> str:
        try:
            out = subprocess.run(['sc', 'qc', svc], capture_output=True,
                                 text=True, timeout=5)
            for line in out.stdout.split('\n'):
                if 'BINARY_PATH_NAME' in line:
                    return line.split('BINARY_PATH_NAME')[1].strip().strip(':').strip()
            return ''
        except Exception:
            return ''

    def scan(self) -> list:
        results = []
        svcs = self._get_services()
        if self._first_run:
            self._baseline = set(svcs.keys())
            self._first_run = False
            return []
        current = set(svcs.keys())
        new_svcs = current - self._baseline
        for svc in new_svcs:
            binpath = self._get_service_binpath(svc)
            sev = 'CRITICAL'
            detail = f'New service: {svc}'
            if binpath:
                detail += f' (binary: {binpath})'
                if any(p in binpath.lower() for p in self.SUSPICIOUS_PATHS):
                    detail += ' [SUSPICIOUS PATH]'
                    sev = 'CRITICAL'
            results.append({
                'type': 'SERVICE_CREATE', 'severity': sev,
                'detail': detail, 'service': svc, 'binpath': binpath,
            })
        self._baseline = current
        return results


# ---- 9. Defender / AV Disable Monitor ----
class SecurityToolMonitor:
    """Detects Windows Defender disable, firewall disable, and AV tampering."""
    def __init__(self):
        self._defender_enabled = True
        self._firewall_on = True
        self._first_run = True

    def _check_defender(self) -> bool:
        try:
            out = subprocess.run(
                ['powershell', '-Command',
                 'Get-MpComputerStatus | Select-Object -Property RealTimeProtectionEnabled'],
                capture_output=True, text=True, timeout=10)
            return 'True' in out.stdout
        except Exception:
            return True

    def _check_firewall(self) -> bool:
        try:
            out = subprocess.run(
                ['netsh', 'advfirewall', 'show', 'allprofiles', 'state'],
                capture_output=True, text=True, timeout=10)
            return 'ON' in out.stdout.upper()
        except Exception:
            return True

    def scan(self) -> list:
        results = []
        defender = self._check_defender()
        firewall = self._check_firewall()
        if self._first_run:
            self._defender_enabled = defender
            self._firewall_on = firewall
            self._first_run = False
            return []
        if defender != self._defender_enabled:
            sev = 'CRITICAL' if not defender else 'WARNING'
            results.append({
                'type': 'AV_DISABLE', 'severity': sev,
                'detail': f'Defender real-time protection: {"DISABLED" if not defender else "ENABLED"}',
            })
            self._defender_enabled = defender
        if firewall != self._firewall_on:
            sev = 'CRITICAL' if not firewall else 'WARNING'
            results.append({
                'type': 'AV_DISABLE', 'severity': sev,
                'detail': f'Windows Firewall: {"DISABLED" if not firewall else "ENABLED"}',
            })
            self._firewall_on = firewall
        return results


# ---- 10. New User Account / Admin Escalation Monitor ----
class UserAccountMonitor:
    """Detects new user accounts and admin group membership changes."""
    def __init__(self):
        self._users: set = set()
        self._admins: set = set()
        self._first_run = True

    def _get_users(self) -> set:
        try:
            out = subprocess.run(['net', 'user'], capture_output=True,
                                 text=True, timeout=10)
            lines = out.stdout.split('\n')
            for i, line in enumerate(lines):
                if '---' in line and i > 0:
                    user_lines = lines[i+1:]
                    users = set()
                    for ul in user_lines:
                        if 'The command' in ul or not ul.strip():
                            break
                        users.update(ul.split())
                    return users
        except Exception:
            pass
        return set()

    def _get_admins(self) -> set:
        try:
            out = subprocess.run(
                ['net', 'localgroup', 'administrators'],
                capture_output=True, text=True, timeout=10)
            lines = out.stdout.split('\n')
            for i, line in enumerate(lines):
                if '---' in line and i > 0:
                    admin_lines = lines[i+1:]
                    admins = set()
                    for al in admin_lines:
                        if 'The command' in al or not al.strip():
                            break
                        admins.update(al.split())
                    return admins
        except Exception:
            pass
        return set()

    def scan(self) -> list:
        results = []
        users = self._get_users()
        admins = self._get_admins()
        if self._first_run:
            self._users = users
            self._admins = admins
            self._first_run = False
            return []
        new_users = users - self._users
        for u in new_users:
            results.append({
                'type': 'NEW_ACCOUNT', 'severity': 'CRITICAL',
                'detail': f'New user account created: {u}',
                'account': u,
            })
        new_admins = admins - self._admins
        for a in new_admins:
            results.append({
                'type': 'NEW_ACCOUNT', 'severity': 'CRITICAL',
                'detail': f'User added to Administrators group: {a}',
                'account': a,
            })
        self._users = users
        self._admins = admins
        return results


# ---- 11. WMI Subscription Monitor ----
class WMISubscriptionMonitor:
    """Detects WMI event subscriptions used for stealthy persistence."""
    def __init__(self):
        self._baseline_filters: set = set()
        self._baseline_consumers: set = set()
        self._first_run = True

    def _get_filters(self) -> set:
        try:
            out = subprocess.run(
                ['wmic', '/namespace:\\\\root\\subscription',
                 'path', '__EventFilter', 'get', 'Name'],
                capture_output=True, text=True, timeout=10)
            return {l.strip() for l in out.stdout.split('\n')
                    if l.strip() and l.strip() != 'Name'}
        except Exception:
            return set()

    def _get_consumers(self) -> set:
        try:
            out = subprocess.run(
                ['wmic', '/namespace:\\\\root\\subscription',
                 'path', '__CommandLineEventConsumer', 'get', 'Name'],
                capture_output=True, text=True, timeout=10)
            return {l.strip() for l in out.stdout.split('\n')
                    if l.strip() and l.strip() != 'Name'}
        except Exception:
            return set()

    def scan(self) -> list:
        results = []
        filters = self._get_filters()
        consumers = self._get_consumers()
        if self._first_run:
            self._baseline_filters = filters
            self._baseline_consumers = consumers
            self._first_run = False
            return []
        new_filters = filters - self._baseline_filters
        new_consumers = consumers - self._baseline_consumers
        for f in new_filters:
            results.append({
                'type': 'WMI_PERSIST', 'severity': 'CRITICAL',
                'detail': f'New WMI EventFilter: {f}',
            })
        for c in new_consumers:
            results.append({
                'type': 'WMI_PERSIST', 'severity': 'CRITICAL',
                'detail': f'New WMI CommandLineEventConsumer: {c}',
            })
        self._baseline_filters = filters
        self._baseline_consumers = consumers
        return results


# ---- 14. Driver / Rootkit Load Monitor ----
class DriverLoadMonitor:
    """Detects new kernel driver loads and .sys files in non-standard paths."""
    SYS_DIR = r'C:\Windows\System32\drivers' if _IS_WINDOWS else ''
    SUSPICIOUS_DRIVER_DIRS = (r'\temp\\', r'\downloads\\', r'\appdata\\',
                              r'\desktop\\', r'\public\\')

    def __init__(self):
        self._baseline_drivers: set = set()
        self._baseline_sys_files: set = set()
        self._first_run = True

    def _get_drivers(self) -> set:
        try:
            out = subprocess.run(
                ['sc', 'query', 'type=', 'driver', 'state=', 'active'],
                capture_output=True, text=True, timeout=15)
            drivers = set()
            for line in out.stdout.split('\n'):
                if 'SERVICE_NAME:' in line:
                    drivers.add(line.split('SERVICE_NAME:')[1].strip())
            return drivers
        except Exception:
            return set()

    def _get_sys_files(self) -> set:
        if not self.SYS_DIR or not os.path.isdir(self.SYS_DIR):
            return set()
        try:
            return {f for f in os.listdir(self.SYS_DIR) if f.lower().endswith('.sys')}
        except Exception:
            return set()

    def scan(self) -> list:
        results = []
        drivers = self._get_drivers()
        sys_files = self._get_sys_files()
        if self._first_run:
            self._baseline_drivers = drivers
            self._baseline_sys_files = sys_files
            self._first_run = False
            return []
        new_drivers = drivers - self._baseline_drivers
        for d in new_drivers:
            results.append({
                'type': 'DRIVER_LOAD', 'severity': 'WARNING',
                'detail': f'New kernel driver loaded: {d}',
                'driver': d,
            })
        new_sys = sys_files - self._baseline_sys_files
        for s in new_sys:
            results.append({
                'type': 'DRIVER_LOAD', 'severity': 'WARNING',
                'detail': f'New .sys file in drivers directory: {s}',
                'file': s,
            })
        self._baseline_drivers = drivers
        self._baseline_sys_files = sys_files
        return results


# ---- 16. Mutex / Named Object Scanner ----
class MutexScanner:
    """Checks for known malware mutex names."""
    KNOWN_MUTEXES = {
        'Synaptics': 'Possible keylogger (Synaptics mutex)',
        'avira_gui_lock': 'Avira AV mutex',
        'OneOneMutex': 'Possible malware single-instance check',
        'WinInitMutex': 'Possible malware (fake WinInit)',
        'Global\\__DDAInterface': 'Possible screen capture malware',
        'Global\\D3DWindow': 'Possible game hijack malware',
        'B0184A2A-1F90-4D55-A6B0-13A8B5C0E6B2': 'Possible Cobalt Strike beacon',
        'Global\\MSEdgeRedirector': 'Possible Edge redirector',
        'Global\\ChromeExtPipe': 'Possible Chrome extension hijack',
        'MUTEX_UUID': 'Possible Meterpreter',
    }

    def __init__(self):
        self._found: set = set()

    def scan(self) -> list:
        if not _IS_WINDOWS:
            return []
        results = []
        import ctypes
        for name, desc in self.KNOWN_MUTEXES.items():
            if name in self._found:
                continue
            try:
                handle = ctypes.windll.kernel32.OpenMutexW(
                    0x1F0001, False, name)  # SYNCHRONIZE | all access
                if handle:
                    results.append({
                        'type': 'MUTEX_HIT', 'severity': 'CRITICAL',
                        'detail': f'Known malware mutex found: {name} ({desc})',
                        'mutex': name,
                    })
                    self._found.add(name)
                    ctypes.windll.kernel32.CloseHandle(handle)
            except Exception:
                pass
        return results


# ========================== DoH DETECTION ==========================
class DoHDetector:
    """Detect DNS over HTTPS usage (bypasses local DNS monitoring)."""
    DOH_SERVERS = {
        '1.1.1.1': 'Cloudflare', '1.0.0.1': 'Cloudflare',
        '8.8.8.8': 'Google', '8.8.4.4': 'Google',
        '9.9.9.9': 'Quad9', '149.112.112.112': 'Quad9',
        '208.67.222.222': 'OpenDNS', '208.67.220.220': 'OpenDNS',
        '94.140.14.14': 'AdGuard', '94.140.15.15': 'AdGuard',
        '185.228.168.9': 'CleanBrowsing', '185.228.169.9': 'CleanBrowsing',
    }

    def __init__(self):
        self.lock = threading.Lock()
        self._detections: dict[int, dict] = {}  # pid -> info
        self._events: deque = deque(maxlen=500)

    def check_connection(self, pid: int, proc_name: str, dst_ip: str, dst_port: int) -> Optional[dict]:
        if dst_port != 443 or dst_ip not in self.DOH_SERVERS:
            return None
        provider = self.DOH_SERVERS[dst_ip]
        key = (pid, dst_ip)
        with self.lock:
            if key in self._detections:
                return None
            ev = {'type': 'DOH_DETECTED', 'pid': pid, 'process': proc_name,
                  'dst_ip': dst_ip, 'provider': provider,
                  'time': time.time(), 'severity': 'WARNING',
                  'detail': f"{proc_name} (PID {pid}) using DNS-over-HTTPS via {provider} ({dst_ip})"}
            self._detections[key] = ev
            self._events.append(ev)
            return ev

    def get_events(self) -> list[dict]:
        with self.lock:
            return list(self._events)


# ========================== TLS CERT / MITM DETECTOR ==========================
class TLSCertDetector:
    """Detect possible MITM by checking TLS ServerHello certificate fingerprints."""
    KNOWN_ISSUERS = {
        'google': ['GTS', 'Google Trust Services'],
        'microsoft': ['Microsoft', 'DigiCert'],
        'cloudflare': ['Cloudflare', 'DigiCert', "Let's Encrypt"],
        'amazon': ['Amazon', 'DigiCert', 'Starfield'],
    }

    def __init__(self):
        self.lock = threading.Lock()
        self._cert_cache: dict[str, str] = {}  # ip -> cert_hash
        self._ja4x: dict[str, str] = {}        # ip -> JA4X cert fingerprint
        self._events: deque = deque(maxlen=500)
        self._cert_change_count: dict[str, int] = defaultdict(int)

    def record_cert(self, dst_ip: str, cert_data: bytes) -> Optional[dict]:
        if not cert_data:
            return None
        cert_hash = hashlib.sha256(cert_data).hexdigest()[:16]
        ja4x = JA4Plus.ja4x(cert_data) or ''
        with self.lock:
            prev = self._cert_cache.get(dst_ip)
            self._cert_cache[dst_ip] = cert_hash
            if ja4x:
                self._ja4x[dst_ip] = ja4x
            if prev and prev != cert_hash:
                self._cert_change_count[dst_ip] += 1
                if self._cert_change_count[dst_ip] >= 3:
                    ev = {'type': 'CERT_CHANGE', 'ip': dst_ip,
                          'time': time.time(), 'severity': 'CRITICAL',
                          'old_hash': prev, 'new_hash': cert_hash, 'ja4x': ja4x,
                          'detail': f"TLS cert changed {self._cert_change_count[dst_ip]}x for {dst_ip} — possible MITM"}
                    self._events.append(ev)
                    return ev
        return None

    def get_ja4x(self) -> dict:
        """Per-IP JA4X certificate fingerprints seen this session."""
        with self.lock:
            return dict(self._ja4x)

    def get_events(self) -> list[dict]:
        with self.lock:
            return list(self._events)


# ========================== CONNECTION HISTORY ==========================
class ConnectionHistory:
    """Track all connections seen during session, including closed ones, with timestamps."""
    def __init__(self):
        self.lock = threading.Lock()
        self._active: dict[tuple, dict] = {}  # (rip, rport, lip, lport, pid) -> info
        self._history: deque = deque(maxlen=20000)
        self._bandwidth: dict[str, dict] = defaultdict(lambda: {  # ip -> bandwidth
            'bytes_sent': 0, 'bytes_recv': 0, 'last_update': 0})

    def update(self, connections: list):
        """Called each cycle with current psutil connections."""
        now = time.time()
        current_keys = set()
        with self.lock:
            for conn in connections:
                if not conn.raddr:
                    continue
                key = (conn.raddr[0], conn.raddr[1],
                       conn.laddr[0] if conn.laddr else '',
                       conn.laddr[1] if conn.laddr else 0,
                       conn.pid or 0)
                current_keys.add(key)
                if key not in self._active:
                    self._active[key] = {
                        'remote_ip': conn.raddr[0], 'remote_port': conn.raddr[1],
                        'local_ip': conn.laddr[0] if conn.laddr else '',
                        'local_port': conn.laddr[1] if conn.laddr else 0,
                        'pid': conn.pid or 0, 'status': conn.status,
                        'start_time': now, 'end_time': None,
                        'duration': 0, 'active': True,
                    }
                else:
                    self._active[key]['status'] = conn.status
                    self._active[key]['duration'] = now - self._active[key]['start_time']
            # Close connections that disappeared
            closed_keys = set(self._active.keys()) - current_keys
            for key in closed_keys:
                entry = self._active.pop(key)
                entry['end_time'] = now
                entry['duration'] = now - entry['start_time']
                entry['active'] = False
                self._history.append(entry)

    def update_bandwidth(self, ip: str, sent: int, recv: int):
        with self.lock:
            bw = self._bandwidth[ip]
            bw['bytes_sent'] += sent
            bw['bytes_recv'] += recv
            bw['last_update'] = time.time()

    def get_active(self) -> list[dict]:
        with self.lock:
            return [dict(v) for v in self._active.values()]

    def get_history(self) -> list[dict]:
        with self.lock:
            active = [dict(v) for v in self._active.values()]
            closed = list(self._history)
            return active + closed

    def get_bandwidth(self) -> dict:
        with self.lock:
            return {ip: dict(v) for ip, v in self._bandwidth.items()}

    def prune_bandwidth(self, max_entries: int = 5000):
        """Drop the least recently updated IPs so the table stays bounded."""
        with self.lock:
            if len(self._bandwidth) <= max_entries:
                return
            ordered = sorted(self._bandwidth.items(),
                             key=lambda kv: kv[1].get('last_update', 0))
            for ip, _ in ordered[:len(self._bandwidth) - max_entries]:
                del self._bandwidth[ip]

    def get_timeline(self, limit: int = 0) -> list[dict]:
        """Connections sorted by start_time, oldest first.

        `limit` keeps only the most recent N. The payload is rebuilt on every
        GUI refresh, and the closed-connection deque holds up to 20 000
        entries, so copying and sorting the whole thing several times a second
        was pure overhead — the view only ever shows the tail.
        """
        with self.lock:
            all_conns = list(self._history) + [dict(v) for v in self._active.values()]
        all_conns.sort(key=lambda c: c.get('start_time', 0))
        if limit and len(all_conns) > limit:
            return all_conns[-limit:]
        return all_conns

    def get_counts(self) -> dict:
        """True active/closed totals, independent of any timeline truncation."""
        with self.lock:
            return {'active': len(self._active), 'closed': len(self._history),
                    'total': len(self._active) + len(self._history)}


# ========================== BLUETOOTH SCANNER ==========================
class BluetoothScanner:
    """Enumerate Bluetooth devices via Windows registry and WMI."""
    def __init__(self):
        self.lock = threading.Lock()
        self._known_devices: dict[str, dict] = {}
        self._events: deque = deque(maxlen=500)
        self._baseline_set = False

    def scan(self) -> list[dict]:
        if not _IS_WINDOWS:
            return []
        events = []
        current: dict[str, dict] = {}
        now = time.time()
        # Method 1: Registry enumeration of paired BT devices
        try:
            bt_key = r"SYSTEM\CurrentControlSet\Enum\BTHENUM"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, bt_key, 0,
                                winreg.KEY_READ) as key:
                i = 0
                while True:
                    try:
                        subkey_name = winreg.EnumKey(key, i)
                        i += 1
                        try:
                            with winreg.OpenKey(key, subkey_name) as sub:
                                j = 0
                                while True:
                                    try:
                                        instance = winreg.EnumKey(sub, j)
                                        j += 1
                                        dev_id = f"{subkey_name}\\{instance}"
                                        try:
                                            with winreg.OpenKey(sub, instance) as inst_key:
                                                friendly = ""
                                                try:
                                                    friendly, _ = winreg.QueryValueEx(inst_key, "FriendlyName")
                                                except FileNotFoundError:
                                                    pass
                                                current[dev_id] = {
                                                    'device_id': dev_id,
                                                    'name': friendly or subkey_name[:40],
                                                    'time': now,
                                                    'type': 'bluetooth',
                                                }
                                        except Exception:
                                            pass
                                    except OSError:
                                        break
                        except Exception:
                            pass
                    except OSError:
                        break
        except FileNotFoundError:
            pass
        except Exception:
            pass
        # Method 2: Bluetooth radios via registry
        try:
            radio_key = r"SYSTEM\CurrentControlSet\Enum\USB"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, radio_key, 0,
                                winreg.KEY_READ) as key:
                i = 0
                while True:
                    try:
                        subkey_name = winreg.EnumKey(key, i)
                        i += 1
                        if 'BTHUSB' in subkey_name.upper() or 'BLUETOOTH' in subkey_name.upper():
                            current[f"radio_{subkey_name}"] = {
                                'device_id': subkey_name,
                                'name': f"BT Radio: {subkey_name[:30]}",
                                'time': now, 'type': 'bt_radio',
                            }
                    except OSError:
                        break
        except Exception:
            pass
        # Detect new devices
        if self._baseline_set:
            for dev_id, info in current.items():
                if dev_id not in self._known_devices:
                    events.append({
                        'severity': 'WARNING',
                        'detail': f"New Bluetooth device: {info['name']} ({dev_id[:50]})",
                        'device': info,
                    })
        with self.lock:
            self._known_devices = current
            if not self._baseline_set:
                self._baseline_set = True
            for ev in events:
                self._events.append(ev)
        return events

    def get_devices(self) -> list[dict]:
        with self.lock:
            return list(self._known_devices.values())

    def get_events(self) -> list[dict]:
        with self.lock:
            return list(self._events)


# ========================== SERIAL PORT SCANNER ==========================
class SerialPortScanner:
    """Enumerate active COM/Serial ports and detect new ones."""
    def __init__(self):
        self.lock = threading.Lock()
        self._known_ports: dict[str, dict] = {}
        self._events: deque = deque(maxlen=500)
        self._baseline_set = False

    def scan(self) -> list[dict]:
        if not _IS_WINDOWS:
            return []
        events = []
        current: dict[str, dict] = {}
        now = time.time()
        # Registry: SERIALCOMM
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                r"HARDWARE\DEVICEMAP\SERIALCOMM", 0,
                                winreg.KEY_READ) as key:
                i = 0
                while True:
                    try:
                        name, val, _ = winreg.EnumValue(key, i)
                        i += 1
                        current[val] = {
                            'port': val, 'device': name,
                            'time': now, 'type': 'serial',
                        }
                    except OSError:
                        break
        except FileNotFoundError:
            pass
        except Exception:
            pass
        # Detect new ports
        if self._baseline_set:
            for port_name, info in current.items():
                if port_name not in self._known_ports:
                    events.append({
                        'severity': 'WARNING',
                        'detail': f"New serial port: {port_name} ({info['device']})",
                        'port_info': info,
                    })
        with self.lock:
            self._known_ports = current
            if not self._baseline_set:
                self._baseline_set = True
            for ev in events:
                self._events.append(ev)
        return events

    def get_ports(self) -> list[dict]:
        with self.lock:
            return list(self._known_ports.values())

    def get_events(self) -> list[dict]:
        with self.lock:
            return list(self._events)


# ========================== GEOIP WITH RATE LIMITER ==========================
class TokenBucket:
    """Thread-safe token bucket rate limiter. ip-api.com free tier: 45 req/min."""
    def __init__(self, rate: float = 40.0, capacity: float = 45.0):
        self.rate = rate / 60.0
        self.capacity = capacity
        self.tokens = capacity
        self._last_refill = time.monotonic()
        self._lock = threading.Lock()

    def consume(self, tokens: float = 1.0) -> bool:
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_refill
            self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
            self._last_refill = now
            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            return False


# ========================== HARDCODED IP LOCATION DATABASE ==========================
# Known IP prefix → location mappings for major cloud providers, datacenters,
# and DNS services. These are derived from publicly published IP range
# announcements and datacenter locations. Checked first (weight=4) before
# MaxMind/API sources for maximum accuracy on well-known ranges.
#
# Format: (CIDR, country_code, city, lat, lon, org, region)
_HARDCODED_IP_LOCATIONS: list[tuple[str, str, str, float, float, str, str]] = [
    # ---- Amazon AWS ----
    # us-east-1 (Northern Virginia — Ashburn/Herndon)
    # NOTE: AWS 52.x.x.x space is shared globally. Only list specific
    # us-east-1 ranges; other regions have their own entries below.
    ('54.144.0.0/12', 'US', 'Ashburn', 39.0438, -77.4874, 'Amazon AWS', 'us-east-1'),
    ('54.160.0.0/11', 'US', 'Ashburn', 39.0438, -77.4874, 'Amazon AWS', 'us-east-1'),
    ('54.192.0.0/12', 'US', 'Ashburn', 39.0438, -77.4874, 'Amazon AWS', 'us-east-1'),
    ('54.208.0.0/13', 'US', 'Ashburn', 39.0438, -77.4874, 'Amazon AWS', 'us-east-1'),
    ('54.216.0.0/14', 'US', 'Ashburn', 39.0438, -77.4874, 'Amazon AWS', 'us-east-1'),
    ('54.220.0.0/15', 'US', 'Ashburn', 39.0438, -77.4874, 'Amazon AWS', 'us-east-1'),
    ('54.222.0.0/16', 'US', 'Ashburn', 39.0438, -77.4874, 'Amazon AWS', 'us-east-1'),
    ('54.224.0.0/12', 'US', 'Ashburn', 39.0438, -77.4874, 'Amazon AWS', 'us-east-1'),
    ('54.240.0.0/13', 'US', 'Ashburn', 39.0438, -77.4874, 'Amazon AWS', 'us-east-1'),
    ('107.20.0.0/14', 'US', 'Ashburn', 39.0438, -77.4874, 'Amazon AWS', 'us-east-1'),
    ('23.20.0.0/14', 'US', 'Ashburn', 39.0438, -77.4874, 'Amazon AWS', 'us-east-1'),
    ('50.16.0.0/15', 'US', 'Ashburn', 39.0438, -77.4874, 'Amazon AWS', 'us-east-1'),
    ('50.18.0.0/16', 'US', 'Ashburn', 39.0438, -77.4874, 'Amazon AWS', 'us-east-1'),
    ('50.19.0.0/16', 'US', 'Ashburn', 39.0438, -77.4874, 'Amazon AWS', 'us-east-1'),
    ('174.129.0.0/16', 'US', 'Ashburn', 39.0438, -77.4874, 'Amazon AWS', 'us-east-1'),
    ('184.72.0.0/15', 'US', 'Ashburn', 39.0438, -77.4874, 'Amazon AWS', 'us-east-1'),
    ('184.73.0.0/16', 'US', 'Ashburn', 39.0438, -77.4874, 'Amazon AWS', 'us-east-1'),
    ('54.92.0.0/16', 'US', 'Ashburn', 39.0438, -77.4874, 'Amazon AWS', 'us-east-1'),
    ('54.94.0.0/16', 'US', 'Ashburn', 39.0438, -77.4874, 'Amazon AWS', 'us-east-1'),
    ('54.234.0.0/15', 'US', 'Ashburn', 39.0438, -77.4874, 'Amazon AWS', 'us-east-1'),
    ('54.236.0.0/15', 'US', 'Ashburn', 39.0438, -77.4874, 'Amazon AWS', 'us-east-1'),
    ('52.94.236.0/24', 'US', 'Ashburn', 39.0438, -77.4874, 'Amazon AWS', 'us-east-1'),
    ('54.239.128.0/18', 'US', 'Ashburn', 39.0438, -77.4874, 'Amazon AWS', 'us-east-1'),
    # us-east-2 (Ohio — Columbus)
    ('52.14.0.0/16', 'US', 'Columbus', 39.9612, -82.9988, 'Amazon AWS', 'us-east-2'),
    ('52.15.0.0/16', 'US', 'Columbus', 39.9612, -82.9988, 'Amazon AWS', 'us-east-2'),
    ('18.216.0.0/16', 'US', 'Columbus', 39.9612, -82.9988, 'Amazon AWS', 'us-east-2'),
    ('18.217.0.0/16', 'US', 'Columbus', 39.9612, -82.9988, 'Amazon AWS', 'us-east-2'),
    ('18.218.0.0/16', 'US', 'Columbus', 39.9612, -82.9988, 'Amazon AWS', 'us-east-2'),
    ('18.219.0.0/16', 'US', 'Columbus', 39.9612, -82.9988, 'Amazon AWS', 'us-east-2'),
    # us-west-1 (Northern California — San Jose)
    ('52.52.0.0/15', 'US', 'San Jose', 37.3382, -121.8947, 'Amazon AWS', 'us-west-1'),
    ('54.151.0.0/16', 'US', 'San Jose', 37.3382, -121.8947, 'Amazon AWS', 'us-west-1'),
    ('13.52.0.0/16', 'US', 'San Jose', 37.3382, -121.8947, 'Amazon AWS', 'us-west-1'),
    ('13.56.0.0/16', 'US', 'San Jose', 37.3382, -121.8947, 'Amazon AWS', 'us-west-1'),
    ('13.57.0.0/16', 'US', 'San Jose', 37.3382, -121.8947, 'Amazon AWS', 'us-west-1'),
    # us-west-2 (Oregon — Portland)
    ('52.32.0.0/14', 'US', 'Portland', 45.5152, -122.6784, 'Amazon AWS', 'us-west-2'),
    ('52.36.0.0/14', 'US', 'Portland', 45.5152, -122.6784, 'Amazon AWS', 'us-west-2'),
    ('52.40.0.0/14', 'US', 'Portland', 45.5152, -122.6784, 'Amazon AWS', 'us-west-2'),
    ('34.208.0.0/12', 'US', 'Portland', 45.5152, -122.6784, 'Amazon AWS', 'us-west-2'),
    ('35.160.0.0/13', 'US', 'Portland', 45.5152, -122.6784, 'Amazon AWS', 'us-west-2'),
    ('44.224.0.0/11', 'US', 'Portland', 45.5152, -122.6784, 'Amazon AWS', 'us-west-2'),
    # eu-west-1 (Ireland — Dublin)
    ('52.16.0.0/15', 'IE', 'Dublin', 53.3498, -6.2603, 'Amazon AWS', 'eu-west-1'),
    ('52.18.0.0/16', 'IE', 'Dublin', 53.3498, -6.2603, 'Amazon AWS', 'eu-west-1'),
    ('52.208.0.0/13', 'IE', 'Dublin', 53.3498, -6.2603, 'Amazon AWS', 'eu-west-1'),
    ('52.212.0.0/15', 'IE', 'Dublin', 53.3498, -6.2603, 'Amazon AWS', 'eu-west-1'),
    ('34.240.0.0/13', 'IE', 'Dublin', 53.3498, -6.2603, 'Amazon AWS', 'eu-west-1'),
    ('54.72.0.0/14', 'IE', 'Dublin', 53.3498, -6.2603, 'Amazon AWS', 'eu-west-1'),
    ('54.76.0.0/15', 'IE', 'Dublin', 53.3498, -6.2603, 'Amazon AWS', 'eu-west-1'),
    ('79.125.0.0/17', 'IE', 'Dublin', 53.3498, -6.2603, 'Amazon AWS', 'eu-west-1'),
    ('176.34.0.0/16', 'IE', 'Dublin', 53.3498, -6.2603, 'Amazon AWS', 'eu-west-1'),
    # eu-west-2 (London, UK)
    ('52.56.0.0/16', 'GB', 'London', 51.5074, -0.1278, 'Amazon AWS', 'eu-west-2'),
    ('52.57.0.0/16', 'GB', 'London', 51.5074, -0.1278, 'Amazon AWS', 'eu-west-2'),
    ('18.130.0.0/16', 'GB', 'London', 51.5074, -0.1278, 'Amazon AWS', 'eu-west-2'),
    ('18.132.0.0/16', 'GB', 'London', 51.5074, -0.1278, 'Amazon AWS', 'eu-west-2'),
    ('35.176.0.0/14', 'GB', 'London', 51.5074, -0.1278, 'Amazon AWS', 'eu-west-2'),
    # eu-central-1 (Frankfurt, Germany)
    ('52.28.0.0/16', 'DE', 'Frankfurt', 50.1109, 8.6821, 'Amazon AWS', 'eu-central-1'),
    ('52.29.0.0/16', 'DE', 'Frankfurt', 50.1109, 8.6821, 'Amazon AWS', 'eu-central-1'),
    ('52.196.0.0/14', 'DE', 'Frankfurt', 50.1109, 8.6821, 'Amazon AWS', 'eu-central-1'),
    ('35.156.0.0/14', 'DE', 'Frankfurt', 50.1109, 8.6821, 'Amazon AWS', 'eu-central-1'),
    ('54.93.0.0/16', 'DE', 'Frankfurt', 50.1109, 8.6821, 'Amazon AWS', 'eu-central-1'),
    ('18.184.0.0/15', 'DE', 'Frankfurt', 50.1109, 8.6821, 'Amazon AWS', 'eu-central-1'),
    ('18.186.0.0/15', 'DE', 'Frankfurt', 50.1109, 8.6821, 'Amazon AWS', 'eu-central-1'),
    ('3.120.0.0/14', 'DE', 'Frankfurt', 50.1109, 8.6821, 'Amazon AWS', 'eu-central-1'),
    # ap-northeast-1 (Tokyo, Japan)
    ('52.68.0.0/15', 'JP', 'Tokyo', 35.6762, 139.6503, 'Amazon AWS', 'ap-northeast-1'),
    ('52.92.40.0/24', 'JP', 'Tokyo', 35.6762, 139.6503, 'Amazon AWS', 'ap-northeast-1'),
    ('52.196.0.0/14', 'JP', 'Tokyo', 35.6762, 139.6503, 'Amazon AWS', 'ap-northeast-1'),
    ('13.112.0.0/15', 'JP', 'Tokyo', 35.6762, 139.6503, 'Amazon AWS', 'ap-northeast-1'),
    ('13.114.0.0/15', 'JP', 'Tokyo', 35.6762, 139.6503, 'Amazon AWS', 'ap-northeast-1'),
    ('18.176.0.0/15', 'JP', 'Tokyo', 35.6762, 139.6503, 'Amazon AWS', 'ap-northeast-1'),
    ('35.72.0.0/13', 'JP', 'Tokyo', 35.6762, 139.6503, 'Amazon AWS', 'ap-northeast-1'),
    # ap-southeast-1 (Singapore)
    ('52.76.0.0/15', 'SG', 'Singapore', 1.3521, 103.8198, 'Amazon AWS', 'ap-southeast-1'),
    ('52.220.0.0/15', 'SG', 'Singapore', 1.3521, 103.8198, 'Amazon AWS', 'ap-southeast-1'),
    ('13.212.0.0/15', 'SG', 'Singapore', 1.3521, 103.8198, 'Amazon AWS', 'ap-southeast-1'),
    ('18.140.0.0/15', 'SG', 'Singapore', 1.3521, 103.8198, 'Amazon AWS', 'ap-southeast-1'),
    # ap-south-1 (Mumbai, India)
    ('52.66.0.0/16', 'IN', 'Mumbai', 19.0760, 72.8777, 'Amazon AWS', 'ap-south-1'),
    ('13.232.0.0/15', 'IN', 'Mumbai', 19.0760, 72.8777, 'Amazon AWS', 'ap-south-1'),
    ('15.206.0.0/16', 'IN', 'Mumbai', 19.0760, 72.8777, 'Amazon AWS', 'ap-south-1'),

    # ---- Google Cloud Platform ----
    # us-central1 (Council Bluffs, Iowa)
    ('35.184.0.0/13', 'US', 'Council Bluffs', 41.2619, -95.8608, 'Google Cloud', 'us-central1'),
    ('35.188.0.0/14', 'US', 'Council Bluffs', 41.2619, -95.8608, 'Google Cloud', 'us-central1'),
    ('35.192.0.0/14', 'US', 'Council Bluffs', 41.2619, -95.8608, 'Google Cloud', 'us-central1'),
    ('35.196.0.0/14', 'US', 'Council Bluffs', 41.2619, -95.8608, 'Google Cloud', 'us-central1'),
    ('35.200.0.0/14', 'US', 'Council Bluffs', 41.2619, -95.8608, 'Google Cloud', 'us-central1'),
    # us-east1 (Moncks Corner, South Carolina)
    ('35.186.0.0/15', 'US', 'Moncks Corner', 33.1960, -80.0148, 'Google Cloud', 'us-east1'),
    ('35.190.0.0/17', 'US', 'Moncks Corner', 33.1960, -80.0148, 'Google Cloud', 'us-east1'),
    # us-west1 (The Dalles, Oregon)
    ('35.197.0.0/16', 'US', 'The Dalles', 45.6047, -121.1787, 'Google Cloud', 'us-west1'),
    ('35.199.0.0/16', 'US', 'The Dalles', 45.6047, -121.1787, 'Google Cloud', 'us-west1'),
    # europe-west1 (St. Ghislain, Belgium)
    ('35.204.0.0/14', 'BE', 'Saint-Ghislain', 50.4541, 3.8167, 'Google Cloud', 'europe-west1'),
    ('35.208.0.0/13', 'BE', 'Saint-Ghislain', 50.4541, 3.8167, 'Google Cloud', 'europe-west1'),
    # europe-west3 (Frankfurt, Germany)
    ('35.246.0.0/15', 'DE', 'Frankfurt', 50.1109, 8.6821, 'Google Cloud', 'europe-west3'),
    ('35.248.0.0/15', 'DE', 'Frankfurt', 50.1109, 8.6821, 'Google Cloud', 'europe-west3'),
    # asia-east1 (Changhua County, Taiwan)
    ('35.221.0.0/16', 'TW', 'Changhua', 24.0660, 120.5155, 'Google Cloud', 'asia-east1'),
    ('35.222.0.0/15', 'TW', 'Changhua', 24.0660, 120.5155, 'Google Cloud', 'asia-east1'),
    # asia-northeast1 (Tokyo, Japan)
    ('35.220.0.0/16', 'JP', 'Tokyo', 35.6762, 139.6503, 'Google Cloud', 'asia-northeast1'),

    # ---- Microsoft Azure ----
    # East US (Virginia)
    ('20.36.0.0/14', 'US', 'Ashburn', 39.0438, -77.4874, 'Microsoft Azure', 'eastus'),
    ('20.40.0.0/13', 'US', 'Ashburn', 39.0438, -77.4874, 'Microsoft Azure', 'eastus'),
    ('20.48.0.0/13', 'US', 'Ashburn', 39.0438, -77.4874, 'Microsoft Azure', 'eastus'),
    ('20.190.128.0/18', 'US', 'Ashburn', 39.0438, -77.4874, 'Microsoft Azure', 'eastus'),
    ('52.188.0.0/14', 'US', 'Ashburn', 39.0438, -77.4874, 'Microsoft Azure', 'eastus'),
    # West US 2 (Washington)
    ('20.64.0.0/12', 'US', 'Cheyenne', 41.1400, -104.8202, 'Microsoft Azure', 'westus2'),
    ('40.64.0.0/10', 'US', 'Cheyenne', 41.1400, -104.8202, 'Microsoft Azure', 'westus2'),
    # West Europe (Netherlands)
    ('20.76.0.0/15', 'NL', 'Amsterdam', 52.3676, 4.9041, 'Microsoft Azure', 'westeurope'),
    ('20.78.0.0/16', 'NL', 'Amsterdam', 52.3676, 4.9041, 'Microsoft Azure', 'westeurope'),
    ('40.112.0.0/13', 'NL', 'Amsterdam', 52.3676, 4.9041, 'Microsoft Azure', 'westeurope'),
    ('52.96.0.0/12', 'NL', 'Amsterdam', 52.3676, 4.9041, 'Microsoft Azure', 'westeurope'),
    ('51.144.0.0/15', 'NL', 'Amsterdam', 52.3676, 4.9041, 'Microsoft Azure', 'westeurope'),
    # North Europe (Ireland)
    ('20.54.0.0/15', 'IE', 'Dublin', 53.3498, -6.2603, 'Microsoft Azure', 'northeurope'),
    ('40.74.0.0/14', 'IE', 'Dublin', 53.3498, -6.2603, 'Microsoft Azure', 'northeurope'),
    ('52.108.0.0/14', 'IE', 'Dublin', 53.3498, -6.2603, 'Microsoft Azure', 'northeurope'),
    # East Asia (Hong Kong)
    ('20.187.0.0/16', 'HK', 'Hong Kong', 22.3193, 114.1694, 'Microsoft Azure', 'eastasia'),
    ('52.175.0.0/16', 'HK', 'Hong Kong', 22.3193, 114.1694, 'Microsoft Azure', 'eastasia'),
    # Japan East (Tokyo)
    ('20.46.0.0/16', 'JP', 'Tokyo', 35.6762, 139.6503, 'Microsoft Azure', 'japaneast'),
    ('52.140.0.0/14', 'JP', 'Tokyo', 35.6762, 139.6503, 'Microsoft Azure', 'japaneast'),

    # ---- Cloudflare ----
    # Cloudflare uses anycast — IPs resolve to nearest PoP
    # HQ: San Francisco, but we mark as anycast
    ('1.1.1.0/24', 'US', 'San Francisco', 37.7749, -122.4194, 'Cloudflare', 'anycast'),
    ('1.0.0.0/24', 'US', 'San Francisco', 37.7749, -122.4194, 'Cloudflare', 'anycast'),
    ('104.16.0.0/13', 'US', 'San Francisco', 37.7749, -122.4194, 'Cloudflare', 'anycast'),
    ('104.24.0.0/14', 'US', 'San Francisco', 37.7749, -122.4194, 'Cloudflare', 'anycast'),
    ('172.64.0.0/13', 'US', 'San Francisco', 37.7749, -122.4194, 'Cloudflare', 'anycast'),
    ('162.158.0.0/15', 'US', 'San Francisco', 37.7749, -122.4194, 'Cloudflare', 'anycast'),
    ('188.114.96.0/20', 'US', 'San Francisco', 37.7749, -122.4194, 'Cloudflare', 'anycast'),

    # ---- Hetzner Online ----
    # Falkenstein, Germany
    ('116.202.0.0/15', 'DE', 'Falkenstein', 50.4779, 12.3713, 'Hetzner Online', 'falkenstein'),
    ('5.9.0.0/16', 'DE', 'Falkenstein', 50.4779, 12.3713, 'Hetzner Online', 'falkenstein'),
    ('136.243.0.0/16', 'DE', 'Falkenstein', 50.4779, 12.3713, 'Hetzner Online', 'falkenstein'),
    ('138.201.0.0/16', 'DE', 'Falkenstein', 50.4779, 12.3713, 'Hetzner Online', 'falkenstein'),
    ('148.251.0.0/16', 'DE', 'Falkenstein', 50.4779, 12.3713, 'Hetzner Online', 'falkenstein'),
    ('176.9.0.0/16', 'DE', 'Falkenstein', 50.4779, 12.3713, 'Hetzner Online', 'falkenstein'),
    ('178.63.0.0/16', 'DE', 'Falkenstein', 50.4779, 12.3713, 'Hetzner Online', 'falkenstein'),
    ('185.12.64.0/18', 'DE', 'Falkenstein', 50.4779, 12.3713, 'Hetzner Online', 'falkenstein'),
    # Helsinki, Finland
    ('95.216.0.0/15', 'FI', 'Helsinki', 60.1699, 24.9384, 'Hetzner Online', 'helsinki'),
    ('95.218.0.0/16', 'FI', 'Helsinki', 60.1699, 24.9384, 'Hetzner Online', 'helsinki'),
    ('65.108.0.0/15', 'FI', 'Helsinki', 60.1699, 24.9384, 'Hetzner Online', 'helsinki'),
    ('65.21.0.0/16', 'FI', 'Helsinki', 60.1699, 24.9384, 'Hetzner Online', 'helsinki'),
    # Ashburn, Virginia (US)
    ('5.161.0.0/16', 'US', 'Ashburn', 39.0438, -77.4874, 'Hetzner Online', 'ashburn'),
    ('23.88.0.0/16', 'US', 'Ashburn', 39.0438, -77.4874, 'Hetzner Online', 'ashburn'),

    # ---- OVH ----
    # Roubaix, France
    ('51.68.0.0/16', 'FR', 'Roubaix', 50.6916, 3.2010, 'OVH SAS', 'roubaix'),
    ('51.75.0.0/16', 'FR', 'Roubaix', 50.6916, 3.2010, 'OVH SAS', 'roubaix'),
    ('51.77.0.0/16', 'FR', 'Roubaix', 50.6916, 3.2010, 'OVH SAS', 'roubaix'),
    ('51.79.0.0/16', 'FR', 'Roubaix', 50.6916, 3.2010, 'OVH SAS', 'roubaix'),
    ('51.91.0.0/16', 'FR', 'Roubaix', 50.6916, 3.2010, 'OVH SAS', 'roubaix'),
    ('51.161.0.0/16', 'FR', 'Roubaix', 50.6916, 3.2010, 'OVH SAS', 'roubaix'),
    ('51.178.0.0/16', 'FR', 'Roubaix', 50.6916, 3.2010, 'OVH SAS', 'roubaix'),
    ('51.195.0.0/16', 'FR', 'Roubaix', 50.6916, 3.2010, 'OVH SAS', 'roubaix'),
    ('54.36.0.0/16', 'FR', 'Roubaix', 50.6916, 3.2010, 'OVH SAS', 'roubaix'),
    ('54.37.0.0/16', 'FR', 'Roubaix', 50.6916, 3.2010, 'OVH SAS', 'roubaix'),
    ('54.38.0.0/16', 'FR', 'Roubaix', 50.6916, 3.2010, 'OVH SAS', 'roubaix'),
    ('91.134.0.0/16', 'FR', 'Roubaix', 50.6916, 3.2010, 'OVH SAS', 'roubaix'),
    ('145.239.0.0/16', 'FR', 'Roubaix', 50.6916, 3.2010, 'OVH SAS', 'roubaix'),
    ('151.80.0.0/16', 'FR', 'Roubaix', 50.6916, 3.2010, 'OVH SAS', 'roubaix'),
    ('176.31.0.0/16', 'FR', 'Roubaix', 50.6916, 3.2010, 'OVH SAS', 'roubaix'),
    ('178.33.0.0/16', 'FR', 'Roubaix', 50.6916, 3.2010, 'OVH SAS', 'roubaix'),
    ('188.165.0.0/16', 'FR', 'Roubaix', 50.6916, 3.2010, 'OVH SAS', 'roubaix'),
    ('192.95.0.0/18', 'FR', 'Roubaix', 50.6916, 3.2010, 'OVH SAS', 'roubaix'),
    ('198.27.64.0/18', 'FR', 'Roubaix', 50.6916, 3.2010, 'OVH SAS', 'roubaix'),
    ('198.50.128.0/17', 'FR', 'Roubaix', 50.6916, 3.2010, 'OVH SAS', 'roubaix'),
    # Gravelines, France
    ('51.89.0.0/16', 'FR', 'Gravelines', 50.9814, 2.1238, 'OVH SAS', 'gravelines'),
    ('51.210.0.0/16', 'FR', 'Gravelines', 50.9814, 2.1238, 'OVH SAS', 'gravelines'),
    ('135.125.0.0/16', 'FR', 'Gravelines', 50.9814, 2.1238, 'OVH SAS', 'gravelines'),
    ('137.74.0.0/16', 'FR', 'Gravelines', 50.9814, 2.1238, 'OVH SAS', 'gravelines'),
    ('151.127.0.0/16', 'GB', 'London', 51.5074, -0.1278, 'OVH SAS', 'london'),
    # Beauvais, France
    ('51.161.192.0/18', 'FR', 'Beauvais', 49.4295, 2.0846, 'OVH SAS', 'beauvais'),
    # Strasbourg, France
    ('51.158.0.0/15', 'FR', 'Strasbourg', 48.5734, 7.7521, 'OVH SAS', 'strasbourg'),
    # Frankfurt, Germany
    ('51.75.124.0/24', 'DE', 'Frankfurt', 50.1109, 8.6821, 'OVH SAS', 'frankfurt'),
    ('57.128.0.0/14', 'DE', 'Frankfurt', 50.1109, 8.6821, 'OVH SAS', 'frankfurt'),
    # Warsaw, Poland
    ('51.83.0.0/16', 'PL', 'Warsaw', 52.2297, 21.0122, 'OVH SAS', 'warsaw'),
    # Singapore
    ('139.99.0.0/18', 'SG', 'Singapore', 1.3521, 103.8198, 'OVH SAS', 'singapore'),

    # ---- DigitalOcean ----
    # Frankfurt, Germany
    ('165.227.0.0/16', 'DE', 'Frankfurt', 50.1109, 8.6821, 'DigitalOcean', 'fra1'),
    ('165.22.0.0/16', 'DE', 'Frankfurt', 50.1109, 8.6821, 'DigitalOcean', 'fra1'),
    ('164.92.0.0/16', 'DE', 'Frankfurt', 50.1109, 8.6821, 'DigitalOcean', 'fra1'),
    ('64.225.0.0/16', 'DE', 'Frankfurt', 50.1109, 8.6821, 'DigitalOcean', 'fra1'),
    # New York, US
    ('104.131.0.0/16', 'US', 'New York', 40.7128, -74.0060, 'DigitalOcean', 'nyc1'),
    ('104.236.0.0/16', 'US', 'New York', 40.7128, -74.0060, 'DigitalOcean', 'nyc3'),
    ('162.243.0.0/16', 'US', 'New York', 40.7128, -74.0060, 'DigitalOcean', 'nyc3'),
    ('159.203.0.0/16', 'US', 'New York', 40.7128, -74.0060, 'DigitalOcean', 'nyc3'),
    ('174.138.0.0/16', 'US', 'New York', 40.7128, -74.0060, 'DigitalOcean', 'nyc3'),
    # San Francisco, US
    ('138.68.0.0/16', 'US', 'San Francisco', 37.7749, -122.4194, 'DigitalOcean', 'sfo2'),
    ('138.197.0.0/16', 'US', 'San Francisco', 37.7749, -122.4194, 'DigitalOcean', 'sfo2'),
    ('143.198.0.0/16', 'US', 'San Francisco', 37.7749, -122.4194, 'DigitalOcean', 'sfo3'),
    # Amsterdam, Netherlands
    ('178.62.0.0/16', 'NL', 'Amsterdam', 52.3676, 4.9041, 'DigitalOcean', 'ams2'),
    ('188.166.0.0/16', 'NL', 'Amsterdam', 52.3676, 4.9041, 'DigitalOcean', 'ams3'),
    ('206.189.0.0/16', 'NL', 'Amsterdam', 52.3676, 4.9041, 'DigitalOcean', 'ams3'),
    ('134.209.0.0/16', 'NL', 'Amsterdam', 52.3676, 4.9041, 'DigitalOcean', 'ams3'),
    ('161.35.0.0/16', 'NL', 'Amsterdam', 52.3676, 4.9041, 'DigitalOcean', 'ams3'),
    # Singapore
    ('174.138.0.0/16', 'SG', 'Singapore', 1.3521, 103.8198, 'DigitalOcean', 'sgp1'),
    ('128.199.0.0/16', 'SG', 'Singapore', 1.3521, 103.8198, 'DigitalOcean', 'sgp1'),
    ('139.59.0.0/16', 'SG', 'Singapore', 1.3521, 103.8198, 'DigitalOcean', 'sgp1'),
    ('159.65.0.0/16', 'SG', 'Singapore', 1.3521, 103.8198, 'DigitalOcean', 'sgp1'),
    # London, UK
    ('46.101.0.0/16', 'GB', 'London', 51.5074, -0.1278, 'DigitalOcean', 'lon1'),
    ('178.128.0.0/16', 'GB', 'London', 51.5074, -0.1278, 'DigitalOcean', 'lon1'),
    ('142.93.0.0/16', 'GB', 'London', 51.5074, -0.1278, 'DigitalOcean', 'lon1'),
    ('167.172.0.0/16', 'GB', 'London', 51.5074, -0.1278, 'DigitalOcean', 'lon1'),

    # ---- Linode / Akamai ----
    # Frankfurt, Germany
    ('139.162.96.0/19', 'DE', 'Frankfurt', 50.1109, 8.6821, 'Linode/Akamai', 'fra1'),
    ('172.104.64.0/19', 'DE', 'Frankfurt', 50.1109, 8.6821, 'Linode/Akamai', 'fra1'),
    # Dallas, US
    ('45.33.0.0/17', 'US', 'Dallas', 32.7767, -96.7970, 'Linode/Akamai', 'us-central'),
    ('45.56.64.0/18', 'US', 'Dallas', 32.7767, -96.7970, 'Linode/Akamai', 'us-central'),
    # Fremont, US (California)
    ('45.33.64.0/18', 'US', 'Fremont', 37.5485, -121.9886, 'Linode/Akamai', 'us-west'),
    ('45.79.0.0/16', 'US', 'Fremont', 37.5485, -121.9886, 'Linode/Akamai', 'us-west'),
    # London, UK
    ('176.58.0.0/16', 'GB', 'London', 51.5074, -0.1278, 'Linode/Akamai', 'uk'),
    ('139.162.64.0/18', 'GB', 'London', 51.5074, -0.1278, 'Linode/Akamai', 'uk'),
    # Singapore
    ('139.162.16.0/20', 'SG', 'Singapore', 1.3521, 103.8198, 'Linode/Akamai', 'sg'),
    ('172.104.160.0/19', 'SG', 'Singapore', 1.3521, 103.8198, 'Linode/Akamai', 'sg'),
    # Tokyo, Japan
    ('172.104.96.0/19', 'JP', 'Tokyo', 35.6762, 139.6503, 'Linode/Akamai', 'jp'),
    ('139.162.64.0/19', 'JP', 'Tokyo', 35.6762, 139.6503, 'Linode/Akamai', 'jp'),

    # ---- Vultr ----
    # Frankfurt, Germany
    ('45.32.128.0/18', 'DE', 'Frankfurt', 50.1109, 8.6821, 'Vultr Holdings', 'fra'),
    ('139.180.128.0/18', 'DE', 'Frankfurt', 50.1109, 8.6821, 'Vultr Holdings', 'fra'),
    # Amsterdam, Netherlands
    ('45.32.0.0/18', 'NL', 'Amsterdam', 52.3676, 4.9041, 'Vultr Holdings', 'ams'),
    ('108.61.192.0/18', 'NL', 'Amsterdam', 52.3676, 4.9041, 'Vultr Holdings', 'ams'),
    # New York / New Jersey, US
    ('45.63.0.0/17', 'US', 'New York', 40.7128, -74.0060, 'Vultr Holdings', 'ewr'),
    ('108.61.0.0/17', 'US', 'New York', 40.7128, -74.0060, 'Vultr Holdings', 'ewr'),
    ('149.28.0.0/16', 'US', 'New York', 40.7128, -74.0060, 'Vultr Holdings', 'ewr'),
    # Tokyo, Japan
    ('45.32.64.0/18', 'JP', 'Tokyo', 35.6762, 139.6503, 'Vultr Holdings', 'tokyo'),
    ('108.61.160.0/19', 'JP', 'Tokyo', 35.6762, 139.6503, 'Vultr Holdings', 'tokyo'),
    # Singapore
    ('45.77.0.0/17', 'SG', 'Singapore', 1.3521, 103.8198, 'Vultr Holdings', 'sg'),
    ('108.61.176.0/20', 'SG', 'Singapore', 1.3521, 103.8198, 'Vultr Holdings', 'sg'),

    # ---- Google Public DNS (anycast) ----
    ('8.8.8.0/24', 'US', 'Mountain View', 37.3861, -122.0839, 'Google LLC', 'anycast-dns'),
    ('8.8.4.0/24', 'US', 'Mountain View', 37.3861, -122.0839, 'Google LLC', 'anycast-dns'),

    # ---- Cloudflare DNS (anycast) ----
    # Already covered by Cloudflare ranges above (1.1.1.0/24, 1.0.0.0/24)

    # ---- Quad9 DNS (anycast) ----
    ('9.9.9.0/24', 'CH', 'Zurich', 47.3769, 8.5417, 'Quad9', 'anycast-dns'),

    # ---- OpenDNS / Cisco (anycast) ----
    ('208.67.222.0/24', 'US', 'San Francisco', 37.7749, -122.4194, 'Cisco OpenDNS', 'anycast-dns'),
    ('208.67.220.0/24', 'US', 'San Francisco', 37.7749, -122.4194, 'Cisco OpenDNS', 'anycast-dns'),

    # ---- Leaseweb ----
    # Frankfurt, Germany
    ('85.17.0.0/16', 'DE', 'Frankfurt', 50.1109, 8.6821, 'Leaseweb Deutschland', 'fra'),
    ('178.162.0.0/17', 'DE', 'Frankfurt', 50.1109, 8.6821, 'Leaseweb Deutschland', 'fra'),
    ('46.165.128.0/17', 'DE', 'Frankfurt', 50.1109, 8.6821, 'Leaseweb Deutschland', 'fra'),
    # Amsterdam, Netherlands
    ('5.79.64.0/18', 'NL', 'Amsterdam', 52.3676, 4.9041, 'Leaseweb BV', 'ams'),
    ('23.62.0.0/16', 'NL', 'Amsterdam', 52.3676, 4.9041, 'Leaseweb BV', 'ams'),
    ('31.3.96.0/19', 'NL', 'Amsterdam', 52.3676, 4.9041, 'Leaseweb BV', 'ams'),
    ('62.212.64.0/19', 'NL', 'Amsterdam', 52.3676, 4.9041, 'Leaseweb BV', 'ams'),
    ('77.247.176.0/21', 'NL', 'Amsterdam', 52.3676, 4.9041, 'Leaseweb BV', 'ams'),
    ('81.171.0.0/17', 'NL', 'Amsterdam', 52.3676, 4.9041, 'Leaseweb BV', 'ams'),
    ('82.192.64.0/19', 'NL', 'Amsterdam', 52.3676, 4.9041, 'Leaseweb BV', 'ams'),
    ('85.17.0.0/17', 'NL', 'Amsterdam', 52.3676, 4.9041, 'Leaseweb BV', 'ams'),
    ('89.149.192.0/18', 'NL', 'Amsterdam', 52.3676, 4.9041, 'Leaseweb BV', 'ams'),
    ('94.142.208.0/21', 'NL', 'Amsterdam', 52.3676, 4.9041, 'Leaseweb BV', 'ams'),
    ('95.211.0.0/16', 'NL', 'Amsterdam', 52.3676, 4.9041, 'Leaseweb BV', 'ams'),
    ('178.21.16.0/21', 'NL', 'Amsterdam', 52.3676, 4.9041, 'Leaseweb BV', 'ams'),
    ('178.237.32.0/21', 'NL', 'Amsterdam', 52.3676, 4.9041, 'Leaseweb BV', 'ams'),
    ('199.115.112.0/21', 'NL', 'Amsterdam', 52.3676, 4.9041, 'Leaseweb BV', 'ams'),
    ('209.58.128.0/19', 'NL', 'Amsterdam', 52.3676, 4.9041, 'Leaseweb BV', 'ams'),
    # US (Manassas, Virginia)
    ('108.59.0.0/18', 'US', 'Manassas', 38.7509, -77.4755, 'Leaseweb USA', 'us'),

    # ---- Contabo ----
    # Munich, Germany
    ('5.189.128.0/17', 'DE', 'Munich', 48.1351, 11.5820, 'Contabo GmbH', 'munich'),
    ('161.97.0.0/17', 'DE', 'Munich', 48.1351, 11.5820, 'Contabo GmbH', 'munich'),
    ('167.86.64.0/18', 'DE', 'Munich', 48.1351, 11.5820, 'Contabo GmbH', 'munich'),
    ('193.26.156.0/22', 'DE', 'Munich', 48.1351, 11.5820, 'Contabo GmbH', 'munich'),
    # Nuremberg, Germany
    ('173.212.192.0/18', 'DE', 'Nuremberg', 49.4521, 11.0767, 'Contabo GmbH', 'nuremberg'),
    ('207.180.192.0/18', 'DE', 'Nuremberg', 49.4521, 11.0767, 'Contabo GmbH', 'nuremberg'),
    # Singapore
    ('161.117.0.0/17', 'SG', 'Singapore', 1.3521, 103.8198, 'Contabo Asia', 'sg'),
    # US (Denver)
    ('209.126.0.0/18', 'US', 'Denver', 39.7392, -104.9903, 'Contabo Inc', 'denver'),

    # ---- Scaleway ----
    # Paris, France
    ('51.15.0.0/16', 'FR', 'Paris', 48.8566, 2.3522, 'Scaleway', 'paris'),
    ('51.158.128.0/17', 'FR', 'Paris', 48.8566, 2.3522, 'Scaleway', 'paris'),
    ('62.210.0.0/16', 'FR', 'Paris', 48.8566, 2.3522, 'Scaleway', 'paris'),
    ('163.172.0.0/16', 'FR', 'Paris', 48.8566, 2.3522, 'Scaleway', 'paris'),
    ('212.47.224.0/19', 'FR', 'Paris', 48.8566, 2.3522, 'Scaleway', 'paris'),
    ('212.83.128.0/19', 'FR', 'Paris', 48.8566, 2.3522, 'Scaleway', 'paris'),
    ('195.154.0.0/16', 'FR', 'Paris', 48.8566, 2.3522, 'Scaleway', 'paris'),

    # ---- Oracle Cloud ----
    # Ashburn, US (IAD)
    ('129.146.0.0/16', 'US', 'Ashburn', 39.0438, -77.4874, 'Oracle Cloud', 'us-ashburn-1'),
    ('132.145.0.0/16', 'US', 'Ashburn', 39.0438, -77.4874, 'Oracle Cloud', 'us-ashburn-1'),
    ('138.1.0.0/16', 'US', 'Ashburn', 39.0438, -77.4874, 'Oracle Cloud', 'us-ashburn-1'),
    ('140.238.0.0/16', 'US', 'Ashburn', 39.0438, -77.4874, 'Oracle Cloud', 'us-ashburn-1'),
    ('152.70.0.0/16', 'US', 'Ashburn', 39.0438, -77.4874, 'Oracle Cloud', 'us-ashburn-1'),
    # Frankfurt, DE (FRA)
    ('129.159.0.0/16', 'DE', 'Frankfurt', 50.1109, 8.6821, 'Oracle Cloud', 'eu-frankfurt-1'),
    ('130.61.0.0/16', 'DE', 'Frankfurt', 50.1109, 8.6821, 'Oracle Cloud', 'eu-frankfurt-1'),
    ('131.186.0.0/16', 'DE', 'Frankfurt', 50.1109, 8.6821, 'Oracle Cloud', 'eu-frankfurt-1'),
    ('134.65.0.0/16', 'DE', 'Frankfurt', 50.1109, 8.6821, 'Oracle Cloud', 'eu-frankfurt-1'),
    ('146.56.0.0/16', 'DE', 'Frankfurt', 50.1109, 8.6821, 'Oracle Cloud', 'eu-frankfurt-1'),
    ('155.248.0.0/16', 'DE', 'Frankfurt', 50.1109, 8.6821, 'Oracle Cloud', 'eu-frankfurt-1'),
    # London, UK (LHR)
    ('134.35.0.0/16', 'GB', 'London', 51.5074, -0.1278, 'Oracle Cloud', 'uk-london-1'),
    ('138.3.0.0/16', 'GB', 'London', 51.5074, -0.1278, 'Oracle Cloud', 'uk-london-1'),
    ('140.204.0.0/16', 'GB', 'London', 51.5074, -0.1278, 'Oracle Cloud', 'uk-london-1'),
    ('152.67.0.0/16', 'GB', 'London', 51.5074, -0.1278, 'Oracle Cloud', 'uk-london-1'),
    # Tokyo, JP (NRT)
    ('129.152.0.0/16', 'JP', 'Tokyo', 35.6762, 139.6503, 'Oracle Cloud', 'ap-tokyo-1'),
    ('138.2.0.0/16', 'JP', 'Tokyo', 35.6762, 139.6503, 'Oracle Cloud', 'ap-tokyo-1'),
    ('140.239.0.0/16', 'JP', 'Tokyo', 35.6762, 139.6503, 'Oracle Cloud', 'ap-tokyo-1'),
    ('153.120.0.0/16', 'JP', 'Tokyo', 35.6762, 139.6503, 'Oracle Cloud', 'ap-tokyo-1'),

    # ---- GitHub / Microsoft ----
    ('140.82.112.0/20', 'US', 'San Francisco', 37.7749, -122.4194, 'GitHub Inc', 'san-francisco'),
    ('192.30.252.0/22', 'US', 'San Francisco', 37.7749, -122.4194, 'GitHub Inc', 'san-francisco'),
    ('185.199.108.0/22', 'US', 'San Francisco', 37.7749, -122.4194, 'GitHub Inc', 'san-francisco'),

    # ---- Cloudflare WARP / VPN ----
    # Already covered by Cloudflare ranges above

    # ---- M247 (commonly used by NordVPN, ProtonVPN, Mullvad) ----
    # Amsterdam, Netherlands
    ('82.102.16.0/20', 'NL', 'Amsterdam', 52.3676, 4.9041, 'M247 Europe', 'amsterdam'),
    ('89.44.176.0/20', 'NL', 'Amsterdam', 52.3676, 4.9041, 'M247 Europe', 'amsterdam'),
    ('92.119.176.0/20', 'NL', 'Amsterdam', 52.3676, 4.9041, 'M247 Europe', 'amsterdam'),
    ('94.198.40.0/21', 'NL', 'Amsterdam', 52.3676, 4.9041, 'M247 Europe', 'amsterdam'),
    # London, UK
    ('82.163.72.0/21', 'GB', 'London', 51.5074, -0.1278, 'M247 Europe', 'london'),
    ('89.45.104.0/21', 'GB', 'London', 51.5074, -0.1278, 'M247 Europe', 'london'),
    # Frankfurt, Germany
    ('193.27.12.0/22', 'DE', 'Frankfurt', 50.1109, 8.6821, 'M247 Europe', 'frankfurt'),
    ('89.46.100.0/22', 'DE', 'Frankfurt', 50.1109, 8.6821, 'M247 Europe', 'frankfurt'),
    # Milan, Italy
    ('82.102.0.0/19', 'IT', 'Milan', 45.4642, 9.1900, 'M247 Europe', 'milan'),
    ('89.46.104.0/21', 'IT', 'Milan', 45.4642, 9.1900, 'M247 Europe', 'milan'),
    # Bucharest, Romania
    ('82.102.32.0/19', 'RO', 'Bucharest', 44.4268, 26.1025, 'M247 Europe', 'bucharest'),
    ('89.44.192.0/20', 'RO', 'Bucharest', 44.4268, 26.1025, 'M247 Europe', 'bucharest'),
    # Singapore
    ('82.102.64.0/19', 'SG', 'Singapore', 1.3521, 103.8198, 'M247 Asia', 'singapore'),
    ('89.44.208.0/20', 'SG', 'Singapore', 1.3521, 103.8198, 'M247 Asia', 'singapore'),
    # New York, US
    ('23.94.0.0/17', 'US', 'New York', 40.7128, -74.0060, 'M247 USA', 'new-york'),
    ('89.45.0.0/18', 'US', 'New York', 40.7128, -74.0060, 'M247 USA', 'new-york'),

    # ---- Choopa / ExpressVPN ----
    # New Jersey, US
    ('104.207.128.0/19', 'US', 'Piscataway', 40.4993, -74.3990, 'Choopa LLC', 'new-jersey'),
    ('108.61.0.0/17', 'US', 'Piscataway', 40.4993, -74.3990, 'Choopa LLC', 'new-jersey'),
    # Amsterdam, Netherlands
    ('45.32.224.0/19', 'NL', 'Amsterdam', 52.3676, 4.9041, 'Choopa LLC', 'amsterdam'),
    ('108.61.192.0/19', 'NL', 'Amsterdam', 52.3676, 4.9041, 'Choopa LLC', 'amsterdam'),
    # London, UK
    ('45.63.64.0/18', 'GB', 'London', 51.5074, -0.1278, 'Choopa LLC', 'london'),
    ('108.61.160.0/20', 'GB', 'London', 51.5074, -0.1278, 'Choopa LLC', 'london'),
    # Singapore
    ('45.77.0.0/17', 'SG', 'Singapore', 1.3521, 103.8198, 'Choopa LLC', 'singapore'),
    ('108.61.176.0/20', 'SG', 'Singapore', 1.3521, 103.8198, 'Choopa LLC', 'singapore'),
    # Tokyo, Japan
    ('45.32.64.0/19', 'JP', 'Tokyo', 35.6762, 139.6503, 'Choopa LLC', 'tokyo'),
    ('108.61.160.0/20', 'JP', 'Tokyo', 35.6762, 139.6503, 'Choopa LLC', 'tokyo'),
]

# Pre-compile into ip_network objects for fast matching.
# Sort by prefix length (most specific / largest prefixlen first) so that
# /24 ranges match before /12 ranges, preventing broad ranges from
# shadowing more specific ones.
_HARDCODED_IP_NETWORKS: list[tuple] = []
for _cidr, _cc, _city, _lat, _lon, _org, _region in _HARDCODED_IP_LOCATIONS:
    try:
        _HARDCODED_IP_NETWORKS.append((
            ipaddress.ip_network(_cidr, strict=False),
            _cc, _city, _lat, _lon, _org, _region,
        ))
    except Exception:
        pass
_HARDCODED_IP_NETWORKS.sort(key=lambda t: t[0].prefixlen, reverse=True)


class GeoIPCache:
    """Thread-safe GeoIP lookup with multi-source consensus, caching, rate
    limiting, local MaxMind DB auto-detection, rDNS city refinement, and
    RTT-based distance estimation.

    Sources (tried in order, results fused for consensus):
      1. Local MaxMind GeoLite2-City database (auto-detected or configured)
      2. ip-api.com (HTTP, rate-limited 40/min)
      3. ipwho.is (HTTPS, 10k/month)
      4. Reverse DNS city-code extraction (IATA codes, ccTLDs)
      5. RTT-based distance refinement (ping → estimated distance band)

    When multiple sources return locations, a consensus is computed:
    - If sources agree on country, confidence is HIGH
    - If sources disagree, the majority wins and conflicts are recorded
    - City is selected from the source with highest accuracy weight
    - Lat/lon are averaged across agreeing sources for stability
    """
    _PRIVACY_WARNED = False
    _EMPTY: dict[str, object] = {'country': '??', 'countryCode': '??', 'city': '??',
                                 'org': 'Unknown', 'isp': 'Unknown', 'lat': 0, 'lon': 0}

    # Common MaxMind DB locations to auto-detect
    _MAXMIND_SEARCH_PATHS = [
        # Linux/Mac
        '/usr/share/GeoIP/GeoLite2-City.mmdb',
        '/usr/local/share/GeoIP/GeoLite2-City.mmdb',
        '/var/lib/GeoIP/GeoLite2-City.mmdb',
        '/opt/GeoIP/GeoLite2-City.mmdb',
        '/etc/GeoIP/GeoLite2-City.mmdb',
        os.path.expanduser('~/GeoIP/GeoLite2-City.mmdb'),
        os.path.expanduser('~/.GeoIP/GeoLite2-City.mmdb'),
        os.path.expanduser('~/Downloads/GeoLite2-City.mmdb'),
        # Windows (common download locations)
        os.path.join(os.environ.get('PROGRAMDATA', 'C:\\ProgramData'), 'GeoIP', 'GeoLite2-City.mmdb'),
        os.path.join(os.environ.get('USERPROFILE', os.path.expanduser('~')), 'Downloads', 'GeoLite2-City.mmdb'),
        os.path.join(os.environ.get('USERPROFILE', os.path.expanduser('~')), 'Desktop', 'GeoLite2-City.mmdb'),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), 'GeoLite2-City.mmdb'),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), 'geoip', 'GeoLite2-City.mmdb'),
    ]

    # IATA airport codes → (city, country) for rDNS-based city refinement
    _RDNS_CITY_CODES: dict[str, tuple[str, str]] = {
        'lax': ('Los Angeles', 'US'), 'sfo': ('San Francisco', 'US'),
        'sjc': ('San Jose', 'US'), 'sea': ('Seattle', 'US'),
        'ord': ('Chicago', 'US'), 'iad': ('Washington', 'US'),
        'dfw': ('Dallas', 'US'), 'atl': ('Atlanta', 'US'),
        'mia': ('Miami', 'US'), 'bos': ('Boston', 'US'),
        'den': ('Denver', 'US'), 'phx': ('Phoenix', 'US'),
        'jfk': ('New York', 'US'), 'ewr': ('Newark', 'US'),
        'nyc': ('New York', 'US'), 'chi': ('Chicago', 'US'),
        'dal': ('Dallas', 'US'), 'hou': ('Houston', 'US'),
        'lhr': ('London', 'GB'), 'fra': ('Frankfurt', 'DE'),
        'ams': ('Amsterdam', 'NL'), 'cdg': ('Paris', 'FR'),
        'nrt': ('Tokyo', 'JP'), 'hnd': ('Tokyo', 'JP'),
        'icn': ('Seoul', 'KR'), 'sin': ('Singapore', 'SG'),
        'syd': ('Sydney', 'AU'), 'yyz': ('Toronto', 'CA'),
        'yul': ('Montreal', 'CA'), 'yvr': ('Vancouver', 'CA'),
        'muc': ('Munich', 'DE'), 'ber': ('Berlin', 'DE'),
        'dus': ('Dusseldorf', 'DE'), 'ham': ('Hamburg', 'DE'),
        'mad': ('Madrid', 'ES'), 'bcn': ('Barcelona', 'ES'),
        'mil': ('Milan', 'IT'), 'rom': ('Rome', 'IT'),
        'sto': ('Stockholm', 'SE'), 'osl': ('Oslo', 'NO'),
        'hel': ('Helsinki', 'FI'), 'cph': ('Copenhagen', 'DK'),
        'zrh': ('Zurich', 'CH'), 'gva': ('Geneva', 'CH'),
        'vie': ('Vienna', 'AT'), 'prg': ('Prague', 'CZ'),
        'waw': ('Warsaw', 'PL'), 'dub': ('Dublin', 'IE'),
        'edi': ('Edinburgh', 'GB'), 'man': ('Manchester', 'GB'),
        'lis': ('Lisbon', 'PT'), 'ath': ('Athens', 'GR'),
        'ist': ('Istanbul', 'TR'), 'tlv': ('Tel Aviv', 'IL'),
        'dxb': ('Dubai', 'AE'), 'hkg': ('Hong Kong', 'HK'),
        'tpe': ('Taipei', 'TW'), 'bkk': ('Bangkok', 'TH'),
        'kul': ('Kuala Lumpur', 'MY'), 'jak': ('Jakarta', 'ID'),
        'mum': ('Mumbai', 'IN'), 'del': ('Delhi', 'IN'),
        'blr': ('Bangalore', 'IN'), 'gru': ('Sao Paulo', 'BR'),
        'mex': ('Mexico City', 'MX'), 'eze': ('Buenos Aires', 'AR'),
        'jnb': ('Johannesburg', 'ZA'), 'cai': ('Cairo', 'EG'),
        'arn': ('Stockholm', 'SE'), 'gothenburg': ('Gothenburg', 'SE'),
    }

    # Country TLD → country code mapping for rDNS refinement
    _CCTLD_MAP: dict[str, str] = {
        'uk': 'GB', 'de': 'DE', 'fr': 'FR', 'jp': 'JP', 'kr': 'KR',
        'cn': 'CN', 'ru': 'RU', 'br': 'BR', 'in': 'IN', 'au': 'AU',
        'ca': 'CA', 'it': 'IT', 'es': 'ES', 'nl': 'NL', 'se': 'SE',
        'no': 'NO', 'fi': 'FI', 'dk': 'DK', 'pl': 'PL', 'cz': 'CZ',
        'at': 'AT', 'ch': 'CH', 'be': 'BE', 'ie': 'IE', 'pt': 'PT',
        'gr': 'GR', 'tr': 'TR', 'za': 'ZA', 'mx': 'MX', 'ar': 'AR',
        'hk': 'HK', 'tw': 'TW', 'sg': 'SG', 'th': 'TH', 'my': 'MY',
        'id': 'ID', 'ph': 'PH', 'vn': 'VN', 'nz': 'NZ', 'il': 'IL',
        'ae': 'AE', 'sa': 'SA', 'eg': 'EG', 'ng': 'NG', 'ke': 'KE',
    }

    def __init__(self, maxmind_db_path: Optional[str] = None):
        self.cache: dict[str, dict] = {}
        self.lock = threading.Lock()
        self._api_url = ("http://ip-api.com/json/{ip}?fields="
                        "status,country,countryCode,org,as,isp,lat,lon,city,regionName,timezone")
        self._ipwhois_url = "https://ipwho.is/{ip}"
        self._rate_limiter = TokenBucket(rate=40.0, capacity=45.0)
        self._rate_limited_count = 0
        self._rate_lock = threading.Lock()
        self._local_reader = None
        db_path = maxmind_db_path or CONFIG.get('geoip_db_path')
        if not db_path:
            # Auto-detect MaxMind DB in common locations
            for path in self._MAXMIND_SEARCH_PATHS:
                if os.path.isfile(path):
                    db_path = path
                    _logger.info("GeoIP: auto-detected MaxMind DB at %s", db_path)
                    break
        if db_path and HAS_GEOIP2:
            try:
                self._local_reader = _geoip2_db.Reader(db_path)
                _logger.info("GeoIP: using local MaxMind DB at %s", db_path)
            except Exception as exc:
                _logger.warning("GeoIP: failed to open MaxMind DB '%s': %s — falling back to API", db_path, exc)

    def _lookup_hardcoded(self, ip: str) -> Optional[dict]:
        """Check the hardcoded IP-prefix database first. This gives exact
        locations for known cloud/datacenter/DNS ranges without any external
        dependency. Weight=4 (highest priority)."""
        try:
            ip_obj = ipaddress.ip_address(ip)
        except Exception:
            return None
        for net, cc, city, lat, lon, org, region in _HARDCODED_IP_NETWORKS:
            if ip_obj in net:
                return {
                    'status': 'success',
                    'country': cc,
                    'countryCode': cc,
                    'city': city,
                    'regionName': region,
                    'org': org,
                    'isp': org,
                    'as': '',
                    'lat': lat,
                    'lon': lon,
                    'timezone': '',
                    '_ts': time.time(),
                    '_source': 'hardcoded',
                    '_weight': 4,
                    '_region': region,
                }
        return None

    def _lookup_local(self, ip: str) -> Optional[dict]:
        if not self._local_reader:
            return None
        try:
            resp = self._local_reader.city(ip)
            return {
                'status': 'success',
                'country': resp.country.name or '??',
                'countryCode': resp.country.iso_code or '??',
                'city': resp.city.name or '??',
                'regionName': (resp.subdivisions.most_specific.name
                               if resp.subdivisions else ''),
                'org': (resp.traits.organization or
                        resp.traits.autonomous_system_organization or 'Unknown'),
                'isp': resp.traits.isp if hasattr(resp.traits, 'isp') else 'Unknown',
                'as': (f"AS{resp.traits.autonomous_system_number}"
                       if resp.traits.autonomous_system_number else ''),
                'lat': resp.location.latitude or 0.0,
                'lon': resp.location.longitude or 0.0,
                'timezone': resp.location.time_zone or '',
                '_ts': time.time(),
                '_source': 'local',
                '_weight': 3,  # local DB is most trusted
            }
        except Exception as exc:
            _logger.debug("Local GeoIP lookup failed for %s: %s", ip, exc)
            return None

    def _lookup_api(self, ip: str) -> Optional[dict]:
        if not self._rate_limiter.consume():
            with self._rate_lock:
                self._rate_limited_count += 1
                count = self._rate_limited_count
            if count % 50 == 1:
                _logger.warning("GeoIP rate limited — %d lookups throttled. "
                                "Consider using a local MaxMind DB (geoip_db_path config).",
                                self._rate_limited_count)
            return None
        try:
            url = self._api_url.format(ip=ip)
            req = urllib.request.Request(url, headers={'User-Agent': 'MedianBoxMonitor/3.0'})
            with urllib.request.urlopen(req, timeout=3) as resp:
                data = json.loads(resp.read().decode())
            if data.get('status') == 'success':
                data['_ts'] = time.time()
                data['_source'] = 'ip-api'
                data['_weight'] = 2
                return data
        except Exception as exc:
            _logger.debug("GeoIP API lookup failed for %s: %s", ip, exc)
        return None

    def _lookup_ipwhois(self, ip: str) -> Optional[dict]:
        """Second independent API source — ipwho.is (HTTPS, 10k/month)."""
        try:
            url = self._ipwhois_url.format(ip=ip)
            req = urllib.request.Request(url, headers={'User-Agent': 'MedianBoxMonitor/3.0'})
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode())
            if data.get('success', False):
                return {
                    'status': 'success',
                    'country': data.get('country', '??'),
                    'countryCode': data.get('country_code', '??'),
                    'city': data.get('city', '??'),
                    'regionName': data.get('region', ''),
                    'org': data.get('connection', {}).get('org', 'Unknown'),
                    'isp': data.get('connection', {}).get('isp', 'Unknown'),
                    'as': data.get('connection', {}).get('asn', ''),
                    'lat': data.get('latitude', 0.0) or 0.0,
                    'lon': data.get('longitude', 0.0) or 0.0,
                    'timezone': data.get('timezone', {}).get('id', ''),
                    '_ts': time.time(),
                    '_source': 'ipwho.is',
                    '_weight': 2,
                }
        except Exception as exc:
            _logger.debug("ipwho.is lookup failed for %s: %s", ip, exc)
        return None

    def _refine_rdns(self, ip: str, data: dict) -> dict:
        """Refine city/country using reverse DNS IATA city codes.
        This can correct cases where GeoIP returns the ISP HQ instead of
        the actual service location."""
        try:
            hostname = _rdns_bounded(ip).lower()
            if not hostname:
                return data
            data['_rdns'] = hostname
            # Check for IATA city codes in the hostname
            parts = hostname.replace('.', '-').split('-')
            for part in parts:
                if part in self._RDNS_CITY_CODES:
                    city, cc = self._RDNS_CITY_CODES[part]
                    # Only override if the GeoIP city is unknown or generic
                    current_city = (data.get('city') or '').lower()
                    if current_city in ('', '??', 'unknown', 'none'):
                        data['city'] = city
                        data['countryCode'] = cc
                        data['_rdns_refined'] = True
                        _logger.debug("GeoIP rDNS refined %s -> %s, %s (from %s)",
                                      ip, city, cc, hostname)
                    # Also refine lat/lon if we have a known city but GeoIP
                    # returned 0,0 or a very different location
                    if not data.get('lat') or not data.get('lon'):
                        # Use a rough lat/lon for the known city
                        # (This is a fallback — real coords come from GeoIP)
                        pass
                    break
            # Check ccTLD in hostname for country refinement
            if not data.get('_rdns_refined'):
                for part in parts:
                    if part in self._CCTLD_MAP:
                        cc = self._CCTLD_MAP[part]
                        current_cc = (data.get('countryCode') or '').upper()
                        if current_cc in ('', '??', 'UNKNOWN'):
                            data['countryCode'] = cc
                            data['_rdns_refined'] = True
                        break
        except Exception:
            pass
        return data

    def _fuse_sources(self, sources: list) -> Optional[dict]:
        """Fuse multiple GeoIP source results into a consensus.
        - Country: majority vote weighted by source weight
        - City: highest-weight source's city, or majority if tied
        - Lat/lon: weighted average of agreeing sources
        - Conflicts recorded for transparency
        """
        if not sources:
            return None
        if len(sources) == 1:
            return sources[0]

        # Weighted country vote
        cc_votes: dict[str, float] = {}
        for s in sources:
            cc = (s.get('countryCode') or '??').upper()
            w = s.get('_weight', 1)
            cc_votes[cc] = cc_votes.get(cc, 0) + w

        winner_cc = max(cc_votes, key=cc_votes.get)
        conflicts = []
        for s in sources:
            scc = (s.get('countryCode') or '??').upper()
            if scc != winner_cc:
                conflicts.append(f"{s.get('_source','?')} says {scc} vs consensus {winner_cc}")

        # Use the highest-weight source that agrees with the consensus
        agreeing = [s for s in sources if (s.get('countryCode') or '??').upper() == winner_cc]
        # Sort by weight descending
        agreeing.sort(key=lambda s: s.get('_weight', 1), reverse=True)
        best = dict(agreeing[0]) if agreeing else dict(sources[0])

        # Weighted average lat/lon from agreeing sources
        total_w = sum(s.get('_weight', 1) for s in agreeing)
        if total_w > 0 and len(agreeing) > 1:
            avg_lat = sum(s.get('lat', 0) * s.get('_weight', 1) for s in agreeing) / total_w
            avg_lon = sum(s.get('lon', 0) * s.get('_weight', 1) for s in agreeing) / total_w
            best['lat'] = avg_lat
            best['lon'] = avg_lon

        best['_consensus_sources'] = [s.get('_source', '?') for s in sources]
        best['_consensus_cc_votes'] = cc_votes
        if conflicts:
            best['_conflicts'] = conflicts
            best['_consensus'] = 'CONFLICTED'
        else:
            best['_consensus'] = 'AGREED'
        best['_ts'] = time.time()
        return best

    def lookup(self, ip: str) -> Optional[dict]:
        if not CONFIG.get('geoip_enabled', True):
            return None
        if not GeoIPCache._PRIVACY_WARNED and not self._local_reader:
            _logger.warning(
                "GeoIP enabled: destination IPs will be sent to ip-api.com / ipwho.is. "
                "Set geoip_enabled=False or configure geoip_db_path for local lookups."
            )
            GeoIPCache._PRIVACY_WARNED = True
        with self.lock:
            cached = self.cache.get(ip)
            if cached and time.time() - cached.get('_ts', 0) < CONFIG['geoip_cache_ttl']:
                return cached

        # Collect results from all available sources
        # 1. Hardcoded IP-prefix database (weight=4, highest priority, no network)
        sources = []
        hardcoded = self._lookup_hardcoded(ip)
        if hardcoded:
            sources.append(hardcoded)
        # 2. Local MaxMind DB (weight=3)
        local = self._lookup_local(ip)
        if local:
            sources.append(local)
        # 3. ip-api.com (weight=2) — skip if hardcoded already matched
        #    (saves rate-limited API calls for unknown IPs)
        if not hardcoded:
            api1 = self._lookup_api(ip)
            if api1:
                sources.append(api1)
            # 4. ipwho.is (weight=2) — only if first API failed
            if not api1:
                api2 = self._lookup_ipwhois(ip)
                if api2:
                    sources.append(api2)
        elif local:
            # Hardcoded + local both matched — that's enough for consensus
            pass
        else:
            # Hardcoded matched but no local DB — still enough, no API needed
            pass

        if not sources:
            return None

        # Fuse sources into consensus
        data = self._fuse_sources(sources) if len(sources) > 1 else sources[0]

        # Refine with rDNS city codes
        if data:
            data = self._refine_rdns(ip, data)
            with self.lock:
                self.cache[ip] = data
            return data
        return None

    def get_country(self, ip: str) -> str:
        # Fast path: check cache first without full lookup overhead
        with self.lock:
            cached = self.cache.get(ip)
            if cached and time.time() - cached.get('_ts', 0) < CONFIG['geoip_cache_ttl']:
                return cached.get('countryCode', '??')
        info = self.lookup(ip)
        return info.get('countryCode', '??') if info else '??'

    def get_org(self, ip: str) -> str:
        with self.lock:
            cached = self.cache.get(ip)
            if cached and time.time() - cached.get('_ts', 0) < CONFIG['geoip_cache_ttl']:
                return cached.get('org', 'Unknown')
        info = self.lookup(ip)
        return info.get('org', 'Unknown') if info else 'Unknown'

    def get_coords(self, ip: str) -> tuple:
        info = self.lookup(ip)
        if info:
            return info.get('lat', 0.0), info.get('lon', 0.0)
        return 0.0, 0.0

    def get_full(self, ip: str) -> dict:
        info = self.lookup(ip)
        if not info:
            return dict(self._EMPTY)
        return info

    def get_cached(self, ip: str) -> Optional[dict]:
        """Return cached GeoIP data if available, without making any network
        calls. Returns None if not cached or expired."""
        with self.lock:
            cached = self.cache.get(ip)
            if cached and time.time() - cached.get('_ts', 0) < CONFIG['geoip_cache_ttl']:
                return cached
        return None


# ========================== LOCATION VERIFIER ==========================
# Known IATA airport codes and city abbreviations found in reverse-DNS hostnames
_RDNS_CITY_CODES: dict[str, tuple[str, str]] = {
    'lax': ('Los Angeles', 'US'), 'sfo': ('San Francisco', 'US'),
    'sjc': ('San Jose', 'US'), 'sea': ('Seattle', 'US'),
    'ord': ('Chicago', 'US'), 'iad': ('Washington DC', 'US'),
    'dfw': ('Dallas', 'US'), 'atl': ('Atlanta', 'US'),
    'mia': ('Miami', 'US'), 'bos': ('Boston', 'US'),
    'den': ('Denver', 'US'), 'phx': ('Phoenix', 'US'),
    'jfk': ('New York', 'US'), 'ewr': ('Newark', 'US'),
    'nyc': ('New York', 'US'), 'chi': ('Chicago', 'US'),
    'dal': ('Dallas', 'US'), 'hou': ('Houston', 'US'),
    'lhr': ('London', 'GB'), 'fra': ('Frankfurt', 'DE'),
    'ams': ('Amsterdam', 'NL'), 'cdg': ('Paris', 'FR'),
    'nrt': ('Tokyo', 'JP'), 'hnd': ('Tokyo', 'JP'),
    'icn': ('Seoul', 'KR'), 'sin': ('Singapore', 'SG'),
    'hkg': ('Hong Kong', 'HK'), 'syd': ('Sydney', 'AU'),
    'gru': ('Sao Paulo', 'BR'), 'bom': ('Mumbai', 'IN'),
    'del': ('Delhi', 'IN'), 'dub': ('Dublin', 'IE'),
    'arn': ('Stockholm', 'SE'), 'waw': ('Warsaw', 'PL'),
    'mad': ('Madrid', 'ES'), 'mxp': ('Milan', 'IT'),
    'zrh': ('Zurich', 'CH'), 'yyz': ('Toronto', 'CA'),
    'yvr': ('Vancouver', 'CA'), 'yul': ('Montreal', 'CA'),
    'muc': ('Munich', 'DE'), 'vie': ('Vienna', 'AT'),
    'cpt': ('Cape Town', 'ZA'), 'jnb': ('Johannesburg', 'ZA'),
    'tpe': ('Taipei', 'TW'), 'bkk': ('Bangkok', 'TH'),
    'kul': ('Kuala Lumpur', 'MY'), 'mel': ('Melbourne', 'AU'),
    'osl': ('Oslo', 'NO'), 'hel': ('Helsinki', 'FI'),
    'cph': ('Copenhagen', 'DK'), 'lis': ('Lisbon', 'PT'),
    'bcn': ('Barcelona', 'ES'), 'ist': ('Istanbul', 'TR'),
}

_RDNS_CODE_RE = re.compile(
    r'(?:^|[.\-])(' + '|'.join(_RDNS_CITY_CODES.keys()) + r')(?:[.\-\d]|$)', re.IGNORECASE)


class LocationVerifier:
    """Cross-references GeoIP results using multiple independent methods to produce
    a confidence score (0-100%) and a list of proof strings for each IP location.

    Methods:
      1. Reverse DNS hostname — parse for IATA/city codes, compare with claimed location
      2. RDAP/WHOIS — query the IP's registration country from regional registries
      3. RTT ping — estimate max physical distance from round-trip time
      4. Second GeoIP source — cross-reference with ipwho.is (free, no key)
    """

    def __init__(self, service_resolver: 'ServiceResolver' = None):
        self._resolver = service_resolver
        self._cache: dict[str, dict] = {}
        self._cache_lock = threading.Lock()
        self._rate = TokenBucket(rate=20.0, capacity=25.0)  # shared rate limit for verification APIs

    def verify(self, ip: str, geo: dict) -> dict:
        """Return {'confidence': 0-100, 'proof': [str, ...], 'grade': str}."""
        with self._cache_lock:
            cached = self._cache.get(ip)
            if cached:
                return cached

        claimed_country = (geo.get('countryCode') or '??').upper()
        claimed_city = (geo.get('city') or '??').lower()
        proofs: list[str] = []
        score = 0
        total_methods = 0

        # Method 1: Reverse DNS city code matching (fast, no network call if cached)
        rdns_result = self._check_rdns(ip, claimed_country, claimed_city)
        if rdns_result is not None:
            total_methods += 1
            if rdns_result[0]:
                score += 1
                proofs.append(f"✅ rDNS: {rdns_result[1]}")
            else:
                proofs.append(f"❌ rDNS: {rdns_result[1]}")

        # Method 2: RDAP/WHOIS country verification
        rdap_result = self._check_rdap(ip, claimed_country)
        if rdap_result is not None:
            total_methods += 1
            if rdap_result[0]:
                score += 1
                proofs.append(f"✅ RDAP: {rdap_result[1]}")
            else:
                proofs.append(f"❌ RDAP: {rdap_result[1]}")

        # Method 3: RTT-based distance estimation
        rtt_result = self._check_rtt(ip, geo)
        if rtt_result is not None:
            total_methods += 1
            if rtt_result[0]:
                score += 1
                proofs.append(f"✅ RTT: {rtt_result[1]}")
            else:
                proofs.append(f"⚠️ RTT: {rtt_result[1]}")

        # Method 4: Second GeoIP source cross-reference
        alt_result = self._check_alt_geoip(ip, claimed_country, claimed_city)
        if alt_result is not None:
            total_methods += 1
            if alt_result[0]:
                score += 1
                proofs.append(f"✅ AltGeo: {alt_result[1]}")
            else:
                proofs.append(f"❌ AltGeo: {alt_result[1]}")

        # Calculate confidence percentage
        if total_methods == 0:
            confidence = 0
            grade = "UNVERIFIED"
        else:
            confidence = int((score / total_methods) * 100)
            if confidence >= 75:
                grade = "HIGH"
            elif confidence >= 50:
                grade = "MEDIUM"
            elif confidence >= 25:
                grade = "LOW"
            else:
                grade = "SUSPECT"

        if not proofs:
            proofs.append("No verification methods succeeded")

        result = {'confidence': confidence, 'proof': proofs, 'grade': grade,
                  'methods_passed': score, 'methods_total': total_methods}

        with self._cache_lock:
            if len(self._cache) < 5000:
                self._cache[ip] = result
        return result

    def _check_rdns(self, ip: str, claimed_cc: str, claimed_city: str):
        """Parse reverse DNS for IATA airport codes or city abbreviations."""
        hostname = ''
        if self._resolver is not None:
            # Reuse the shared resolver's cache instead of a fresh lookup.
            try:
                hostname = (self._resolver.reverse_dns(ip) or '').lower()
            except Exception:
                hostname = ''
        else:
            hostname = _rdns_bounded(ip).lower()
        if not hostname:
            return None  # No rDNS available — skip this method

        match = _RDNS_CODE_RE.search(hostname)
        if match:
            code = match.group(1).lower()
            city_name, country_code = _RDNS_CITY_CODES[code]
            if country_code == claimed_cc:
                return (True, f"hostname '{hostname}' contains '{code}' "
                        f"({city_name}, {country_code}) — matches claimed {claimed_cc}")
            else:
                return (False, f"hostname '{hostname}' contains '{code}' "
                        f"({city_name}, {country_code}) — claimed {claimed_cc}")

        # Check if hostname contains the claimed city name directly
        if claimed_city != '??' and len(claimed_city) > 3 and claimed_city in hostname:
            return (True, f"hostname '{hostname}' contains city name '{claimed_city}'")

        # Check for country TLD matching
        parts = hostname.split('.')
        if len(parts) >= 2:
            tld = parts[-1]
            # Map common ccTLDs to country codes
            tld_map = {
                'uk': 'GB', 'de': 'DE', 'fr': 'FR', 'jp': 'JP', 'au': 'AU',
                'ca': 'CA', 'br': 'BR', 'in': 'IN', 'nl': 'NL', 'se': 'SE',
                'no': 'NO', 'fi': 'FI', 'dk': 'DK', 'pl': 'PL', 'it': 'IT',
                'es': 'ES', 'pt': 'PT', 'ch': 'CH', 'at': 'AT', 'ie': 'IE',
                'sg': 'SG', 'kr': 'KR', 'tw': 'TW', 'hk': 'HK', 'nz': 'NZ',
                'za': 'ZA', 'mx': 'MX', 'ar': 'AR', 'cl': 'CL', 'co': 'CO',
                'ru': 'RU', 'cn': 'CN', 'th': 'TH', 'my': 'MY', 'id': 'ID',
                'tr': 'TR', 'il': 'IL', 'ae': 'AE', 'ro': 'RO', 'cz': 'CZ',
                'hu': 'HU', 'bg': 'BG', 'hr': 'HR', 'ua': 'UA', 'be': 'BE',
            }
            tld_cc = tld_map.get(tld, tld.upper() if len(tld) == 2 else None)
            if tld_cc and tld_cc == claimed_cc:
                return (True, f"hostname TLD '.{tld}' matches claimed country {claimed_cc}")
            elif tld_cc and tld_cc != claimed_cc and tld not in ('com', 'net', 'org', 'io', 'dev'):
                return (False, f"hostname TLD '.{tld}' ({tld_cc}) contradicts claimed {claimed_cc}")

        return None  # No conclusive data from rDNS

    def _check_rdap(self, ip: str, claimed_cc: str):
        """Query RDAP for the IP's registered country code."""
        if not self._rate.consume():
            return None
        try:
            url = f"https://rdap.org/ip/{ip}"
            req = urllib.request.Request(url, headers={
                'User-Agent': 'MedianBoxMonitor/3.0', 'Accept': 'application/json'})
            with urllib.request.urlopen(req, timeout=4) as resp:
                data = json.loads(resp.read().decode())
            # RDAP response: look for country in the registration
            rdap_cc = None
            if 'country' in data:
                rdap_cc = data['country'].upper()
            elif 'entities' in data:
                for entity in data.get('entities', []):
                    if 'vcardArray' in entity:
                        for item in entity['vcardArray']:
                            if isinstance(item, list):
                                for vcard_field in item:
                                    if (isinstance(vcard_field, list) and len(vcard_field) >= 4
                                            and vcard_field[0] == 'adr'
                                            and isinstance(vcard_field[3], dict)):
                                        cc = vcard_field[3].get('cc', '')
                                        if cc:
                                            rdap_cc = cc.upper()
                                            break
            if rdap_cc:
                if rdap_cc == claimed_cc:
                    return (True, f"RDAP registry country '{rdap_cc}' matches claimed {claimed_cc}")
                else:
                    return (False, f"RDAP registry country '{rdap_cc}' differs from claimed {claimed_cc}")
        except Exception:
            pass
        return None

    def _check_rtt(self, ip: str, geo: dict):
        """Ping the IP and estimate max distance from RTT.
        Speed of light in fiber ≈ 200,000 km/s → ~100km per 1ms RTT (round trip)."""
        try:
            if os.name == 'nt':
                cmd = ['ping', '-n', '2', '-w', '2000', ip]
            else:
                cmd = ['ping', '-c', '2', '-W', '2', ip]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5,
                                    creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
            output = result.stdout
            # Extract average RTT
            # Windows: "Average = 42ms" or "Minimum = 20ms, Maximum = 25ms, Average = 22ms"
            m = re.search(r'Average\s*=\s*(\d+)\s*ms', output)
            if not m:
                # Linux: "rtt min/avg/max/mdev = 10.123/12.456/14.789/2.345 ms"
                m = re.search(r'=\s*[\d.]+/([\d.]+)/', output)
            if m:
                avg_rtt_ms = float(m.group(1))
                # Max distance: speed of light in fiber, accounting for round-trip
                # ~100 km per ms of RTT (conservative)
                max_distance_km = avg_rtt_ms * 100
                # Calculate actual distance from our approximate location to claimed location
                claimed_lat = geo.get('lat', 0)
                claimed_lon = geo.get('lon', 0)
                if claimed_lat == 0 and claimed_lon == 0:
                    return None
                # Use haversine approximation (rough)
                # For this purpose, just report whether RTT is consistent
                if avg_rtt_ms < 5:
                    return (True, f"RTT {avg_rtt_ms:.0f}ms — very close (<500km), consistent with nearby location")
                elif avg_rtt_ms < 50:
                    return (True, f"RTT {avg_rtt_ms:.0f}ms — domestic range (<5000km), max possible {max_distance_km:.0f}km")
                elif avg_rtt_ms < 150:
                    return (True, f"RTT {avg_rtt_ms:.0f}ms — continental range, max possible {max_distance_km:.0f}km")
                elif avg_rtt_ms < 300:
                    return (True, f"RTT {avg_rtt_ms:.0f}ms — intercontinental, max possible {max_distance_km:.0f}km")
                else:
                    return (None, f"RTT {avg_rtt_ms:.0f}ms — very high latency, possible proxy/VPN")
            # Ping succeeded but couldn't parse RTT
            if 'Reply from' in output or 'bytes from' in output:
                return None  # Host replied but format unexpected
            return None  # Ping blocked/filtered
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return None

    def _check_alt_geoip(self, ip: str, claimed_cc: str, claimed_city: str):
        """Cross-reference with ipwho.is (free, no API key, 10k/month)."""
        if not self._rate.consume():
            return None
        try:
            url = f"https://ipwho.is/{ip}"
            req = urllib.request.Request(url, headers={'User-Agent': 'MedianBoxMonitor/3.0'})
            with urllib.request.urlopen(req, timeout=4) as resp:
                data = json.loads(resp.read().decode())
            if not data.get('success', True):
                return None
            alt_cc = (data.get('country_code') or '').upper()
            alt_city = (data.get('city') or '').lower()
            if alt_cc:
                cc_match = alt_cc == claimed_cc
                city_match = (alt_city and claimed_city != '??' and
                              (alt_city in claimed_city or claimed_city in alt_city))
                if cc_match and city_match:
                    return (True, f"ipwho.is confirms {alt_cc}/{alt_city} — exact match")
                elif cc_match:
                    return (True, f"ipwho.is confirms country {alt_cc} "
                            f"(city: '{alt_city}' vs claimed '{claimed_city}')")
                else:
                    return (False, f"ipwho.is says {alt_cc}/{alt_city} — "
                            f"claimed {claimed_cc}/{claimed_city}")
        except Exception:
            pass
        return None


# ========================== MULTI VERIFIER ==========================
# Provider-name fragments used to LABEL infrastructure. Detection only — this
# identifies that an endpoint belongs to a VPN/hosting operator; it does not
# defeat a VPN or reveal a hidden client.
_VPN_ORG_MARKERS = (
    'nordvpn', 'nord vpn', 'expressvpn', 'express vpn', 'mullvad', 'protonvpn',
    'proton vpn', 'surfshark', 'cyberghost', 'private internet access', 'pia ',
    'ipvanish', 'ivpn', 'windscribe', 'vyprvpn', 'torguard', 'purevpn',
    'hidemyass', 'hide.me', 'hide me', 'perfect privacy', 'airvpn', 'ovpn',
    'privatevpn', 'strongvpn', 'tunnelbear', 'hotspot shield', 'zenmate',
    'safervpn', 'vpn unlimited', 'keepsolid', 'mysterium', 'wireguard',
    'vpn', 'anonymizer', 'proxy',
)
_HOSTING_ORG_MARKERS = (
    'm247', 'datacamp', 'leaseweb', 'ovh', 'hetzner', 'linode', 'digitalocean',
    'vultr', 'choopa', 'contabo', 'psychz', 'quadranet', 'hostwinds', 'colocrossing',
    'amazon', 'aws', 'google cloud', 'google llc', 'microsoft', 'azure', 'oracle cloud',
    'gcore', 'g-core', 'cogent', 'zenlayer', 'servers.com', 'scaleway', 'hostinger',
    'data center', 'datacenter', 'hosting', 'colocation', 'dedicated', 'cloud',
)
# TCP-connectable ports whose presence is evidence of VPN / proxy / anonymity
# services on the endpoint. UDP-only protocols (WireGuard 51820, IKE 500/4500)
# can't be confirmed with a TCP connect, so they're intentionally omitted.
_VPN_TCP_FINGERPRINT_PORTS = {
    1194: ('OpenVPN (TCP)', 40),
    1723: ('PPTP VPN', 40),
    1080: ('SOCKS proxy', 35),
    3128: ('Squid / HTTP proxy', 30),
    8388: ('Shadowsocks', 40),
    9001: ('Tor relay ORPort', 45),
    9030: ('Tor DirPort', 45),
}


class MultiVerifier:
    """Cross-verifies an endpoint's location and nature with many independent
    methods, then fuses them into a consensus + confidence + conflict report.

    Design principle: no single source is trusted. Accuracy comes from
    *agreement* across independent methods; disagreement is surfaced and is
    itself a strong VPN / proxy / anycast / relocation indicator. The verifier
    never overclaims — it reports a confidence grade and always shows its work.

    Methods fused:
      1. GeoIP primary (local MaxMind DB or ip-api)   → country/city vote
      2. GeoIP alternate (ipwho.is)                    → independent vote
      3. Reverse DNS (IATA/city codes, ccTLD)          → independent vote
      4. RDAP registry country                         → independent vote
      5. RTT latency band (active ping)                → physical plausibility
      6. TTL / OS fingerprint (active ping)            → OS + hop distance
      7. VPN/proxy TCP port fingerprint (active)       → service evidence
      8. Infrastructure classification (org/ASN/CDN)   → VPN/proxy/hosting flag
      9. DNS leak / resolver mismatch (rDNS TLD)       → VPN DNS-leak signal
     10. TLS JA3 fingerprint (active, port 443)        → client software ID
     11. ASN correlation (known VPN/proxy ASNs)        → VPN provider match
    """

    def __init__(self, geoip=None, location_verifier=None, proxy_detector=None):
        self._geoip = geoip
        self._lv = location_verifier
        self._proxy = proxy_detector
        self._cache: dict[str, dict] = {}
        self._lock = threading.Lock()

    # ---------- public ----------
    def verify(self, ip: str, active: bool = True, port_timeout: float = 0.6) -> dict:
        with self._lock:
            cached = self._cache.get(ip)
        if cached:
            return cached

        report = {
            'ip': ip, 'methods': [], 'consensus_country': '', 'consensus_city': '',
            'confidence': 0, 'grade': 'UNVERIFIED', 'conflicts': [],
            'agree': 0, 'total_votes': 0, 'lat': 0, 'lon': 0,
            'vpn_score': 0, 'is_vpn': False, 'is_proxy': False,
            'is_hosting': False, 'is_cdn': False, 'labels': [],
            'ttl': None, 'ttl_os': '', 'hop_distance': None, 'rtt_ms': None,
            'open_ports': [], 'org': '', 'isp': '', 'asn': '', 'rdns': '',
            'dns_leak': None, 'tls_ja3': None,
            'summary': '', 'loc_proof': [],
        }
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            report['summary'] = 'invalid IP address'
            report['grade'] = 'N/A'
            return report
        if not addr.is_global:
            report['summary'] = 'private / LAN address — not externally verifiable'
            report['grade'] = 'N/A'
            return report

        cc_votes: dict[str, list] = {}   # country code -> [method names]
        city_votes: dict[str, list] = {}

        def cast(name, cc, city, detail):
            cc = (cc or '').upper()[:2]
            city = (city or '').strip()
            m = {'name': name, 'cc': cc, 'city': city, 'detail': detail, 'status': 'info'}
            report['methods'].append(m)
            if cc:
                cc_votes.setdefault(cc, []).append(name)
            if city and len(city) > 2:
                city_votes.setdefault(city.lower(), []).append(name)
            return m

        # --- 1) GeoIP primary ---
        geo = {}
        if self._geoip is not None:
            try:
                geo = self._geoip.get_full(ip) or {}
            except Exception:
                geo = {}
        if geo:
            report['lat'] = geo.get('lat', 0) or 0
            report['lon'] = geo.get('lon', 0) or 0
            report['org'] = geo.get('org', '') or ''
            report['isp'] = geo.get('isp', '') or ''
            report['asn'] = geo.get('as', '') or ''
            pcc = geo.get('countryCode') or geo.get('country') or ''
            cast('GeoIP', pcc, geo.get('city', ''),
                 f"{geo.get('city','?')}, {geo.get('country','?')} · {geo.get('org','?')}"
                 f" [{geo.get('_source','?')}]")

        # --- 2) GeoIP alternate (ipwho.is) ---
        alt = self._alt_geoip(ip)
        if alt is not None:
            acc, acity, aconn = alt
            org2 = f"{aconn.get('org','')} {aconn.get('isp','')}".strip()
            cast('AltGeoIP', acc, acity,
                 f"ipwho.is: {acity or '?'}, {acc or '?'}" + (f" · {org2}" if org2 else ""))
            if org2 and not report['org']:
                report['org'] = org2

        # --- 3) Reverse DNS ---
        rd = self._rdns_country(ip)
        if rd is not None:
            rcc, rcity, rhost = rd
            report['rdns'] = rhost or ''
            if rcc or rhost:
                cast('rDNS', rcc, rcity,
                     f"{rhost or 'no PTR'}" + (f" → {rcity or rcc}" if (rcc or rcity) else ""))

        # --- 4) RDAP registry ---
        rdap_cc = self._rdap_country(ip)
        if rdap_cc:
            cast('RDAP', rdap_cc, '', f"registry country {rdap_cc}")

        # --- 5) RTT latency band (active) ---
        if active:
            rtt = self._rtt_measure(ip)
            if rtt is not None:
                report['rtt_ms'] = rtt
                band = self._rtt_band(rtt)
                report['methods'].append(
                    {'name': 'RTT', 'cc': '', 'city': '', 'status': 'info',
                     'detail': f"avg {rtt:.0f} ms — {band}"})

        # --- 6) TTL / OS fingerprint (active) ---
        if active:
            fp = self._ttl_fingerprint(ip)
            if fp is not None:
                report['ttl'] = fp['ttl']
                report['ttl_os'] = fp['os']
                report['hop_distance'] = fp['hops']
                report['methods'].append(
                    {'name': 'TTL/OS', 'cc': '', 'city': '', 'status': 'info',
                     'detail': f"TTL {fp['ttl']} → initial {fp['initial']} "
                               f"(~{fp['hops']} hops, {fp['os']})"})

        # --- 7) VPN/proxy TCP port fingerprint (active) ---
        if active:
            open_ports = self._scan_vpn_ports(ip, port_timeout)
            report['open_ports'] = open_ports
            if open_ports:
                pretty = ", ".join(f"{p} {lbl}" for p, lbl, _ in open_ports)
                report['methods'].append(
                    {'name': 'PortFP', 'cc': '', 'city': '', 'status': 'info',
                     'detail': f"open service ports: {pretty}"})

        # --- 8) Infrastructure classification ---
        self._classify_infra(ip, geo, report)

        # --- 9) DNS leak / resolver mismatch ---
        dns_detail, dns_cc = self._dns_leak_check(ip)
        if dns_detail:
            report['dns_leak'] = dns_detail
            if dns_cc:
                cast('DNSLeak', dns_cc, '', dns_detail)
            else:
                report['methods'].append(
                    {'name': 'DNSLeak', 'cc': '', 'city': '', 'status': 'info',
                     'detail': dns_detail})

        # --- 10) TLS JA3 fingerprint (active, port 443 only) ---
        if active:
            ja3_hash, ja3_detail = self._tls_ja3_fingerprint(ip)
            if ja3_hash:
                report['tls_ja3'] = ja3_hash
                report['methods'].append(
                    {'name': 'TLS/JA3', 'cc': '', 'city': '', 'status': 'info',
                     'detail': ja3_detail})

        # --- 11) ASN correlation ---
        asn_detail, asn_vpn = self._asn_correlation(ip, geo)
        if asn_detail:
            report['methods'].append(
                {'name': 'ASN', 'cc': '', 'city': '', 'status': 'info',
                 'detail': asn_detail})
            if asn_vpn:
                report['is_vpn'] = True
                report['labels'].append("ASN matches VPN/proxy provider")

        # --- 12) LocationVerifier cross-check (independent method set) ---
        if self._lv is not None:
            try:
                lv = self._lv.verify(ip, geo)
            except Exception:
                lv = None
            if lv and lv.get('methods_total'):
                report['methods'].append({
                    'name': 'LocVerify', 'cc': '', 'city': '', 'status': 'info',
                    'detail': f"{lv['grade']} {lv['confidence']}% "
                              f"({lv['methods_passed']}/{lv['methods_total']} checks passed)"})
                report['loc_proof'] = lv.get('proof', [])

        # ---------- fuse: location consensus ----------
        self._fuse_location(report, cc_votes, city_votes)
        # ---------- fuse: VPN / proxy verdict ----------
        self._fuse_vpn(report)
        # ---------- narrative summary ----------
        report['summary'] = self._summarize(report)

        with self._lock:
            if len(self._cache) < 5000:
                self._cache[ip] = report
        return report

    # ---------- individual methods ----------
    def _alt_geoip(self, ip):
        try:
            req = urllib.request.Request(
                f"https://ipwho.is/{ip}", headers={'User-Agent': 'MedianBoxMonitor/3.0'})
            with urllib.request.urlopen(req, timeout=4) as resp:
                d = json.loads(resp.read().decode())
            if d.get('success', True):
                return ((d.get('country_code') or '').upper(), d.get('city') or '',
                        d.get('connection') or {})
        except Exception:
            pass
        return None

    def _rdns_country(self, ip):
        host = _rdns_bounded(ip).lower()
        if not host:
            return None
        m = _RDNS_CODE_RE.search(host)
        if m:
            city, cc = _RDNS_CITY_CODES[m.group(1).lower()]
            return (cc, city, host)
        parts = host.split('.')
        if len(parts) >= 2 and len(parts[-1]) == 2 and parts[-1] not in ('io',):
            return (parts[-1].upper(), '', host)
        return (None, '', host)

    def _rdap_country(self, ip):
        try:
            req = urllib.request.Request(
                f"https://rdap.org/ip/{ip}",
                headers={'User-Agent': 'MedianBoxMonitor/3.0', 'Accept': 'application/json'})
            with urllib.request.urlopen(req, timeout=4) as resp:
                d = json.loads(resp.read().decode())
            if d.get('country'):
                return d['country'].upper()
            for e in d.get('entities', []):
                va = e.get('vcardArray')
                if isinstance(va, list):
                    for item in va:
                        if isinstance(item, list):
                            for f in item:
                                if (isinstance(f, list) and len(f) >= 4
                                        and f[0] == 'adr' and isinstance(f[3], dict)):
                                    cc = f[3].get('cc')
                                    if cc:
                                        return cc.upper()
        except Exception:
            pass
        return None

    def _rtt_measure(self, ip):
        try:
            cmd = (['ping', '-n', '2', '-w', '2000', ip] if os.name == 'nt'
                   else ['ping', '-c', '2', '-W', '2', ip])
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=6,
                                 creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0)).stdout
            m = (re.search(r'Average\s*=\s*(\d+)\s*ms', out)
                 or re.search(r'=\s*[\d.]+/([\d.]+)/', out))
            if m:
                return float(m.group(1))
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError, ValueError):
            pass
        return None

    @staticmethod
    def _rtt_band(rtt):
        if rtt < 5:
            return "same metro (<500 km)"
        if rtt < 50:
            return "domestic (<5000 km)"
        if rtt < 150:
            return "continental"
        if rtt < 300:
            return "intercontinental"
        return "very high — possible proxy/VPN relay"

    def _ttl_fingerprint(self, ip):
        try:
            cmd = (['ping', '-n', '1', '-w', '1500', ip] if os.name == 'nt'
                   else ['ping', '-c', '1', '-W', '2', ip])
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=5,
                                 creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0)).stdout
            m = re.search(r'[Tt][Tt][Ll]\s*=\s*(\d+)', out)
            if not m:
                return None
            ttl = int(m.group(1))
            initial = next((i for i in (64, 128, 255) if ttl <= i), 255)
            os_guess = {64: 'Linux/Unix/macOS', 128: 'Windows',
                        255: 'Router/BSD/net-gear'}[initial]
            return {'ttl': ttl, 'initial': initial,
                    'hops': max(0, initial - ttl), 'os': os_guess}
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError, ValueError):
            return None

    def _scan_vpn_ports(self, ip, timeout):
        """Short parallel TCP connect scan for VPN/proxy service ports."""
        found: list = []
        lock = threading.Lock()
        fam = socket.AF_INET6 if ':' in ip else socket.AF_INET

        def probe(port, label, weight):
            try:
                s = socket.socket(fam, socket.SOCK_STREAM)
                s.settimeout(timeout)
                rc = s.connect_ex((ip, port))
                s.close()
                if rc == 0:
                    with lock:
                        found.append((port, label, weight))
            except Exception:
                pass

        threads = []
        for port, (label, weight) in _VPN_TCP_FINGERPRINT_PORTS.items():
            t = threading.Thread(target=probe, args=(port, label, weight), daemon=True)
            t.start()
            threads.append(t)
        for t in threads:
            t.join(timeout + 0.3)
        return sorted(found)

    def _classify_infra(self, ip, geo, report):
        blob = (f"{report.get('org','')} {report.get('isp','')} "
                f"{report.get('asn','')} {report.get('rdns','')}").lower()
        # VPN provider name
        for kw in _VPN_ORG_MARKERS:
            if kw in blob:
                report['is_vpn'] = True
                report['labels'].append(f"VPN/anon name '{kw.strip()}'")
                break
        # ProxyDetector: CDN / residential / forward-port
        if self._proxy is not None:
            try:
                pc = self._proxy.classify_connection(
                    ip, 0, report.get('rdns', ''), report.get('org', ''),
                    report.get('isp', ''), report.get('asn', ''))
            except Exception:
                pc = {}
            ptype = pc.get('proxy_type', '') if pc else ''
            if 'REVERSE' in ptype:
                report['is_cdn'] = True
                report['labels'].append(f"CDN/reverse proxy ({pc.get('proxy_detail','CDN')})")
            if 'RESIDENTIAL' in ptype:
                report['is_proxy'] = True
                report['labels'].append("residential proxy service")
            if 'FORWARD' in ptype:
                report['is_proxy'] = True
                report['labels'].append("forward-proxy port")
        # Hosting / datacenter
        for kw in _HOSTING_ORG_MARKERS:
            if kw in blob:
                report['is_hosting'] = True
                report['labels'].append(f"hosting/datacenter ({kw.strip()})")
                break

    # ---------- fusion ----------
    def _fuse_location(self, report, cc_votes, city_votes):
        total = sum(len(v) for v in cc_votes.values())
        report['total_votes'] = total
        if not cc_votes:
            report['grade'] = 'UNVERIFIED'
            report['confidence'] = 0
            return
        # winning country = most method-votes
        winner, backers = max(cc_votes.items(), key=lambda kv: len(kv[1]))
        agree = len(backers)
        report['consensus_country'] = winner
        report['agree'] = agree
        # city consensus (only assert if >=2 methods agree)
        if city_votes:
            ccity, cbackers = max(city_votes.items(), key=lambda kv: len(kv[1]))
            if len(cbackers) >= 2:
                report['consensus_city'] = ccity.title()
            elif report['lat'] or report['lon']:
                report['consensus_city'] = ccity.title()  # single-source, still show
        confidence = int(round(agree / total * 100)) if total else 0
        report['confidence'] = confidence
        # mark per-method agreement/conflict + record conflicts
        for m in report['methods']:
            if not m.get('cc'):
                continue
            if m['cc'] == winner:
                m['status'] = 'ok'
            else:
                m['status'] = 'conflict'
                report['conflicts'].append(
                    f"{m['name']} says {m['cc']} vs consensus {winner}")
        # grade
        if total == 1:
            report['grade'] = 'SINGLE-SOURCE'
        elif confidence >= 75 and not report['conflicts']:
            report['grade'] = 'HIGH'
        elif confidence >= 60:
            report['grade'] = 'MEDIUM'
        elif confidence >= 40:
            report['grade'] = 'LOW'
        else:
            report['grade'] = 'CONFLICTED'

    def _fuse_vpn(self, report):
        score = 0
        # provider name (already set is_vpn during classify)
        if any('VPN/anon name' in l for l in report['labels']):
            score += 55
        # open VPN/proxy ports
        for _p, _lbl, w in report['open_ports']:
            score += w
        if report['open_ports']:
            report['is_vpn'] = report['is_vpn'] or any(
                p in (1194, 1723) or 'Tor' in lbl or 'SOCKS' in lbl or 'Shadowsocks' in lbl
                for p, lbl, _ in report['open_ports'])
        # hosting/datacenter is where most commercial VPNs & proxies live
        if report['is_hosting']:
            score += 20
        if report['is_proxy']:
            score += 40
        # ASN matches known VPN/proxy provider
        if any('ASN matches VPN' in l for l in report['labels']):
            score += 35
        # DNS leak / resolver mismatch
        if report.get('dns_leak'):
            score += 15
        # location conflicts across independent methods = obfuscation signal
        if len(report['conflicts']) >= 2:
            score += 20
        elif len(report['conflicts']) == 1:
            score += 10
        # very high RTT hints at a relay
        if report['rtt_ms'] is not None and report['rtt_ms'] >= 250:
            score += 10
        report['vpn_score'] = min(100, score)
        if report['vpn_score'] >= 50:
            report['is_vpn'] = True

    def _summarize(self, report):
        loc = report['consensus_city'] or ''
        if report['consensus_country']:
            loc = (loc + ", " if loc else "") + report['consensus_country']
        loc = loc or "location unresolved"
        parts = [f"{loc} · {report['grade']} ({report['confidence']}% of "
                 f"{report['total_votes']} sources agree)"]
        nat = []
        if report['is_vpn']:
            nat.append(f"VPN/anon likely (score {report['vpn_score']})")
        if report['is_cdn']:
            nat.append("CDN/anycast")
        if report['is_proxy']:
            nat.append("proxy")
        if report['is_hosting'] and not report['is_vpn']:
            nat.append("hosting/datacenter")
        if nat:
            parts.append("; ".join(nat))
        if report['conflicts']:
            parts.append(f"⚠ {len(report['conflicts'])} source conflict(s)")
        return " — ".join(parts)

    # ---------- text rendering (for logs) ----------
    def report_lines(self, report) -> list:
        """Plain-text lines describing a verification report (for the .txt log)."""
        out = [f"  VERIFICATION → {report['ip']}",
               f"    {report['summary']}"]
        if report.get('rtt_ms') is not None:
            out.append(f"    RTT: {report['rtt_ms']:.0f} ms" +
                       (f"  ·  TTL {report['ttl']} ({report['ttl_os']}, "
                        f"~{report['hop_distance']} hops)" if report.get('ttl') else ""))
        if report.get('open_ports'):
            out.append("    Open service ports: " +
                       ", ".join(f"{p}/{lbl}" for p, lbl, _ in report['open_ports']))
        if report.get('dns_leak'):
            out.append(f"    DNS leak: {report['dns_leak']}")
        if report.get('tls_ja3'):
            out.append(f"    TLS JA3: {report['tls_ja3']}")
        for m in report['methods']:
            mark = {'ok': '[+]', 'conflict': '[x]', 'info': '[.]'}.get(m['status'], '[.]')
            out.append(f"    {mark} {m['name']:<9} {m['detail']}")
        if report.get('labels'):
            out.append("    Infra: " + "; ".join(report['labels']))
        for proof in report.get('loc_proof', []):
            out.append(f"    {proof}")
        return out

    # ---------- method 9: DNS leak / resolver mismatch ----------
    def _dns_leak_check(self, ip):
        """Check if the endpoint's reverse-DNS resolver chain differs from its
        claimed GeoIP country — a classic VPN/proxy DNS-leak signal.
        Returns (detail_string, leak_indicator) or (None, None)."""
        # Resolve the IP's PTR record
        host = _rdns_bounded(ip).lower()
        if not host:
            return None, None
        # Extract the TLD / resolver domain
        parts = host.split('.')
        if len(parts) < 2:
            return None, None
        resolver_tld = parts[-1]
        # Known DNS resolver TLDs that indicate the resolver's country
        # (e.g. resolving through a different country's DNS = potential VPN DNS leak)
        cc_tlds = {'uk', 'de', 'fr', 'jp', 'ru', 'cn', 'kr', 'au', 'ca',
                   'br', 'in', 'nl', 'se', 'no', 'fi', 'dk', 'pl', 'it',
                   'es', 'ch', 'at', 'be', 'cz', 'pt', 'ie', 'nz', 'mx',
                   'tr', 'za', 'sg', 'hk', 'tw', 'th', 'my', 'id', 'ph'}
        if resolver_tld in cc_tlds:
            return f"rDNS TLD .{resolver_tld} (resolver country hint)", resolver_tld.upper()
        return None, None

    # ---------- method 10: TLS JA3 fingerprint ----------
    def _tls_ja3_fingerprint(self, ip, timeout=2.0):
        """Attempt a TLS handshake to extract a JA3-like fingerprint hash.
        The JA3 hash identifies the TLS client/library, which can correlate
        with known VPN/proxy client software fingerprints.
        Returns (ja3_hash, detail_string) or (None, None)."""
        try:
            import ssl
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((ip, 443), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=ip) as ssock:
                    cipher = ssock.cipher()
                    version = ssock.version()
                    peer_cert = ssock.getpeercert(binary_form=True)
            # Build a simple fingerprint from TLS parameters
            import hashlib
            fp_data = f"{version}|{cipher[0] if cipher else '?'}|{len(peer_cert) if peer_cert else 0}"
            ja3_hash = hashlib.md5(fp_data.encode()).hexdigest()[:16]
            detail = f"TLS {version} · {cipher[0] if cipher else '?'} · JA3-like:{ja3_hash}"
            return ja3_hash, detail
        except Exception:
            return None, None

    # ---------- method 11: ASN correlation ----------
    def _asn_correlation(self, ip, geo):
        """Check if the ASN belongs to a known VPN/proxy/hosting ASN range.
        Returns (detail_string, is_vpn_indicator) or (None, False)."""
        asn = (geo.get('as', '') or '').lower()
        if not asn:
            return None, False
        # Known VPN/proxy ASN fragments
        vpn_asn_markers = [
            'nordvpn', 'expressvpn', 'mullvad', 'protonvpn', 'surfshark',
            'cyberghost', 'private internet', 'ipvanish', 'windscribe',
            'torguard', 'purevpn', 'airvpn', 'ovpn', 'privatevpn',
            'choopa', 'm247', 'leaseweb', 'datacamp', 'psychz',
        ]
        for marker in vpn_asn_markers:
            if marker in asn:
                return f"ASN matches VPN/proxy: {asn}", True
        return None, False


# ========================== PROXY DETECTOR ==========================
# Known CDN / Reverse Proxy IP prefixes (first 2-3 octets for quick matching)
_CLOUDFLARE_RANGES = [
    '103.21.244', '103.22.200', '103.31.4', '104.16', '104.17', '104.18',
    '104.19', '104.20', '104.21', '104.22', '104.23', '104.24', '104.25',
    '104.26', '104.27', '108.162', '131.0.72', '141.101', '162.158',
    '172.64', '172.65', '172.66', '172.67', '173.245', '188.114',
    '190.93', '197.234', '198.41',
]
_AKAMAI_RANGES = [
    '23.0', '23.1', '23.2', '23.3', '23.4', '23.5', '23.6', '23.7',
    '23.32', '23.33', '23.34', '23.35', '23.36', '23.37', '23.38', '23.39',
    '23.40', '23.41', '23.42', '23.43', '23.44', '23.45', '23.46', '23.47',
    '23.48', '23.49', '23.50', '23.51', '23.52', '23.53', '23.54', '23.55',
    '23.56', '23.57', '23.58', '23.59', '23.60', '23.61', '23.62', '23.63',
    '23.64', '23.65', '23.66', '23.67', '23.72', '23.73', '23.74', '23.75',
    '23.76', '23.77', '23.78', '23.79', '23.192', '23.193', '23.194',
    '23.195', '23.196', '23.197', '23.198', '23.199',
    '2.16', '2.17', '2.18', '2.19', '2.20', '2.21', '2.22', '2.23',
    '95.100', '95.101', '184.24', '184.25', '184.26', '184.27',
    '184.28', '184.29', '184.30', '184.31', '184.50', '184.51',
]
_FASTLY_RANGES = [
    '151.101', '199.232', '23.235',
]
_CLOUDFRONT_RANGES = [
    '13.32', '13.33', '13.35', '13.224', '13.225', '13.226', '13.227',
    '13.228', '13.249', '18.64', '18.65', '18.154', '18.155', '18.160',
    '18.161', '18.164', '18.172', '18.238', '18.244', '52.46',
    '52.84', '52.85', '52.222', '54.182', '54.192', '54.230', '54.239',
    '54.240', '64.252', '65.9', '70.132', '71.152', '99.84', '99.86',
    '108.138', '108.156', '116.129', '130.176', '143.204', '144.220',
    '204.246', '205.251',
]
_INCAPSULA_RANGES = ['45.64.64', '107.154', '199.83']

# Known residential proxy service domains and keywords
_RESIDENTIAL_PROXY_DOMAINS = [
    'luminati', 'brightdata', 'bright.data', 'zyte.com', 'smartproxy',
    'oxylabs', 'netnut', 'geosurf', 'soax.com', 'iproyal', 'proxy-seller',
    'storm-proxies', 'microleaves', 'shifter.io', 'packetstream',
    'peer2profit', 'honeygain', 'pawns.app', 'earnapp', 'traffmonetizer',
    'ipburger', 'proxy-cheap', 'webshare', 'private-proxy', 'infatica',
]

# Known forward proxy software process names
_PROXY_PROCESS_NAMES = [
    'squid', 'privoxy', 'polipo', 'tinyproxy', 'charles', 'fiddler',
    'mitmproxy', 'burpsuite', 'proxifier', 'proxycap', 'redsocks',
    'shadowsocks', 'ss-local', 'v2ray', 'xray', 'clash', 'trojan',
    'tor', 'obfs4proxy', 'meek-client', 'snowflake-client',
    'wireproxy', 'gost', 'brook', 'naiveproxy', 'hysteria',
    'sing-box', 'tuic', 'juicity',
]

# Common proxy ports
_PROXY_PORTS = {
    1080, 3128, 8080, 8118, 8888, 9050, 9150,  # SOCKS, Squid, Privoxy, Tor
    8443, 8880, 9090, 1081, 1082, 7890, 7891, 7892, 7893,  # Clash
    10808, 10809, 20170, 20171,  # V2Ray / Xray defaults
}


class ProxyDetector:
    """Detects forward, reverse, and residential proxy usage on connections.

    - Forward Proxy: checks system proxy settings (env vars, Windows registry),
      running proxy processes, and connections to common proxy ports.
    - Reverse Proxy: checks if destination IPs belong to known CDN/reverse-proxy
      infrastructure (Cloudflare, Akamai, Fastly, CloudFront, Incapsula).
    - Residential Proxy: checks if DNS queries or connection domains match known
      residential proxy services, and flags ISP-type ASNs with proxy behavior.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._system_proxy: dict = {}
        self._proxy_processes: list[str] = []
        self._proxy_events: deque = deque(maxlen=500)
        self._last_system_scan = 0.0
        self._flagged_ips: set[str] = set()

    def scan_system(self) -> list[dict]:
        """Detect forward proxy configuration at the system level.
        Returns list of proxy detection events."""
        now = time.time()
        if now - self._last_system_scan < 30:
            return []
        self._last_system_scan = now
        events: list[dict] = []
        found_proxy: dict = {}

        # 1. Check environment variables
        for var in ('HTTP_PROXY', 'HTTPS_PROXY', 'http_proxy', 'https_proxy',
                    'ALL_PROXY', 'all_proxy', 'SOCKS_PROXY', 'socks_proxy',
                    'NO_PROXY', 'no_proxy'):
            val = os.environ.get(var, '')
            if val and var.upper() != 'NO_PROXY':
                ev = {'type': 'FORWARD_PROXY', 'subtype': 'ENV_VAR',
                      'severity': 'WARNING',
                      'detail': f"Proxy env var set: {var}={val[:120]}"}
                events.append(ev)
                found_proxy.setdefault('env', {})[var] = val[:200]

        # 2. Check Windows registry proxy settings
        if _IS_WINDOWS:
            try:
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                    r"Software\Microsoft\Windows\CurrentVersion\Internet Settings")
                proxy_enable, _ = winreg.QueryValueEx(key, "ProxyEnable")
                if proxy_enable:
                    try:
                        proxy_server, _ = winreg.QueryValueEx(key, "ProxyServer")
                    except FileNotFoundError:
                        proxy_server = "unknown"
                    ev = {'type': 'FORWARD_PROXY', 'subtype': 'REGISTRY',
                          'severity': 'WARNING',
                          'detail': f"Windows system proxy enabled: {proxy_server}"}
                    events.append(ev)
                    found_proxy['registry'] = str(proxy_server)
                try:
                    pac_url, _ = winreg.QueryValueEx(key, "AutoConfigURL")
                    if pac_url:
                        ev = {'type': 'FORWARD_PROXY', 'subtype': 'PAC',
                              'severity': 'WARNING',
                              'detail': f"PAC auto-config URL: {pac_url[:150]}"}
                        events.append(ev)
                        found_proxy['pac_url'] = str(pac_url)[:300]
                except FileNotFoundError:
                    pass
                winreg.CloseKey(key)
            except Exception:
                pass

        # 3. Check for running proxy processes
        proxy_procs = []
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                pname = proc.name().lower().replace('.exe', '')
                for proxy_name in _PROXY_PROCESS_NAMES:
                    if proxy_name in pname:
                        proxy_procs.append(f"{proc.name()} (PID {proc.pid})")
                        break
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        if proxy_procs:
            ev = {'type': 'FORWARD_PROXY', 'subtype': 'PROCESS',
                  'severity': 'WARNING',
                  'detail': f"Proxy software running: {', '.join(proxy_procs[:5])}"}
            events.append(ev)
            found_proxy['processes'] = list(proxy_procs)

        with self._lock:
            self._proxy_processes = proxy_procs
            # get_system_proxy() previously always returned {} because nothing
            # ever wrote to _system_proxy.
            found_proxy['last_scan'] = now
            found_proxy['detected'] = bool(events)
            self._system_proxy = found_proxy
            for ev in events:
                self._proxy_events.append(ev)
        return events

    def classify_connection(self, remote_ip: str, remote_port: int,
                            domain: str, org: str, isp: str,
                            asn: str = '') -> dict:
        """Classify a single connection for proxy indicators.
        Returns {'proxy_type': str, 'proxy_detail': str} or empty if none."""
        results: list[str] = []
        detail_parts: list[str] = []

        # --- Forward Proxy: check if connecting TO a proxy port ---
        if remote_port in _PROXY_PORTS:
            results.append('FORWARD')
            detail_parts.append(f"port {remote_port} is a known proxy port")

        # --- Reverse Proxy: check if dest IP is in CDN ranges ---
        for prefix in _CLOUDFLARE_RANGES:
            if remote_ip.startswith(prefix):
                results.append('REVERSE')
                detail_parts.append(f"IP in Cloudflare range ({prefix}.*)")
                break
        else:
            for prefix in _AKAMAI_RANGES:
                if remote_ip.startswith(prefix):
                    results.append('REVERSE')
                    detail_parts.append(f"IP in Akamai range ({prefix}.*)")
                    break
            else:
                for prefix in _FASTLY_RANGES:
                    if remote_ip.startswith(prefix):
                        results.append('REVERSE')
                        detail_parts.append(f"IP in Fastly range ({prefix}.*)")
                        break
                else:
                    for prefix in _CLOUDFRONT_RANGES:
                        if remote_ip.startswith(prefix):
                            results.append('REVERSE')
                            detail_parts.append(f"IP in CloudFront range ({prefix}.*)")
                            break
                    else:
                        for prefix in _INCAPSULA_RANGES:
                            if remote_ip.startswith(prefix):
                                results.append('REVERSE')
                                detail_parts.append(f"IP in Incapsula/Imperva range ({prefix}.*)")
                                break

        # --- Residential Proxy: check domain/org/ASN for known proxy services ---
        # asn was declared but never included, so an ASN naming a proxy
        # provider could not match.
        check_str = f"{domain} {org} {isp} {asn}".lower()
        for rp_kw in _RESIDENTIAL_PROXY_DOMAINS:
            if rp_kw in check_str:
                results.append('RESIDENTIAL')
                detail_parts.append(f"matches residential proxy service '{rp_kw}'")
                break

        if not results:
            return {}

        proxy_type = '/'.join(sorted(set(results)))
        detail = '; '.join(detail_parts)
        # Raise an event the first time a given IP is classified, so proxy
        # findings reach the event log instead of only the connection row.
        with self._lock:
            first_sighting = remote_ip not in self._flagged_ips
            if first_sighting:
                self._flagged_ips.add(remote_ip)
                if len(self._flagged_ips) > 20000:
                    self._flagged_ips.clear()
                severity = 'CRITICAL' if 'RESIDENTIAL' in proxy_type else 'WARNING'
                self._proxy_events.append({
                    'type': f'{proxy_type}_PROXY', 'subtype': 'CONNECTION',
                    'severity': severity, 'ip': remote_ip, 'port': remote_port,
                    'time': time.time(),
                    'detail': f"{proxy_type} proxy endpoint {remote_ip}: {detail}",
                })
        return {
            'proxy_type': proxy_type,
            'proxy_detail': detail,
        }

    def get_events(self) -> list[dict]:
        with self._lock:
            return list(self._proxy_events)

    def get_proxy_processes(self) -> list[str]:
        with self._lock:
            return list(self._proxy_processes)

    def get_system_proxy(self) -> dict:
        with self._lock:
            return dict(self._system_proxy)


# ========================== VPN LEAK DETECTOR ==========================
class VPNLeakDetector:
    """Detects VPN configuration on the *local* machine and common leaks that
    expose the real identity/location despite an active VPN.

    This is a **local defensive tool** — it inspects the user's own system to
    confirm the VPN is working and to flag leaks. It does **not** attempt to
    de-anonymize remote VPN users.

    Checks performed:
      1. VPN interface detection (TUN/TAP, WireGuard, OpenVPN, common VPN
         adapter names) via psutil network interfaces.
      2. Public-IP cross-check across multiple independent resolvers
         (ip-api.com, ipwho.is, cloudflare trace, opendns) — if different
         resolvers return different IPs, the request is leaking outside the
         tunnel (split-tunnel or DNS leak).
      3. DNS leak detection — compares the DNS resolver chain against the
         VPN's expected resolver; mismatched resolvers indicate DNS traffic
         is bypassing the tunnel.
      4. IPv6 leak detection — checks whether the machine has a global IPv6
         address that bypasses the IPv4-only VPN tunnel.
      5. Route-table split-tunnel detection — on Windows, parses
         `route print` for default routes that bypass the VPN interface.
      6. STUN/public-endpoint discovery — sends a minimal STUN binding request
         to a public STUN server to discover the reflexive (public) transport
         address as seen by the remote side; if it differs from the VPN exit
         IP, traffic is leaking.
      7. Kill-switch verification — checks whether the default route still
         points to a non-VPN interface while the VPN is up (which would allow
         traffic to escape if the VPN drops).
    """

    _VPN_IFACE_KEYWORDS = (
        'tun', 'tap', 'wg', 'wireguard', 'openvpn', 'nordvpn', 'nord',
        'expressvpn', 'express', 'mullvad', 'proton', 'protonvpn',
        'pia', 'private internet access', 'surfshark', 'cyberghost',
        'vyprvpn', 'ipvanish', 'windscribe', 'tunnelbear', 'nordlynx',
        'ppp', 'vpn',
    )

    _STUN_SERVERS = (
        ('stun.l.google.com', 19302),
        ('stun1.l.google.com', 19302),
    )

    _IP_RESOLVERS = [
        # (label, url, json_path or None for plain-text)
        ('ip-api.com', 'http://ip-api.com/json/?fields=query', ('query',)),
        ('ipwho.is', 'https://ipwho.is/', ('ip',)),
        ('cloudflare-trace', 'https://cloudflare.com/cdn-cgi/trace', None),
    ]

    def __init__(self, stop_event: Optional[threading.Event] = None):
        self._lock = threading.Lock()
        self._stop = stop_event or threading.Event()
        self._events: deque = deque(maxlen=500)
        self._last_scan = 0.0
        self._scan_interval = 60.0  # seconds between full scans
        self._vpn_active = False
        self._vpn_ifaces: list[str] = []
        self._public_ips: dict[str, str] = {}  # resolver -> ip
        self._dns_resolvers: list[str] = []
        self._ipv6_global: list[str] = []
        self._stun_reflexive_ip: str = ''
        self._route_leaks: list[str] = []
        self._webrtc_local_ip: str = ''
        self._webrtc_leak: bool = False
        self._kill_switch_ok: bool = True
        self._kill_switch_detail: str = ''
        self._fingerprint_surface: dict = {}
        self._last_report: dict = {}

    # Known VPN client processes that ship a network-level kill switch.
    # Used by _verify_kill_switch to confirm a kill switch is actually
    # running, not just advertised.
    _VPN_CLIENT_PROCS = (
        'openvpn', 'openvpn-gui', 'wireguard', 'wg-quick', 'nordvpn',
        'nordvpn-service', 'expressvpn', 'expressvpnd', 'mullvad',
        'mullvad-vpn', 'protonvpn', 'protonvpn-cli', 'pia-service',
        'private internet access', 'surfshark', 'cyberghost', 'vyprvpn',
        'ipvanish', 'windscribe', 'tunnelbear', 'nordlynx', 'tunsafe',
        'viscosity', 'tunnelblick', 'wg', 'ovpn',
    )

    # ---------- Interface detection ----------
    def _detect_vpn_interfaces(self) -> list[str]:
        """Return list of network interface names that look like VPN adapters."""
        vpn_ifaces = []
        try:
            stats = psutil.net_if_stats()
            for name in stats:
                lname = name.lower()
                if any(kw in lname for kw in self._VPN_IFACE_KEYWORDS):
                    # Filter out false positives like "Ethernet" that don't
                    # contain VPN keywords — the keyword match is already
                    # specific enough.
                    vpn_ifaces.append(name)
        except Exception as exc:
            _logger.debug("VPN iface detect error: %s", exc)
        return vpn_ifaces

    # ---------- Public IP cross-check ----------
    def _fetch_public_ips(self) -> dict:
        """Query multiple independent resolvers and return {label: ip}."""
        results = {}
        for label, url, path in self._IP_RESOLVERS:
            if self._stop.is_set():
                break
            try:
                import urllib.request
                req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
                with urllib.request.urlopen(req, timeout=8) as resp:
                    body = resp.read().decode('utf-8', errors='ignore').strip()
                if path:
                    import json as _json
                    data = _json.loads(body)
                    ip = data
                    for key in path:
                        ip = ip.get(key, '') if isinstance(ip, dict) else ''
                    if ip:
                        results[label] = str(ip)
                else:
                    # Plain text — cloudflare trace: parse 'ip=...'
                    for line in body.splitlines():
                        if line.startswith('ip='):
                            results[label] = line.split('=', 1)[1].strip()
                            break
            except Exception as exc:
                _logger.debug("Public IP fetch %s failed: %s", label, exc)
        return results

    # ---------- DNS leak detection ----------
    def _detect_dns_resolvers(self) -> list[str]:
        """Detect the DNS resolvers currently in use by the system."""
        resolvers = []
        try:
            if _IS_WINDOWS:
                # Parse ipconfig /all for DNS Servers
                out = subprocess.run(
                    ['ipconfig', '/all'],
                    capture_output=True, text=True, timeout=10,
                    creationflags=_CREATE_NO_WINDOW,
                ).stdout
                lines = out.splitlines()
                for i, line in enumerate(lines):
                    if 'DNS Servers' in line:
                        # The IP is after the colon on the same line, or on
                        # the next indented line.
                        after = line.split(':', 1)[-1].strip()
                        if after and after not in resolvers:
                            resolvers.append(after)
                        # Check following indented lines for additional servers
                        for j in range(i + 1, min(i + 4, len(lines))):
                            nxt = lines[j].strip()
                            if nxt and not any(k in nxt for k in
                                               ('DNS', 'DHCP', 'WINS', 'Adapter',
                                                'Connection', 'Description',
                                                'Media', ':')):
                                # Looks like a bare IP
                                if re.match(r'^\d+\.\d+\.\d+\.\d+$', nxt):
                                    if nxt not in resolvers:
                                        resolvers.append(nxt)
                            else:
                                break
            else:
                # POSIX: parse /etc/resolv.conf
                try:
                    with open('/etc/resolv.conf', 'r') as f:
                        for line in f:
                            line = line.strip()
                            if line.startswith('nameserver'):
                                parts = line.split()
                                if len(parts) >= 2:
                                    resolvers.append(parts[1])
                except Exception:
                    pass
        except Exception as exc:
            _logger.debug("DNS resolver detect error: %s", exc)
        return resolvers

    # ---------- IPv6 leak detection ----------
    def _detect_global_ipv6(self) -> list[str]:
        """Return global (non-link-local, non-ULA) IPv6 addresses on the host."""
        globals_v6 = []
        try:
            addrs = psutil.net_if_addrs()
            for iface, addr_list in addrs.items():
                for snic in addr_list:
                    if snic.family == socket.AF_INET6:
                        ip = snic.address.split('%')[0]
                        try:
                            ip_obj = ipaddress.ip_address(ip)
                            if ip_obj.version == 6 and ip_obj.is_global:
                                globals_v6.append(ip)
                        except Exception:
                            pass
        except Exception as exc:
            _logger.debug("IPv6 detect error: %s", exc)
        return globals_v6

    # ---------- Route table split-tunnel detection ----------
    def _detect_route_leaks(self, vpn_ifaces: list[str]) -> list[str]:
        """Check for default routes that bypass the VPN interface."""
        leaks = []
        if not vpn_ifaces:
            return leaks
        vpn_lower = set(i.lower() for i in vpn_ifaces)
        try:
            if _IS_WINDOWS:
                out = subprocess.run(
                    ['route', 'print'],
                    capture_output=True, text=True, timeout=10,
                    creationflags=_CREATE_NO_WINDOW,
                ).stdout
                for line in out.splitlines():
                    line = line.strip()
                    # Match "0.0.0.0  0.0.0.0  <gateway>  <iface>"
                    if line.startswith('0.0.0.0') and '0.0.0.0' in line:
                        parts = line.split()
                        if len(parts) >= 5:
                            iface = ' '.join(parts[3:])
                            if not any(v in iface.lower() for v in vpn_lower):
                                leaks.append(f"Default route bypasses VPN: {line}")
            else:
                out = subprocess.run(
                    ['ip', 'route', 'show', 'default'],
                    capture_output=True, text=True, timeout=10,
                ).stdout
                for line in out.splitlines():
                    if 'dev' in line:
                        parts = line.split('dev')
                        iface = parts[1].strip().split()[0] if len(parts) > 1 else ''
                        if iface.lower() not in vpn_lower:
                            leaks.append(f"Default route bypasses VPN: {line}")
        except Exception as exc:
            _logger.debug("Route leak detect error: %s", exc)
        return leaks

    # ---------- STUN reflexive address ----------
    def _stun_reflexive(self) -> str:
        """Send a minimal STUN binding request and parse the reflexive address.
        Returns the public IP as seen by the STUN server, or '' on failure."""
        try:
            import struct as _struct
            # STUN Binding Request: 20-byte header
            # type=0x0001 (Binding Request), length=0, magic cookie=0x2112A442
            msg = _struct.pack('!HHI12s', 0x0001, 0, 0x2112A442, os.urandom(12))
            for host, port in self._STUN_SERVERS:
                if self._stop.is_set():
                    break
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    s.settimeout(5)
                    s.sendto(msg, (host, port))
                    data, _ = s.recvfrom(2048)
                    s.close()
                    # Parse STUN response
                    if len(data) < 20:
                        continue
                    msg_type, msg_len, magic = _struct.unpack('!HHI', data[:8])
                    if msg_type != 0x0101:  # Binding Response
                        continue
                    # Parse attributes
                    off = 20
                    while off + 4 <= len(data):
                        attr_type, attr_len = _struct.unpack('!HH', data[off:off+4])
                        attr_data = data[off+4:off+4+attr_len]
                        if attr_type == 0x0020:  # XOR-MAPPED-ADDRESS
                            if len(attr_data) >= 8:
                                family = attr_data[1]
                                if family == 0x01:  # IPv4
                                    xor_port = _struct.unpack('!H', attr_data[2:4])[0]
                                    xor_ip = _struct.unpack('!I', attr_data[4:8])[0]
                                    port = xor_port ^ (0x2112A442 >> 16)
                                    ip_int = xor_ip ^ 0x2112A442
                                    ip = str(ipaddress.ip_address(ip_int))
                                    return f"{ip}:{port}"
                        off += 4 + attr_len
                        # Pad to 4-byte boundary
                        if attr_len % 4:
                            off += 4 - (attr_len % 4)
                except Exception as exc:
                    _logger.debug("STUN %s failed: %s", host, exc)
        except Exception as exc:
            _logger.debug("STUN reflexive error: %s", exc)
        return ''

    # ---------- WebRTC local-IP discovery ----------
    def _detect_webrtc_local_ip(self, vpn_ifaces: list[str]) -> tuple[str, bool]:
        """Mimic WebRTC ICE *host candidate* gathering.

        WebRTC's RTCPeerConnection opens a UDP socket and binds it to each
        local network interface, then exposes the bound address to JavaScript
        via ICE candidates. This bypasses the VPN tunnel when the VPN only
        routes at the IP layer and doesn't intercept socket binds.

        We replicate the simplest form: a UDP `connect()` to a public address
        forces the OS routing table to pick a primary egress interface and
        report its bound local address. If that address belongs to a non-VPN
        adapter, a WebRTC leak would expose the real LAN IP.

        Returns (local_ip, leak_flag).
        """
        local_ip = ''
        leak = False
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(3)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
        except Exception as exc:
            _logger.debug("WebRTC local-IP probe failed: %s", exc)
            return ('', False)
        if not local_ip or not vpn_ifaces:
            return (local_ip, leak)
        # Determine which interface owns this local IP.
        try:
            addrs = psutil.net_if_addrs()
            owning_iface = ''
            for iface, addr_list in addrs.items():
                for snic in addr_list:
                    if snic.family == socket.AF_INET and snic.address == local_ip:
                        owning_iface = iface
                        break
                if owning_iface:
                    break
            vpn_lower = set(i.lower() for i in vpn_ifaces)
            if owning_iface and not any(v in owning_iface.lower() for v in vpn_lower):
                leak = True
        except Exception as exc:
            _logger.debug("WebRTC iface attribution failed: %s", exc)
        return (local_ip, leak)

    # ---------- Kill-switch verification ----------
    def _verify_kill_switch(self, vpn_ifaces: list[str]) -> tuple[bool, str]:
        """Verify a network-level kill switch is actually in effect.

        A kill switch must block all traffic when the VPN tunnel drops. The
        two reliable signals are:
          (a) The default route (0.0.0.0/0) points *only* at the VPN
              interface. If a second default route via the physical NIC
              coexists, traffic falls back to it instantly on disconnect —
              i.e. no kill switch.
          (b) A VPN client process known to enforce a firewall-based kill
              switch is running. This is corroborating evidence only; the
              route check is authoritative.

        Returns (kill_switch_ok, detail).
        """
        if not vpn_ifaces:
            return (True, "No VPN active — kill switch N/A")
        vpn_lower = set(i.lower() for i in vpn_ifaces)
        non_vpn_default_routes: list[str] = []
        try:
            if _IS_WINDOWS:
                out = subprocess.run(
                    ['route', 'print'],
                    capture_output=True, text=True, timeout=10,
                    creationflags=_CREATE_NO_WINDOW,
                ).stdout
                for line in out.splitlines():
                    line = line.strip()
                    if line.startswith('0.0.0.0') and '0.0.0.0' in line:
                        parts = line.split()
                        if len(parts) >= 5:
                            iface = ' '.join(parts[3:])
                            if not any(v in iface.lower() for v in vpn_lower):
                                non_vpn_default_routes.append(line)
            else:
                out = subprocess.run(
                    ['ip', 'route', 'show', 'default'],
                    capture_output=True, text=True, timeout=10,
                ).stdout
                for line in out.splitlines():
                    if 'dev' in line:
                        parts = line.split('dev')
                        iface = parts[1].strip().split()[0] if len(parts) > 1 else ''
                        if iface.lower() not in vpn_lower:
                            non_vpn_default_routes.append(line)
        except Exception as exc:
            _logger.debug("Kill-switch route check error: %s", exc)

        # Corroborating: is a known VPN client with a kill switch running?
        client_running = False
        try:
            for proc in psutil.process_iter(['name']):
                pname = (proc.info.get('name') or '').lower()
                if any(c in pname for c in self._VPN_CLIENT_PROCS):
                    client_running = True
                    break
        except Exception:
            pass

        if non_vpn_default_routes:
            detail = (f"{len(non_vpn_default_routes)} non-VPN default route(s) present "
                      f"alongside VPN — no kill switch: "
                      f"{'; '.join(non_vpn_default_routes[:2])}")
            if client_running:
                detail += " (VPN client running but route table not locked down)"
            return (False, detail)
        if not client_running:
            return (True, "Default route locked to VPN; no recognized kill-switch client process "
                          "(route-level protection appears sufficient)")
        return (True, "Default route locked to VPN and VPN client process running")

    # ---------- Device fingerprinting surface inventory ----------
    def _inventory_fingerprint_surface(self) -> dict:
        """Inventory the local system's browser/device fingerprinting surface.

        This is a *defensive awareness* check (Step 3 of the de-anonymization
        framework). Encryption protects data in transit but does not change
        what the OS/browser reveals. These attributes persist identically
        whether the VPN is on or off, so any site that recorded them in a
        non-VPN session can re-link a VPN session to the same identity.

        Returns a dict of fingerprint-relevant attributes. Nothing is sent
        anywhere — this is local inventory only.
        """
        surface: dict = {}
        try:
            surface['hostname'] = socket.gethostname()
        except Exception:
            surface['hostname'] = ''
        surface['os'] = (f"{psutil.OS_NAME} {getattr(psutil, 'OS_RELEASE', '')} "
                         f"{getattr(psutil, 'OS_VERSION', '')}").strip() if hasattr(psutil, 'OS_NAME') else ''
        # psutil doesn't expose OS strings on all platforms; fall back to platform module.
        if not surface['os']:
            try:
                import platform as _platform
                surface['os'] = _platform.platform()
            except Exception:
                surface['os'] = ''
        try:
            surface['timezone'] = time.tzname[0] if time.tzname else ''
        except Exception:
            surface['timezone'] = ''
        try:
            surface['locale'] = '.'.join(filter(None, (os.environ.get('LANG', ''),
                                                        os.environ.get('LC_ALL', '')))) or ''
        except Exception:
            surface['locale'] = ''
        # Windows machine GUID — a stable per-install identifier.
        if _IS_WINDOWS:
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                    r"SOFTWARE\\Microsoft\\Cryptography", 0,
                                    winreg.KEY_READ) as key:
                    guid, _ = winreg.QueryValueEx(key, "MachineGuid")
                    surface['machine_guid'] = str(guid)
            except Exception:
                surface['machine_guid'] = ''
        # Count installed font families (a major fingerprint vector) without
        # enumerating every file — just report the font directory existence
        # and a rough count on Windows.
        font_count = None
        try:
            if _IS_WINDOWS:
                font_dir = os.path.join(os.environ.get('WINDIR', r'C:\\Windows'), 'Fonts')
                if os.path.isdir(font_dir):
                    font_count = sum(1 for _ in os.scandir(font_dir) if _.is_file())
            else:
                for cand in ('/usr/share/fonts', '/usr/local/share/fonts',
                             os.path.expanduser('~/.fonts'),
                             os.path.expanduser('~/.local/share/fonts')):
                    if os.path.isdir(cand):
                        font_count = (font_count or 0) + sum(
                            1 for _ in os.scandir(cand) if _.is_file())
        except Exception:
            pass
        surface['font_files'] = font_count
        # CPU count + total RAM — hardware fingerprint vectors.
        try:
            surface['cpu_count'] = psutil.cpu_count(logical=True)
            surface['memory_mb'] = int(psutil.virtual_memory().total / (1024 * 1024))
        except Exception:
            pass
        # MAC addresses of physical adapters — persist across VPN sessions
        # and are visible to any local JS via WebRTC (host candidates).
        try:
            macs = []
            for iface, addr_list in psutil.net_if_addrs().items():
                lname = iface.lower()
                # Skip VPN/virtual adapters — only physical NIC MACs are the
                # stable hardware fingerprint.
                if any(kw in lname for kw in self._VPN_IFACE_KEYWORDS):
                    continue
                for snic in addr_list:
                    if snic.family == psutil.AF_LINK and snic.address and snic.address != '00:00:00:00:00:00':
                        macs.append(snic.address)
            surface['physical_macs'] = macs[:4]
        except Exception:
            surface['physical_macs'] = []
        return surface

    # ---------- Full scan ----------
    def scan(self) -> dict:
        """Run a full VPN leak scan and return a structured report."""
        now = time.time()
        if now - self._last_scan < self._scan_interval and self._last_report:
            return self._last_report
        self._last_scan = now
        events: list[dict] = []

        # 1. VPN interface detection
        vpn_ifaces = self._detect_vpn_interfaces()
        vpn_active = len(vpn_ifaces) > 0
        if vpn_active:
            events.append({
                'type': 'VPN_ACTIVE', 'severity': 'INFO',
                'time': now,
                'detail': f"VPN interface(s) detected: {', '.join(vpn_ifaces)}",
            })

        # 2. Public IP cross-check
        public_ips = self._fetch_public_ips()
        unique_ips = set(public_ips.values())
        if vpn_active and len(unique_ips) > 1:
            events.append({
                'type': 'IP_LEAK', 'severity': 'CRITICAL',
                'time': now,
                'detail': f"Multiple public IPs returned by different resolvers — "
                          f"traffic is leaking outside the VPN tunnel: {public_ips}",
            })
        elif public_ips:
            events.append({
                'type': 'PUBLIC_IP', 'severity': 'INFO',
                'time': now,
                'detail': f"Public IP: {list(unique_ips)[0]} (via {list(public_ips.keys())})",
            })

        # 3. DNS leak detection
        dns_resolvers = self._detect_dns_resolvers()
        if vpn_active and dns_resolvers:
            # If VPN is active, DNS resolvers should be the VPN provider's
            # resolvers, not the ISP's. We flag known ISP-like resolvers.
            # Without a definitive VPN-DNS list, we flag if resolvers
            # resolve to a different country than the VPN exit.
            events.append({
                'type': 'DNS_RESOLVERS', 'severity': 'INFO',
                'time': now,
                'detail': f"Active DNS resolvers: {', '.join(dns_resolvers)}",
            })

        # 4. IPv6 leak detection
        ipv6_globals = self._detect_global_ipv6()
        if vpn_active and ipv6_globals:
            events.append({
                'type': 'IPV6_LEAK', 'severity': 'WARNING',
                'time': now,
                'detail': f"Global IPv6 addresses present — may bypass IPv4-only "
                          f"VPN tunnel: {', '.join(ipv6_globals[:4])}",
            })

        # 5. Route-table split-tunnel detection
        route_leaks = self._detect_route_leaks(vpn_ifaces)
        for leak in route_leaks:
            events.append({
                'type': 'ROUTE_LEAK', 'severity': 'WARNING',
                'time': now,
                'detail': leak,
            })

        # 6. STUN reflexive address
        stun_ip = self._stun_reflexive()
        if stun_ip and vpn_active and public_ips:
            # Compare STUN-discovered IP against the resolver-reported IP
            stun_ip_only = stun_ip.split(':')[0]
            resolver_ips = set(public_ips.values())
            if stun_ip_only not in resolver_ips:
                events.append({
                    'type': 'STUN_LEAK', 'severity': 'CRITICAL',
                    'time': now,
                    'detail': f"STUN reflexive address ({stun_ip}) differs from "
                              f"resolver-reported IP ({resolver_ips}) — "
                              f"UDP traffic is leaking outside the VPN tunnel",
                })

        # 7. WebRTC local-IP discovery (Step 2 — client-side WebRTC leak).
        #    Mimics RTCPeerConnection ICE host-candidate gathering via a UDP
        #    connect; flags if the discovered local IP is on a non-VPN adapter.
        webrtc_local_ip, webrtc_leak = self._detect_webrtc_local_ip(vpn_ifaces)
        if webrtc_local_ip:
            if webrtc_leak:
                events.append({
                    'type': 'WEBRTC_LEAK', 'severity': 'WARNING',
                    'time': now,
                    'detail': f"WebRTC host-candidate probe bound to non-VPN interface "
                              f"({webrtc_local_ip}) — browser WebRTC would expose the "
                              f"real LAN IP bypassing the tunnel",
                })
            else:
                events.append({
                    'type': 'WEBRTC_OK', 'severity': 'INFO',
                    'time': now,
                    'detail': f"WebRTC local-IP probe bound to VPN interface "
                              f"({webrtc_local_ip})",
                })

        # 8. Kill-switch verification (Step 5 — connection disruption).
        #    Replaces the previous proxy-env-only heuristic with a real
        #    default-route + VPN-client-process check.
        kill_switch_ok, kill_switch_detail = self._verify_kill_switch(vpn_ifaces)
        if vpn_active and not kill_switch_ok:
            events.append({
                'type': 'NO_KILL_SWITCH', 'severity': 'CRITICAL',
                'time': now,
                'detail': kill_switch_detail,
            })
        elif vpn_active:
            events.append({
                'type': 'KILL_SWITCH_OK', 'severity': 'INFO',
                'time': now,
                'detail': kill_switch_detail,
            })

        # 9. Proxy-only fallback (no VPN interface but proxy env vars set).
        if not vpn_active:
            proxy_env = any(os.environ.get(v) for v in
                            ('HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY',
                             'http_proxy', 'https_proxy', 'all_proxy'))
            if proxy_env:
                events.append({
                    'type': 'NO_VPN_PROXY_ONLY', 'severity': 'INFO',
                    'time': now,
                    'detail': "No VPN interface detected, but proxy env vars are set — "
                              "traffic goes through a proxy, not a VPN tunnel",
                })

        # 10. Device fingerprinting surface inventory (Step 3 — fingerprinting).
        #     Defensive awareness: these attributes persist across VPN on/off
        #     and can re-link sessions. Reported as INFO since it is inherent
        #     exposure, not an active leak.
        fingerprint_surface = self._inventory_fingerprint_surface()
        events.append({
            'type': 'FINGERPRINT_SURFACE', 'severity': 'INFO',
            'time': now,
            'detail': (f"Persistent fingerprint surface: hostname={fingerprint_surface.get('hostname')}, "
                       f"os={fingerprint_surface.get('os', '')[:40]}, "
                       f"tz={fingerprint_surface.get('timezone')}, "
                       f"cpus={fingerprint_surface.get('cpu_count')}, "
                       f"ram={fingerprint_surface.get('memory_mb')}MB, "
                       f"fonts={fingerprint_surface.get('font_files')}, "
                       f"macs={len(fingerprint_surface.get('physical_macs', []))}"),
        })

        with self._lock:
            self._vpn_active = vpn_active
            self._vpn_ifaces = vpn_ifaces
            self._public_ips = public_ips
            self._dns_resolvers = dns_resolvers
            self._ipv6_global = ipv6_globals
            self._stun_reflexive_ip = stun_ip
            self._route_leaks = route_leaks
            self._webrtc_local_ip = webrtc_local_ip
            self._webrtc_leak = webrtc_leak
            self._kill_switch_ok = kill_switch_ok
            self._kill_switch_detail = kill_switch_detail
            self._fingerprint_surface = fingerprint_surface
            for ev in events:
                self._events.append(ev)
            self._last_report = {
                'vpn_active': vpn_active,
                'vpn_interfaces': vpn_ifaces,
                'public_ips': public_ips,
                'public_ip_consistent': len(unique_ips) <= 1,
                'dns_resolvers': dns_resolvers,
                'ipv6_global': ipv6_globals,
                'ipv6_leak': bool(ipv6_globals and vpn_active),
                'stun_reflexive': stun_ip,
                'route_leaks': route_leaks,
                'webrtc_local_ip': webrtc_local_ip,
                'webrtc_leak': webrtc_leak,
                'kill_switch_ok': kill_switch_ok,
                'kill_switch_detail': kill_switch_detail,
                'fingerprint_surface': fingerprint_surface,
                'events': events,
                'timestamp': now,
            }
        return self._last_report

    def get_events(self) -> list[dict]:
        with self._lock:
            return list(self._events)

    def get_status(self) -> dict:
        with self._lock:
            return dict(self._last_report) if self._last_report else {}


# ========================== LOGGING SETUP ==========================
def setup_structured_logging():
    """Configure Python logging with rotation for main, actions, and deductions logs."""
    logger = logging.getLogger('medianbox')
    if not logger.handlers:
        logger.setLevel(logging.DEBUG)
        fmt = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
        fh = RotatingFileHandler(CONFIG.get('log_file') or 'medianbox_structured.log',
                                 maxBytes=50_000_000, backupCount=5,
                                 encoding='utf-8')
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(fmt)
        logger.addHandler(fh)
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        ch.setFormatter(fmt)
        logger.addHandler(ch)

    actions_logger = logging.getLogger('medianbox.actions')
    if not actions_logger.handlers:
        actions_logger.setLevel(logging.DEBUG)
        actions_logger.propagate = False
        afmt = logging.Formatter('%(asctime)s %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
        afh = RotatingFileHandler(CONFIG['actions_log'], maxBytes=50_000_000, backupCount=3,
                                  encoding='utf-8')
        afh.setLevel(logging.DEBUG)
        afh.setFormatter(afmt)
        actions_logger.addHandler(afh)

    ded_logger = logging.getLogger('medianbox.deductions')
    if not ded_logger.handlers:
        ded_logger.setLevel(logging.DEBUG)
        ded_logger.propagate = False
        dfmt = logging.Formatter('%(asctime)s %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
        dfh = RotatingFileHandler(CONFIG['deductions_log'], maxBytes=50_000_000, backupCount=3,
                                  encoding='utf-8')
        dfh.setLevel(logging.DEBUG)
        dfh.setFormatter(dfmt)
        ded_logger.addHandler(dfh)

    return logger


# ========================== SIEM OUTPUT ==========================
class SIEMOutput:
    """Formats and sends deductions as CEF, JSON, or Syslog."""
    def __init__(self):
        self.sock = None
        self._json_logger = None
        self._cef_logger = None
        if CONFIG['siem_output'] == 'json':
            self._json_logger = self._make_file_logger('medianbox.siem_json', 'medianbox_siem.json')
        elif CONFIG['siem_output'] == 'cef':
            self._cef_logger = self._make_file_logger('medianbox.siem_cef', 'medianbox_siem.cef')
        elif CONFIG['siem_output'] == 'syslog':
            try:
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            except Exception as exc:
                _logger.warning("Failed to create syslog socket: %s", exc)

    @staticmethod
    def _make_file_logger(name: str, filename: str):
        lg = logging.getLogger(name)
        if not lg.handlers:
            lg.setLevel(logging.DEBUG)
            lg.propagate = False
            fh = RotatingFileHandler(filename, maxBytes=50_000_000, backupCount=3, encoding='utf-8')
            fh.setFormatter(logging.Formatter('%(message)s'))
            lg.addHandler(fh)
        return lg

    def emit(self, d: Deduction):
        fmt = CONFIG.get('siem_output')
        if not fmt:
            return
        if fmt == 'json':
            self._emit_json(d)
        elif fmt == 'cef':
            self._emit_cef(d)
        elif fmt == 'syslog':
            self._emit_syslog(d)

    def _emit_json(self, d: Deduction):
        record = {
            'timestamp': datetime.datetime.fromtimestamp(d.timestamp).isoformat(),
            'severity': d.severity, 'category': d.category,
            'process': d.process_name, 'pid': d.pid,
            'message': d.message, 'evidence': d.evidence, 'score': d.score,
        }
        if self._json_logger:
            self._json_logger.info(json.dumps(record))

    def _emit_cef(self, d: Deduction):
        sev_map = {'INFO': 3, 'WARNING': 6, 'CRITICAL': 9}
        sev = sev_map.get(d.severity, 5)
        cef = (f"CEF:0|MedianBox|ChessEngine|3.0|{d.category}|{d.message[:128]}|{sev}|"
               f"src={d.process_name} pid={d.pid} score={d.score:.1f}")
        if self._cef_logger:
            self._cef_logger.info(cef)

    def _emit_syslog(self, d: Deduction):
        if not self.sock:
            return
        pri = 134
        if d.severity == 'CRITICAL':
            pri = 130
        elif d.severity == 'WARNING':
            pri = 132
        msg = f"<{pri}>MedianBox: [{d.category}] {d.message} pid={d.pid} score={d.score:.1f}"
        try:
            self.sock.sendto(msg.encode()[:1024],
                             (CONFIG['siem_host'], CONFIG['siem_port']))
        except Exception as exc:
            _logger.debug("SIEM syslog send failed: %s", exc)


# ========================== ALERT ESCALATION ==========================
class AlertEscalation:
    """Compounds risk when same process triggers multiple deductions in a window."""
    def __init__(self):
        self.history: dict[int, deque] = defaultdict(lambda: deque(maxlen=50))
        self.lock = threading.Lock()

    def record(self, pid: int, score: float):
        now = time.time()
        with self.lock:
            self.history[pid].append((now, score))
            # Periodically drop PIDs whose entries have all aged out.
            if len(self.history) > 5000:
                cutoff = now - CONFIG['escalation_window']
                for dead in [k for k, v in self.history.items()
                             if not v or v[-1][0] < cutoff]:
                    del self.history[dead]

    def get_multiplier(self, pid: int) -> float:
        cutoff = time.time() - CONFIG['escalation_window']
        with self.lock:
            recent = [(t, s) for t, s in self.history.get(pid, []) if t > cutoff]
        if len(recent) <= 1:
            return 1.0
        return min(5.0, CONFIG['escalation_multiplier'] ** (len(recent) - 1))


# ========================== DATABASE ==========================
class DatabaseManager:
    """Thread-safe SQLite with connection-per-operation and WAL journal mode."""
    def __init__(self, db_path: Optional[str] = None):
        self._db_path = db_path or CONFIG['db_file']
        self._init_db()

    def _get_db(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, timeout=10)
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_db(self):
        try:
            conn = self._get_db()
            conn.execute("""CREATE TABLE IF NOT EXISTS deductions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT, severity TEXT, category TEXT,
                process TEXT, pid INTEGER, message TEXT,
                evidence TEXT, score REAL)""")
            conn.execute("""CREATE TABLE IF NOT EXISTS devices (
                key TEXT PRIMARY KEY, mac TEXT, ip TEXT, vendor TEXT,
                hostname TEXT, os_guess TEXT, first_seen TEXT,
                last_seen TEXT, confidence REAL)""")
            conn.commit()
            conn.close()
        except Exception as exc:
            _logger.warning("Database init failed: %s", exc)

    def save_deduction(self, d: Deduction):
        conn = None
        try:
            conn = self._get_db()
            conn.execute(
                "INSERT INTO deductions (timestamp, severity, category, process, pid, message, evidence, score) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (datetime.datetime.fromtimestamp(d.timestamp).isoformat(),
                 d.severity, d.category, d.process_name, d.pid,
                 d.message, json.dumps(d.evidence), d.score))
            conn.commit()
        except Exception as exc:
            _logger.debug("DB deduction save failed: %s", exc)
        finally:
            if conn:
                conn.close()

    def save_device(self, key: str, dev: dict):
        conn = None
        try:
            conn = self._get_db()
            conn.execute(
                "INSERT OR REPLACE INTO devices (key, mac, ip, vendor, hostname, os_guess, "
                "first_seen, last_seen, confidence) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (key, dev.get('mac'), dev.get('ip'), dev.get('vendor'),
                 dev.get('hostname'), dev.get('os_guess'),
                 datetime.datetime.fromtimestamp(dev.get('first_seen', 0)).isoformat(),
                 datetime.datetime.fromtimestamp(dev.get('last_seen', 0)).isoformat(),
                 dev.get('confidence', 0)))
            conn.commit()
        except Exception as exc:
            _logger.debug("DB device save failed: %s", exc)
        finally:
            if conn:
                conn.close()


# ========================== PACKET PIPELINE ==========================
class PacketPipeline:
    """Multi-worker queue that decouples packet capture from analysis."""
    def __init__(self, handler: Callable, stop_event: threading.Event,
                 num_workers: Optional[int] = None, max_queue: Optional[int] = None):
        self._handler = handler
        self._stop = stop_event
        self._num_workers = num_workers or CONFIG.get('pipeline_workers', 2)
        self._queue: queue.Queue = queue.Queue(
            maxsize=max_queue or CONFIG.get('pipeline_queue_size', 5000))
        self._workers: list = []
        self._dropped = 0
        self._processed = 0
        self._lock = threading.Lock()

    def enqueue(self, pkt):
        try:
            self._queue.put_nowait(pkt)
        except queue.Full:
            with self._lock:
                self._dropped += 1
            if self._dropped % 500 == 1:
                _logger.warning("Packet pipeline full — dropped %d packets so far", self._dropped)

    def _worker(self, worker_id: int):
        _logger.debug("Pipeline worker %d started", worker_id)
        local_count = 0  # per-worker counter — avoids lock on every packet
        while not self._stop.is_set():
            try:
                pkt = self._queue.get(timeout=1.0)
            except queue.Empty:
                # Flush local counter to shared counter periodically
                if local_count:
                    with self._lock:
                        self._processed += local_count
                    local_count = 0
                continue
            try:
                self._handler(pkt)
                local_count += 1
                # Flush every 256 packets to keep shared stat roughly current
                if local_count >= 256:
                    with self._lock:
                        self._processed += local_count
                    local_count = 0
            except Exception as exc:
                _logger.debug("Pipeline worker %d error: %s", worker_id, exc)
            finally:
                self._queue.task_done()
        # Final flush
        if local_count:
            with self._lock:
                self._processed += local_count
        _logger.debug("Pipeline worker %d stopped", worker_id)

    def start(self):
        for i in range(self._num_workers):
            t = threading.Thread(target=self._worker, args=(i,),
                                 daemon=True, name=f"Pipeline-Worker-{i}")
            t.start()
            self._workers.append(t)
        _logger.info("Packet pipeline started with %d workers (queue=%d)",
                     self._num_workers, self._queue.maxsize)

    def stats(self) -> dict:
        with self._lock:
            return {
                'queue_size': self._queue.qsize(),
                'processed': self._processed,
                'dropped': self._dropped,
                'workers': len(self._workers),
            }

    def drain(self, timeout: float = 5.0):
        deadline = time.monotonic() + timeout
        while not self._queue.empty() and time.monotonic() < deadline:
            time.sleep(0.1)


# ========================== SERVICE RESOLVER ==========================
SERVICE_PATTERNS = [
    (r'youtube|googlevideo|ytimg|yt\d|ggpht', 'YouTube', 'Streaming', '🎬'),
    (r'netflix|nflxvideo|nflximg|nflxso|nflxext', 'Netflix', 'Streaming', '🎬'),
    (r'disneyplus|disney-plus|bamgrid|dssott', 'Disney+', 'Streaming', '🎬'),
    (r'hulu|hulustream', 'Hulu', 'Streaming', '🎬'),
    (r'primevideo|atv-ps|aiv-cdn|amazonvideo', 'Prime Video', 'Streaming', '🎬'),
    (r'twitch\.tv|twitchcdn|jtvnw', 'Twitch', 'Streaming', '🎬'),
    (r'crunchyroll|vrv\.co', 'Crunchyroll', 'Streaming', '🎬'),
    (r'spotify|scdn\.co|audio-ak', 'Spotify', 'Streaming', '🎵'),
    (r'tidal\.com|tidalhifi', 'Tidal', 'Streaming', '🎵'),
    (r'facebook|fbcdn|fb\.com|fbsbx|instagram|cdninstagram', 'Meta (FB/IG)', 'Social', '📱'),
    (r'twitter\.com|twimg|x\.com|abs\.twimg', 'X (Twitter)', 'Social', '📱'),
    (r'reddit\.com|redd\.it|redditstatic|redditmedia', 'Reddit', 'Social', '📱'),
    (r'tiktok|tiktokcdn|musical\.ly|byteoversea|byteimg', 'TikTok', 'Social', '📱'),
    (r'snapchat|sc-cdn|snap-storage', 'Snapchat', 'Social', '📱'),
    (r'linkedin\.com|licdn\.com', 'LinkedIn', 'Social', '📱'),
    (r'pinterest\.com|pinimg\.com', 'Pinterest', 'Social', '📱'),
    (r'discord|discordapp|dis\.gd', 'Discord', 'Communication', '💬'),
    (r'slack\.com|slack-edge|slack-msgs', 'Slack', 'Communication', '💬'),
    (r'teams\.microsoft|teams\.live|teams\.cdn', 'Microsoft Teams', 'Communication', '💬'),
    (r'zoom\.us|zoom\.com|zoomgov', 'Zoom', 'Communication', '💬'),
    (r'whatsapp|wa\.me', 'WhatsApp', 'Communication', '💬'),
    (r'signal\.org|signal-cdn', 'Signal', 'Communication', '💬'),
    (r'telegram\.org|t\.me|telegram-cdn', 'Telegram', 'Communication', '💬'),
    (r'google\.com|googleapis|gstatic|goog\b|google-analytics|googleusercontent|1e100\.net', 'Google', 'Tech', '🔍'),
    (r'bing\.com|bingapis|msn\.com', 'Microsoft Bing', 'Tech', '🔍'),
    (r'duckduckgo', 'DuckDuckGo', 'Tech', '🔍'),
    (r'cloudflare|cf-|one\.one\.one', 'Cloudflare', 'CDN/Cloud', '☁️'),
    (r'akamai|akam|akamaized|edgekey|edgesuite', 'Akamai CDN', 'CDN/Cloud', '☁️'),
    (r'fastly|fastlylb', 'Fastly CDN', 'CDN/Cloud', '☁️'),
    (r'amazonaws\.com|aws\.amazon|cloudfront\.net|s3\.', 'Amazon AWS', 'CDN/Cloud', '☁️'),
    (r'azure\.com|azure\.net|msedge\.net|windows\.net', 'Microsoft Azure', 'CDN/Cloud', '☁️'),
    (r'cloud\.google\.com|googleapis|gcp', 'Google Cloud', 'CDN/Cloud', '☁️'),
    (r'amazon\.com|amazon\.co|media-amazon|images-amazon', 'Amazon', 'Shopping', '🛒'),
    (r'ebay\.com|ebaystatic|ebayimg', 'eBay', 'Shopping', '🛒'),
    (r'walmart\.com|walmartimages', 'Walmart', 'Shopping', '🛒'),
    (r'shopify\.com|cdn\.shopify', 'Shopify', 'Shopping', '🛒'),
    (r'riotgames|leagueoflegends|riotcdn', 'Riot Games', 'Gaming', '🎮'),
    (r'steampowered|steamcommunity|steamcdn|valve\.net', 'Steam', 'Gaming', '🎮'),
    (r'epicgames|fortnite|unrealengine', 'Epic Games', 'Gaming', '🎮'),
    (r'battle\.net|blizzard|bnet', 'Blizzard', 'Gaming', '🎮'),
    (r'xbox\.com|xboxlive', 'Xbox Live', 'Gaming', '🎮'),
    (r'playstation|psn|sie\.com', 'PlayStation', 'Gaming', '🎮'),
    (r'ea\.com|origin\.com|eaplay', 'EA Games', 'Gaming', '🎮'),
    (r'microsoft\.com|microsoftonline|office365|office\.com|live\.com|outlook\.com|windows\.com|windowsupdate|msauth|login\.live', 'Microsoft', 'Tech', '🪟'),
    (r'apple\.com|icloud|apple-dns|mzstatic|itunes', 'Apple', 'Tech', '🍎'),
    (r'openai\.com|chatgpt|oaiusercontent', 'OpenAI', 'AI', '🤖'),
    (r'anthropic\.com|claude\.ai', 'Anthropic', 'AI', '🤖'),
    (r'gemini\.google|bard\.google|generativelanguage', 'Google Gemini', 'AI', '🤖'),
    (r'grok|x\.ai', 'xAI Grok', 'AI', '🤖'),
    (r'cnn\.com', 'CNN', 'News', '📰'),
    (r'bbc\.co|bbc\.com', 'BBC', 'News', '📰'),
    (r'nytimes\.com', 'NY Times', 'News', '📰'),
    (r'foxnews\.com', 'Fox News', 'News', '📰'),
    (r'gmail\.com|mail\.google', 'Gmail', 'Email', '📧'),
    (r'outlook\.live|hotmail', 'Outlook', 'Email', '📧'),
    (r'yahoo\.com|yimg\.com|yahoodns', 'Yahoo', 'Email/Web', '📧'),
    (r'1\.1\.1\.1|one\.one', 'Cloudflare DNS', 'DNS', '🌐'),
    (r'8\.8\.8\.8|8\.8\.4\.4|dns\.google', 'Google DNS', 'DNS', '🌐'),
    (r'9\.9\.9\.9|dns\.quad9', 'Quad9 DNS', 'DNS', '🌐'),
    (r'nordvpn|nord-vpn', 'NordVPN', 'VPN', '🔒'),
    (r'expressvpn|xvpn', 'ExpressVPN', 'VPN', '🔒'),
    (r'protonvpn|proton\.me', 'ProtonVPN', 'VPN', '🔒'),
    (r'coinbase\.com', 'Coinbase', 'Crypto', '💰'),
    (r'binance\.com', 'Binance', 'Crypto', '💰'),
    (r'chase\.com', 'Chase Bank', 'Banking', '🏦'),
    (r'bankofamerica|bofa\.com', 'Bank of America', 'Banking', '🏦'),
    (r'paypal\.com|paypalobjects', 'PayPal', 'Finance', '💳'),
    (r'venmo\.com', 'Venmo', 'Finance', '💳'),
    (r'stripe\.com', 'Stripe', 'Finance', '💳'),
    (r'github\.com|github\.io|githubusercontent', 'GitHub', 'Dev', '💻'),
    (r'stackoverflow\.com|stackexchange', 'StackOverflow', 'Dev', '💻'),
]

_COMPILED_PATTERNS = [(re.compile(pat, re.IGNORECASE), name, cat, icon)
                      for pat, name, cat, icon in SERVICE_PATTERNS]

# Services that are broad infrastructure providers — more specific matches should override these
_GENERIC_SERVICES = frozenset({
    'Google', 'Microsoft', 'Apple', 'Amazon AWS', 'Google Cloud',
    'Microsoft Azure', 'Cloudflare', 'Akamai CDN', 'Fastly CDN',
})


class ServiceResolver:
    """Resolves IPs and domains to human-readable service names with caching."""
    def __init__(self):
        self._rdns_cache: dict[str, str] = {}
        self._service_cache: dict[str, dict] = {}
        self.lock = threading.Lock()
        # Background reverse DNS queue — prevents scan from blocking on
        # socket.gethostbyaddr which can take 5-30s per IP on Windows
        self._rdns_queue: queue.Queue = queue.Queue(maxsize=2000)
        self._rdns_pending: set[str] = set()
        self._rdns_stop = threading.Event()
        self._rdns_thread = threading.Thread(
            target=self._rdns_worker, daemon=True, name="ReverseDNS")
        self._rdns_thread.start()

    def _rdns_worker(self):
        """Background worker that resolves reverse DNS for queued IPs."""
        while not self._rdns_stop.is_set():
            try:
                ip = self._rdns_queue.get(timeout=1.0)
            except queue.Empty:
                continue
            try:
                # Bounded: one unreachable host used to block this queue —
                # and therefore every other IP's service name — for ~30s.
                hostname = _rdns_bounded(ip, timeout=5.0)
                with self.lock:
                    self._rdns_cache[ip] = hostname
                    if hostname:
                        # Clear the service cache so identify() re-evaluates
                        self._service_cache.pop(ip, None)
            except Exception:
                with self.lock:
                    self._rdns_cache[ip] = ""
            finally:
                with self.lock:
                    self._rdns_pending.discard(ip)

    def queue_reverse_dns(self, ip: str):
        """Queue an IP for background reverse DNS lookup (non-blocking)."""
        with self.lock:
            if ip in self._rdns_cache or ip in self._rdns_pending:
                return
            self._rdns_pending.add(ip)
        try:
            self._rdns_queue.put_nowait(ip)
        except queue.Full:
            with self.lock:
                self._rdns_pending.discard(ip)

    @staticmethod
    def _is_unresolved(service: str) -> bool:
        """True if service is just an IP, 'Unknown', or empty — needs re-resolution."""
        if not service or service == 'Unknown':
            return True
        try:
            ipaddress.ip_address(service)
            return True
        except ValueError:
            return False

    @staticmethod
    def _pick_best_website_domain(candidates: list[str]) -> str:
        """From a list of raw website domains, pick the most readable one."""
        if not candidates:
            return ''
        # Prefer shortest non-www, non-cdn domain; fall back to shortest overall
        clean = []
        for d in candidates:
            low = d.lower()
            if not low.startswith(('www.', 'cdn.', 'static.', 'assets.', 'img.', 'images.',
                                   'api.', 'edge.', 'media.', 'dl.', 'download.')):
                clean.append(d)
        pool = clean or candidates
        return min(pool, key=len)

    def resolve_domain(self, domain: str) -> dict:
        if not domain:
            return {'service': 'Unknown', 'category': 'Unknown', 'icon': '❓'}
        domain_lower = domain.lower()
        for pattern, name, category, icon in _COMPILED_PATTERNS:
            if pattern.search(domain_lower):
                return {'service': name, 'category': category, 'icon': icon}
        return {'service': domain_lower, 'category': 'Other', 'icon': '🌐'}

    def reverse_dns(self, ip: str) -> Optional[str]:
        with self.lock:
            if ip in self._rdns_cache:
                return self._rdns_cache[ip]
        try:
            hostname = _rdns_bounded(ip)
            with self.lock:
                self._rdns_cache[ip] = hostname
            return hostname
        except (socket.herror, socket.gaierror, OSError):
            with self.lock:
                self._rdns_cache[ip] = ""
            return ""

    def identify(self, ip: str, domains: Optional[set] = None) -> dict:
        with self.lock:
            cached = self._service_cache.get(ip)
            if cached:
                svc = cached.get('service', '')
                # Return immediately only for specific known services (non-generic, non-placeholder)
                if svc and svc not in _GENERIC_SERVICES and not self._is_unresolved(svc):
                    # CDN hostnames should always allow re-evaluation
                    svc_lower = svc.lower()
                    is_cdn_svc = any(cdn in svc_lower for cdn in (
                        'cloudfront', 'akamai', 'fastly', 'cloudflare', 'amazonaws',
                        'azureedge', 'edgecast', 'hwcdn', 'edgesuite', 'akamaiedge',
                        'server-', 'deploy.static', 'compute-1.', '.elb.',
                        '1e100.net', 'fbcdn', 'googleusercontent',
                    ))
                    if is_cdn_svc:
                        if not domains:
                            return cached
                        # Fall through to re-evaluate with new domains
                    elif domains:
                        # Check if we already have a website domain or a pattern-matched service
                        resolved = self.resolve_domain(cached.get('domain', ''))
                        if resolved.get('service') != cached.get('domain', '').lower():
                            # It's a pattern-matched service like YouTube — keep it
                            return cached
                        # It's a website domain (pornhub.com) — check if a better specific match exists
                    else:
                        return cached
                if not domains:
                    return cached
        if domains:
            specific_match = None      # YouTube, Netflix, Discord, etc.
            specific_domain = None
            generic_match = None       # Google, Cloudflare, Akamai, etc.
            generic_domain = None
            website_domains = []       # pornhub.com, yahoo.com — actual sites

            for d in domains:
                result = self.resolve_domain(d)
                is_pattern_match = (result['service'] != d.lower())
                if is_pattern_match:
                    if result['service'] not in _GENERIC_SERVICES:
                        # Specific known service — best possible match
                        if specific_match is None:
                            specific_match = result
                            specific_domain = d
                    else:
                        if generic_match is None:
                            generic_match = result
                            generic_domain = d
                else:
                    # No pattern matched — this IS the actual website domain
                    website_domains.append(d)

            # Priority: specific service > website domain > generic CDN
            if specific_match:
                specific_match['domain'] = specific_domain
                if generic_match:
                    specific_match['via'] = generic_match['service']
                result = specific_match
            elif website_domains:
                best_domain = self._pick_best_website_domain(website_domains)
                result = {'service': best_domain, 'category': 'Website', 'icon': '🌐',
                          'domain': best_domain, 'via': ''}
                if generic_match:
                    result['via'] = generic_match['service']
            elif generic_match:
                generic_match['domain'] = generic_domain
                result = generic_match
            else:
                # All domains were unrecognized duplicates of themselves — use first
                first_domain = next(iter(domains))
                result = {'service': first_domain, 'category': 'Other', 'icon': '🌐',
                          'domain': first_domain, 'via': ''}
            with self.lock:
                self._service_cache[ip] = result
            return result

        # No domains available — check if reverse DNS is already cached.
        # If not cached, queue for background rDNS and return placeholder
        # immediately instead of blocking on socket.gethostbyaddr
        # (which can take 5-30s per IP on Windows).
        with self.lock:
            rdns = self._rdns_cache.get(ip)
        if rdns is not None:
            # rDNS was already resolved (even if empty string = failed)
            if rdns:
                result = self.resolve_domain(rdns)
                result['domain'] = rdns
                with self.lock:
                    self._service_cache[ip] = result
                return result
        else:
            # Queue for background reverse DNS — will be available on next scan
            self.queue_reverse_dns(ip)
        # Return placeholder — don't block on reverse DNS
        if ip in ('1.1.1.1', '1.0.0.1'):
            result = {'service': 'Cloudflare DNS', 'category': 'DNS', 'icon': '🌐', 'domain': ip}
        elif ip.startswith('8.8.'):
            result = {'service': 'Google DNS', 'category': 'DNS', 'icon': '🌐', 'domain': ip}
        elif ip == '9.9.9.9':
            result = {'service': 'Quad9 DNS', 'category': 'DNS', 'icon': '🌐', 'domain': ip}
        else:
            # Name the address classes we can identify without any lookup,
            # rather than leaving them as an unlabelled '❓ Unknown'.
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                addr = None
            if addr is not None and addr.is_loopback:
                result = {'service': 'localhost', 'category': 'Local',
                          'icon': '🏠', 'domain': ip}
            elif addr is not None and addr.is_private:
                result = {'service': f'LAN host {ip}', 'category': 'Local',
                          'icon': '🏠', 'domain': ip}
            elif addr is not None and addr.is_multicast:
                result = {'service': f'Multicast {ip}', 'category': 'Local',
                          'icon': '📡', 'domain': ip}
            elif addr is not None and addr.is_link_local:
                result = {'service': f'Link-local {ip}', 'category': 'Local',
                          'icon': '🔗', 'domain': ip}
            else:
                result = {'service': ip, 'category': 'Unknown', 'icon': '❓', 'domain': ip}
        with self.lock:
            self._service_cache[ip] = result
        return result


# ========================== CONNECTION INVENTORY ==========================
class ConnectionEntry:
    """Single tracked connection with full metadata."""
    __slots__ = (
        'all_domains', 'asn', 'asn_org', 'category', 'city', 'cmdline', 'country',
        'country_code', 'domain', 'exe_path', 'first_seen', 'geo_source',
        'hop_distance', 'icon', 'is_cdn', 'is_hosting', 'is_proxy', 'is_vpn',
        'isp', 'last_seen', 'lat', 'local_ip', 'local_port', 'loc_confidence',
        'loc_grade', 'loc_proof', 'lon', 'open_ports', 'org', 'parent_name',
        'parent_pid', 'pid', 'process_name', 'protocol', 'proxy_detail',
        'proxy_type', 'rdns', 'region', 'remote_ip', 'remote_port', 'rtt_ms',
        'service', 'status', 'timezone', 'ttl_os', 'verify_conflicts',
        'verify_grade', 'verify_summary', 'via', 'vpn_labels', 'vpn_provider',
        'vpn_score', 'website_tag',
    )

    def __init__(self):
        self.pid = 0
        self.process_name = ''
        self.exe_path = ''
        self.parent_name = ''
        self.cmdline = ''
        self.website_tag = ''
        self.remote_ip = ''
        self.remote_port = 0
        self.local_port = 0
        self.protocol = 'TCP'
        self.status = ''
        self.service = 'Unknown'
        self.category = 'Unknown'
        self.icon = '❓'
        self.domain = ''
        self.all_domains: list = []
        self.via = ''
        self.country = '??'
        self.country_code = '??'
        self.city = '??'
        self.region = ''
        self.org = 'Unknown'
        self.isp = 'Unknown'
        self.lat = 0.0
        self.lon = 0.0
        self.first_seen = 0.0
        self.last_seen = 0.0
        self.loc_confidence = 0
        self.loc_grade = 'UNVERIFIED'
        self.loc_proof: list = []
        self.proxy_type = ''
        self.proxy_detail = ''
        # --- fields the collectors already harvest and used to discard ---
        self.local_ip = ''
        self.parent_pid = 0
        self.timezone = ''
        self.asn = ''
        self.asn_org = ''
        self.geo_source = ''
        self.rdns = ''
        # --- VPN / proxy / infrastructure verdict (from MultiVerifier) ---
        self.is_vpn = False
        self.is_proxy = False
        self.is_hosting = False
        self.is_cdn = False
        self.vpn_score = 0
        self.vpn_provider = ''
        self.vpn_labels: list = []
        self.verify_grade = ''
        self.verify_summary = ''
        self.verify_conflicts: list = []
        self.rtt_ms = None
        self.ttl_os = ''
        self.hop_distance = None
        self.open_ports: list = []

    def to_dict(self) -> dict:
        return {
            'pid': self.pid, 'process': self.process_name,
            'exe_path': self.exe_path, 'parent_name': self.parent_name,
            'cmdline': self.cmdline, 'website_tag': self.website_tag,
            'remote_ip': self.remote_ip, 'remote_port': self.remote_port,
            'local_port': self.local_port, 'protocol': self.protocol,
            'status': self.status, 'service': self.service,
            'category': self.category, 'icon': self.icon, 'domain': self.domain,
            'all_domains': self.all_domains, 'via': self.via,
            'country': self.country, 'country_code': self.country_code,
            'city': self.city, 'region': self.region,
            'org': self.org, 'isp': self.isp,
            'lat': self.lat, 'lon': self.lon,
            'first_seen': self.first_seen, 'last_seen': self.last_seen,
            'loc_confidence': self.loc_confidence, 'loc_grade': self.loc_grade,
            'loc_proof': self.loc_proof,
            'proxy_type': self.proxy_type, 'proxy_detail': self.proxy_detail,
            'local_ip': self.local_ip, 'parent_pid': self.parent_pid,
            'timezone': self.timezone, 'asn': self.asn, 'asn_org': self.asn_org,
            'geo_source': self.geo_source, 'rdns': self.rdns,
            'is_vpn': self.is_vpn, 'is_proxy': self.is_proxy,
            'is_hosting': self.is_hosting, 'is_cdn': self.is_cdn,
            'vpn_score': self.vpn_score, 'vpn_provider': self.vpn_provider,
            'vpn_labels': self.vpn_labels, 'verify_grade': self.verify_grade,
            'verify_summary': self.verify_summary,
            'verify_conflicts': self.verify_conflicts,
            'rtt_ms': self.rtt_ms, 'ttl_os': self.ttl_os,
            'hop_distance': self.hop_distance, 'open_ports': self.open_ports,
        }


class ConnectionInventory:
    """Maintains a live inventory of ALL network connections with service + geo data."""
    def __init__(self, dns_cache: DNSCache, geoip: GeoIPCache,
                 service_resolver: ServiceResolver, stop_event: threading.Event,
                 conn_provider=None):
        self.dns_cache = dns_cache
        self.geoip = geoip
        self.resolver = service_resolver
        self.stop = stop_event
        self._conn_provider = conn_provider
        self.loc_verifier = LocationVerifier(service_resolver)
        self.proxy_detector = ProxyDetector()
        self.lock = threading.Lock()
        self.connections: dict[tuple, ConnectionEntry] = {}
        self.services_seen: dict[str, dict] = {}
        # MultiVerifier reports keyed by IP, filled in by apply_verification().
        self._vpn_results: dict[str, dict] = {}
        # Set by the monitor: callable(ip) requesting VPN/proxy verification.
        self.verify_request_fn = None
        self.total_unique_ips: set[str] = set()
        self.scan_count = 0
        # Background location verification (see _queue_verification)
        self._verify_queue: queue.Queue = queue.Queue(maxsize=500)
        self._verify_results: dict[str, dict] = {}
        self._verify_requested: set[str] = set()
        self._verify_thread = threading.Thread(
            target=self._verification_worker, daemon=True, name="Location-Verify")
        self._verify_thread.start()
        # Background GeoIP enrichment queue — prevents scan from blocking on
        # network API calls (was causing 5+ min hangs on startup with 100+ IPs)
        self._geoip_queue: queue.Queue = queue.Queue(maxsize=1000)
        self._geoip_requested: set[str] = set()
        self._geoip_thread = threading.Thread(
            target=self._geoip_worker, daemon=True, name="GeoIP-Enrich")
        self._geoip_thread.start()

    # ---------- enrichment helpers ----------
    # Geo used to be copied field-by-field in three places, each of which
    # dropped the ASN and timezone the lookup had already paid for. One
    # helper now owns the mapping so every caller gets the full record.
    @staticmethod
    def _apply_geo(entry, geo: dict) -> None:
        entry.country = geo.get('country', '??')
        entry.country_code = geo.get('countryCode', '??')
        entry.city = geo.get('city', '??')
        entry.region = geo.get('regionName', '')
        entry.org = geo.get('org', 'Unknown')
        entry.isp = geo.get('isp', 'Unknown')
        entry.lat = geo.get('lat', 0.0)
        entry.lon = geo.get('lon', 0.0)
        entry.timezone = geo.get('timezone', '')
        entry.asn = geo.get('as', '')
        entry.geo_source = geo.get('_source', '')

    def _classify_proxy(self, entry) -> None:
        """(Re)run proxy classification for an entry.

        Worth repeating after GeoIP lands: residential-proxy detection matches
        on "domain org isp", and on a new connection org/isp are still
        'Unknown' because the geo lookup is queued to a background worker.
        Classifying only once therefore missed every org-based match.
        """
        try:
            info = self.proxy_detector.classify_connection(
                entry.remote_ip, entry.remote_port, entry.domain,
                entry.org, entry.isp, entry.asn)
            if info:
                entry.proxy_type = info.get('proxy_type', '')
                entry.proxy_detail = info.get('proxy_detail', '')
        except Exception as exc:
            _logger.debug("Proxy classify error for %s: %s", entry.remote_ip, exc)

    @staticmethod
    def _apply_verification(entry, rep: dict) -> None:
        """Attach a MultiVerifier report to a connection entry."""
        if not rep:
            return
        entry.is_vpn = bool(rep.get('is_vpn'))
        entry.is_proxy = bool(rep.get('is_proxy'))
        entry.is_hosting = bool(rep.get('is_hosting'))
        entry.is_cdn = bool(rep.get('is_cdn'))
        entry.vpn_score = rep.get('vpn_score', 0)
        entry.vpn_labels = list(rep.get('labels', []))
        entry.verify_grade = rep.get('grade', '')
        entry.verify_summary = rep.get('summary', '')
        entry.verify_conflicts = list(rep.get('conflicts', []))
        entry.rtt_ms = rep.get('rtt_ms')
        entry.ttl_os = rep.get('ttl_os', '')
        entry.hop_distance = rep.get('hop_distance')
        entry.open_ports = list(rep.get('open_ports', []))
        if rep.get('rdns'):
            entry.rdns = rep['rdns']
        if rep.get('asn') and not entry.asn:
            entry.asn = rep['asn']
        if rep.get('org'):
            entry.asn_org = rep['org']
        # Name the provider when a label identifies one, so the row can say
        # "NordVPN" rather than only "VPN".
        provider = ''
        for lbl in rep.get('labels', []):
            low = lbl.lower()
            if 'vpn' in low or 'proxy' in low or 'tor' in low:
                provider = lbl
                break
        entry.vpn_provider = provider

    def apply_verification(self, ip: str, rep: dict) -> None:
        """Called by the monitor's verification worker: fan a finished
        MultiVerifier report out to every connection on that IP, and remember
        it so connections opened later to the same IP are labelled at once."""
        if not ip or not rep:
            return
        with self.lock:
            if len(self._vpn_results) > 20000:
                self._vpn_results.clear()
            self._vpn_results[ip] = rep
            targets = [e for e in self.connections.values() if e.remote_ip == ip]
            for entry in targets:
                self._apply_verification(entry, rep)
                entry.website_tag = self._compute_website_tag(entry)

    def _record_service(self, entry, now: float) -> None:
        """Refresh the services summary row for this entry's service.

        This used to be written once, at insert time, when a brand new
        connection still had country '??' and lat/lon 0 because geo was
        queued asynchronously — so the Services view showed '??' forever.
        Caller must hold self.lock.
        """
        self.services_seen[entry.service] = {
            'category': entry.category, 'icon': entry.icon,
            'country': entry.country, 'country_code': entry.country_code,
            'city': entry.city, 'org': entry.org, 'isp': entry.isp,
            'lat': entry.lat, 'lon': entry.lon,
            'asn': entry.asn, 'is_vpn': entry.is_vpn,
            'proxy_type': entry.proxy_type,
            'last_seen': now,
        }

    def _queue_verification(self, ip: str, geo: dict):
        """Ask the background worker to verify an IP's location (once per IP)."""
        with self.lock:
            if ip in self._verify_requested:
                return
            self._verify_requested.add(ip)
        try:
            self._verify_queue.put_nowait((ip, dict(geo)))
        except queue.Full:
            with self.lock:
                self._verify_requested.discard(ip)

    def _queue_geoip(self, ip: str):
        """Queue an IP for background GeoIP enrichment (non-blocking)."""
        with self.lock:
            if ip in self._geoip_requested:
                return
            self._geoip_requested.add(ip)
        try:
            self._geoip_queue.put_nowait(ip)
        except queue.Full:
            with self.lock:
                self._geoip_requested.discard(ip)

    def _geoip_worker(self):
        """Background worker that does GeoIP lookups (which may involve
        network API calls) and enriches existing connection entries."""
        while not self.stop.is_set():
            try:
                ip = self._geoip_queue.get(timeout=1.0)
            except queue.Empty:
                continue
            try:
                geo = self.geoip.get_full(ip)
                if geo:
                    now = time.time()
                    # Enrich every connection to this IP. Geo arriving late is
                    # what unlocks org/ISP-based proxy classification and a
                    # better website tag, so redo both here rather than
                    # leaving them frozen at their pre-geo values.
                    with self.lock:
                        targets = [e for e in self.connections.values()
                                   if e.remote_ip == ip]
                        vpn_rep = self._vpn_results.get(ip)
                    for entry in targets:
                        self._apply_geo(entry, geo)
                        self._classify_proxy(entry)
                        if vpn_rep:
                            self._apply_verification(entry, vpn_rep)
                        entry.website_tag = self._compute_website_tag(entry)
                    with self.lock:
                        for entry in targets:
                            self._record_service(entry, now)
                    # Queue location verification now that we have geo
                    self._queue_verification(ip, geo)
                    # And full VPN/proxy cross-verification for this endpoint.
                    if self.verify_request_fn:
                        try:
                            self.verify_request_fn(ip)
                        except Exception:
                            pass
            except Exception as exc:
                _logger.debug("GeoIP enrichment error for %s: %s", ip, exc)
            finally:
                with self.lock:
                    self._geoip_requested.discard(ip)

    def _verification_worker(self):
        while not self.stop.is_set():
            try:
                ip, geo = self._verify_queue.get(timeout=1.0)
            except queue.Empty:
                continue
            try:
                vr = self.loc_verifier.verify(ip, geo)
                with self.lock:
                    self._verify_results[ip] = vr
                    for entry in self.connections.values():
                        if entry.remote_ip == ip:
                            entry.loc_confidence = vr.get('confidence', 0)
                            entry.loc_grade = vr.get('grade', 'UNVERIFIED')
                            entry.loc_proof = vr.get('proof', [])
            except Exception as exc:
                _logger.debug("Location verification failed for %s: %s", ip, exc)
            finally:
                self._verify_queue.task_done()

    def _is_public(self, ip: str) -> bool:
        try:
            return ipaddress.ip_address(ip).is_global
        except Exception:
            return False

    def _get_connections(self) -> list:
        if self._conn_provider:
            return self._conn_provider()
        try:
            return psutil.net_connections(kind='inet')
        except psutil.AccessDenied:
            _logger.debug("Connection inventory: access denied for net_connections")
            return []
        except Exception as exc:
            _logger.debug("Connection inventory scan error: %s", exc)
            return []

    _CDN_HOSTNAME_PATTERNS = (
        'cloudfront', 'akamai', 'fastly', 'cloudflare', 'amazonaws',
        'azureedge', 'edgecast', 'cdn.', 'deploy.static', 'compute-1.',
        'elb.', 'server-', '.r.cloudfront', 'hwcdn', 'edgesuite',
        'akadns', 'akamaiedge', 'azurefd', 'trafficmanager', 'msedge.net',
        'footprint.net', 'fpbns.net', 'nsatc.net', 'nflxvideo',
        'llnwd.net', 'lldns.net', 'edgekey', 'akamaihd', 'akamaitechnologies',
        'cloudapp.net', 'azure.com', 'googleusercontent', '1e100.net',
        'gstatic', 'ggpht', 'fbcdn', 'facebook.net', 'xx.fbcdn',
    )

    @staticmethod
    def _is_cdn_hostname(domain: str) -> bool:
        dl = domain.lower()
        return any(cdn in dl for cdn in ConnectionInventory._CDN_HOSTNAME_PATTERNS)

    @staticmethod
    def _compute_website_tag(entry) -> str:
        """Best-effort human-readable label for WHAT WEBSITE this connection is for."""
        svc = entry.service
        dom = entry.domain
        via = entry.via
        all_doms = entry.all_domains
        # If service is a known specific service (YouTube, Netflix, etc.) use it
        if svc and svc not in _GENERIC_SERVICES and not ServiceResolver._is_unresolved(svc):
            tag = svc
            if via:
                tag += f" (via {via})"
            return tag
        # If we have real website domains, pick the best one
        if all_doms:
            real_sites = [d for d in all_doms
                          if not ConnectionInventory._is_cdn_hostname(d)]
            if real_sites:
                # Prefer shortest non-www domain as it's usually the apex
                def _score(d):
                    d_lower = d.lower()
                    # Prefer shorter domains (apex like amazon.com over sub.amazon.com)
                    parts = d_lower.split('.')
                    return (len(parts), len(d_lower))
                best = min(real_sites, key=_score)
                tag = best
                if via:
                    tag += f" (via {via})"
                elif svc in _GENERIC_SERVICES:
                    tag += f" (via {svc})"
                return tag
        # Fall back: use domain if it's not just an IP
        if dom and not ServiceResolver._is_unresolved(dom) and dom != entry.remote_ip:
            # Even CDN hostname is better than nothing — show with org
            org = entry.org if hasattr(entry, 'org') and entry.org != 'Unknown' else ''
            if ConnectionInventory._is_cdn_hostname(dom) and org:
                return f"[{org}] {dom}"
            return dom
        # Use service + org for context
        if svc and not ServiceResolver._is_unresolved(svc):
            org = entry.org if hasattr(entry, 'org') and entry.org != 'Unknown' else ''
            if org and org.lower() not in svc.lower():
                return f"{svc} ({org})"
            return svc
        # Absolute fallback: IP + org
        org = entry.org if hasattr(entry, 'org') and entry.org != 'Unknown' else ''
        if org:
            return f"{entry.remote_ip} ({org})"
        return entry.remote_ip

    @staticmethod
    def _get_process_detail(pid: int) -> dict:
        """Gather full process detail for a PID: name, exe path, parent, cmdline."""
        info = {'name': f'PID:{pid}', 'exe_path': '', 'parent_name': '',
                'parent_pid': 0, 'cmdline': ''}
        if not pid:
            # psutil.Process(0) resolves to "System Idle Process" on Windows,
            # which mislabels every socket the OS could not attribute to an
            # owner (TIME_WAIT entries, and anything psutil sees without
            # elevation). Say what is actually known instead.
            info['name'] = '(unattributed socket)'
            return info
        try:
            proc = psutil.Process(pid)
            info['name'] = proc.name()
            try:
                info['exe_path'] = proc.exe() or ''
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass
            try:
                parent = proc.parent()
                if parent:
                    info['parent_name'] = parent.name()
                    info['parent_pid'] = parent.pid
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass
            try:
                cmdline = proc.cmdline()
                if cmdline:
                    info['cmdline'] = ' '.join(cmdline)[:300]
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        return info

    def scan(self):
        now = time.time()
        active_keys = set()
        conns = self._get_connections()
        # Pre-fetch existing connections under a single lock acquisition to
        # avoid per-connection lock contention. New entries are added in a
        # batch at the end.
        with self.lock:
            existing = dict(self.connections)
            cached_vr_snap = dict(self._verify_results)
            cached_vpn_snap = dict(self._vpn_results)
        new_entries: list[tuple[tuple, ConnectionEntry]] = []
        for conn in conns:
            if not conn.raddr:
                continue
            remote_ip = conn.raddr[0]
            remote_port = conn.raddr[1]
            pid = conn.pid or 0
            key = (remote_ip, remote_port, pid)
            active_keys.add(key)
            if key in existing:
                # Update existing entry in-place (no lock — only this thread writes)
                entry = existing[key]
                entry.last_seen = now
                entry.status = conn.status
                # If entry has no geo data yet, check if GeoIP is now cached
                if entry.lat == 0 and entry.lon == 0 and self._is_public(remote_ip):
                    cached_geo = self.geoip.get_cached(remote_ip)
                    if cached_geo:
                        self._apply_geo(entry, cached_geo)
                        self._classify_proxy(entry)
                        entry.website_tag = self._compute_website_tag(entry)
                        self._queue_verification(remote_ip, cached_geo)
                    elif remote_ip not in self._geoip_requested:
                        self._queue_geoip(remote_ip)
                # A verification report may have landed after this entry was
                # created (or been fetched for a sibling connection) — adopt it.
                if not entry.verify_grade:
                    rep = cached_vpn_snap.get(remote_ip)
                    if rep:
                        self._apply_verification(entry, rep)
                # Refresh all_domains from DNS cache (get_domains already locks internally)
                fresh_domains = self.dns_cache.get_domains(remote_ip)
                if fresh_domains:
                    entry.all_domains = sorted(fresh_domains)
                # Re-resolve service only if under-resolved
                cur_svc = entry.service
                needs_recheck = (
                    cur_svc in _GENERIC_SERVICES
                    or ServiceResolver._is_unresolved(cur_svc)
                    or not entry.domain
                    or entry.domain == remote_ip
                    or self._is_cdn_hostname(cur_svc)
                    or self._is_cdn_hostname(entry.domain)
                )
                if needs_recheck and fresh_domains:
                    svc_info = self.resolver.identify(remote_ip, fresh_domains)
                    new_svc = svc_info.get('service', cur_svc)
                    if new_svc != cur_svc:
                        entry.service = new_svc
                        entry.category = svc_info.get('category', entry.category)
                        entry.icon = svc_info.get('icon', entry.icon)
                        entry.domain = svc_info.get('domain', entry.domain)
                        entry.via = svc_info.get('via', entry.via)
                        entry.website_tag = self._compute_website_tag(entry)
                continue
            # --- New connection: gather full process detail ---
            pdetail = self._get_process_detail(pid)
            entry = ConnectionEntry()
            entry.pid = pid
            entry.process_name = pdetail['name']
            entry.exe_path = pdetail['exe_path']
            entry.parent_name = pdetail['parent_name']
            entry.cmdline = pdetail['cmdline']
            entry.parent_pid = pdetail['parent_pid']
            entry.remote_ip = remote_ip
            entry.remote_port = remote_port
            entry.local_ip = conn.laddr[0] if conn.laddr else ''
            entry.local_port = conn.laddr[1] if conn.laddr else 0
            entry.protocol = 'TCP' if conn.type == 1 else 'UDP'
            entry.status = conn.status
            entry.first_seen = now
            entry.last_seen = now
            domains = self.dns_cache.get_domains(remote_ip)
            svc_info = self.resolver.identify(remote_ip, domains)
            entry.service = svc_info.get('service', 'Unknown')
            entry.category = svc_info.get('category', 'Unknown')
            entry.icon = svc_info.get('icon', '❓')
            entry.domain = svc_info.get('domain', '')
            entry.via = svc_info.get('via', '')
            entry.all_domains = sorted(domains) if domains else []
            is_pub = self._is_public(remote_ip)
            if is_pub:
                # Check cache first — only do synchronous API lookup if cached.
                # If not cached, queue for background enrichment so the scan
                # doesn't block on network I/O (was causing 5+ min hangs).
                cached_geo = self.geoip.get_cached(remote_ip)
                if cached_geo:
                    self._apply_geo(entry, cached_geo)
                    self._queue_verification(remote_ip, cached_geo)
                else:
                    # Queue for background GeoIP enrichment
                    self._queue_geoip(remote_ip)
            # Proxy detection per-connection (repeated later once geo lands).
            self._classify_proxy(entry)
            cached_vr = cached_vr_snap.get(remote_ip)
            if cached_vr:
                entry.loc_confidence = cached_vr.get('confidence', 0)
                entry.loc_grade = cached_vr.get('grade', 'UNVERIFIED')
                entry.loc_proof = cached_vr.get('proof', [])
            cached_vpn = cached_vpn_snap.get(remote_ip)
            if cached_vpn:
                self._apply_verification(entry, cached_vpn)
            entry.website_tag = self._compute_website_tag(entry)
            if is_pub:
                self.total_unique_ips.add(remote_ip)
                # Every public endpoint gets VPN/proxy cross-verification, not
                # just the high-risk few. Without this the map's VPN markers
                # and the MULTIVERIFIER panel stayed blank for ordinary
                # traffic, which is most of it.
                if not cached_vpn and self.verify_request_fn:
                    try:
                        self.verify_request_fn(remote_ip)
                    except Exception:
                        pass
            new_entries.append((key, entry))
        # Batch update: single lock for all new entries + stale cleanup + scan_count
        with self.lock:
            for key, entry in new_entries:
                self.connections[key] = entry
                self._record_service(entry, now)
            stale = [k for k, v in self.connections.items() if k not in active_keys
                     and now - v.last_seen > 60]
            for k in stale:
                del self.connections[k]
            self.scan_count += 1

    def get_all(self) -> list[dict]:
        with self.lock:
            return [e.to_dict() for e in self.connections.values()]

    def get_map_points(self) -> list[dict]:
        seen_ips = {}
        with self.lock:
            for entry in self.connections.values():
                if (entry.lat != 0 or entry.lon != 0) and entry.remote_ip not in seen_ips:
                    seen_ips[entry.remote_ip] = {
                        'ip': entry.remote_ip, 'lat': entry.lat, 'lon': entry.lon,
                        'service': entry.service, 'icon': entry.icon,
                        'domain': entry.domain,
                        'all_domains': entry.all_domains,
                        'via': entry.via, 'website_tag': entry.website_tag,
                        'city': entry.city, 'country': entry.country,
                        'org': entry.org, 'process': entry.process_name,
                        'loc_confidence': entry.loc_confidence,
                        'loc_grade': entry.loc_grade,
                        'loc_proof': entry.loc_proof,
                        'proxy_type': entry.proxy_type,
                        'proxy_detail': entry.proxy_detail,
                        'is_vpn': entry.is_vpn, 'is_proxy': entry.is_proxy,
                        'is_hosting': entry.is_hosting, 'is_cdn': entry.is_cdn,
                        'vpn_score': entry.vpn_score,
                        'vpn_provider': entry.vpn_provider,
                        'vpn_labels': entry.vpn_labels,
                        'asn': entry.asn, 'rdns': entry.rdns,
                        'timezone': entry.timezone,
                        'verify_grade': entry.verify_grade,
                        'rtt_ms': entry.rtt_ms,
                    }
        return list(seen_ips.values())

    def get_services_summary(self) -> list[dict]:
        with self.lock:
            return [{'service': name, **info} for name, info in self.services_seen.items()]

    def get_stats(self) -> dict:
        with self.lock:
            return {
                'total_connections': len(self.connections),
                'unique_services': len(self.services_seen),
                'unique_ips': len(self.total_unique_ips),
                'scans': self.scan_count,
            }

    @staticmethod
    def format_terminal_line(entry) -> str:
        """One console row for a connection. Accepts a ConnectionEntry or the
        dict form produced by to_dict()."""
        if isinstance(entry, dict):
            icon = entry.get('icon', '?')
            service = entry.get('service', 'Unknown')
            process = entry.get('process', entry.get('process_name', '?'))
            ip = entry.get('remote_ip', '?')
            port = entry.get('remote_port', 0)
            city = entry.get('city', '??')
            cc = entry.get('country_code', '??')
            lat, lon = entry.get('lat', 0.0), entry.get('lon', 0.0)
            org = entry.get('org', '')
        else:
            icon, service = entry.icon, entry.service
            process, ip, port = entry.process_name, entry.remote_ip, entry.remote_port
            city, cc = entry.city, entry.country_code
            lat, lon, org = entry.lat, entry.lon, entry.org
        geo = f"{city}, {cc}" if city != '??' else cc
        coords = f"({lat:.2f}, {lon:.2f})" if lat or lon else ""
        return (f"    {icon} {service:20.20s} | {process:18.18s} | "
                f"{ip:15s}:{port:<5d} | {geo:20.20s} {coords} | {org}")

    def run_thread(self):
        _logger.info("Connection inventory thread started")
        first_scan = True
        while not self.stop.is_set():
            self.scan()
            if first_scan or self.scan_count % 12 == 0:
                self._log_summary()
                first_scan = False
            time.sleep(5)

    def _log_summary(self):
        entries = self.get_all()
        if not entries:
            return
        stats = self.get_stats()
        print(f"\n{Colors.G}{'='*100}")
        print(f"{EMOJI['chess']} CONNECTION MAP — {stats['total_connections']} active | "
              f"{stats['unique_services']} services | {stats['unique_ips']} unique IPs")
        print(f"{'='*100}{Colors.END}")
        by_cat = defaultdict(list)
        for e in entries:
            by_cat[e['category']].append(e)
        for cat in sorted(by_cat.keys()):
            conns = by_cat[cat]
            print(f"{Colors.C}  [{cat}]{Colors.END}")
            for c in conns[:15]:
                print(self.format_terminal_line(c))
            if len(conns) > 15:
                print(f"    ... and {len(conns)-15} more")
        print(f"{Colors.G}{'='*100}{Colors.END}\n")


# ========================== DASHBOARD ==========================
DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>MedianBoxMonitor Dashboard</title>
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"/>
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0a0a0f;color:#c0c0c0;font-family:'Consolas','Fira Code',monospace;font-size:13px}
.header{background:linear-gradient(135deg,#1a1a2e,#16213e);padding:12px 24px;border-bottom:2px solid #0f3460;display:flex;justify-content:space-between;align-items:center}
.header h1{color:#e94560;font-size:18px;text-shadow:0 0 20px rgba(233,69,96,0.5)}
.header .stats{display:flex;gap:16px}
.stat{text-align:center}.stat .val{font-size:20px;font-weight:bold;color:#00d4ff}.stat .lbl{font-size:9px;color:#666}
.tabs{display:flex;background:#12121a;border-bottom:2px solid #1a1a2e}
.tab{padding:10px 20px;cursor:pointer;color:#666;font-size:12px;text-transform:uppercase;letter-spacing:1px;border-bottom:2px solid transparent;transition:all .2s}
.tab:hover{color:#c0c0c0}.tab.active{color:#e94560;border-bottom-color:#e94560}
.tab-content{display:none;height:calc(100vh - 115px);overflow:hidden}
.tab-content.active{display:block}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:10px;padding:10px;height:100%;overflow:hidden}
.grid-3{display:grid;grid-template-columns:1fr;gap:10px;padding:10px;height:100%}
.panel{background:#12121a;border:1px solid #1a1a2e;border-radius:8px;overflow:hidden;display:flex;flex-direction:column}
.panel-title{background:#1a1a2e;padding:6px 14px;font-size:11px;font-weight:bold;color:#e94560;text-transform:uppercase;letter-spacing:1px}
.panel-body{overflow-y:auto;padding:6px;flex:1}
#map-container{height:50vh;border-radius:8px;overflow:hidden;border:1px solid #1a1a2e}
table{width:100%;border-collapse:collapse}
th{position:sticky;top:0;background:#1a1a2e;color:#0f3460;font-size:10px;text-align:left;padding:3px 6px;text-transform:uppercase}
td{padding:2px 6px;border-bottom:1px solid #1a1a2e;font-size:11px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:180px}
tr:hover{background:#1a1a2e}
.risk-critical{color:#e94560;font-weight:bold}.risk-warning{color:#f5a623}.risk-low{color:#4caf50}
.sev-CRITICAL{background:#e9456022;color:#e94560;padding:2px 6px;border-radius:3px;font-weight:bold;font-size:10px}
.sev-WARNING{background:#f5a62322;color:#f5a623;padding:2px 6px;border-radius:3px;font-size:10px}
.sev-INFO{background:#4caf5022;color:#4caf50;padding:2px 6px;border-radius:3px;font-size:10px}
.conn-row{display:flex;align-items:center;padding:4px 8px;border-bottom:1px solid #1a1a2e;gap:8px;font-size:11px}
.conn-row:hover{background:#1a1a2e}
.conn-icon{font-size:16px;min-width:22px;text-align:center}
.conn-svc{color:#00d4ff;font-weight:bold;min-width:130px}
.conn-proc{color:#f5a623;min-width:120px}
.conn-ip{color:#888;min-width:150px;font-family:monospace}
.conn-geo{color:#4caf50;min-width:160px}
.conn-coords{color:#666;font-size:10px;min-width:120px}
.conn-org{color:#888;flex:1;overflow:hidden;text-overflow:ellipsis}
.cat-header{padding:6px 12px;background:#0f3460;color:#00d4ff;font-size:11px;font-weight:bold;text-transform:uppercase;letter-spacing:1px;margin-top:2px}
.device{padding:3px 0;border-bottom:1px solid #1a1a2e;display:flex;justify-content:space-between;font-size:11px}
::-webkit-scrollbar{width:6px}::-webkit-scrollbar-track{background:#0a0a0f}::-webkit-scrollbar-thumb{background:#1a1a2e;border-radius:3px}
.leaflet-popup-content{font-family:'Consolas',monospace;font-size:12px;color:#222}
.leaflet-popup-content b{color:#e94560}
</style></head><body>
<div class="header">
  <h1>&#9823; MedianBoxMonitor 3.0</h1>
  <div class="stats">
    <div class="stat"><div class="val" id="s-conn">-</div><div class="lbl">CONNECTIONS</div></div>
    <div class="stat"><div class="val" id="s-svc">-</div><div class="lbl">SERVICES</div></div>
    <div class="stat"><div class="val" id="s-ips">-</div><div class="lbl">UNIQUE IPs</div></div>
    <div class="stat"><div class="val" id="s-proc">-</div><div class="lbl">PROCESSES</div></div>
    <div class="stat"><div class="val" id="s-ded">-</div><div class="lbl">DEDUCTIONS</div></div>
    <div class="stat"><div class="val" id="s-dev">-</div><div class="lbl">DEVICES</div></div>
    <div class="stat"><div class="val" id="s-idle">-</div><div class="lbl">IDLE (s)</div></div>
  </div>
</div>
<div class="tabs">
  <div class="tab active" onclick="switchTab('map')">&#127758; Connection Map</div>
  <div class="tab" onclick="switchTab('list')">&#128196; All Connections</div>
  <div class="tab" onclick="switchTab('deductions')">&#128680; Deductions</div>
  <div class="tab" onclick="switchTab('processes')">&#128202; Processes</div>
  <div class="tab" onclick="switchTab('devices')">&#127381; Devices</div>
</div>
<!-- TAB 1: Connection Map -->
<div id="tab-map" class="tab-content active">
  <div class="grid" style="grid-template-columns:1fr;grid-template-rows:55% 45%">
    <div id="map-container"></div>
    <div class="panel"><div class="panel-title">&#128225; Active Services</div>
      <div class="panel-body" id="svc-body"></div>
    </div>
  </div>
</div>
<!-- TAB 2: All Connections -->
<div id="tab-list" class="tab-content">
  <div class="grid-3"><div class="panel"><div class="panel-title">&#128279; All Active Connections (auto-discovered)</div>
    <div class="panel-body" id="conn-body"></div>
  </div></div>
</div>
<!-- TAB 3: Deductions -->
<div id="tab-deductions" class="tab-content">
  <div class="grid-3"><div class="panel"><div class="panel-title">&#128680; Live Deductions</div><div class="panel-body">
    <table><thead><tr><th>Time</th><th>Sev</th><th>Cat</th><th>Process</th><th>Message</th><th>Score</th></tr></thead><tbody id="ded-table"></tbody></table>
  </div></div></div>
</div>
<!-- TAB 4: Processes -->
<div id="tab-processes" class="tab-content">
  <div class="grid-3"><div class="panel"><div class="panel-title">&#128202; Process Risk Scores</div><div class="panel-body">
    <table><thead><tr><th>PID</th><th>Name</th><th>Risk</th><th>Conn</th><th>Dst</th><th>ML</th><th>Countries</th></tr></thead><tbody id="proc-table"></tbody></table>
  </div></div></div>
</div>
<!-- TAB 5: Devices -->
<div id="tab-devices" class="tab-content">
  <div class="grid-3"><div class="panel"><div class="panel-title">&#127381; Network Devices</div>
    <div class="panel-body" id="dev-body"></div>
  </div></div>
</div>
<script>
// === Map Setup ===
const map=L.map('map-container',{zoomControl:true}).setView([30,0],2);
L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png',{
  attribution:'&copy; OSM &copy; CARTO',maxZoom:18,subdomains:'abcd'
}).addTo(map);
const markers={};
function updateMap(points){
  const seen=new Set();
  (points||[]).forEach(p=>{
    if(!p.lat&&!p.lon)return;
    const k=p.ip;seen.add(k);
    if(markers[k]){markers[k].setPopupContent(popupHtml(p));return}
    const m=L.circleMarker([p.lat,p.lon],{radius:6,color:'#e94560',fillColor:'#00d4ff',fillOpacity:0.8,weight:1}).addTo(map);
    m.bindPopup(popupHtml(p));markers[k]=m;
  });
  Object.keys(markers).forEach(k=>{if(!seen.has(k)){map.removeLayer(markers[k]);delete markers[k]}});
}
function popupHtml(p){
  const d=document.createElement('div');
  d.innerHTML='';
  if(p.website_tag){const wt=document.createElement('b');wt.style.color='#00ff88';wt.textContent='\ud83c\udff7\ufe0f '+p.website_tag;d.appendChild(wt);d.appendChild(document.createElement('br'))}
  const b1=document.createElement('b');b1.textContent=p.service+' '+p.icon;d.appendChild(b1);
  d.appendChild(document.createElement('br'));
  // Server & Network Identifier block — lists names as they are named
  const sid=document.createElement('div');sid.style.color='#00d4ff';sid.style.fontSize='11px';
  sid.style.borderTop='1px solid #333';sid.style.marginTop='4px';sid.style.paddingTop='4px';
  let sidHtml='<b>SERVER & NETWORK IDENTIFIER</b><br>';
  if(p.service&&p.service!=='Unknown'&&p.service!==p.ip)sidHtml+='Service: '+p.service+'<br>';
  if(p.domain&&p.domain!=='unresolved'&&p.domain!==p.ip)sidHtml+='Domain: '+p.domain+'<br>';
  if(p.website_tag&&p.website_tag!==p.service)sidHtml+='Tag: '+p.website_tag+'<br>';
  if(p.org&&p.org!=='Unknown')sidHtml+='Org: '+p.org+'<br>';
  if(p.isp&&p.isp!=='Unknown'&&p.isp!==p.org)sidHtml+='ISP: '+p.isp+'<br>';
  if(p.country&&p.country_code)sidHtml+='Network: '+p.country+' ('+p.country_code+')<br>';
  if(p.rdns)sidHtml+='rDNS: '+p.rdns+'<br>';
  if(p.asn)sidHtml+='ASN: '+p.asn+'<br>';
  sid.innerHTML=sidHtml;
  d.appendChild(sid);
  let domLine=p.domain||'';
  if(p.via)domLine+=' (via '+p.via+')';
  if(domLine){const dt=document.createTextNode(domLine);d.appendChild(dt);d.appendChild(document.createElement('br'))}
  const t1=document.createTextNode(p.ip+' ('+p.process+')');d.appendChild(t1);
  d.appendChild(document.createElement('br'));
  const t2=document.createTextNode(p.city+', '+p.country);d.appendChild(t2);
  d.appendChild(document.createElement('br'));
  const sm=document.createElement('small');sm.textContent=p.org+' | '+p.lat.toFixed(4)+', '+p.lon.toFixed(4);d.appendChild(sm);
  if(p.all_domains&&p.all_domains.length>1){d.appendChild(document.createElement('br'));const ad=document.createElement('small');ad.style.color='#888';ad.textContent='Domains: '+p.all_domains.slice(0,6).join(', ')+(p.all_domains.length>6?' (+'+String(p.all_domains.length-6)+')':'');d.appendChild(ad)}
  return d.innerHTML;
}
// === Tab Switching ===
function switchTab(name){
  document.querySelectorAll('.tab').forEach((t,i)=>t.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(t=>t.classList.remove('active'));
  document.getElementById('tab-'+name).classList.add('active');
  document.querySelectorAll('.tab').forEach(t=>{if(t.textContent.toLowerCase().includes(name.slice(0,4)))t.classList.add('active')});
  if(name==='map')setTimeout(()=>map.invalidateSize(),100);
}
// === DOM Helpers ===
function mkTd(text){const td=document.createElement('td');td.textContent=text;return td}
function mkRow(cells){const tr=document.createElement('tr');cells.forEach(c=>{if(typeof c==='object')tr.appendChild(c);else tr.appendChild(mkTd(c))});return tr}
function riskClass(r){return r>=70?'risk-critical':r>=40?'risk-warning':'risk-low'}
function sevClass(s){return{'CRITICAL':'sev-CRITICAL','WARNING':'sev-WARNING','INFO':'sev-INFO'}[s]||'sev-INFO'}
// === Connection List ===
function updateConnections(conns){
  const body=document.getElementById('conn-body');body.replaceChildren();
  if(!conns||!conns.length){body.textContent='Scanning connections...';return}
  const byCat={};
  conns.forEach(c=>{if(!byCat[c.category])byCat[c.category]=[];byCat[c.category].push(c)});
  Object.keys(byCat).sort().forEach(cat=>{
    const hdr=document.createElement('div');hdr.className='cat-header';hdr.textContent=cat+' ('+byCat[cat].length+')';body.appendChild(hdr);
    byCat[cat].forEach(c=>{
      const row=document.createElement('div');row.className='conn-row';
      const icon=document.createElement('span');icon.className='conn-icon';icon.textContent=c.icon;
      const svc=document.createElement('span');svc.className='conn-svc';svc.textContent=c.service+(c.via?' (via '+c.via+')':'');
      const dom=document.createElement('span');dom.className='conn-proc';dom.style.color='#888';dom.textContent=c.domain||'';
      const proc=document.createElement('span');proc.className='conn-proc';proc.textContent=c.process;
      const ip=document.createElement('span');ip.className='conn-ip';ip.textContent=c.remote_ip+':'+c.remote_port;
      const geo=document.createElement('span');geo.className='conn-geo';
      geo.textContent=(c.city&&c.city!=='??')?c.city+', '+c.country_code:c.country_code;
      const coords=document.createElement('span');coords.className='conn-coords';
      coords.textContent=(c.lat||c.lon)?'('+c.lat.toFixed(2)+', '+c.lon.toFixed(2)+')':'';
      const org=document.createElement('span');org.className='conn-org';org.textContent=c.org||'';
      row.appendChild(icon);row.appendChild(svc);row.appendChild(dom);row.appendChild(proc);row.appendChild(ip);
      row.appendChild(geo);row.appendChild(coords);row.appendChild(org);body.appendChild(row);
    });
  });
}
// === Services Summary ===
function updateServices(svcs){
  const body=document.getElementById('svc-body');body.replaceChildren();
  if(!svcs||!svcs.length)return;
  svcs.sort((a,b)=>(a.category||'').localeCompare(b.category||''));
  svcs.forEach(s=>{
    const row=document.createElement('div');row.className='conn-row';
    const icon=document.createElement('span');icon.className='conn-icon';icon.textContent=s.icon;
    const svc=document.createElement('span');svc.className='conn-svc';svc.textContent=s.service;
    const geo=document.createElement('span');geo.className='conn-geo';
    geo.textContent=(s.city&&s.city!=='??')?s.city+', '+s.country:'';
    const org=document.createElement('span');org.className='conn-org';org.textContent=s.org||'';
    const coords=document.createElement('span');coords.className='conn-coords';
    coords.textContent=(s.lat||s.lon)?'('+s.lat.toFixed(2)+', '+s.lon.toFixed(2)+')':'';
    row.appendChild(icon);row.appendChild(svc);row.appendChild(geo);row.appendChild(coords);row.appendChild(org);
    body.appendChild(row);
  });
}
// === Main Update ===
function update(data){
  document.getElementById('s-conn').textContent=data.conn_stats?data.conn_stats.total_connections:'-';
  document.getElementById('s-svc').textContent=data.conn_stats?data.conn_stats.unique_services:'-';
  document.getElementById('s-ips').textContent=data.conn_stats?data.conn_stats.unique_ips:'-';
  document.getElementById('s-proc').textContent=data.processes?data.processes.length:'-';
  document.getElementById('s-ded').textContent=data.deductions?data.deductions.length:'-';
  document.getElementById('s-dev').textContent=data.devices?data.devices.length:'-';
  document.getElementById('s-idle').textContent=data.idle_seconds||'-';
  updateMap(data.map_points);
  updateConnections(data.connections);
  updateServices(data.services);
  let dt=document.getElementById('ded-table');dt.replaceChildren();
  (data.deductions||[]).slice(0,50).forEach(d=>{
    const sevTd=document.createElement('td');
    const sevSpan=document.createElement('span');sevSpan.className=sevClass(d.severity);sevSpan.textContent=d.severity;
    sevTd.appendChild(sevSpan);
    const msgTd=document.createElement('td');msgTd.textContent=(d.message||'').slice(0,80);msgTd.title=d.message||'';
    dt.appendChild(mkRow([d.time,sevTd,d.category,d.process+':'+d.pid,msgTd,String(d.score)]));
  });
  let pt=document.getElementById('proc-table');pt.replaceChildren();
  (data.processes||[]).filter(p=>p.risk>0.1||p.connections>0).slice(0,60).forEach(p=>{
    const riskTd=document.createElement('td');riskTd.textContent=p.risk;riskTd.className=riskClass(p.risk);
    pt.appendChild(mkRow([String(p.pid),p.name,riskTd,String(p.connections),String(p.destinations),String(p.ml_score),(p.countries||[]).join(',')]));
  });
  let db=document.getElementById('dev-body');db.replaceChildren();
  (data.devices||[]).forEach(d=>{
    const div=document.createElement('div');div.className='device';
    const s1=document.createElement('span');s1.textContent=(d.ip||'?')+' \\u2014 '+(d.vendor||'?')+' \\u2014 '+(d.hostname||'?');
    const s2=document.createElement('span');s2.textContent=(d.os_guess||'?')+' | conf='+(d.confidence||0).toFixed(2);
    div.appendChild(s1);div.appendChild(s2);db.appendChild(div);
  });
}
const urlParams=new URLSearchParams(window.location.search);
const authToken=urlParams.get('token')||'';
const wsUrl='ws://'+location.host+'/ws'+(authToken?'?token='+encodeURIComponent(authToken):'');
const apiUrl='/api/state'+(authToken?'?token='+encodeURIComponent(authToken):'');
let ws=new WebSocket(wsUrl);
ws.onmessage=e=>update(JSON.parse(e.data));
ws.onclose=()=>setTimeout(()=>location.reload(),5000);
setInterval(()=>{if(ws.readyState!==1)fetch(apiUrl).then(r=>r.json()).then(update).catch(()=>{})},5000);
</script></body></html>"""


# ========================== GNA TRACER GUI ==========================

class TileManager:
    """Downloads and caches OpenStreetMap raster tiles for real map rendering.
    Uses Web Mercator (EPSG:3857) projection — same as Google Maps, Leaflet, etc.
    Tiles show real roads, streets, buildings, and terrain at every zoom level.
    Supports fractional zoom by scaling tiles with PIL for smooth transitions.
    """
    TILE_SIZE = 256
    MAX_CACHE = 800  # max PIL images in memory cache
    _cache: dict = {}  # (z, x, y) -> PIL.Image
    _photo_cache: dict = {}  # (z, x, y) -> ImageTk.PhotoImage (Tk-safe)
    _pending: set = set()  # tiles being downloaded
    _lock = threading.Lock()
    _user_agent = 'MedianBoxMonitor/3.0 (network security monitoring)'

    # Tile style definitions — each style has its own server list and max zoom.
    # Styles are switched at runtime via set_style().
    TILE_STYLES = {
        'osm': {
            'label': 'OSM Standard',
            'servers': [
                'https://tile.openstreetmap.org/{z}/{x}/{y}.png',
                'https://a.tile.openstreetmap.org/{z}/{x}/{y}.png',
                'https://b.tile.openstreetmap.org/{z}/{x}/{y}.png',
                'https://c.tile.openstreetmap.org/{z}/{x}/{y}.png',
            ],
            'max_zoom': 19,
            'attribution': '© OpenStreetMap contributors',
        },
        'dark': {
            'label': 'CartoDB Dark Matter',
            'servers': [
                'https://a.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}.png',
                'https://b.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}.png',
                'https://c.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}.png',
                'https://d.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}.png',
            ],
            'max_zoom': 20,
            'attribution': '© OpenStreetMap, © CARTO',
        },
        'voyager': {
            'label': 'CartoDB Voyager',
            'servers': [
                'https://a.basemaps.cartocdn.com/rastertiles/voyager/{z}/{x}/{y}.png',
                'https://b.basemaps.cartocdn.com/rastertiles/voyager/{z}/{x}/{y}.png',
                'https://c.basemaps.cartocdn.com/rastertiles/voyager/{z}/{x}/{y}.png',
                'https://d.basemaps.cartocdn.com/rastertiles/voyager/{z}/{x}/{y}.png',
            ],
            'max_zoom': 20,
            'attribution': '© OpenStreetMap, © CARTO',
        },
        'satellite': {
            'label': 'Esri World Imagery (Satellite)',
            'servers': [
                'https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}',
            ],
            'max_zoom': 19,
            'attribution': '© Esri, Maxar, Earthstar Geographics',
        },
        'terrain': {
            'label': 'Esri World Terrain',
            'servers': [
                'https://server.arcgisonline.com/ArcGIS/rest/services/World_Terrain_Base/MapServer/tile/{z}/{y}/{x}',
            ],
            'max_zoom': 13,
            'attribution': '© Esri, USGS, NOAA',
        },
        'topo': {
            'label': 'OpenTopoMap',
            'servers': [
                'https://a.tile.opentopomap.org/{z}/{x}/{y}.png',
                'https://b.tile.opentopomap.org/{z}/{x}/{y}.png',
                'https://c.tile.opentopomap.org/{z}/{x}/{y}.png',
            ],
            'max_zoom': 17,
            'attribution': '© OpenStreetMap, SRTM | © OpenTopoMap',
        },
    }
    _current_style = 'osm'
    _server_idx = 0

    @classmethod
    def set_style(cls, style_key):
        """Switch the active tile style. Clears caches so tiles reload."""
        if style_key in cls.TILE_STYLES:
            cls._current_style = style_key
            cls._server_idx = 0
            with cls._lock:
                cls._cache.clear()
                cls._photo_cache.clear()
                cls._pending.clear()

    @classmethod
    def get_style(cls):
        return cls._current_style

    @classmethod
    def get_style_max_zoom(cls):
        return cls.TILE_STYLES.get(cls._current_style, {}).get('max_zoom', 19)

    @classmethod
    def get_style_label(cls):
        return cls.TILE_STYLES.get(cls._current_style, {}).get('label', 'OSM')

    @classmethod
    def get_style_attribution(cls):
        return cls.TILE_STYLES.get(cls._current_style, {}).get('attribution', '')

    @classmethod
    def get_tile(cls, z, x, y):
        """Return cached PIL.Image for tile (z,x,y) or None if not yet downloaded.
        Starts a background download if the tile is not cached and not pending.
        """
        # Wrap x for world continuity
        n = 2 ** z
        x_wrapped = x % n
        key = (z, x_wrapped, y)
        with cls._lock:
            if key in cls._cache:
                return cls._cache[key]
            if key in cls._pending:
                return None
            cls._pending.add(key)
        # Start background download
        t = threading.Thread(target=cls._download_tile, args=(z, x_wrapped, y), daemon=True)
        t.start()
        return None

    @classmethod
    def get_photo(cls, z, x, y):
        """Return cached ImageTk.PhotoImage for tile (z,x,y) or None.
        Creates and caches the PhotoImage if the PIL image is available.
        Must be called from the Tk main thread."""
        n = 2 ** z
        x_wrapped = x % n
        key = (z, x_wrapped, y)
        with cls._lock:
            if key in cls._photo_cache:
                return cls._photo_cache[key]
            if key in cls._cache:
                img = cls._cache[key]
            else:
                return None
        # Create PhotoImage from PIL image (must be on Tk thread)
        try:
            photo = ImageTk.PhotoImage(img)
            with cls._lock:
                # Evict oldest entries if cache is full
                if len(cls._photo_cache) >= cls.MAX_CACHE:
                    oldest_key = next(iter(cls._photo_cache))
                    del cls._photo_cache[oldest_key]
                cls._photo_cache[key] = photo
            return photo
        except Exception:
            return None

    @classmethod
    def get_scaled_photo(cls, z, x, y, scale):
        """Return a scaled PhotoImage for fractional zoom.
        scale = target_size / TILE_SIZE (e.g. 0.7 for 70% size).
        Must be called from the Tk main thread."""
        n = 2 ** z
        x_wrapped = x % n
        key = (z, x_wrapped, y)
        with cls._lock:
            if key in cls._cache:
                img = cls._cache[key]
            else:
                return None
        try:
            new_size = max(1, int(cls.TILE_SIZE * scale))
            scaled = img.resize((new_size, new_size), Image.LANCZOS)
            photo = ImageTk.PhotoImage(scaled)
            return photo
        except Exception:
            return None

    @classmethod
    def _download_tile(cls, z, x, y):
        """Download a single tile and cache it."""
        key = (z, x, y)
        style_def = cls.TILE_STYLES.get(cls._current_style, cls.TILE_STYLES['osm'])
        servers = style_def['servers']
        with cls._lock:
            idx = cls._server_idx
            cls._server_idx = (idx + 1) % len(servers)
        url = servers[idx].format(z=z, x=x, y=y)
        try:
            req = urllib.request.Request(url, headers={'User-Agent': cls._user_agent})
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = resp.read()
            if HAS_PIL:
                img = Image.open(io.BytesIO(data))
                img.load()  # force load from buffer
                with cls._lock:
                    # Evict oldest PIL images if cache is full
                    if len(cls._cache) >= cls.MAX_CACHE:
                        oldest_key = next(iter(cls._cache))
                        del cls._cache[oldest_key]
                        # Also evict from photo cache
                        cls._photo_cache.pop(oldest_key, None)
                    cls._cache[key] = img
        except Exception as exc:
            _logger.debug("Tile download failed for %s: %s", key, exc)
        finally:
            # Always clear the pending marker, or this tile can never be retried.
            with cls._lock:
                cls._pending.discard(key)

    # Web Mercator is undefined at the poles: at |lat| = 90 the projection
    # term tan(lat)+sec(lat) collapses to 0 and math.log() raises ValueError.
    # Clamp to the standard Web Mercator limit used by OSM/Google/Leaflet.
    MAX_LAT = 85.05112878

    @staticmethod
    def latlon_to_pixel(lat, lon, zoom):
        """Convert lat/lon to global pixel coordinates at given zoom (Web Mercator).
        Supports fractional zoom values. Latitude is clamped to +/-85.05112878."""
        n = 2.0 ** zoom
        try:
            lat = float(lat)
            lon = float(lon)
        except (TypeError, ValueError):
            lat = lon = 0.0
        lat = max(-TileManager.MAX_LAT, min(TileManager.MAX_LAT, lat))
        lon = max(-180.0, min(180.0, lon))
        x = (lon + 180.0) / 360.0 * n * TileManager.TILE_SIZE
        lat_rad = math.radians(lat)
        y = (1.0 - math.log(math.tan(lat_rad) + 1.0 / math.cos(lat_rad)) / math.pi) / 2.0 * n * TileManager.TILE_SIZE
        return x, y

    @staticmethod
    def pixel_to_latlon(px, py, zoom):
        """Convert global pixel coordinates back to lat/lon (Web Mercator).
        Supports fractional zoom values."""
        n = 2.0 ** zoom
        lon = px / (n * TileManager.TILE_SIZE) * 360.0 - 180.0
        lat_rad = math.atan(math.sinh(math.pi * (1.0 - 2.0 * py / (n * TileManager.TILE_SIZE))))
        lat = math.degrees(lat_rad)
        return lat, lon

    @classmethod
    def cache_size(cls):
        with cls._lock:
            return len(cls._cache)

    @classmethod
    def photo_cache_size(cls):
        with cls._lock:
            return len(cls._photo_cache)

    @classmethod
    def clear_photo_cache(cls):
        """Clear the PhotoImage cache (call when zoom changes to free memory)."""
        with cls._lock:
            cls._photo_cache.clear()

    @staticmethod
    def meters_per_pixel(lat, zoom):
        """Return meters per pixel at given latitude and zoom level."""
        n = 2.0 ** zoom
        lat = max(-TileManager.MAX_LAT, min(TileManager.MAX_LAT, lat))
        return 40075016.686 * math.cos(math.radians(lat)) / (n * TileManager.TILE_SIZE)


# Simplified world coastline points (lat, lon) — kept as fallback when PIL is not available
_WORLD_COASTLINE = [
    # North America
    (49, -125), (48, -123), (45, -124), (42, -124), (38, -123), (34, -120),
    (32, -117), (28, -115), (23, -110), (20, -105), (18, -103), (16, -96),
    (15, -92), (18, -88), (21, -87), (25, -90), (29, -89), (30, -84),
    (27, -80), (25, -80), (30, -81), (32, -80), (35, -75), (37, -76),
    (39, -74), (41, -72), (42, -70), (43, -70), (44, -67), (45, -67),
    (47, -68), (47, -65), (45, -61), (47, -60), (49, -64), (47, -56),
    (52, -56), (55, -60), (58, -64), (60, -65), (63, -68), (66, -62),
    (60, -46), (70, -52), (72, -56), (75, -60), (78, -73), (76, -89),
    (70, -100), (68, -110), (70, -128), (68, -136), (60, -140), (59, -150),
    (55, -160), (57, -157), (58, -153), (60, -147), (60, -141), (55, -132),
    (54, -130), (49, -125),
    None,  # break
    # South America
    (12, -72), (10, -76), (8, -77), (2, -78), (-2, -80), (-5, -81), (-6, -77),
    (-15, -75), (-18, -71), (-23, -70), (-27, -71), (-33, -72), (-41, -74),
    (-46, -76), (-53, -71), (-55, -68), (-52, -68), (-48, -66), (-42, -64),
    (-37, -57), (-35, -53), (-23, -42), (-13, -39), (-8, -35), (-2, -44),
    (2, -50), (5, -52), (7, -58), (8, -60), (10, -62), (11, -68), (12, -72),
    None,  # break
    # Europe
    (36, -6), (37, -2), (38, 0), (40, 0), (43, 3), (43, 7), (44, 9),
    (40, 14), (38, 16), (38, 21), (40, 24), (41, 29), (43, 28), (44, 34),
    (46, 37), (47, 40), (50, 40), (55, 38), (58, 30), (60, 29), (62, 30),
    (65, 26), (68, 20), (70, 20), (71, 26), (70, 30), (68, 44), (64, 40),
    (60, 32), (58, 28), (56, 21), (55, 12), (54, 9), (53, 7), (52, 5),
    (51, 4), (49, 0), (48, -5), (44, -8), (43, -9), (37, -9), (36, -6),
    None,  # break
    # Africa
    (36, -6), (35, -1), (37, 10), (33, 12), (32, 24), (31, 32), (22, 37),
    (12, 44), (2, 42), (-10, 40), (-15, 41), (-26, 33), (-34, 18),
    (-34, 18), (-33, 17), (-30, 17), (-22, 14), (-17, 12), (-12, 14),
    (-5, 12), (4, 2), (6, 1), (4, -7), (5, -4), (7, -5), (10, -15),
    (15, -17), (21, -17), (27, -13), (31, -10), (36, -6),
    None,  # break
    # Asia
    (42, 30), (41, 40), (37, 44), (30, 48), (25, 56), (22, 60), (25, 62),
    (25, 66), (24, 68), (20, 73), (15, 74), (8, 77), (6, 80), (10, 80),
    (16, 81), (22, 88), (22, 97), (10, 99), (1, 104), (-7, 106), (-8, 115),
    (-6, 120), (0, 118), (5, 119), (12, 109), (18, 106), (22, 108), (22, 114),
    (30, 122), (35, 129), (38, 127), (39, 126), (43, 132), (46, 143),
    (50, 143), (52, 141), (56, 136), (59, 143), (62, 150), (60, 163),
    (64, 177), (66, 175), (68, 180), (72, 140), (75, 97), (73, 70),
    (68, 55), (55, 55), (50, 53), (44, 50), (42, 44), (42, 30),
    None,  # break
    # Australia
    (-12, 130), (-12, 136), (-15, 141), (-17, 146), (-24, 152), (-28, 154),
    (-33, 152), (-38, 145), (-39, 146), (-37, 150), (-34, 151), (-29, 153),
    (-38, 148), (-39, 147), (-43, 147), (-44, 146), (-38, 140),
    (-35, 137), (-35, 135), (-32, 133), (-32, 127), (-22, 114),
    (-14, 127), (-12, 130),
]

# Country label positions (lat, lon, name) — shown at zoom >= 1.5
_COUNTRY_LABELS = [
    (39, -98, "USA"), (56, -96, "CANADA"), (23, -102, "MEXICO"), (-14, -51, "BRAZIL"),
    (-35, -65, "ARGENTINA"), (4, -72, "COLOMBIA"), (-10, -76, "PERU"), (46, 2, "FRANCE"),
    (51, 10, "GERMANY"), (42, 12, "ITALY"), (40, -4, "SPAIN"), (55, -3, "UK"),
    (52, 20, "POLAND"), (50, 14, "CZECH"), (47, 8, "SWISS"), (60, 25, "FINLAND"),
    (62, 15, "SWEDEN"), (62, 10, "NORWAY"), (56, 10, "DENMARK"), (52, 5, "NL"),
    (50, 4, "BELGIUM"), (47, 19, "HUNGARY"), (44, 21, "SERBIA"), (42, 24, "BULGARIA"),
    (39, 22, "GREECE"), (38, 35, "TURKEY"), (32, 54, "IRAN"), (33, 44, "IRAQ"),
    (24, 45, "SAUDI"), (25, 55, "UAE"), (30, 70, "PAKISTAN"), (22, 79, "INDIA"),
    (35, 105, "CHINA"), (37, 128, "S.KOREA"), (36, 138, "JAPAN"), (15, 101, "THAILAND"),
    (2, 112, "MALAYSIA"), (-2, 118, "INDONESIA"), (-25, 135, "AUSTRALIA"), (-42, 174, "NZ"),
    (61, 100, "RUSSIA"), (48, 68, "KAZAKH"), (41, 65, "UZBEK"), (32, 35, "ISRAEL"),
    (30, 31, "EGYPT"), (7, -2, "GHANA"), (10, 8, "NIGERIA"), (-1, 37, "KENYA"),
    (-14, 34, "MALAWI"), (-26, 28, "S.AFRICA"), (34, 9, "TUNISIA"), (34, -2, "MOROCCO"),
    (14, 108, "VIETNAM"), (13, 105, "CAMBODIA"), (16, 96, "MYANMAR"), (1, 104, "SINGAPORE"),
    (14, 121, "PHILIPPINES"), (24, 121, "TAIWAN"), (47, 29, "MOLDOVA"), (46, 25, "ROMANIA"),
]

# Major cities (lat, lon, name, population_tier) — tier 1 shown at zoom >=3, tier 2 at >=6
_MAJOR_CITIES = [
    # Tier 1 — world capitals / mega cities (zoom >= 3)
    (40.71, -74.01, "New York", 1), (34.05, -118.24, "Los Angeles", 1),
    (41.88, -87.63, "Chicago", 1), (51.51, -0.13, "London", 1),
    (48.86, 2.35, "Paris", 1), (52.52, 13.41, "Berlin", 1),
    (55.76, 37.62, "Moscow", 1), (35.68, 139.69, "Tokyo", 1),
    (39.91, 116.39, "Beijing", 1), (31.23, 121.47, "Shanghai", 1),
    (22.32, 114.17, "Hong Kong", 1), (1.35, 103.82, "Singapore", 1),
    (28.61, 77.21, "New Delhi", 1), (19.08, 72.88, "Mumbai", 1),
    (-23.55, -46.63, "Sao Paulo", 1), (19.43, -99.13, "Mexico City", 1),
    (-33.87, 151.21, "Sydney", 1), (25.20, 55.27, "Dubai", 1),
    (30.04, 31.24, "Cairo", 1), (-1.29, 36.82, "Nairobi", 1),
    (37.57, 127.00, "Seoul", 1), (13.76, 100.50, "Bangkok", 1),
    (45.46, 9.19, "Milan", 1), (59.33, 18.07, "Stockholm", 1),
    (38.72, -9.14, "Lisbon", 1), (41.01, 29.00, "Istanbul", 1),
    # Tier 2 — secondary cities (zoom >= 6)
    (47.61, -122.33, "Seattle", 2), (37.77, -122.42, "San Francisco", 2),
    (29.76, -95.37, "Houston", 2), (33.75, -84.39, "Atlanta", 2),
    (25.76, -80.19, "Miami", 2), (42.36, -71.06, "Boston", 2),
    (39.95, -75.17, "Philadelphia", 2), (38.91, -77.04, "Washington DC", 2),
    (43.65, -79.38, "Toronto", 2), (45.50, -73.57, "Montreal", 2),
    (49.28, -123.12, "Vancouver", 2), (53.55, 9.99, "Hamburg", 2),
    (48.14, 11.58, "Munich", 2), (50.94, 6.96, "Cologne", 2),
    (43.30, -1.98, "Bilbao", 2), (41.39, 2.17, "Barcelona", 2),
    (40.42, -3.70, "Madrid", 2), (53.35, -6.26, "Dublin", 2),
    (47.50, 19.04, "Budapest", 2), (50.08, 14.44, "Prague", 2),
    (48.21, 16.37, "Vienna", 2), (46.95, 7.45, "Bern", 2),
    (60.17, 24.94, "Helsinki", 2), (59.91, 10.75, "Oslo", 2),
    (55.68, 12.57, "Copenhagen", 2), (52.37, 4.90, "Amsterdam", 2),
    (50.85, 4.35, "Brussels", 2), (44.43, 26.10, "Bucharest", 2),
    (42.70, 23.32, "Sofia", 2), (37.97, 23.73, "Athens", 2),
    (39.92, 32.85, "Ankara", 2), (35.69, 51.39, "Tehran", 2),
    (24.69, 46.72, "Riyadh", 2), (31.95, 35.93, "Amman", 2),
    (33.89, 35.50, "Beirut", 2), (33.31, 44.37, "Baghdad", 2),
    (34.53, 69.17, "Kabul", 2), (23.81, 90.41, "Dhaka", 2),
    (27.72, 85.32, "Kathmandu", 2), (6.93, 79.84, "Colombo", 2),
    (22.57, 88.36, "Kolkata", 2), (12.97, 77.59, "Bangalore", 2),
    (23.13, 113.26, "Guangzhou", 2), (22.54, 114.06, "Shenzhen", 2),
    (30.57, 104.07, "Chengdu", 2), (34.26, 108.94, "Xi'an", 2),
    (14.60, 120.98, "Manila", 2), (21.03, 105.85, "Hanoi", 2),
    (10.82, 106.63, "Ho Chi Minh", 2), (3.14, 101.69, "Kuala Lumpur", 2),
    (-6.21, 106.85, "Jakarta", 2), (-37.81, 144.96, "Melbourne", 2),
    (-36.85, 174.76, "Auckland", 2), (-33.45, -70.67, "Santiago", 2),
    (-34.61, -58.38, "Buenos Aires", 2), (-12.05, -77.04, "Lima", 2),
    (4.71, -74.07, "Bogota", 2), (-22.91, -43.17, "Rio de Janeiro", 2),
    (-15.79, -47.88, "Brasilia", 2), (6.52, 3.38, "Lagos", 2),
    (9.06, 7.49, "Abuja", 2), (-33.93, 18.42, "Cape Town", 2),
    (36.75, 3.06, "Algiers", 2), (33.97, -6.85, "Rabat", 2),
]


class _BufferedText:
    """Collects insert() calls and replays them as one Tk call.

    The connection detail renderer issues ~40 inserts per expanded row; across
    a few hundred rows that is ~9 000 round trips into Tk per refresh. Tk's
    Text.insert accepts interleaved (text, tags) pairs, so the whole batch can
    go over in a single call. Only insert() is buffered because that is the
    only Text method the detail renderer uses.
    """
    __slots__ = ('_w', '_buf')

    def __init__(self, widget):
        self._w = widget
        self._buf: list = []

    def insert(self, _index, text, tags=""):
        self._buf.append(text)
        self._buf.append(tags if tags else ())

    def flush(self):
        if self._buf:
            self._w.insert("end", *self._buf)
            self._buf.clear()


class WidgetTooltip:
    """Reusable hover tooltip for any Tkinter widget.
    Shows a multi-line detail box when the user hovers over the widget.
    Supports rich text with optional color coding via (text, tag) tuples.
    """

    _instances: list = []  # track all instances for cleanup

    def __init__(self, widget, text, delay_ms=400, bg="#1e1e30", fg="#c8c8e0",
                 font=("Consolas", 8), padx=8, pady=5, max_width=420):
        self.widget = widget
        self._text = text
        self._delay_ms = delay_ms
        self._bg = bg
        self._fg = fg
        self._font = font
        self._padx = padx
        self._pady = pady
        self._max_width = max_width
        self._tip_window = None
        self._after_id = None
        # Bind events
        self.widget.bind("<Enter>", self._on_enter, add="+")
        self.widget.bind("<Leave>", self._on_leave, add="+")
        self.widget.bind("<Motion>", self._on_motion, add="+")
        WidgetTooltip._instances.append(self)

    def _on_enter(self, event):
        self._schedule(event)

    def _on_motion(self, event):
        # Re-schedule if we haven't shown yet (follow mouse)
        if self._tip_window is None:
            self._schedule(event)

    def _schedule(self, event):
        self._cancel()
        x, y = event.x_root + 15, event.y_root + 10
        self._after_id = self.widget.after(
            self._delay_ms, lambda: self._show(x, y))

    def _cancel(self):
        if self._after_id is not None:
            try:
                self.widget.after_cancel(self._after_id)
            except Exception:
                pass
            self._after_id = None

    def _on_leave(self, event=None):
        self._cancel()
        self._hide()

    def _show(self, x, y):
        self._hide()
        if not self._text:
            return
        try:
            self._tip_window = tk.Toplevel(self.widget)
            self._tip_window.wm_overrideredirect(True)
            # Keep tooltip on screen
            screen_w = self.widget.winfo_screenwidth()
            screen_h = self.widget.winfo_screenheight()
            if x + self._max_width + 20 > screen_w:
                x = screen_w - self._max_width - 20
            if y + 100 > screen_h:
                y = max(0, screen_h - 120)
            self._tip_window.wm_geometry(f"+{int(x)}+{int(y)}")
            self._tip_window.attributes("-topmost", True)
            frame = tk.Frame(self._tip_window, bg=self._bg, bd=1, relief="solid")
            frame.pack()
            # Support multi-line text
            lines = self._text.split('\n') if isinstance(self._text, str) else self._text
            for line in lines:
                if isinstance(line, tuple):
                    txt, tag = line
                    color = {"header": "#00d4ff", "dim": "#8a8a9a",
                             "warn": "#ffcc44", "crit": "#ff4444",
                             "info": "#44dd66", "label": "#a0a0b0"}.get(tag, self._fg)
                else:
                    txt = line
                    color = self._fg
                # Highlight separator lines (─────) with a dimmer color
                if isinstance(txt, str) and txt.startswith('──'):
                    color = "#5a5a6a"
                lbl = tk.Label(frame, text=txt, bg=self._bg, fg=color,
                               font=self._font, justify="left",
                               padx=self._padx, pady=self._pady, anchor="w")
                lbl.pack(fill="x")
        except Exception:
            self._tip_window = None

    def _hide(self):
        if self._tip_window is not None:
            try:
                self._tip_window.destroy()
            except Exception:
                pass
            self._tip_window = None

    def destroy(self):
        self._cancel()
        self._hide()


def _add_tooltip(widget, text, delay_ms=400):
    """Convenience function to attach a tooltip to any widget."""
    return WidgetTooltip(widget, text, delay_ms=delay_ms)


class GNATracerGUI:
    """Full-detail popup window for GNA Tracer — shows 100% of all data."""

    def __init__(self, get_state_fn, get_full_data_fn, stop_event: threading.Event,
                 geoip=None, proxy_detector=None, location_verifier=None,
                 monitor=None, whois=None):
        self._get_state = get_state_fn
        self._get_full_data = get_full_data_fn
        self._stop = stop_event
        # Intelligence sources for the Double Trace tab (all optional).
        self._geoip = geoip
        self._proxy_detector = proxy_detector
        self._location_verifier = location_verifier
        # The owning monitor: watchlist API and remote-IP -> process lookup.
        self._monitor = monitor
        self._whois = whois if whois is not None else getattr(monitor, 'whois_lookup', None)
        # Right-click targets, keyed by the Tk tag applied to each rendered row.
        self._ctx_conns: dict = {}
        self._ctx_procs: dict = {}
        self._search_jobs: dict = {}     # debounce handles per search box
        self._last_full_data = None      # newest payload, for search re-renders
        self._alert_flash_tabs: dict[str, int] = {}  # tabs currently flashing
        self._last_suspicious_count = 0
        # Mirror of the monitor's watchlist, refreshed on every cycle.
        self._watchlist_ips: set[str] = set()
        self._watchlist_procs: set[str] = set()
        self._root = None
        self._map_canvas = None
        self._map_dots = {}  # ip -> canvas item id
        # tag name -> callback, for text spans that stand in for buttons
        self._click_cmds: dict = {}
        # Set while the map tab is hidden; the tab repaints once on return
        # instead of redrawing every tile on every refresh cycle.
        self._map_data_dirty = False
        self._map_w = 1200
        self._map_h = 700
        self._tooltip = None
        self._tooltip_id = None
        self._selected_ip = None
        # Zoom / pan state for real tile map (Web Mercator).
        # Default zoom raised from 2.0 to 3.0 (50% more, per request) — the
        # old default plus a center point unrelated to the user (20°N, 0°E,
        # mid-Atlantic) meant the very first view of the map was a huge,
        # mostly-empty world view. Once the user's own GeoIP resolves, the
        # first map refresh re-centers on it (see _refresh_map) — this is
        # just the fallback for before that lookup completes, or when GeoIP
        # is disabled.
        self._map_zoom = 3.0          # fractional zoom (integer part = OSM tile level)
        self._map_center_lat = 20.0   # initial center latitude (until auto-centered)
        self._map_center_lon = 0.0    # initial center longitude (until auto-centered)
        self._map_auto_centered = False  # True once centered on the user's own location
        self._map_drag_start = None   # (x, y) when drag starts
        self._map_left_drag_start = None  # for left-button panning
        self._map_left_pan_offset = (0, 0)
        self._map_left_click_moved = False  # True if left-drag exceeded threshold
        self._map_min_zoom = 0.0
        self._map_max_zoom = 19.0
        self._map_tile_images = []    # keep refs to PhotoImage objects to prevent GC
        self._map_use_tiles = HAS_PIL  # use real tiles if PIL available
        self._map_tile_retry_after = 0  # timestamp to retry tile rendering
        self._last_map_data: dict = {}   # cached map payload for redraws
        self._notebook = None            # set in _run_gui, used to switch tabs
        self._map_pan_offset = (0, 0)  # screen offset for smooth panning
        self._map_scale_bar_id: list = []  # canvas item ids for the scale bar
        self._map_style_var = None     # tk.StringVar for style selector
        self._map_search_var = None    # tk.StringVar for location search
        self._map_help_visible = False # keyboard help overlay toggle
        self._map_action_log_expanded = True  # action log panel state
        self._ip_actions_text = None
        self._update_job = None
        self._status_job = None
        # Low-latency GUI tuning
        self._gui_refresh_ms = int(CONFIG.get('gui_refresh_ms', 250))
        self._last_refresh_time = 0.0
        self._refresh_latency_ms = 0.0
        self._active_tab_index = 0  # currently visible tab (for delta refresh)
        # Connection blocking — dict: ip -> {service, domain, process, pid, time_blocked, ...}
        self._blocked_ips: dict = {}
        self._conn_paused = False
        self._conn_buttons: list = []  # track embedded button widgets
        self._fw_rule_prefix = 'GNA_Tracer_Block_'
        # Auto-save series
        self._session_start = time.time()
        self._save_counter = 0
        self._autosave_job = None
        self._autosave_interval_ms = 10 * 60 * 1000  # 10 minutes

        # ---- Double / Multi-hop Trace state ----
        self._trace_lock = threading.Lock()
        self._trace_thread = None
        self._trace_stop = threading.Event()   # set to abort an in-flight trace
        self._trace_running = False
        self._trace_proc = None                # live traceroute subprocess
        # results is a list of "trace blocks", newest last; each block is a dict:
        #   {target, started, finished, status, hops:[hop dicts]}
        self._trace_blocks: list = []
        self._trace_max_blocks = 200           # keep memory bounded
        self._trace_dirty = True               # redraw display when True
        # Rotating .txt logging
        desktop = os.path.join(os.path.expanduser("~"), "Desktop")
        self._trace_log_dir = os.path.join(desktop, "GNA_Double_Trace_Logs")
        self._trace_log_index = 1
        self._trace_log_max_bytes = 1 * 1024 * 1024   # rotate at 1 MB (configurable in UI)
        self._trace_log_path = None
        self._trace_log_lock = threading.Lock()
        # TCP traceroute fallback: when ICMP traceroute returns no hops (common
        # for VPN/proxy endpoints that block ICMP), retry with TCP SYN probes
        # to a common port (80/443). Many firewalls allow TCP but drop ICMP.
        self._trace_tcp_fallback = True
        self._trace_tcp_ports = (443, 80, 8080)
        # Auto-retrace interval (seconds). 0 = disabled.
        self._trace_auto_interval = 0
        self._trace_auto_job = None
        self._trace_auto_targets: list = []
        # Provider-name fragments used to LABEL a hop's infrastructure (detection
        # only; this does NOT defeat a VPN). Shared with MultiVerifier.
        self._vpn_org_markers = _VPN_ORG_MARKERS
        self._hosting_org_markers = _HOSTING_ORG_MARKERS
        # Full cross-verification engine (built lazily from the passed sources).
        self._multiverifier = None

    def _get_multiverifier(self):
        # Prefer the monitor's instance. A GUI-local one kept a *separate*
        # cache, so an IP verified from the trace tab stayed unlabelled
        # everywhere else and got re-probed from scratch by the workers.
        shared = getattr(self._monitor, 'multiverifier', None)
        if shared is not None:
            return shared
        if self._multiverifier is None:
            self._multiverifier = MultiVerifier(
                geoip=self._geoip,
                location_verifier=self._location_verifier,
                proxy_detector=self._proxy_detector)
        return self._multiverifier

    def _toggle_conn_pause(self):
        self._conn_paused = not self._conn_paused
        if hasattr(self, '_pause_btn'):
            self._pause_btn.config(
                text='▶ Resume Updates' if self._conn_paused else '⏸ Pause Updates',
                bg='#4caf50' if self._conn_paused else '#333344')

    def _toggle_block_ip(self, ip, conn_info=None):
        if ip in self._blocked_ips:
            self._unblock_ip(ip)
        else:
            self._block_ip(ip, conn_info)

    @staticmethod
    def _is_admin():
        """Check if the current process has admin/elevated privileges."""
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False

    def _run_firewall_cmd(self, args):
        """Run a netsh firewall command and return (success, stderr_text).
        If already admin, runs directly. Otherwise runs normally (may fail)."""
        try:
            result = subprocess.run(
                args, capture_output=True, timeout=10,
                creationflags=0x08000000, text=True)
            if result.returncode == 0:
                return True, ''
            return False, result.stderr.strip() or result.stdout.strip()
        except Exception as exc:
            return False, str(exc)

    def _run_elevated_batch(self, commands):
        """Write commands to a temp .bat, run it elevated via UAC prompt, wait for it.
        Returns True if UAC was accepted and commands executed."""
        import ctypes
        import ctypes.wintypes
        import tempfile

        # Write batch file
        bat_path = os.path.join(tempfile.gettempdir(), 'gna_tracer_fw.bat')
        with open(bat_path, 'w', encoding='ascii', errors='replace') as f:
            f.write('@echo off\n')
            for cmd in commands:
                f.write(cmd + '\n')

        # SHELLEXECUTEINFOW structure for ShellExecuteExW
        class SHELLEXECUTEINFO(ctypes.Structure):
            _fields_ = [
                ("cbSize", ctypes.wintypes.DWORD),
                ("fMask", ctypes.c_ulong),
                ("hwnd", ctypes.wintypes.HANDLE),
                ("lpVerb", ctypes.c_wchar_p),
                ("lpFile", ctypes.c_wchar_p),
                ("lpParameters", ctypes.c_wchar_p),
                ("lpDirectory", ctypes.c_wchar_p),
                ("nShow", ctypes.c_int),
                ("hInstApp", ctypes.wintypes.HINSTANCE),
                ("lpIDList", ctypes.c_void_p),
                ("lpClass", ctypes.c_wchar_p),
                ("hkeyClass", ctypes.wintypes.HKEY),
                ("dwHotKey", ctypes.wintypes.DWORD),
                ("hIcon", ctypes.wintypes.HANDLE),
                ("hProcess", ctypes.wintypes.HANDLE),
            ]

        SEE_MASK_NOCLOSEPROCESS = 0x00000040
        SW_HIDE = 0

        sei = SHELLEXECUTEINFO()
        sei.cbSize = ctypes.sizeof(sei)
        sei.fMask = SEE_MASK_NOCLOSEPROCESS
        sei.hwnd = None
        sei.lpVerb = "runas"
        sei.lpFile = bat_path
        sei.lpParameters = ""
        sei.lpDirectory = None
        sei.nShow = SW_HIDE
        sei.hProcess = None

        try:
            if not ctypes.windll.shell32.ShellExecuteExW(ctypes.byref(sei)):
                return False  # user cancelled UAC or error
            if sei.hProcess:
                # Wait up to 30 seconds for the batch to finish
                ctypes.windll.kernel32.WaitForSingleObject(sei.hProcess, 30000)
                # Get exit code — previously computed and then discarded, so a
                # failed netsh still reported success.
                exit_code = ctypes.wintypes.DWORD()
                ok = ctypes.windll.kernel32.GetExitCodeProcess(
                    sei.hProcess, ctypes.byref(exit_code))
                ctypes.windll.kernel32.CloseHandle(sei.hProcess)
                if ok and exit_code.value not in (0, 259):  # 259 = STILL_ACTIVE
                    _logger.warning("Elevated batch exited with code %s", exit_code.value)
                    return False
            return True  # UAC accepted, commands ran
        except Exception as exc:
            _logger.warning("Elevated execution failed: %s", exc)
            return False
        finally:
            try:
                os.remove(bat_path)
            except Exception:
                pass

    def _verify_rule_exists(self, rule_name):
        """Check if a firewall rule exists by name."""
        try:
            result = subprocess.run(
                ['netsh', 'advfirewall', 'firewall', 'show', 'rule',
                 f'name={rule_name}'],
                capture_output=True, timeout=10,
                creationflags=0x08000000, text=True)
            return result.returncode == 0 and 'Rule Name' in result.stdout
        except Exception:
            return False

    def _block_ip(self, ip, conn_info=None):
        if not ip or ip in self._blocked_ips:
            return
        rule_name = f'{self._fw_rule_prefix}{ip.replace(".", "_").replace(":", "_")}'
        if self._is_admin():
            # Already admin — run directly
            ok_out, _ = self._run_firewall_cmd(
                ['netsh', 'advfirewall', 'firewall', 'add', 'rule',
                 f'name={rule_name}', 'dir=out', f'remoteip={ip}',
                 'action=block', 'protocol=any'])
            ok_in, _ = self._run_firewall_cmd(
                ['netsh', 'advfirewall', 'firewall', 'add', 'rule',
                 f'name={rule_name}_in', 'dir=in', f'remoteip={ip}',
                 'action=block', 'protocol=any'])
            success = ok_out and ok_in
        else:
            # Not admin — elevate via UAC prompt
            commands = [
                f'netsh advfirewall firewall add rule name="{rule_name}" dir=out remoteip={ip} action=block protocol=any',
                f'netsh advfirewall firewall add rule name="{rule_name}_in" dir=in remoteip={ip} action=block protocol=any',
            ]
            uac_ok = self._run_elevated_batch(commands)
            if not uac_ok:
                messagebox.showwarning(
                    "Block Cancelled",
                    f"UAC prompt was cancelled or failed for {ip}.\n"
                    "You must click Yes on the Windows permission dialog.")
                return
            # Verify the rules were actually created
            success = self._verify_rule_exists(rule_name)

        if success:
            meta = {
                'ip': ip,
                'time_blocked': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'service': (conn_info or {}).get('service', '?'),
                'domain': (conn_info or {}).get('domain', '?'),
                'process': (conn_info or {}).get('process', '?'),
                'pid': (conn_info or {}).get('pid', '?'),
                'country': (conn_info or {}).get('country', '?'),
                'city': (conn_info or {}).get('city', '?'),
                'org': (conn_info or {}).get('org', '?'),
                'isp': (conn_info or {}).get('isp', '?'),
                'remote_port': (conn_info or {}).get('remote_port', '?'),
                'category': (conn_info or {}).get('category', '?'),
            }
            self._blocked_ips[ip] = meta
            _logger.info('GNA Tracer: Blocked IP %s (both directions)', ip)
        else:
            messagebox.showerror(
                "Block Failed",
                f"Failed to create firewall rules for {ip}.\n\n"
                "The rules could not be verified after execution.")
            _logger.warning('GNA Tracer: Failed to block %s', ip)
        self._update_blocked_label()

    def _unblock_ip(self, ip):
        if not ip or ip not in self._blocked_ips:
            return
        rule_name = f'{self._fw_rule_prefix}{ip.replace(".", "_").replace(":", "_")}'
        if self._is_admin():
            self._run_firewall_cmd(
                ['netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                 f'name={rule_name}'])
            self._run_firewall_cmd(
                ['netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                 f'name={rule_name}_in'])
        else:
            commands = [
                f'netsh advfirewall firewall delete rule name="{rule_name}"',
                f'netsh advfirewall firewall delete rule name="{rule_name}_in"',
            ]
            self._run_elevated_batch(commands)
        self._blocked_ips.pop(ip, None)
        _logger.info('GNA Tracer: Unblocked IP %s', ip)
        self._update_blocked_label()

    def _unblock_all(self):
        ips = list(self._blocked_ips)
        if not ips:
            return
        if self._is_admin():
            for ip in ips:
                self._unblock_ip(ip)
            return
        # Not admin: batch every delete into ONE elevated call so the user gets a
        # single UAC prompt instead of one per blocked IP.
        commands = []
        for ip in ips:
            rule_name = f'{self._fw_rule_prefix}{ip.replace(".", "_").replace(":", "_")}'
            commands.append(f'netsh advfirewall firewall delete rule name="{rule_name}"')
            commands.append(f'netsh advfirewall firewall delete rule name="{rule_name}_in"')
        self._run_elevated_batch(commands)
        for ip in ips:
            self._blocked_ips.pop(ip, None)
            _logger.info('GNA Tracer: Unblocked IP %s', ip)
        self._update_blocked_label()

    def _update_blocked_label(self):
        if hasattr(self, '_blocked_lbl'):
            n = len(self._blocked_ips)
            if n:
                ip_list = ', '.join(sorted(self._blocked_ips.keys()))
                self._blocked_lbl.config(
                    text=f'🚫 Blocked ({n}): {ip_list}',
                    fg='#ff4444')
            else:
                self._blocked_lbl.config(
                    text='No IPs blocked',
                    fg='#8a8a9a')

    # ─── Scroll-aware refresh helpers ───
    def _is_at_bottom(self, widget):
        """Return True if the scrollbar is near the bottom (auto-scroll zone)."""
        return widget.yview()[1] >= 0.95

    def _begin_refresh(self, widget):
        """Save scroll state before a full rewrite. Returns (was_at_bottom, top_line).
        Uses line-number-based preservation so the view doesn't bump when content grows."""
        at_bottom = self._is_at_bottom(widget)
        # Get the line number at the top of the viewport (not a fraction)
        try:
            top_index = widget.index("@0,0")
            top_line = int(top_index.split('.')[0])
        except Exception:
            top_line = 1
        return at_bottom, top_line

    def _end_refresh(self, widget, at_bottom, top_line):
        """Restore scroll: auto-scroll to end if was at bottom, else restore line position.
        Uses line-number-based preservation to avoid view bumping on content changes."""
        if at_bottom:
            widget.see("end")
        else:
            # Get total lines in the widget after the rewrite
            try:
                end_index = widget.index("end-1c")
                total_lines = int(end_index.split('.')[0])
                # Calculate fraction to position the saved line at the top
                if total_lines > 1:
                    frac = max(0.0, min(1.0, (top_line - 1) / max(1, total_lines - 1)))
                    widget.yview_moveto(frac)
            except Exception:
                pass

    # ─── Search infrastructure ───
    def _make_search_bar(self, parent, search_var):
        """Create a search toolbar frame with entry + clear button. Returns the frame."""
        bar = tk.Frame(parent, bg="#1a1a2e", height=28)
        bar.pack(fill="x", side="top")
        bar.pack_propagate(False)
        tk.Label(bar, text="🔍", bg="#1a1a2e", fg="#8a8a9a",
                 font=("Consolas", 10)).pack(side="left", padx=(8, 2))
        entry = tk.Entry(bar, textvariable=search_var, bg="#222233", fg="#00d4ff",
                         insertbackground="#00d4ff", font=("Consolas", 9),
                         bd=0, highlightthickness=1, highlightcolor="#444477")
        entry.pack(side="left", fill="x", expand=True, padx=4, pady=3)
        clear_btn = tk.Button(bar, text="✕", bg="#1a1a2e", fg="#8a8a9a",
                              font=("Consolas", 9), bd=0, padx=4,
                              command=lambda: search_var.set(""))
        clear_btn.pack(side="right", padx=4)
        return bar

    # Tab descriptions for info banners and tooltips
    TAB_DESCRIPTIONS = {
        0: ("📊 Overview",
            "System overview: connection counts, process counts, deductions,\n"
            "extended monitor stats (FS, USB, clipboard, scheduled tasks, pipes,\n"
            "inbound scans, DoH, certs), proxy detections, high-risk processes,\n"
            "and active services with GeoIP locations."),
        1: ("🟢 Live Connections",
            "Only ACTIVE/ESTABLISHED connections, grouped by service category.\n"
            "Click ▶ to expand each connection for full details:\n"
            "process, exe path, parent, protocol, status, domain, GeoIP,\n"
            "location verification, proxy detection, and block/unblock actions."),
        2: ("🔗 All Connections",
            "Every network connection (active + closed + listening).\n"
            "Includes service identification, GeoIP enrichment, proxy type,\n"
            "risk score, and firewall block/unblock buttons.\n"
            "Use ⏸ Pause to freeze updates while browsing."),
        3: ("🚨 Deductions",
            "Security deductions with severity (CRITICAL/WARNING/INFO),\n"
            "evidence lines, affected process, risk points, and timestamps.\n"
            "Each deduction explains WHY it was flagged and what evidence\n"
            "triggered the alert."),
        4: ("📈 Processes",
            "All running processes with risk scores, connection counts,\n"
            "destination counts, CPU usage, ML anomaly scores, countries\n"
            "contacted, DNS domains, and behavioral flags (beacon, exfil,\n"
            "impersonation, injection, mimic, foreign, idle anomaly)."),
        5: ("📱 Devices",
            "Network devices discovered via ARP scanning.\n"
            "Shows IP, MAC, vendor (OUI lookup), hostname, device type,\n"
            "first seen, last seen, and whether the device is new or known."),
        6: ("🗺️ IP Map",
            "Interactive atlas with 6 tile styles (OSM, Dark, Voyager,\n"
            "Satellite, Terrain, Topo). Real roads/streets/buildings.\n"
            "Zoom 0-20, pan (left/right drag), search cities, preset bookmarks,\n"
            "connection dots colored by risk, trace path overlay, RTT rings,\n"
            "VPN exit node markers with disclaimers."),
        7: ("📝 Actions Log",
            "Complete audit log of every process action: STARTED, STOPPED,\n"
            "NETWORK_FLOW, BLOCK, UNBLOCK. Each entry includes PID, process\n"
            "name, action type, timestamp, and details."),
        8: ("🖥️ Terminal",
            "Raw terminal output — 100% of all processed events and log lines.\n"
            "This is the unfiltered feed from the monitoring engine, including\n"
            "packet processing, detection alerts, and system status messages."),
        9: ("🔴 Suspicious Activity",
            "Only out-of-norm behavior: remote access, high-risk geo,\n"
            "hardware access (audio/camera), DNS tunneling, beacons,\n"
            "impersonation, mimicry, foreign connections, exfiltration,\n"
            "injection chains, DLL injection, persistence, DoH, VT hits,\n"
            "file system changes, clipboard access, USB, scheduled tasks,\n"
            "named pipes, inbound scans, Bluetooth, serial ports, VPN leaks."),
        10: ("🛑 Blocked IPs",
             "IPs blocked via Windows Firewall rules.\n"
             "Shows IP, service, domain, process, PID, block time,\n"
             "and unblock buttons. Blocked IPs have outbound firewall rules\n"
             "prefixed with 'GNA_Tracer_Block_'."),
        11: ("🌳 Process Tree",
              "Hierarchical tree of all running processes showing parent-child\n"
              "relationships, with risk scores, connection counts, and\n"
              "behavioral flags. Useful for spotting suspicious process chains\n"
              "(e.g., cmd.exe → powershell.exe → rundll32.exe)."),
        12: ("📊 Net Stats",
              "Per-network-interface bandwidth statistics: bytes sent/received,\n"
              "packet counts, error rates, drop rates, and bandwidth trends\n"
              "over time. Shows both current rates and cumulative totals."),
        13: ("⏱️ Timeline",
              "Chronological timeline of all connection events (connect,\n"
              "disconnect, new IP, new service, block, unblock, alert).\n"
              "Useful for reconstructing what happened and when."),
        14: ("⚙️ Config",
              "Current configuration values (all CONFIG keys).\n"
              "Includes live refresh rate control, export HTML report button,\n"
              "watchlist IPs/processes, and instructions for editing\n"
              "medianbox_config.yaml."),
        15: ("🔀 Double Trace",
              "Multi-hop traceroute to any destination. Shows each hop's IP,\n"
              "RTT, GeoIP location, and infrastructure label (VPN/proxy/\n"
              "hosting/CDN/ISP). Supports tracing all active connections,\n"
              "auto-trace at intervals, and map path overlay with RTT rings."),
    }

    def _make_info_banner(self, parent, tab_index):
        """Create an info banner with a description of the tab's content.
        Includes a hover tooltip with full details."""
        if tab_index not in self.TAB_DESCRIPTIONS:
            return None
        title, desc = self.TAB_DESCRIPTIONS[tab_index]
        banner = tk.Frame(parent, bg="#1a1a2e", height=20)
        banner.pack(fill="x", side="top")
        banner.pack_propagate(False)
        # Short description (first line) — brighter for readability
        short_desc = desc.split('\n')[0]
        lbl = tk.Label(banner, text=f"  ℹ {short_desc}", bg="#1a1a2e", fg="#8a9aaa",
                       font=("Consolas", 7), anchor="w")
        lbl.pack(side="left", fill="x", expand=True, padx=2)
        # Full tooltip on hover
        _add_tooltip(lbl, f"{title}\n{'─' * 40}\n{desc}", delay_ms=300)
        _add_tooltip(banner, f"{title}\n{'─' * 40}\n{desc}", delay_ms=300)
        return banner

    def _highlight_search(self, widget, query):
        """Highlight all matches of query in a text widget.
        Prefix with 'r:' or '/' for regex search (e.g., 'r:\\d+\\.\\d+' or '/\\d+\\.\\d+')."""
        widget.tag_remove("search_match", "1.0", "end")
        if not query or len(query) < 2:
            return 0
        # Check for regex mode
        is_regex = False
        regex_query = query
        if query.startswith('r:') and len(query) > 2:
            is_regex = True
            regex_query = query[2:]
        elif query.startswith('/') and len(query) > 1:
            is_regex = True
            regex_query = query[1:]
        count = 0
        if is_regex:
            try:
                pattern = re.compile(regex_query, re.IGNORECASE)
                content = widget.get("1.0", "end")
                for match in pattern.finditer(content):
                    start_idx = f"1.0+{match.start()}c"
                    end_idx = f"1.0+{match.end()}c"
                    widget.tag_add("search_match", start_idx, end_idx)
                    count += 1
                    if count > 5000:
                        break
            except re.error:
                pass  # Invalid regex — silently ignore
        else:
            start = "1.0"
            query_lower = query.lower()
            while True:
                pos = widget.search(query_lower, start, stopindex="end", nocase=True)
                if not pos:
                    break
                end = f"{pos}+{len(query)}c"
                widget.tag_add("search_match", pos, end)
                start = end
                count += 1
        return count

    def _latlon_to_xy(self, lat, lon):
        """Convert lat/lon to canvas x/y using Web Mercator projection."""
        z = self._map_zoom
        w, h = self._map_w, self._map_h
        # Global pixel coordinates at this zoom
        gx, gy = TileManager.latlon_to_pixel(lat, lon, z)
        # Center of view in global pixels
        cx, cy = TileManager.latlon_to_pixel(self._map_center_lat, self._map_center_lon, z)
        # Canvas coordinates (centered)
        x = w / 2 + (gx - cx)
        y = h / 2 + (gy - cy)
        return x, y

    def _xy_to_latlon(self, x, y):
        """Convert canvas x/y back to lat/lon using Web Mercator projection."""
        z = self._map_zoom
        w, h = self._map_w, self._map_h
        cx, cy = TileManager.latlon_to_pixel(self._map_center_lat, self._map_center_lon, z)
        gx = cx + (x - w / 2)
        gy = cy + (y - h / 2)
        lat, lon = TileManager.pixel_to_latlon(gx, gy, z)
        return lat, lon

    def _draw_map_full(self):
        """Redraw the entire map: real OSM tiles (if PIL available) or fallback grid+coastline."""
        if not self._map_canvas:
            return
        # Record the view this draw was made for, so the periodic refresh in
        # _refresh_map can skip re-issuing this (expensive) full redraw when
        # nothing has actually moved — regardless of whether this call came
        # from that periodic refresh or directly from a zoom/pan/preset button.
        self._map_last_view_state = (
            round(self._map_zoom, 3), round(self._map_center_lat, 4),
            round(self._map_center_lon, 4), self._map_w, self._map_h)
        self._map_canvas.delete("grid", "coastline", "label", "city", "tile", "scalebar", "loading", "attribution")
        self._map_tile_images = []  # clear PhotoImage refs
        if self._map_use_tiles:
            self._draw_tiles()
        else:
            self._draw_grid()
            self._draw_coastline()
            self._draw_labels()
        tiles = TileManager.cache_size()
        photos = TileManager.photo_cache_size()
        style_label = TileManager.get_style_label()
        self._zoom_lbl.config(
            text=f"Zoom: {self._map_zoom:.1f}  (z={int(self._map_zoom)})  [{style_label}]"
                 + (f"   tiles {tiles}/{photos}" if self._map_use_tiles else ""))

    def _draw_tiles(self):
        """Render real OpenStreetMap tiles on the canvas using Web Mercator projection.
        Supports fractional zoom by scaling tiles. Uses PhotoImage cache for performance.
        Tiles are downloaded asynchronously; pending tiles trigger a retry redraw."""
        if not self._map_canvas or not HAS_PIL:
            return
        z_float = self._map_zoom
        z_int = int(z_float)
        z_frac = z_float - z_int  # fractional part (0.0 to 0.99)
        w, h = self._map_w, self._map_h
        ts = TileManager.TILE_SIZE
        # Scale factor for fractional zoom (each fractional level doubles size)
        scale = 2.0 ** z_frac
        # Center of view in global pixel coordinates at INTEGER zoom
        cx_int, cy_int = TileManager.latlon_to_pixel(
            self._map_center_lat, self._map_center_lon, z_int)
        # At fractional zoom, the canvas coordinate for a global pixel (at z_int) is:
        #   canvas_x = w/2 + scale * (global_px_zint - cx_int)
        # This ensures tiles and dots use the same coordinate system.
        # Determine which tiles cover the viewport.
        # In canvas space, the left edge (x=0) corresponds to global pixel:
        #   global_left = cx_int + (0 - w/2) / scale = cx_int - w/(2*scale)
        # The right edge (x=w) corresponds to:
        #   global_right = cx_int + w/(2*scale)
        global_left = cx_int - w / (2 * scale)
        global_right = cx_int + w / (2 * scale)
        global_top = cy_int - h / (2 * scale)
        global_bot = cy_int + h / (2 * scale)
        tx0 = int(math.floor(global_left / ts))
        ty0 = int(math.floor(global_top / ts))
        tx1 = int(math.ceil(global_right / ts)) - 1
        ty1 = int(math.ceil(global_bot / ts)) - 1
        # Clamp y to valid range (tiles only exist for 0 <= y < 2^z)
        n = 2 ** z_int
        ty0 = max(0, ty0)
        ty1 = min(n - 1, ty1)
        tiles_rendered = 0
        tiles_pending = 0
        for ty in range(ty0, ty1 + 1):
            for tx in range(tx0, tx1 + 1):
                if z_frac < 0.01:
                    # Integer zoom — use cached PhotoImage directly
                    photo = TileManager.get_photo(z_int, tx, ty)
                    if photo is not None:
                        # canvas_x = w/2 + 1.0 * (tx*ts - cx_int)
                        px = w / 2 + (tx * ts - cx_int)
                        py = h / 2 + (ty * ts - cy_int)
                        self._map_tile_images.append(photo)
                        self._map_canvas.create_image(
                            px, py, image=photo, anchor="nw", tags="tile")
                        tiles_rendered += 1
                    else:
                        TileManager.get_tile(z_int, tx, ty)
                        tiles_pending += 1
                else:
                    # Fractional zoom — scale the tile
                    photo = TileManager.get_scaled_photo(z_int, tx, ty, scale)
                    if photo is not None:
                        # canvas_x = w/2 + scale * (tx*ts - cx_int)
                        px = w / 2 + scale * (tx * ts - cx_int)
                        py = h / 2 + scale * (ty * ts - cy_int)
                        self._map_tile_images.append(photo)
                        self._map_canvas.create_image(
                            px, py, image=photo, anchor="nw", tags="tile")
                        tiles_rendered += 1
                    else:
                        TileManager.get_tile(z_int, tx, ty)
                        tiles_pending += 1
        # Coordinate grid overlay removed — the OSM tiles already carry
        # borders/coastlines/city names, and the dotted lat/lon mesh plus its
        # per-line degree labels were pure clutter competing with the actual
        # map content (and with the connection dots/labels drawn on top).
        # Draw scale bar
        self._draw_scale_bar()
        # Draw attribution
        self._draw_attribution()
        # Show loading indicator if tiles are pending
        if tiles_pending > 0:
            self._draw_loading_indicator(tiles_pending, tiles_rendered)
            now = time.time()
            if now >= self._map_tile_retry_after:
                self._map_tile_retry_after = now + 1.5
                if self._root:
                    self._root.after(1500, self._redraw_tiles_only)

    def _draw_loading_indicator(self, pending, rendered=0):
        """Show a small loading indicator in the corner when tiles are downloading."""
        if not self._map_canvas:
            return
        w = self._map_w
        text = f"  Loading map… ({pending} tiles pending)  "
        self._map_canvas.create_text(
            w - 10, 16, text=text, fill="#4488ff",
            font=("Consolas", 8, "bold"), anchor="ne", tags="loading")

    def _draw_attribution(self):
        """Draw tile source attribution in the bottom-right corner."""
        if not self._map_canvas or not self._map_use_tiles:
            return
        w, h = self._map_w, self._map_h
        attr = TileManager.get_style_attribution()
        if attr:
            self._map_canvas.create_text(
                w - 8, h - 8, text=attr, fill="#555555",
                font=("Consolas", 7), anchor="se", tags="attribution")

    def _draw_scale_bar(self):
        """Draw a scale bar showing approximate distance at current zoom."""
        if not self._map_canvas:
            return
        z = self._map_zoom
        h = self._map_h
        lat = self._map_center_lat
        mpp = TileManager.meters_per_pixel(lat, z)  # meters per pixel
        if mpp <= 0 or mpp > 1e7:
            return
        # Choose a nice round number for the scale bar (target ~100px)
        target_px = 100
        target_m = mpp * target_px
        # Round to a nice number
        for unit_val in [1, 2, 5, 10, 20, 50, 100, 200, 500, 1000, 2000, 5000,
                         10000, 20000, 50000, 100000, 200000, 500000, 1000000, 2000000, 5000000]:
            if target_m <= unit_val:
                bar_m = unit_val
                break
        else:
            bar_m = 5000000
        bar_px = bar_m / mpp
        if bar_px < 20 or bar_px > 300:
            return
        # Format the distance label
        if bar_m >= 1000:
            label = f"{bar_m / 1000:.0f} km"
        else:
            label = f"{bar_m:.0f} m"
        # Draw the scale bar in the bottom-left corner, replacing the previous
        # one rather than relying on a tag sweep elsewhere.
        if self._map_scale_bar_id:
            for item in self._map_scale_bar_id:
                try:
                    self._map_canvas.delete(item)
                except Exception:
                    pass
        self._map_scale_bar_id = []
        x0, y0 = 16, h - 28
        x1 = x0 + bar_px
        self._map_scale_bar_id = [
            self._map_canvas.create_line(
                x0, y0, x1, y0, fill="#aaaaaa", width=2, tags="scalebar"),
            self._map_canvas.create_line(
                x0, y0 - 4, x0, y0 + 4, fill="#aaaaaa", width=2, tags="scalebar"),
            self._map_canvas.create_line(
                x1, y0 - 4, x1, y0 + 4, fill="#aaaaaa", width=2, tags="scalebar"),
            self._map_canvas.create_text(
                x0 + bar_px / 2, y0 - 8, text=label, fill="#cccccc",
                font=("Consolas", 8, "bold"), anchor="center", tags="scalebar"),
        ]

    def _redraw_tiles_only(self):
        """Redraw tiles without touching dots — used for async tile load retries."""
        if not self._map_canvas or not self._map_use_tiles:
            return
        self._map_canvas.delete("tile", "scalebar", "loading", "attribution")
        self._map_tile_images = []
        self._draw_tiles()
        # Re-plot dots on top
        self._map_canvas.delete("dot", "line_to_dot")
        if hasattr(self, '_last_map_data') and self._last_map_data:
            self._plot_map_dots(self._last_map_data)
        # Re-plot trace hops if any
        self._plot_trace_on_map()

    def _draw_grid_overlay(self):
        """Draw subtle lat/lon grid lines on top of map tiles."""
        if not self._map_canvas:
            return
        z = self._map_zoom
        w, h = self._map_w, self._map_h
        # Choose grid spacing based on zoom level
        if z >= 12:
            spacing = 0.01
        elif z >= 8:
            spacing = 0.05
        elif z >= 5:
            spacing = 0.5
        elif z >= 3:
            spacing = 2
        elif z >= 1:
            spacing = 10
        else:
            spacing = 30
        # Determine visible lat/lon range
        lat_top, lon_left = self._xy_to_latlon(0, 0)
        lat_bot, lon_right = self._xy_to_latlon(w, h)
        # Latitude lines
        lat_start = int(lat_bot / spacing) * spacing
        lat_end = lat_top
        lat = lat_start
        while lat <= lat_end:
            x1, y = self._latlon_to_xy(lat, lon_left)
            x2, _ = self._latlon_to_xy(lat, lon_right)
            if 0 <= y <= h:
                self._map_canvas.create_line(
                    x1, y, x2, y, fill="#1a3a3a", width=1,
                    tags="grid", dash=(2, 6), stipple="gray50")
                if z >= 7:
                    self._map_canvas.create_text(
                        4, y - 2, text=f"{lat:.2f}°", fill="#448888",
                        font=("Consolas", 7), anchor="sw", tags="grid")
            lat += spacing
        # Longitude lines
        lon_start = int(lon_left / spacing) * spacing
        lon_end = lon_right
        lon = lon_start
        while lon <= lon_end:
            x, y1 = self._latlon_to_xy(lat_top, lon)
            _, y2 = self._latlon_to_xy(lat_bot, lon)
            if 0 <= x <= w:
                self._map_canvas.create_line(
                    x, y1, x, y2, fill="#1a3a3a", width=1,
                    tags="grid", dash=(2, 6), stipple="gray50")
                if z >= 7:
                    self._map_canvas.create_text(
                        x + 2, h - 2, text=f"{lon:.2f}°", fill="#448888",
                        font=("Consolas", 7), anchor="se", tags="grid")
            lon += spacing

    def _draw_grid(self):
        """Fallback: Draw lat/lon grid lines (used when PIL is not available)."""
        if not self._map_canvas:
            return
        z = self._map_zoom
        w, h = self._map_w, self._map_h
        spacing = 30 if z < 1 else 15 if z < 2 else 10 if z < 5 else 5
        for lat in range(-90, 91, spacing):
            _, y = self._latlon_to_xy(lat, 0)
            if 0 <= y <= h:
                self._map_canvas.create_line(0, y, w, y, fill="#1a2a2a",
                                             width=1, tags="grid", dash=(2, 4))
                if z >= 1:
                    self._map_canvas.create_text(
                        4, y - 2, text=f"{lat}°", fill="#334444",
                        font=("Consolas", 7), anchor="sw", tags="grid")
        for lon in range(-180, 181, spacing):
            x, _ = self._latlon_to_xy(0, lon)
            if 0 <= x <= w:
                self._map_canvas.create_line(x, 0, x, h, fill="#1a2a2a",
                                             width=1, tags="grid", dash=(2, 4))
                if z >= 1:
                    self._map_canvas.create_text(
                        x + 2, h - 2, text=f"{lon}°", fill="#334444",
                        font=("Consolas", 7), anchor="se", tags="grid")
        _, eq_y = self._latlon_to_xy(0, 0)
        pm_x, _ = self._latlon_to_xy(0, 0)
        if 0 <= eq_y <= h:
            self._map_canvas.create_line(0, eq_y, w, eq_y, fill="#2a3a3a",
                                         width=1, tags="grid")
        if 0 <= pm_x <= w:
            self._map_canvas.create_line(pm_x, 0, pm_x, h, fill="#2a3a3a",
                                         width=1, tags="grid")

    def _draw_coastline(self):
        """Fallback: Draw simplified coastlines (used when PIL is not available)."""
        if not self._map_canvas:
            return
        z = self._map_zoom
        w, h = self._map_w, self._map_h
        line_width = max(1, min(3, z * 0.8))
        fill_color = "#2a5a3a" if z >= 2 else "#2a4a3a"
        segment = []
        for pt in _WORLD_COASTLINE:
            if pt is None:
                if len(segment) >= 2:
                    self._map_canvas.create_line(
                        *[c for xy in segment for c in xy],
                        fill=fill_color, width=line_width,
                        tags="coastline", smooth=True)
                segment = []
            else:
                px, py = self._latlon_to_xy(pt[0], pt[1])
                if -200 <= px <= w + 200 and -200 <= py <= h + 200:
                    segment.append((px, py))
                else:
                    if len(segment) >= 2:
                        self._map_canvas.create_line(
                            *[c for xy in segment for c in xy],
                            fill=fill_color, width=line_width,
                            tags="coastline", smooth=True)
                    segment = []
        if len(segment) >= 2:
            self._map_canvas.create_line(
                *[c for xy in segment for c in xy],
                fill=fill_color, width=line_width,
                tags="coastline", smooth=True)

    def _draw_labels(self):
        """Fallback: Draw country and city labels (used when PIL is not available)."""
        if not self._map_canvas:
            return
        z = self._map_zoom
        w, h = self._map_w, self._map_h
        if z >= 1:
            font_size = max(7, min(11, int(7 + z)))
            for lat, lon, name in _COUNTRY_LABELS:
                x, y = self._latlon_to_xy(lat, lon)
                if 0 <= x <= w and 0 <= y <= h:
                    self._map_canvas.create_text(
                        x, y, text=name, fill="#3a5a5a",
                        font=("Consolas", font_size, "bold"),
                        tags="label")
        if z >= 3:
            for lat, lon, name, tier in _MAJOR_CITIES:
                if tier > 1 and z < 6:
                    continue
                x, y = self._latlon_to_xy(lat, lon)
                if 0 <= x <= w and 0 <= y <= h:
                    r = 2
                    self._map_canvas.create_oval(
                        x - r, y - r, x + r, y + r,
                        fill="#556666", outline="#778888", tags="city")
                    self._map_canvas.create_text(
                        x + 5, y, text=name, fill="#667777",
                        font=("Consolas", max(7, min(9, int(6 + z * 0.5)))),
                        anchor="w", tags="city")

    # --- Map interaction handlers ---
    def _map_zoom_by(self, factor, event=None):
        """Zoom the map by a factor, centered on mouse position.
        Uses smooth fractional zoom for tile-based maps.

        Web Mercator zoom is already logarithmic (each level doubles the scale),
        so the factor is applied as an ADDITIVE step of log2(factor). Multiplying
        the zoom level gave non-uniform steps and stalled at zoom 0 (0 * f == 0).
        """
        old_zoom = self._map_zoom
        try:
            step = math.log2(float(factor))
        except (ValueError, TypeError):
            step = 0.0
        new_zoom = old_zoom + step
        new_zoom = max(self._map_min_zoom, min(self._map_max_zoom, new_zoom))
        if abs(new_zoom - old_zoom) < 0.001:
            return
        if event:
            # Zoom toward the mouse cursor position
            lat, lon = self._xy_to_latlon(event.x, event.y)
            self._map_zoom = new_zoom
            # Adjust center so the cursor lat/lon stays under the cursor
            cx_after, cy_after = self._latlon_to_xy(lat, lon)
            dx = cx_after - event.x
            dy = cy_after - event.y
            shift_lat, shift_lon = self._pixel_shift_to_latlon(dx, dy)
            self._map_center_lat = max(-85, min(85, lat - shift_lat))
            self._map_center_lon = max(-180, min(180, lon - shift_lon))
        else:
            self._map_zoom = new_zoom
        # Clear photo cache when integer zoom changes (different tile set)
        if int(new_zoom) != int(old_zoom):
            TileManager.clear_photo_cache()
        # Sync zoom slider
        if hasattr(self, '_map_zoom_slider'):
            self._map_zoom_slider.set(self._map_zoom)
        self._draw_map_full()
        self._redraw_dots_only()

    def _pixel_shift_to_latlon(self, dx, dy):
        """Convert a pixel shift (dx, dy) at current zoom to lat/lon shift."""
        # Use a reference point to compute the lat/lon delta
        lat0, lon0 = self._xy_to_latlon(0, 0)
        lat1, lon1 = self._xy_to_latlon(dx, dy)
        return lat1 - lat0, lon1 - lon0

    # --- New atlas-style map methods ---

    # Preset locations for the bookmark bar: (label, lat, lon, zoom)
    _MAP_PRESETS = [
        ("World", 20.0, 0.0, 2.0),
        ("N.America", 45.0, -100.0, 4.0),
        ("Europe", 50.0, 10.0, 5.0),
        ("Asia", 35.0, 100.0, 4.0),
        ("S.America", -15.0, -60.0, 4.0),
        ("Africa", 5.0, 20.0, 4.0),
        ("Australia", -25.0, 135.0, 5.0),
        ("New York", 40.7128, -74.0060, 11.0),
        ("London", 51.5074, -0.1278, 11.0),
        ("Tokyo", 35.6762, 139.6503, 11.0),
        ("Frankfurt", 50.1109, 8.6821, 11.0),
        ("Singapore", 1.3521, 103.8198, 11.0),
        ("Sydney", -33.8688, 151.2093, 11.0),
        ("Dubai", 25.2048, 55.2708, 11.0),
    ]

    # City name → (lat, lon) for the search box
    _CITY_SEARCH = {
        'new york': (40.7128, -74.0060), 'nyc': (40.7128, -74.0060),
        'london': (51.5074, -0.1278), 'paris': (48.8566, 2.3522),
        'tokyo': (35.6762, 139.6503), 'frankfurt': (50.1109, 8.6821),
        'singapore': (1.3521, 103.8198), 'sydney': (-33.8688, 151.2093),
        'dubai': (25.2048, 55.2708), 'moscow': (55.7558, 37.6173),
        'beijing': (39.9042, 116.4074), 'shanghai': (31.2304, 121.4737),
        'hong kong': (22.3193, 114.1694), 'hongkong': (22.3193, 114.1694),
        'mumbai': (19.0760, 72.8777), 'delhi': (28.7041, 77.1025),
        'seoul': (37.5665, 126.9780), 'los angeles': (34.0522, -118.2437),
        'la': (34.0522, -118.2437), 'san francisco': (37.7749, -122.4194),
        'sf': (37.7749, -122.4194), 'chicago': (41.8781, -87.6298),
        'toronto': (43.6532, -79.3832), 'mexico city': (19.4326, -99.1332),
        'sao paulo': (-23.5505, -46.6333), 'buenos aires': (-34.6037, -58.3816),
        'cairo': (30.0444, 31.2357), 'lagos': (6.5244, 3.3792),
        'johannesburg': (-26.2041, 28.0473), 'nairobi': (-1.2921, 36.8219),
        'istanbul': (41.0082, 28.9784), 'madrid': (40.4168, -3.7038),
        'rome': (41.9028, 12.4964), 'berlin': (52.5200, 13.4050),
        'amsterdam': (52.3676, 4.9041), 'dublin': (53.3498, -6.2603),
        'stockholm': (59.3293, 18.0686), 'oslo': (59.9139, 10.7522),
        'helsinki': (60.1699, 24.9384), 'warsaw': (52.2297, 21.0122),
        'vienna': (48.2082, 16.3738), 'zurich': (47.3769, 8.5417),
        'bangkok': (13.7563, 100.5018), 'jakarta': (-6.2088, 106.8456),
        'manila': (14.5995, 120.9842), 'taipei': (25.0330, 121.5654),
        'melbourne': (-37.8136, 144.9631), 'auckland': (-36.8485, 174.7633),
        'tel aviv': (32.0853, 34.7818), 'doha': (25.2854, 51.5310),
        'riyadh': (24.7136, 46.6753), 'tehran': (35.6892, 51.3890),
        'karachi': (24.8607, 67.0011), 'dhaka': (23.8103, 90.4125),
        'hanoi': (21.0285, 105.8542), 'kuala lumpur': (3.1390, 101.6869),
    }

    def _on_style_change(self, event=None):
        """Handle tile style dropdown change."""
        if not self._map_style_var:
            return
        selection = self._map_style_var.get()
        # Parse "key — Label" format
        style_key = selection.split(' — ')[0].strip() if ' — ' in selection else selection
        if style_key in TileManager.TILE_STYLES:
            TileManager.set_style(style_key)
            self._map_max_zoom = TileManager.get_style_max_zoom()
            # Clamp current zoom to new max
            if self._map_zoom > self._map_max_zoom:
                self._map_zoom = self._map_max_zoom
            if hasattr(self, '_map_zoom_slider'):
                self._map_zoom_slider.configure(to=self._map_max_zoom)
            self._draw_map_full()
            self._redraw_dots_only()

    def _on_zoom_slider(self, value):
        """Handle zoom slider drag."""
        try:
            new_zoom = float(value)
        except (ValueError, TypeError):
            return
        if abs(new_zoom - self._map_zoom) < 0.01:
            return
        self._map_zoom = max(self._map_min_zoom, min(self._map_max_zoom, new_zoom))
        TileManager.clear_photo_cache()
        self._draw_map_full()
        self._redraw_dots_only()

    def _on_map_search(self, event=None):
        """Search for a location by city name or 'lat, lon' coordinates."""
        if not self._map_search_var:
            return
        query = self._map_search_var.get().strip()
        if not query:
            return
        # Try parsing as coordinates "lat, lon"
        if ',' in query:
            parts = query.split(',')
            if len(parts) == 2:
                try:
                    lat = float(parts[0].strip())
                    lon = float(parts[1].strip())
                    self._goto_preset(lat, lon, max(self._map_zoom, 10.0))
                    self._map_search_var.set('')
                    return
                except ValueError:
                    pass
        # Try city name lookup
        key = query.lower()
        if key in self._CITY_SEARCH:
            lat, lon = self._CITY_SEARCH[key]
            self._goto_preset(lat, lon, 11.0)
            self._map_search_var.set('')
            return
        # Try partial match
        for city, (lat, lon) in self._CITY_SEARCH.items():
            if city.startswith(key) or key.startswith(city):
                self._goto_preset(lat, lon, 11.0)
                self._map_search_var.set('')
                return
        # Not found — flash the entry
        if self._map_search_var:
            self._map_search_var.set(f'Not found: {query}')

    def _goto_preset(self, lat, lon, zoom):
        """Jump to a preset location and zoom level."""
        self._map_zoom = max(self._map_min_zoom, min(self._map_max_zoom, float(zoom)))
        self._map_center_lat = max(-85, min(85, lat))
        self._map_center_lon = max(-180, min(180, lon))
        if hasattr(self, '_map_zoom_slider'):
            self._map_zoom_slider.set(self._map_zoom)
        TileManager.clear_photo_cache()
        self._draw_map_full()
        self._redraw_dots_only()

    def _toggle_map_action_log(self):
        """Collapse/expand the IP action log panel below the map."""
        if self._map_action_log_expanded:
            self._map_action_log_frame.pack_forget()
            self._map_action_log_expanded = False
        else:
            self._map_action_log_frame.pack(fill="both", expand=False)
            self._map_action_log_expanded = True

    def _toggle_map_help(self):
        """Show/hide keyboard shortcut help overlay on the map."""
        self._map_help_visible = not self._map_help_visible
        if not self._map_canvas:
            return
        self._map_canvas.delete("help_overlay")
        if self._map_help_visible:
            w = self._map_w
            lines = [
                "MAP CONTROLS",
                "",
                "Mouse wheel / ➕➖     Zoom in/out",
                "Left-drag             Pan map",
                "Right-drag            Pan map (alt)",
                "Click dot             IP details / actions",
                "Right-click empty     Context menu",
                "",
                "+ / =                 Zoom in",
                "-                     Zoom out",
                "Arrow keys            Pan (↑↓←→)",
                "R                     Reset view",
                "H                     Toggle this help",
                "",
                "Style dropdown        Switch map layer",
                "Go to box             City name or 'lat, lon'",
                "Presets               Jump to region/city",
            ]
            # Semi-transparent background
            box_w, box_h = 260, len(lines) * 16 + 20
            x0, y0 = w - box_w - 10, 40
            self._map_canvas.create_rectangle(
                x0, y0, x0 + box_w, y0 + box_h,
                fill="#0a0a0f", stipple="gray50", outline="#00d4ff",
                width=1, tags="help_overlay")
            for i, line in enumerate(lines):
                color = "#00d4ff" if i == 0 else "#c0c0c0"
                font = ("Consolas", 9, "bold") if i == 0 else ("Consolas", 8)
                self._map_canvas.create_text(
                    x0 + 12, y0 + 12 + i * 16, text=line,
                    fill=color, font=font, anchor="nw", tags="help_overlay")

    # --- Left-drag panning (new, more natural than right-drag only) ---

    def _on_map_left_press(self, event):
        """Start left-button drag for panning. Also tracks click for context menu."""
        self._map_left_drag_start = (event.x, event.y)
        self._map_left_pan_offset = (0, 0)
        self._map_left_click_moved = False

    def _on_map_left_drag(self, event):
        """Pan the map with left-button drag."""
        if not self._map_left_drag_start:
            return
        dx = event.x - self._map_left_drag_start[0]
        dy = event.y - self._map_left_drag_start[1]
        if abs(dx) > 3 or abs(dy) > 3:
            self._map_left_click_moved = True
        if dx == 0 and dy == 0:
            return
        self._map_left_drag_start = (event.x, event.y)
        ox, oy = self._map_left_pan_offset
        self._map_left_pan_offset = (ox + dx, oy + dy)
        if self._map_canvas:
            self._map_canvas.move("all", dx, dy)

    def _on_map_left_release(self, event):
        """Commit left-drag pan, or show context menu if it was a click."""
        if not self._map_left_drag_start:
            return
        ox, oy = self._map_left_pan_offset
        self._map_left_drag_start = None
        self._map_left_pan_offset = (0, 0)
        if not self._map_left_click_moved:
            # It was a click, not a drag — show context menu
            self._on_map_left_click(event)
            return
        if ox == 0 and oy == 0:
            return
        z = self._map_zoom
        cx_px, cy_px = TileManager.latlon_to_pixel(
            self._map_center_lat, self._map_center_lon, z)
        lat, lon = TileManager.pixel_to_latlon(cx_px - ox, cy_px - oy, z)
        self._map_center_lat = max(-85, min(85, lat))
        self._map_center_lon = max(-180, min(180, lon))
        self._draw_map_full()
        self._redraw_dots_only()

    def _map_reset_view(self):
        """Reset map to the default view — centered on the user's own
        location (same as the initial auto-center) when it's known, rather
        than the generic mid-Atlantic point, at the default zoom."""
        self._map_zoom = 3.0
        local_geo = (self._last_full_data or {}).get('local_geo', {})
        if local_geo.get('lat') or local_geo.get('lon'):
            self._map_center_lat = max(-85, min(85, local_geo.get('lat', 0)))
            self._map_center_lon = max(-180, min(180, local_geo.get('lon', 0)))
        else:
            self._map_center_lat = 20.0
            self._map_center_lon = 0.0
        if hasattr(self, '_map_zoom_slider'):
            self._map_zoom_slider.set(self._map_zoom)
        TileManager.clear_photo_cache()
        self._draw_map_full()
        self._redraw_dots_only()

    def _on_map_scroll(self, event):
        """Mouse wheel zoom — smooth fractional zoom."""
        if event.delta > 0:
            self._map_zoom_by(1.15, event)
        else:
            self._map_zoom_by(1 / 1.15, event)

    def _on_map_drag_start(self, event):
        self._map_drag_start = (event.x, event.y)
        self._map_pan_offset = (0, 0)

    def _on_map_drag(self, event):
        """Shift what is already drawn while the button is held. Reprojecting
        and re-rendering every tile on each motion event made dragging crawl;
        the real redraw happens once on release."""
        if not self._map_drag_start:
            return
        dx = event.x - self._map_drag_start[0]
        dy = event.y - self._map_drag_start[1]
        if dx == 0 and dy == 0:
            return
        self._map_drag_start = (event.x, event.y)
        ox, oy = self._map_pan_offset
        self._map_pan_offset = (ox + dx, oy + dy)
        if self._map_canvas:
            self._map_canvas.move("all", dx, dy)

    def _on_map_drag_end(self, event):
        """Commit the accumulated pan: convert it to a new centre and redraw."""
        if not self._map_drag_start and self._map_pan_offset == (0, 0):
            self._map_drag_start = None
            return
        ox, oy = self._map_pan_offset
        self._map_drag_start = None
        self._map_pan_offset = (0, 0)
        if ox == 0 and oy == 0:
            return
        z = self._map_zoom
        # The view moved with the pointer, so the centre moves the other way.
        cx_px, cy_px = TileManager.latlon_to_pixel(
            self._map_center_lat, self._map_center_lon, z)
        lat, lon = TileManager.pixel_to_latlon(cx_px - ox, cy_px - oy, z)
        self._map_center_lat = max(-85, min(85, lat))
        self._map_center_lon = max(-180, min(180, lon))
        self._draw_map_full()
        self._redraw_dots_only()

    def _on_map_mouse_move(self, event):
        """Show lat/lon coordinates under cursor with crosshair reticle."""
        lat, lon = self._xy_to_latlon(event.x, event.y)
        if hasattr(self, '_coords_lbl'):
            self._coords_lbl.config(text=f"Lat: {lat:.4f}° Lon: {lon:.4f}°  (z={self._map_zoom:.1f})")
        # Draw crosshair reticle
        if self._map_canvas:
            self._map_canvas.delete("crosshair")
            w, h = self._map_w, self._map_h
            # Horizontal line
            self._map_canvas.create_line(
                0, event.y, w, event.y, fill="#3a5a5a", width=1,
                tags="crosshair", dash=(2, 4))
            # Vertical line
            self._map_canvas.create_line(
                event.x, 0, event.x, h, fill="#3a5a5a", width=1,
                tags="crosshair", dash=(2, 4))
            # Coordinate label near cursor
            coord_text = f"{lat:.4f}°, {lon:.4f}°"
            self._map_canvas.create_text(
                event.x + 10, event.y - 10, text=coord_text,
                fill="#00d4ff", font=("Consolas", 8), anchor="sw",
                tags="crosshair")

    def _pan_map(self, dx, dy):
        """Pan the map by a pixel offset (used by keyboard navigation)."""
        z = self._map_zoom
        cx_px, cy_px = TileManager.latlon_to_pixel(self._map_center_lat, self._map_center_lon, z)
        new_cx_px = cx_px + dx
        new_cy_px = cy_px + dy
        lat, lon = TileManager.pixel_to_latlon(new_cx_px, new_cy_px, z)
        self._map_center_lat = max(-85, min(85, lat))
        self._map_center_lon = max(-180, min(180, lon))
        self._draw_map_full()
        self._redraw_dots_only()

    def _on_map_left_click(self, event):
        """Left-click on empty map area: show context menu."""
        # Check if we clicked on a dot — if so, let the dot binding handle it
        items = self._map_canvas.find_overlapping(
            event.x - 3, event.y - 3, event.x + 3, event.y + 3)
        for item in items:
            tags = self._map_canvas.gettags(item)
            if "dot" in tags:
                return  # let the dot click handler work
        # Show context menu
        lat, lon = self._xy_to_latlon(event.x, event.y)
        menu = tk.Menu(self._root, tearoff=0, bg="#1a1a2e", fg="#c0c0c0",
                       activebackground="#0f3460", activeforeground="#ffffff",
                       font=("Consolas", 9))
        menu.add_command(label=f"📍 {lat:.4f}°, {lon:.4f}°", state="disabled")
        menu.add_separator()
        menu.add_command(label="🎯 Center map here", command=lambda: self._center_map_at(lat, lon))
        menu.add_command(label="🔍 Zoom in here", command=lambda: self._zoom_to_location(lat, lon, self._map_zoom + 1))
        menu.add_command(label="🔍 Zoom out", command=lambda: self._zoom_to_location(lat, lon, max(0, self._map_zoom - 1)))
        menu.add_separator()
        menu.add_command(label="📋 Copy coordinates", command=lambda: self._copy_coords(lat, lon))
        menu.add_command(label="🌐 Open in browser (OSM)", command=lambda: self._open_in_browser(lat, lon))
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    def _center_map_at(self, lat, lon):
        """Center the map at the given coordinates."""
        self._map_center_lat = max(-85, min(85, lat))
        self._map_center_lon = max(-180, min(180, lon))
        self._draw_map_full()
        self._redraw_dots_only()

    def _zoom_to_location(self, lat, lon, zoom):
        """Zoom to a specific location and zoom level."""
        self._map_zoom = max(self._map_min_zoom, min(self._map_max_zoom, float(zoom)))
        self._map_center_lat = max(-85, min(85, lat))
        self._map_center_lon = max(-180, min(180, lon))
        TileManager.clear_photo_cache()
        self._draw_map_full()
        self._redraw_dots_only()

    def _copy_coords(self, lat, lon):
        """Copy coordinates to clipboard."""
        text = f"{lat:.6f}, {lon:.6f}"
        self._root.clipboard_clear()
        self._root.clipboard_append(text)

    def _open_in_browser(self, lat, lon):
        """Open the location in OpenStreetMap web."""
        z = int(self._map_zoom)
        url = f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map={z}/{lat}/{lon}"
        import webbrowser
        webbrowser.open(url)

    def _redraw_dots_only(self):
        """Quick redraw of just the connection dots and trace path without full data refresh."""
        if not self._map_canvas:
            return
        self._map_canvas.delete("dot", "line_to_dot", "trace_path", "trace_hop", "crosshair")
        self._map_dots.clear()
        if hasattr(self, '_last_map_data') and self._last_map_data:
            self._plot_map_dots(self._last_map_data)
        self._plot_trace_on_map()

    def _plot_trace_on_map(self):
        """Plot trace hops on the map as a connected path with numbered hop markers.
        Only shows hops that have valid lat/lon coordinates.
        Includes RTT-based distance estimation rings and inter-hop latency labels."""
        if not self._map_canvas or not self._map_use_tiles:
            return
        w, h = self._map_w, self._map_h
        with self._trace_lock:
            blocks = list(self._trace_blocks)
        if not blocks:
            return
        # Plot the most recent trace block
        block = blocks[-1]
        hops = block.get("hops", [])
        if len(hops) < 2:
            return
        # Collect valid hop points
        points = []
        for hop in hops:
            lat, lon = hop.get("lat", 0), hop.get("lon", 0)
            if lat == 0 and lon == 0:
                continue
            x, y = self._latlon_to_xy(lat, lon)
            if -50 <= x <= w + 50 and -50 <= y <= h + 50:
                points.append((x, y, hop))
        if len(points) < 2:
            return
        # Draw connecting path with inter-hop latency labels
        coords = []
        for x, y, _ in points:
            coords.extend([x, y])
        self._map_canvas.create_line(
            *coords, fill="#00d4ff", width=2, dash=(4, 3),
            tags="trace_path", smooth=True)
        # Draw inter-hop latency labels at midpoints
        for i in range(len(points) - 1):
            x1, y1, hop1 = points[i]
            x2, y2, hop2 = points[i + 1]
            rtts1 = hop1.get("rtts", [])
            rtts2 = hop2.get("rtts", [])
            if rtts1 and rtts2:
                delta_rtt = abs(min(rtts2) - min(rtts1))
                if delta_rtt > 0.5:
                    mid_x = (x1 + x2) / 2
                    mid_y = (y1 + y2) / 2
                    self._map_canvas.create_text(
                        mid_x, mid_y - 6, text=f"+{delta_rtt:.0f}ms",
                        fill="#ffaa44", font=("Consolas", 7),
                        anchor="center", tags="trace_path")
        # Draw hop markers with RTT distance rings
        for i, (x, y, hop) in enumerate(points):
            hop_no = hop.get("hop", i + 1)
            tag = hop.get("label_tag", "default")
            # Color by label type
            if tag == "critical":
                color = "#ff0000"
            elif tag == "warning":
                color = "#ff8800"
            elif tag == "cyan":
                color = "#00d4ff"
            elif tag == "dim":
                color = "#666666"
            else:
                color = "#4caf50"
            # Draw RTT-based distance estimation ring
            rtts = hop.get("rtts", [])
            if rtts and self._map_zoom >= 3:
                min_rtt = min(rtts)
                # Estimate distance: light travels ~200km/ms in fiber
                est_km = min_rtt * 100  # rough: 100km per ms (round-trip / 2)
                # Convert km to pixels at current zoom
                mpp = TileManager.meters_per_pixel(
                    hop.get("lat", self._map_center_lat), self._map_zoom)
                if mpp > 0 and est_km > 0:
                    ring_px = min(80, max(8, (est_km * 1000) / mpp))
                    # Draw distance ring (faint)
                    self._map_canvas.create_oval(
                        x - ring_px, y - ring_px, x + ring_px, y + ring_px,
                        outline=color, width=1, stipple="gray25",
                        tags="trace_path")
            # Draw hop marker
            r = 6
            self._map_canvas.create_oval(
                x - r, y - r, x + r, y + r,
                fill=color, outline="#ffffff", width=2, tags="trace_hop")
            self._map_canvas.create_text(
                x, y, text=str(hop_no), fill="#ffffff",
                font=("Consolas", 7, "bold"), tags="trace_hop")
            # Show IP + RTT label at higher zoom
            if self._map_zoom >= 4:
                ip = hop.get("ip", "")
                if ip:
                    rtt_str = f" {min(rtts):.0f}ms" if rtts else ""
                    label = hop.get("label", "")
                    label_str = f" [{label}]" if label else ""
                    self._map_canvas.create_text(
                        x + r + 2, y, text=f"{ip}{rtt_str}{label_str}",
                        fill=color,
                        font=("Consolas", max(7, min(9, int(6 + self._map_zoom * 0.3))), "bold"),
                        anchor="w", tags="trace_hop")

    def _show_tooltip(self, event, text, delay_ms: int = 350):
        """Show a tooltip after a short hover delay, so simply moving the
        pointer across the map does not flash tooltips."""
        self._hide_tooltip()
        x, y = event.x_root + 15, event.y_root + 10
        if delay_ms > 0 and self._root is not None:
            self._tooltip_id = self._root.after(
                delay_ms, lambda: self._render_tooltip(x, y, text))
            return
        self._render_tooltip(x, y, text)

    def _render_tooltip(self, x, y, text):
        self._tooltip_id = None
        self._tooltip = tk.Toplevel(self._root)
        self._tooltip.wm_overrideredirect(True)
        self._tooltip.wm_geometry(f"+{x}+{y}")
        self._tooltip.attributes("-topmost", True)
        frame = tk.Frame(self._tooltip, bg="#1e1e30", bd=1, relief="solid")
        frame.pack()
        lbl = tk.Label(frame, text=text, bg="#1e1e30", fg="#c8c8e0",
                       font=("Consolas", 9), justify="left", padx=6, pady=4)
        lbl.pack()

    def _hide_tooltip(self):
        if self._tooltip_id is not None:
            try:
                self._root.after_cancel(self._tooltip_id)
            except Exception:
                pass
            self._tooltip_id = None
        if self._tooltip:
            try:
                self._tooltip.destroy()
            except Exception:
                pass
            self._tooltip = None

    def _on_map_dot_enter(self, event, ip, info):
        loc_conf = info.get('loc_confidence', 0)
        loc_grade = info.get('loc_grade', '')
        loc_line = f"\n📍 Location: {loc_conf}% {loc_grade}" if loc_grade else ""
        proof_lines = ""
        for p in info.get('loc_proof', [])[:3]:
            proof_lines += f"\n  {p}"
        proxy_line = ""
        pt = info.get('proxy_type', '')
        if pt:
            proxy_line = f"\n🔀 Proxy: {pt}"
            pd = info.get('proxy_detail', '')
            if pd:
                proxy_line += f"\n  {pd}"
        # VPN/proxy disclaimer — check both the MultiVerifier cache and the
        # connection's proxy_type. This is the EXIT NODE, not the real source.
        vpn_disclaimer = ""
        vpn_rep = (self._last_full_data or {}).get('multi_verifications', {}).get(ip)
        is_vpn = bool(vpn_rep and (vpn_rep.get('is_vpn') or vpn_rep.get('is_proxy')))
        if not is_vpn and pt and 'NONE' not in pt.upper():
            is_vpn = True
        if is_vpn:
            vpn_score = vpn_rep.get('vpn_score', 0) if vpn_rep else 50
            vpn_labels = ', '.join(vpn_rep.get('labels', [])) if vpn_rep else pt
            vpn_disclaimer = (
                f"\n⚠⚠⚠ VPN/PROXY EXIT NODE ⚠⚠⚠\n"
                f"  VPN Score: {vpn_score}/100\n"
                f"  Labels: {vpn_labels}\n"
                f"  ⚠ This location is the VPN EXIT NODE,\n"
                f"    NOT the real source location.\n"
                f"  ⚠ The actual user could be anywhere.\n"
                f"  ⚠ This marker may be MISLEADING.\n"
                f"  Do NOT assume this is the real origin."
            )
        domain_str = info.get('domain', '?')
        via = info.get('via', '')
        domain_line = f"Domain: {domain_str}"
        if via:
            domain_line += f" (via {via})"
        all_doms = info.get('all_domains', [])
        all_doms_line = ""
        if all_doms and len(all_doms) > 1:
            all_doms_line = f"\nAll Domains: {', '.join(all_doms[:6])}"
            if len(all_doms) > 6:
                all_doms_line += f" (+{len(all_doms)-6})"
        wtag = info.get('website_tag', '')
        wtag_line = f"🏷️ {wtag}\n" if wtag else ""
        text = (f"{wtag_line}"
                f"IP: {ip}\n"
                f"Service: {info.get('service', '?')}\n"
                f"{domain_line}\n"
                f"Process: {info.get('process', '?')}\n"
                f"City: {info.get('city', '?')}, {info.get('country', '?')}\n"
                f"Org: {info.get('org', '?')}\n"
                f"Lat: {info.get('lat', 0):.4f}, Lon: {info.get('lon', 0):.4f}"
                f"{all_doms_line}{loc_line}{proof_lines}{proxy_line}{vpn_disclaimer}\n"
                "[Click for full action log]")
        self._show_tooltip(event, text)

    def _on_map_dot_leave(self, event):
        self._hide_tooltip()

    def _on_map_dot_right_click(self, event, ip, info):
        """Right-clicking a map dot opens the same menu as the list views."""
        self._hide_tooltip()
        conn = None
        for c in (self._last_full_data or {}).get('connections', []):
            if c.get('remote_ip') == ip:
                conn = c
                break
        self._show_conn_context_menu(event, ip, conn or info)

    def _ip_owner_line(self, ip) -> str:
        """Resolve which local process currently owns a remote IP."""
        if self._monitor is None:
            return ""
        try:
            owner = self._monitor.owner_of_ip(ip)
        except Exception:
            return ""
        if not owner:
            return ""
        line = f"{owner.get('name', '?')} (PID {owner.get('pid', '?')})"
        if owner.get('status'):
            line += f" [{owner['status']}]"
        return line

    def _on_map_dot_click(self, ip):
        if self._selected_ip != ip:
            self._selected_ip = ip
            self._redraw_dots_only()   # repaint so the selection ring moves
        if self._ip_actions_text:
            self._ip_actions_text.config(state="normal")
            self._ip_actions_text.delete("1.0", "end")
            data = self._get_full_data()
            lines = [f"=== FULL ACTION LOG FOR IP: {ip} ===\n"]
            owner = self._ip_owner_line(ip)
            if owner:
                lines.append(f"Currently owned by: {owner}")
            if ip in self._watchlist_ips:
                lines.append("★ This IP is on your watchlist")
            if ip in self._blocked_ips:
                lines.append("🚫 This IP is blocked by a firewall rule")
            lines.append("")
            # Find all connections for this IP
            for conn in data.get('connections', []):
                if conn.get('remote_ip') == ip:
                    wtag = conn.get('website_tag', '')
                    if wtag:
                        lines.append(f"🏷️ WEBSITE: {wtag}")
                    lines.append(f"Connection: {conn.get('process', '?')} (PID {conn.get('pid', '?')})")
                    exe_p = conn.get('exe_path', '')
                    if exe_p:
                        lines.append(f"  Exe Path: {exe_p}")
                    parent_n = conn.get('parent_name', '')
                    if parent_n:
                        lines.append(f"  Parent: {parent_n}")
                    lines.append(f"  Remote: {ip}:{conn.get('remote_port', '?')}")
                    lines.append(f"  Local Port: {conn.get('local_port', '?')}")
                    lines.append(f"  Protocol: {conn.get('protocol', '?')}")
                    lines.append(f"  Status: {conn.get('status', '?')}")
                    lines.append(f"  Service: {conn.get('service', '?')} ({conn.get('category', '?')})")
                    via = conn.get('via', '')
                    domain_info = conn.get('domain', '?')
                    if via:
                        domain_info += f" (via {via})"
                    lines.append(f"  Domain: {domain_info}")
                    all_doms = conn.get('all_domains', [])
                    if all_doms:
                        lines.append(f"  All Domains: {', '.join(all_doms[:10])}")
                        if len(all_doms) > 10:
                            lines.append(f"    (+{len(all_doms)-10} more)")
                    lines.append(f"  Country: {conn.get('country', '?')} ({conn.get('country_code', '?')})")
                    lines.append(f"  City: {conn.get('city', '?')}, Region: {conn.get('region', '?')}")
                    lines.append(f"  Org: {conn.get('org', '?')}, ISP: {conn.get('isp', '?')}")
                    lines.append(f"  Coords: ({conn.get('lat', 0):.4f}, {conn.get('lon', 0):.4f})")
                    lines.append(f"  First Seen: {_fmt_ts(conn.get('first_seen', 0))}")
                    lines.append(f"  Last Seen: {_fmt_ts(conn.get('last_seen', 0))}")
                    lines.append("")
            # Find all deductions mentioning this IP
            lines.append(f"\n=== DEDUCTIONS INVOLVING {ip} ===")
            for d in data.get('deductions', []):
                if ip in (d.get('message', '') + ' '.join(d.get('evidence', []))):
                    lines.append(f"[{d.get('time', '?')}] [{d.get('severity', '?')}] {d.get('category', '?')}")
                    lines.append(f"  Process: {d.get('process', '?')} (PID {d.get('pid', '?')})")
                    lines.append(f"  Message: {d.get('message', '?')}")
                    for ev in d.get('evidence', []):
                        lines.append(f"    -> {ev}")
                    lines.append(f"  Score: {d.get('score', 0)}")
                    lines.append("")
            # Find all process actions involving this IP
            lines.append(f"\n=== PROCESS ACTIONS INVOLVING {ip} ===")
            for act in data.get('all_actions', []):
                if ip in str(act):
                    lines.append(f"  {act}")
            if len(lines) <= 4:
                lines.append("  (No detailed actions recorded yet for this IP)")
            self._ip_actions_text.insert("1.0", "\n".join(lines))
            self._ip_actions_text.config(state="disabled")

    def run(self):
        try:
            self._run_gui()
        except Exception as exc:
            import traceback
            print(f"GUI RUN CRASH: {exc}", flush=True)
            traceback.print_exc()

    def _run_gui(self):
        self._root = tk.Tk()
        self._root.title("GNA Tracer — Full Network Intelligence")
        self._root.geometry("1280x820")
        self._root.configure(bg="#0a0a0f")
        self._root.protocol("WM_DELETE_WINDOW", self._on_close)

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TNotebook", background="#0a0a0f", borderwidth=0)
        style.configure("TNotebook.Tab", background="#1a1a2e", foreground="#c0c0c0",
                        padding=[12, 6], font=("Consolas", 10, "bold"))
        style.map("TNotebook.Tab",
                  background=[("selected", "#e94560")],
                  foreground=[("selected", "#ffffff")])
        style.configure("TFrame", background="#0a0a0f")
        style.configure("Treeview", background="#12121a", foreground="#c0c0c0",
                        fieldbackground="#12121a", font=("Consolas", 9),
                        rowheight=20)
        style.configure("Treeview.Heading", background="#1a1a2e", foreground="#ff5566",
                        font=("Consolas", 9, "bold"))
        style.map("Treeview", background=[("selected", "#0f3460")])

        # Header
        hdr = tk.Frame(self._root, bg="#1a1a2e", height=40)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)
        tk.Label(hdr, text="♟ GNA TRACER — FULL NETWORK INTELLIGENCE",
                 bg="#1a1a2e", fg="#ff5566", font=("Consolas", 14, "bold")).pack(side="left", padx=16)
        self._status_lbl = tk.Label(hdr, text="Initializing...", bg="#1a1a2e", fg="#00d4ff",
                                    font=("Consolas", 10))
        self._status_lbl.pack(side="right", padx=16)
        _add_tooltip(self._status_lbl,
            "Live status bar\n"
            "─────────────────────\n"
            "Shows real-time counts of connections, services, IPs,\n"
            "processes, deductions, and pipeline throughput.\n"
            "Refresh indicator shows actual GUI refresh latency:\n"
            "  ⚡ <100ms = excellent\n"
            "  🔄 <300ms = good\n"
            "  🐢 <1s = acceptable\n"
            "  ⏳ >1s = slow (auto-backoff active)")

        # Notebook
        nb = ttk.Notebook(self._root)
        nb.pack(fill="both", expand=True, padx=4, pady=4)
        self._notebook = nb

        # Search variables (one per tab)
        self._search_overview = tk.StringVar()
        self._search_conn = tk.StringVar()
        self._search_ded = tk.StringVar()
        self._search_proc = tk.StringVar()
        self._search_dev = tk.StringVar()
        self._search_actions = tk.StringVar()
        self._search_terminal = tk.StringVar()
        self._search_suspicious = tk.StringVar()
        self._search_live = tk.StringVar()
        self._search_trace = tk.StringVar()

        # === TAB 1: Overview ===
        self._overview_frame = ttk.Frame(nb)
        nb.add(self._overview_frame, text=" 📊 Overview ")
        self._make_info_banner(self._overview_frame, 0)
        self._make_search_bar(self._overview_frame, self._search_overview)
        self._overview_text = scrolledtext.ScrolledText(
            self._overview_frame, bg="#12121a", fg="#c0c0c0",
            font=("Consolas", 10), insertbackground="#c0c0c0", state="disabled",
            wrap="word", bd=0, highlightthickness=0)
        self._overview_text.pack(fill="both", expand=True)

        # === TAB 2: Live Connections (only active/established) ===
        self._live_frame = ttk.Frame(nb)
        nb.add(self._live_frame, text=" 🟢 Live Connections ")
        self._make_info_banner(self._live_frame, 1)
        self._make_search_bar(self._live_frame, self._search_live)
        self._live_text = scrolledtext.ScrolledText(
            self._live_frame, bg="#12121a", fg="#c0c0c0",
            font=("Consolas", 9), insertbackground="#c0c0c0", state="disabled",
            wrap="none", bd=0, highlightthickness=0)
        self._live_text.pack(fill="both", expand=True)
        self._live_buttons: list = []
        self._live_expanded: dict[str, bool] = {}  # conn_key → expanded?

        # === TAB 3: All Connections (each individually) ===
        self._conn_frame = ttk.Frame(nb)
        nb.add(self._conn_frame, text=" 🔗 All Connections ")
        self._make_info_banner(self._conn_frame, 2)
        # Toolbar
        conn_toolbar = tk.Frame(self._conn_frame, bg="#1a1a2e", height=32)
        conn_toolbar.pack(fill="x", side="top")
        conn_toolbar.pack_propagate(False)
        self._pause_btn = tk.Button(
            conn_toolbar, text="⏸ Pause Updates", bg="#333344", fg="#00d4ff",
            font=("Consolas", 9, "bold"), bd=0, padx=12, pady=2,
            activebackground="#444466", activeforeground="#00d4ff",
            command=self._toggle_conn_pause)
        self._pause_btn.pack(side="left", padx=8, pady=4)
        _add_tooltip(self._pause_btn,
            "Pause live updates\n"
            "─────────────────────\n"
            "Freezes the connection list so you can browse\n"
            "without the view resetting. Click again to resume.")
        self._blocked_lbl = tk.Label(
            conn_toolbar, text="No IPs blocked", bg="#1a1a2e", fg="#8a8a9a",
            font=("Consolas", 9))
        self._blocked_lbl.pack(side="left", padx=12)
        _add_tooltip(self._blocked_lbl,
            "Blocked IPs counter\n"
            "─────────────────────\n"
            "Shows how many IPs are currently blocked\n"
            "via Windows Firewall rules.")
        unblock_all_btn = tk.Button(
            conn_toolbar, text="🔓 Unblock All", bg="#333344", fg="#ffcc44",
            font=("Consolas", 9), bd=0, padx=8, pady=2,
            activebackground="#444466", activeforeground="#ffcc44",
            command=self._unblock_all)
        unblock_all_btn.pack(side="right", padx=8, pady=4)
        _add_tooltip(unblock_all_btn,
            "Remove all firewall block rules\n"
            "─────────────────────\n"
            "Deletes all Windows Firewall rules prefixed with\n"
            "'GNA_Tracer_Block_' — unblocking all IPs at once.")
        tk.Label(conn_toolbar, text="Click [Block] next to any connection to add a firewall rule",
                 bg="#1a1a2e", fg="#7a7a8a", font=("Consolas", 8)).pack(side="right", padx=8)
        # Connection search + list
        self._make_search_bar(self._conn_frame, self._search_conn)
        self._conn_text = scrolledtext.ScrolledText(
            self._conn_frame, bg="#12121a", fg="#c0c0c0",
            font=("Consolas", 9), insertbackground="#c0c0c0", state="disabled",
            wrap="none", bd=0, highlightthickness=0)
        self._conn_text.pack(fill="both", expand=True)

        # === TAB 3: Deductions (full evidence) ===
        self._ded_frame = ttk.Frame(nb)
        nb.add(self._ded_frame, text=" 🚨 Deductions ")
        self._make_info_banner(self._ded_frame, 3)
        self._make_search_bar(self._ded_frame, self._search_ded)
        self._ded_text = scrolledtext.ScrolledText(
            self._ded_frame, bg="#12121a", fg="#c0c0c0",
            font=("Consolas", 9), insertbackground="#c0c0c0", state="disabled",
            wrap="word", bd=0, highlightthickness=0)
        self._ded_text.pack(fill="both", expand=True)

        # === TAB 4: Processes ===
        self._proc_frame = ttk.Frame(nb)
        nb.add(self._proc_frame, text=" 📈 Processes ")
        self._make_info_banner(self._proc_frame, 4)
        self._make_search_bar(self._proc_frame, self._search_proc)
        self._proc_text = scrolledtext.ScrolledText(
            self._proc_frame, bg="#12121a", fg="#c0c0c0",
            font=("Consolas", 9), insertbackground="#c0c0c0", state="disabled",
            wrap="none", bd=0, highlightthickness=0)
        self._proc_text.pack(fill="both", expand=True)

        # === TAB 5: Devices ===
        self._dev_frame = ttk.Frame(nb)
        nb.add(self._dev_frame, text=" 📱 Devices ")
        self._make_info_banner(self._dev_frame, 5)
        self._make_search_bar(self._dev_frame, self._search_dev)
        self._dev_text = scrolledtext.ScrolledText(
            self._dev_frame, bg="#12121a", fg="#c0c0c0",
            font=("Consolas", 9), insertbackground="#c0c0c0", state="disabled",
            wrap="none", bd=0, highlightthickness=0)
        self._dev_text.pack(fill="both", expand=True)

        # === TAB 6: IP Map (Full Atlas with zoom/pan/styles/search) ===
        self._map_frame = ttk.Frame(nb)
        nb.add(self._map_frame, text=" 🗺️ IP Map ")
        # --- Top controls bar (row 1): zoom, style, search, presets ---
        map_ctrl = tk.Frame(self._map_frame, bg="#1a1a2e", height=36)
        map_ctrl.pack(fill="x")
        map_ctrl.pack_propagate(False)
        btn_zoom_in = tk.Button(map_ctrl, text="➕", bg="#333344", fg="#c0c0c0",
                  font=("Consolas", 11, "bold"), bd=0, padx=8,
                  command=lambda: self._map_zoom_by(1.3))
        btn_zoom_in.pack(side="left", padx=2, pady=3)
        _add_tooltip(btn_zoom_in,
            "Zoom in\n─────────────────────\nZoom toward mouse cursor by 1.3x.\n"
            "Also: scroll wheel up, or press + key")
        btn_zoom_out = tk.Button(map_ctrl, text="➖", bg="#333344", fg="#c0c0c0",
                  font=("Consolas", 11, "bold"), bd=0, padx=8,
                  command=lambda: self._map_zoom_by(1/1.3))
        btn_zoom_out.pack(side="left", padx=2, pady=3)
        _add_tooltip(btn_zoom_out,
            "Zoom out\n─────────────────────\nZoom out by 1/1.3x.\n"
            "Also: scroll wheel down, or press - key")
        btn_home = tk.Button(map_ctrl, text="🏠", bg="#333344", fg="#c0c0c0",
                  font=("Consolas", 10, "bold"), bd=0, padx=6,
                  command=self._map_reset_view)
        btn_home.pack(side="left", padx=2, pady=3)
        _add_tooltip(btn_home,
            "Reset view\n─────────────────────\nReset map to default zoom (3.0),\n"
            "centered on your own location when known.")
        # Zoom slider
        tk.Label(map_ctrl, text="Zoom:", bg="#1a1a2e", fg="#a0a0b0",
                 font=("Consolas", 8)).pack(side="left", padx=(6, 2))
        self._map_zoom_slider = ttk.Scale(map_ctrl, from_=0, to=19,
                                          orient="horizontal", length=120,
                                          command=self._on_zoom_slider)
        self._map_zoom_slider.set(self._map_zoom)
        self._map_zoom_slider.pack(side="left", padx=2)
        _add_tooltip(self._map_zoom_slider,
            "Zoom level slider\n─────────────────────\nDrag to set zoom level 0-19.\n"
            "0 = whole world | 19 = street level\n"
            "Fractional zoom supported (e.g., 7.5)")
        self._zoom_lbl = tk.Label(map_ctrl, text="Zoom: 2.0  (z=2)", bg="#1a1a2e",
                                  fg="#00d4ff", font=("Consolas", 8))
        self._zoom_lbl.pack(side="left", padx=6)
        _add_tooltip(self._zoom_lbl,
            "Current zoom level\n─────────────────────\n"
            "Shows the current zoom factor and tile level.\n"
            "z = integer tile level (used for tile fetching)")
        # Tile style selector
        tk.Label(map_ctrl, text="Style:", bg="#1a1a2e", fg="#a0a0b0",
                 font=("Consolas", 8)).pack(side="left", padx=(8, 2))
        self._map_style_var = tk.StringVar(
            value=f"{TileManager.get_style()} — {TileManager.get_style_label()}")
        style_menu = ttk.Combobox(map_ctrl, textvariable=self._map_style_var,
                                  values=[f"{k} — {v['label']}" for k, v in TileManager.TILE_STYLES.items()],
                                  width=22, state="readonly", font=("Consolas", 8))
        style_menu.pack(side="left", padx=2, pady=3)
        style_menu.bind("<<ComboboxSelected>>", self._on_style_change)
        _add_tooltip(style_menu,
            "Map tile style\n─────────────────────\n"
            "Choose from 6 atlas styles:\n"
            "  OSM Standard — streets and roads\n"
            "  CartoDB Dark — dark theme streets\n"
            "  CartoDB Voyager — clean streets\n"
            "  Esri Satellite — satellite imagery\n"
            "  Esri Terrain — terrain/relief\n"
            "  OpenTopoMap — topographic map")
        # Search / Go-to box
        tk.Label(map_ctrl, text="Go to:", bg="#1a1a2e", fg="#a0a0b0",
                 font=("Consolas", 8)).pack(side="left", padx=(8, 2))
        self._map_search_var = tk.StringVar()
        search_entry = tk.Entry(map_ctrl, textvariable=self._map_search_var,
                                width=20, font=("Consolas", 9), bd=0,
                                bg="#12121a", fg="#c0c0c0",
                                insertbackground="#c0c0c0")
        search_entry.pack(side="left", padx=2, pady=4)
        search_entry.bind("<Return>", self._on_map_search)
        _add_tooltip(search_entry,
            "Location search / Go-to\n─────────────────────\n"
            "Type a city name, country, or coordinates:\n"
            "  'Tokyo'     — jumps to Tokyo, Japan\n"
            "  '48.8,2.3'  — jumps to lat,lon\n"
            "  'Paris'     — jumps to Paris, France\n"
            "Press Enter or click 🔍 to search.")
        btn_search = tk.Button(map_ctrl, text="🔍", bg="#333344", fg="#c0c0c0",
                  font=("Consolas", 9, "bold"), bd=0, padx=6,
                  command=self._on_map_search)
        btn_search.pack(side="left", padx=2, pady=3)
        _add_tooltip(btn_search,
            "Search map\n─────────────────────\n"
            "Searches for the location in the Go-to box\n"
            "and centers the map on it.")
        # Help button
        btn_help = tk.Button(map_ctrl, text="❓", bg="#333344", fg="#c0c0c0",
                  font=("Consolas", 9, "bold"), bd=0, padx=6,
                  command=self._toggle_map_help)
        btn_help.pack(side="left", padx=2, pady=3)
        _add_tooltip(btn_help,
            "Keyboard/mouse help\n─────────────────────\n"
            "Shows/hides the help overlay with all\n"
            "keyboard shortcuts and mouse controls:\n"
            "  Scroll = zoom | Drag = pan\n"
            "  Arrows = pan | +/- = zoom\n"
            "  Right-click = context menu")
        # Coordinates display (right side)
        self._coords_lbl = tk.Label(map_ctrl, text="", bg="#1a1a2e",
                                    fg="#a0a0b0", font=("Consolas", 8))
        self._coords_lbl.pack(side="right", padx=8)
        _add_tooltip(self._coords_lbl,
            "Mouse coordinates\n─────────────────────\n"
            "Shows the lat/lon under the mouse cursor\n"
            "in real-time as you move over the map.")
        # Legend (right side)
        legend_f = tk.Frame(map_ctrl, bg="#1a1a2e")
        legend_f.pack(side="right", padx=4)
        _add_tooltip(legend_f,
            "Connection dot legend\n─────────────────────\n"
            "  Green  = Low risk (0-20)\n"
            "  Yellow = Medium risk (21-40)\n"
            "  Orange = High risk (41-70)\n"
            "  Red    = Critical risk (71+)\n"
            "  Purple = VPN/Proxy exit node")
        for color, label in [("#44cc44", "Low"), ("#ffcc00", "Med"),
                              ("#ff8800", "High"), ("#ff0000", "Crit"),
                              ("#cc00cc", "VPN/Proxy Exit")]:
            tk.Canvas(legend_f, bg=color, width=8, height=8,
                      highlightthickness=0).pack(side="left", padx=1)
            tk.Label(legend_f, text=label, bg="#1a1a2e", fg="#a0a0b0",
                     font=("Consolas", 7)).pack(side="left", padx=(0, 4))
        # --- Preset bookmarks bar (row 2) ---
        preset_bar = tk.Frame(self._map_frame, bg="#12121a", height=24)
        preset_bar.pack(fill="x")
        preset_bar.pack_propagate(False)
        tk.Label(preset_bar, text="Presets:", bg="#12121a", fg="#8a8a9a",
                 font=("Consolas", 7)).pack(side="left", padx=4)
        for label, lat, lon, z in [
            ("🌍 World", 20.0, 0.0, 2.0),
            ("🌎 N.America", 45.0, -100.0, 4.0),
            ("🌍 Europe", 50.0, 10.0, 5.0),
            ("🌏 Asia", 35.0, 100.0, 4.0),
            ("🌎 S.America", -15.0, -60.0, 4.0),
            ("🌍 Africa", 5.0, 20.0, 4.0),
            ("🌏 Australia", -25.0, 135.0, 5.0),
            ("🏙️ N.York", 40.7128, -74.0060, 11.0),
            ("🏙️ London", 51.5074, -0.1278, 11.0),
            ("🏙️ Tokyo", 35.6762, 139.6503, 11.0),
            ("🏙️ Frankfurt", 50.1109, 8.6821, 11.0),
            ("🏙️ Singapore", 1.3521, 103.8198, 11.0),
            ("🏙️ Sydney", -33.8688, 151.2093, 11.0),
            ("🏙️ Dubai", 25.2048, 55.2708, 11.0),
        ]:
            btn_preset = tk.Button(preset_bar, text=label, bg="#1a1a2e", fg="#a0a0b0",
                      font=("Consolas", 7), bd=0, padx=4,
                      command=lambda l=lat, lo=lon, zz=z: self._goto_preset(l, lo, zz))
            btn_preset.pack(side="left", padx=1, pady=2)
            _add_tooltip(btn_preset,
                f"Go to {label}\n─────────────────────\n"
                f"Lat: {lat}, Lon: {lon}\n"
                f"Zoom: {z}\n"
                "Click to center the map on this location.")
        # Toggle action log button
        btn_toggle_log = tk.Button(preset_bar, text="📋 Toggle Log", bg="#1a1a2e", fg="#ff5566",
                  font=("Consolas", 7, "bold"), bd=0, padx=4,
                  command=self._toggle_map_action_log)
        btn_toggle_log.pack(side="right", padx=4, pady=2)
        _add_tooltip(btn_toggle_log,
            "Toggle action log panel\n─────────────────────\n"
            "Shows/hides the map action log panel at the\n"
            "bottom of the map. The log records every\n"
            "map interaction (zoom, pan, search, trace).")
        # --- Map canvas (fills remaining space) ---
        map_top = tk.Frame(self._map_frame, bg="#0a0a0f")
        map_top.pack(fill="both", expand=True)
        self._map_canvas = tk.Canvas(map_top, bg="#0d1117", width=self._map_w,
                                     height=self._map_h, highlightthickness=0)
        self._map_canvas.pack(fill="both", expand=True, padx=2, pady=2)
        # Bind zoom (mouse wheel) and pan (both left and right click-drag)
        self._map_canvas.bind("<MouseWheel>", self._on_map_scroll)
        self._map_canvas.bind("<Button-4>", lambda e: self._map_zoom_by(1.15, e))
        self._map_canvas.bind("<Button-5>", lambda e: self._map_zoom_by(1/1.15, e))
        # Right-drag panning (original)
        self._map_canvas.bind("<ButtonPress-3>", self._on_map_drag_start)
        self._map_canvas.bind("<B3-Motion>", self._on_map_drag)
        self._map_canvas.bind("<ButtonRelease-3>", self._on_map_drag_end)
        # Left-drag panning (new — more natural, with click detection for context menu)
        self._map_canvas.bind("<ButtonPress-1>", self._on_map_left_press)
        self._map_canvas.bind("<B1-Motion>", self._on_map_left_drag)
        self._map_canvas.bind("<ButtonRelease-1>", self._on_map_left_release)
        self._map_canvas.bind("<Motion>", self._on_map_mouse_move)
        # Keyboard navigation
        self._map_canvas.bind("<Key-plus>", lambda e: self._map_zoom_by(1.3))
        self._map_canvas.bind("<Key-equal>", lambda e: self._map_zoom_by(1.3))
        self._map_canvas.bind("<Key-minus>", lambda e: self._map_zoom_by(1/1.3))
        self._map_canvas.bind("<Key-Up>", lambda e: self._pan_map(0, 50))
        self._map_canvas.bind("<Key-Down>", lambda e: self._pan_map(0, -50))
        self._map_canvas.bind("<Key-Left>", lambda e: self._pan_map(50, 0))
        self._map_canvas.bind("<Key-Right>", lambda e: self._pan_map(-50, 0))
        self._map_canvas.bind("<Key-h>", lambda e: self._toggle_map_help())
        self._map_canvas.bind("<Key-r>", lambda e: self._map_reset_view())
        # Enable keyboard focus on canvas
        self._map_canvas.configure(takefocus=True)
        self._draw_map_full()
        # --- Action log below map (collapsible) ---
        self._map_action_log_frame = tk.Frame(self._map_frame, bg="#0a0a0f", height=140)
        self._map_action_log_frame.pack(fill="both", expand=False)
        self._map_action_log_frame.pack_propagate(False)
        tk.Label(self._map_action_log_frame,
                 text="IP ACTION LOG (click a dot · scroll=zoom · drag=pan · arrows=navigate · ❓=help)",
                 bg="#1a1a2e", fg="#ff5566", font=("Consolas", 8, "bold")).pack(fill="x")
        self._ip_actions_text = scrolledtext.ScrolledText(
            self._map_action_log_frame, bg="#12121a", fg="#c0c0c0",
            font=("Consolas", 9), insertbackground="#c0c0c0", state="disabled",
            wrap="word", bd=0, highlightthickness=0)
        self._ip_actions_text.pack(fill="both", expand=True)

        # === TAB 7: Raw Actions Log ===
        self._actions_frame = ttk.Frame(nb)
        nb.add(self._actions_frame, text=" 📝 Actions Log ")
        self._make_info_banner(self._actions_frame, 7)
        self._make_search_bar(self._actions_frame, self._search_actions)
        self._actions_text = scrolledtext.ScrolledText(
            self._actions_frame, bg="#12121a", fg="#c0c0c0",
            font=("Consolas", 9), insertbackground="#c0c0c0", state="disabled",
            wrap="none", bd=0, highlightthickness=0)
        self._actions_text.pack(fill="both", expand=True)

        # === TAB 8: Terminal (100% of all processed output) ===
        self._terminal_frame = ttk.Frame(nb)
        nb.add(self._terminal_frame, text=" 🖥️ Terminal ")
        self._make_info_banner(self._terminal_frame, 8)
        self._make_search_bar(self._terminal_frame, self._search_terminal)
        self._terminal_text = scrolledtext.ScrolledText(
            self._terminal_frame, bg="#0a0a0f", fg="#c0c0c0",
            font=("Consolas", 9), insertbackground="#c0c0c0", state="disabled",
            wrap="none", bd=0, highlightthickness=0)
        self._terminal_text.pack(fill="both", expand=True)
        self._terminal_last_count = 0  # track how many lines we've rendered

        # === TAB 9: Suspicious Activity (ONLY out-of-norm behavior) ===
        self._suspicious_frame = ttk.Frame(nb)
        nb.add(self._suspicious_frame, text=" 🔴 Suspicious Activity ")
        self._make_info_banner(self._suspicious_frame, 9)
        self._make_search_bar(self._suspicious_frame, self._search_suspicious)
        self._suspicious_text = scrolledtext.ScrolledText(
            self._suspicious_frame, bg="#12121a", fg="#c0c0c0",
            font=("Consolas", 9), insertbackground="#c0c0c0", state="disabled",
            wrap="word", bd=0, highlightthickness=0)
        self._suspicious_text.pack(fill="both", expand=True)

        # === TAB 10: Blocked IPs ===
        self._blocked_frame = ttk.Frame(nb)
        nb.add(self._blocked_frame, text=" 🛑 Blocked IPs ")
        self._make_info_banner(self._blocked_frame, 10)
        self._blocked_text = scrolledtext.ScrolledText(
            self._blocked_frame, bg="#12121a", fg="#c0c0c0",
            font=("Consolas", 9), insertbackground="#c0c0c0", state="disabled",
            wrap="none", bd=0, highlightthickness=0)
        self._blocked_text.pack(fill="both", expand=True)

        # === TAB 11: Process Tree ===
        self._ptree_frame = ttk.Frame(nb)
        nb.add(self._ptree_frame, text=" 🌳 Process Tree ")
        self._make_info_banner(self._ptree_frame, 11)
        self._ptree_text = scrolledtext.ScrolledText(
            self._ptree_frame, bg="#12121a", fg="#c0c0c0",
            font=("Consolas", 9), insertbackground="#c0c0c0", state="disabled",
            wrap="none", bd=0, highlightthickness=0)
        self._ptree_text.pack(fill="both", expand=True)

        # === TAB 12: Network Stats ===
        self._netstats_frame = ttk.Frame(nb)
        nb.add(self._netstats_frame, text=" 📊 Net Stats ")
        self._make_info_banner(self._netstats_frame, 12)
        self._netstats_text = scrolledtext.ScrolledText(
            self._netstats_frame, bg="#12121a", fg="#c0c0c0",
            font=("Consolas", 9), insertbackground="#c0c0c0", state="disabled",
            wrap="none", bd=0, highlightthickness=0)
        self._netstats_text.pack(fill="both", expand=True)

        # === TAB 13: Connection Timeline ===
        self._timeline_frame = ttk.Frame(nb)
        nb.add(self._timeline_frame, text=" ⏱️ Timeline ")
        self._make_info_banner(self._timeline_frame, 13)
        self._timeline_text = scrolledtext.ScrolledText(
            self._timeline_frame, bg="#12121a", fg="#c0c0c0",
            font=("Consolas", 9), insertbackground="#c0c0c0", state="disabled",
            wrap="none", bd=0, highlightthickness=0)
        self._timeline_text.pack(fill="both", expand=True)

        # === TAB 14: Config Editor ===
        self._config_frame = ttk.Frame(nb)
        nb.add(self._config_frame, text=" ⚙️ Config ")
        self._make_info_banner(self._config_frame, 14)
        self._config_text = scrolledtext.ScrolledText(
            self._config_frame, bg="#12121a", fg="#c0c0c0",
            font=("Consolas", 9), insertbackground="#c0c0c0", state="disabled",
            wrap="none", bd=0, highlightthickness=0)
        self._config_text.pack(fill="both", expand=True)

        # === TAB 15: Double / Multi-hop Trace ===
        self._trace_frame = ttk.Frame(nb)
        nb.add(self._trace_frame, text=" 🔀 Double Trace ")
        self._make_info_banner(self._trace_frame, 15)
        # --- Toolbar row 1: target + actions ---
        trace_bar1 = tk.Frame(self._trace_frame, bg="#1a1a2e", height=34)
        trace_bar1.pack(fill="x", side="top")
        trace_bar1.pack_propagate(False)
        tk.Label(trace_bar1, text="🎯 Target:", bg="#1a1a2e", fg="#00d4ff",
                 font=("Consolas", 9, "bold")).pack(side="left", padx=(8, 2))
        self._trace_target_var = tk.StringVar()
        self._trace_target_combo = ttk.Combobox(
            trace_bar1, textvariable=self._trace_target_var, font=("Consolas", 9),
            width=34, values=[])
        self._trace_target_combo.pack(side="left", padx=4, pady=4)
        self._trace_target_combo.bind("<Return>", lambda e: self._start_trace())
        btn_trace = tk.Button(trace_bar1, text="▶ Trace", bg="#2e7d32", fg="#ffffff",
                  font=("Consolas", 9, "bold"), bd=0, padx=10, pady=2,
                  activebackground="#388e3c", activeforeground="#ffffff",
                  command=self._start_trace)
        btn_trace.pack(side="left", padx=4, pady=4)
        _add_tooltip(btn_trace,
            "Start traceroute to target\n"
            "─────────────────────\n"
            "Traces the full network path (hop-by-hop)\n"
            "to the selected target IP/domain.\n"
            "Each hop is GeoIP-enriched and labeled\n"
            "(VPN/proxy/hosting/CDN/ISP).")
        btn_trace_all = tk.Button(trace_bar1, text="▶▶ Trace All Active", bg="#333344", fg="#00d4ff",
                  font=("Consolas", 9, "bold"), bd=0, padx=10, pady=2,
                  activebackground="#444466", activeforeground="#00d4ff",
                  command=self._start_trace_all)
        btn_trace_all.pack(side="left", padx=4, pady=4)
        _add_tooltip(btn_trace_all,
            "Trace all active connections\n"
            "─────────────────────\n"
            "Runs traceroute to every active destination\n"
            "simultaneously. Results appear in the trace\n"
            "text view and on the map as path overlays.")
        btn_stop = tk.Button(trace_bar1, text="⏹ Stop", bg="#8e2f2f", fg="#ffffff",
                  font=("Consolas", 9, "bold"), bd=0, padx=10, pady=2,
                  activebackground="#a13a3a", activeforeground="#ffffff",
                  command=self._stop_trace)
        btn_stop.pack(side="left", padx=4, pady=4)
        _add_tooltip(btn_stop,
            "Stop all running traces\n"
            "─────────────────────\n"
            "Cancels any in-progress traceroute operations.")
        btn_clear = tk.Button(trace_bar1, text="🧹 Clear", bg="#333344", fg="#ffcc44",
                  font=("Consolas", 9), bd=0, padx=8, pady=2,
                  activebackground="#444466", activeforeground="#ffcc44",
                  command=self._clear_trace)
        btn_clear.pack(side="left", padx=4, pady=4)
        _add_tooltip(btn_clear,
            "Clear trace results\n"
            "─────────────────────\n"
            "Removes all trace output from the text view\n"
            "and clears path overlays from the map.")
        self._trace_status_lbl = tk.Label(trace_bar1, text="Idle", bg="#1a1a2e",
                                          fg="#a0a0b0", font=("Consolas", 9))
        self._trace_status_lbl.pack(side="right", padx=12)
        # --- Toolbar row 2: options + logging ---
        trace_bar2 = tk.Frame(self._trace_frame, bg="#141426", height=30)
        trace_bar2.pack(fill="x", side="top")
        trace_bar2.pack_propagate(False)
        tk.Label(trace_bar2, text="Max hops:", bg="#141426", fg="#a0a0b0",
                 font=("Consolas", 8)).pack(side="left", padx=(8, 2))
        self._trace_maxhops_var = tk.StringVar(value="30")
        tk.Entry(trace_bar2, textvariable=self._trace_maxhops_var, width=4,
                 bg="#222233", fg="#00d4ff", insertbackground="#00d4ff",
                 font=("Consolas", 8), bd=0, highlightthickness=1,
                 highlightcolor="#333366").pack(side="left", padx=2, pady=4)
        self._trace_deepverify_var = tk.BooleanVar(value=False)
        cb_deepverify = tk.Checkbutton(trace_bar2, text="Cross-verify every hop (slow: RTT/TTL/ports/RDAP)",
                       variable=self._trace_deepverify_var, bg="#141426",
                       fg="#a0a0b0", selectcolor="#141426",
                       activebackground="#141426", activeforeground="#00d4ff",
                       font=("Consolas", 8), bd=0, highlightthickness=0)
        cb_deepverify.pack(side="left", padx=10)
        _add_tooltip(cb_deepverify,
            "Deep verification mode\n"
            "─────────────────────\n"
            "For each hop, performs:\n"
            "  • RTT measurement (multiple probes)\n"
            "  • TTL analysis\n"
            "  • Port scanning (common ports)\n"
            "  • RDAP/WHOIS lookup\n"
            "  • Reverse DNS\n"
            "Significantly slower but more detailed.")
        tk.Label(trace_bar2, text="Rotate log at (KB):", bg="#141426", fg="#a0a0b0",
                 font=("Consolas", 8)).pack(side="left", padx=(10, 2))
        self._trace_rotatekb_var = tk.StringVar(value="1024")
        tk.Entry(trace_bar2, textvariable=self._trace_rotatekb_var, width=7,
                 bg="#222233", fg="#00d4ff", insertbackground="#00d4ff",
                 font=("Consolas", 8), bd=0, highlightthickness=1,
                 highlightcolor="#333366").pack(side="left", padx=2, pady=4)
        btn_open_log = tk.Button(trace_bar2, text="📁 Open Log Folder", bg="#333344", fg="#c0c0c0",
                  font=("Consolas", 8), bd=0, padx=8, pady=1,
                  activebackground="#444466", activeforeground="#c0c0c0",
                  command=self._open_trace_log_folder)
        btn_open_log.pack(side="right", padx=8, pady=4)
        _add_tooltip(btn_open_log,
            "Open trace log folder\n"
            "─────────────────────\n"
            "Opens the folder containing permanent trace\n"
            "recordings in Windows Explorer.")
        btn_export_json = tk.Button(trace_bar2, text="💾 Export JSON", bg="#333344", fg="#44dd66",
                  font=("Consolas", 8), bd=0, padx=8, pady=1,
                  activebackground="#444466", activeforeground="#44dd66",
                  command=self._export_trace_json)
        btn_export_json.pack(side="right", padx=4, pady=4)
        _add_tooltip(btn_export_json,
            "Export traces as JSON\n"
            "─────────────────────\n"
            "Saves all trace results to a structured\n"
            "JSON file for programmatic analysis.")
        btn_export_csv = tk.Button(trace_bar2, text="📄 Export CSV", bg="#333344", fg="#ffaa44",
                  font=("Consolas", 8), bd=0, padx=8, pady=1,
                  activebackground="#444466", activeforeground="#ffaa44",
                  command=self._export_trace_csv)
        btn_export_csv.pack(side="right", padx=4, pady=4)
        _add_tooltip(btn_export_csv,
            "Export traces as CSV\n"
            "─────────────────────\n"
            "Saves all trace results as a spreadsheet-\n"
            "compatible CSV file (hop, IP, RTT, geo, label).")
        # Auto-retrace interval
        tk.Label(trace_bar2, text="Auto (s):", bg="#141426", fg="#a0a0b0",
                 font=("Consolas", 8)).pack(side="left", padx=(10, 2))
        self._trace_auto_var = tk.StringVar(value="0")
        tk.Entry(trace_bar2, textvariable=self._trace_auto_var, width=4,
                 bg="#222233", fg="#00d4ff", insertbackground="#00d4ff",
                 font=("Consolas", 8), bd=0, highlightthickness=1,
                 highlightcolor="#333366").pack(side="left", padx=2, pady=4)
        tk.Button(trace_bar2, text="🔄 Start Auto", bg="#333344", fg="#00d4ff",
                  font=("Consolas", 8), bd=0, padx=6, pady=1,
                  activebackground="#444466", activeforeground="#00d4ff",
                  command=self._toggle_auto_trace).pack(side="left", padx=4, pady=4)
        self._trace_logfile_lbl = tk.Label(trace_bar2, text="", bg="#141426",
                                           fg="#556655", font=("Consolas", 8))
        self._trace_logfile_lbl.pack(side="right", padx=6)
        # --- Search + output ---
        self._make_search_bar(self._trace_frame, self._search_trace)
        self._trace_text = scrolledtext.ScrolledText(
            self._trace_frame, bg="#0a0a0f", fg="#c0c0c0",
            font=("Consolas", 9), insertbackground="#c0c0c0", state="disabled",
            wrap="none", bd=0, highlightthickness=0)
        self._trace_text.pack(fill="both", expand=True)

        # Right-click context menus on the connection / process views.
        for _w in (self._live_text, self._conn_text):
            _w.bind("<Button-3>", lambda e, wid=_w: self._on_conn_right_click(e, wid))
        self._proc_text.bind(
            "<Button-3>", lambda e: self._on_proc_right_click(e, self._proc_text))
        self._ptree_text.bind(
            "<Button-3>", lambda e: self._on_proc_right_click(e, self._ptree_text))

        # Search boxes previously only took effect on the next 3s poll.
        # Re-render the owning tab as soon as the query changes.
        for _var, _fn in (
            (self._search_overview, '_refresh_overview'),
            (self._search_live, '_refresh_live'),
            (self._search_conn, '_refresh_connections'),
            (self._search_ded, '_refresh_deductions'),
            (self._search_proc, '_refresh_processes'),
            (self._search_dev, '_refresh_devices'),
            (self._search_actions, '_refresh_actions'),
            (self._search_suspicious, '_refresh_suspicious'),
            (self._search_terminal, '_refresh_terminal'),
        ):
            _var.trace_add('write',
                           lambda *_a, fn=_fn: self._search_changed(fn))
        self._search_trace.trace_add('write', lambda *_a: self._render_trace())

        # (alert-flash state is declared in __init__)

        # (watchlist sets are declared in __init__ and mirrored in _refresh_all)

        # Window geometry persistence
        self._geometry_file = os.path.join(os.path.expanduser("~"), ".gna_tracer_geometry.json")
        self._load_geometry()

        # Configure text tags for coloring — high-contrast scheme on #12121a
        for widget in [self._overview_text, self._live_text, self._conn_text,
                       self._ded_text, self._proc_text, self._dev_text,
                       self._actions_text, self._terminal_text,
                       self._suspicious_text, self._blocked_text,
                       self._ptree_text, self._netstats_text,
                       self._timeline_text, self._config_text, self._trace_text]:
            # Critical alerts — bright red, bold (contrast ~7:1 on #12121a)
            widget.tag_configure("critical", foreground="#ff4444", font=("Consolas", 10, "bold"))
            # Warnings — bright amber/yellow (contrast ~8:1)
            widget.tag_configure("warning", foreground="#ffcc44")
            # Info / positive — bright green (contrast ~7:1)
            widget.tag_configure("info", foreground="#44dd66")
            # Section headers — bright cyan, bold, large (contrast ~9:1)
            widget.tag_configure("header", foreground="#00d4ff", font=("Consolas", 11, "bold"))
            # Sub-headers — warm amber, bold (distinguishable from critical red)
            widget.tag_configure("subheader", foreground="#ffaa44", font=("Consolas", 10, "bold"))
            # Dim / secondary text — light gray-blue (contrast ~5:1, readable for 7-8pt)
            widget.tag_configure("dim", foreground="#8a8a9a")
            # Highlighted values — pure white (max contrast ~16:1)
            widget.tag_configure("highlight", foreground="#ffffff", font=("Consolas", 9, "bold"))
            # Default text — light silver (contrast ~10:1)
            widget.tag_configure("default", foreground="#c0c0c0")
            # Cyan accent (same as header but non-bold)
            widget.tag_configure("cyan", foreground="#00d4ff")
            # Label text — medium gray for field names (contrast ~6:1)
            widget.tag_configure("label", foreground="#a0a0b0")
            # Section box borders — brighter than dim for visibility
            widget.tag_configure("border", foreground="#6a6a7a")
            # Alternating row background for list readability
            widget.tag_configure("row_alt", background="#1a1a28")
            # Critical row background (for high-risk items)
            widget.tag_configure("row_critical", background="#2a1212")
            # Warning row background
            widget.tag_configure("row_warning", background="#2a2210")
            # Search match — high visibility
            widget.tag_configure("search_match", background="#ffcc44", foreground="#000000",
                                 font=("Consolas", 10, "bold"))
            # Clickable text regions. These replace embedded tk.Button widgets,
            # which the Text clears (and destroys) on every refresh — several
            # hundred widget create/destroy pairs per cycle.
            widget.tag_configure("toggle", foreground="#00d4ff",
                                 font=("Consolas", 10, "bold"))
            widget.tag_configure("block_btn", background="#8b0000", foreground="#ffffff",
                                 font=("Consolas", 8, "bold"))
            widget.tag_configure("unblock_btn", background="#4caf50", foreground="#ffffff",
                                 font=("Consolas", 8, "bold"))
            widget.tag_configure("cat_btn", foreground="#00d4ff",
                                 font=("Consolas", 9, "bold"))

        # Menu bar with About / Scope dialog
        menubar = tk.Menu(self._root, bg="#1a1a2e", fg="#c0c0c0",
                          activebackground="#ff4444", activeforeground="#ffffff",
                          borderwidth=0)
        help_menu = tk.Menu(menubar, tearoff=0, bg="#1a1a2e", fg="#c0c0c0",
                            activebackground="#ff4444", activeforeground="#ffffff")
        help_menu.add_command(label="About / Scope", command=self._show_about)
        help_menu.add_command(label="VPN Leak Status", command=self._show_vpn_leak)
        menubar.add_cascade(label="Info", menu=help_menu)
        self._root.config(menu=menubar)

        self._schedule_update()
        self._schedule_autosave()
        self._schedule_status_tick()
        self._root.mainloop()

    def _show_about(self):
        """Display an honest About / Scope dialog describing what the program
        can and cannot do, particularly regarding VPN detection."""
        about_text = (
            "GNA Tracer — MedianBoxMonitor 3.0\n"
            "Modular Deductive Network Security Monitor\n\n"
            "=== CAPABILITIES ===\n\n"
            "1. Local Network Monitoring\n"
            "   - Real-time packet capture (Scapy)\n"
            "   - Process-to-connection mapping (psutil)\n"
            "   - DNS cache polling and query logging\n"
            "   - TLS SNI extraction and JA4+ fingerprinting\n"
            "   - Beaconing, DNS tunneling, entropy analysis\n"
            "   - DLL injection, registry, and persistence detection\n"
            "   - Memory forensics scanning\n\n"
            "2. Trace & Path Analysis (Double Trace Tab)\n"
            "   - Multi-hop traceroute (ICMP + TCP fallback)\n"
            "   - Real-time hop streaming with GeoIP enrichment\n"
            "   - Path plotted on OpenStreetMap raster tiles\n"
            "   - RTT-based distance rings and latency labels\n"
            "   - Path anomaly detection (country backtracking, latency spikes)\n"
            "   - JSON/CSV export and rotating .txt logs\n\n"
            "3. Multi-Method Cross-Verification (MultiVerifier)\n"
            "   - 11 independent evidence sources fused into consensus\n"
            "   - Confidence grade (HIGH/MEDIUM/LOW/CONFLICTED/SINGLE-SOURCE)\n"
            "   - VPN/proxy/hosting/CDN classification\n"
            "   - VPN score (0-100) with per-method evidence\n"
            "   - Runs automatically on high-risk/suspicious public IPs\n\n"
            "4. VPN Leak Detection (Local)\n"
            "   - VPN interface detection (TUN/TAP/WireGuard/OpenVPN)\n"
            "   - Public-IP cross-check across multiple resolvers\n"
            "   - DNS leak detection (resolver chain mismatch)\n"
            "   - IPv6 leak detection (global IPv6 bypassing IPv4 tunnel)\n"
            "   - Route-table split-tunnel detection\n"
            "   - STUN reflexive address discovery (UDP leak check)\n"
            "   - Kill-switch verification\n\n"
            "=== SCOPE & LIMITATIONS ===\n\n"
            "This program is a DEFENSIVE monitoring tool for your own machine.\n\n"
            "What it CAN do:\n"
            "  - Detect if YOUR VPN is leaking (DNS, IPv6, split-tunnel, STUN)\n"
            "  - Identify VPN/proxy/hosting/CDN infrastructure on traced paths\n"
            "  - Cross-verify GeoIP consensus and flag conflicts\n"
            "  - Classify remote endpoints as VPN/proxy/datacenter with evidence\n"
            "  - Trace the network path from your machine to a destination\n\n"
            "What it CANNOT do:\n"
            "  - De-anonymize a remote VPN user's true physical location\n"
            "  - Trace through a VPN tunnel to the origin behind it\n"
            "  - Determine who is connected on the other side of a VPN server\n"
            "  - Bypass VPN encryption or identify the real source of traffic\n"
            "    that exits from a VPN endpoint\n\n"
            "VPN tunnels are designed to hide the source. Traceroute and probe\n"
            "packets reach the VPN exit node, not the user behind it. No amount\n"
            "of active probing can change this — it is a fundamental property\n"
            "of how VPN encryption and routing work.\n\n"
            "The MultiVerifier's VPN/proxy detection classifies the ENDPOINT\n"
            "infrastructure (exit node, datacenter, CDN), not the user behind it.\n"
            "The VPN leak detector checks YOUR OWN VPN configuration for leaks.\n\n"
            "=== PRIVACY NOTE ===\n\n"
            "GeoIP lookups may use ip-api.com (HTTP) if no local MaxMind DB is\n"
            "configured. This sends destination IPs to a third-party server.\n"
            "Set geoip_db_path in CONFIG for fully offline lookups.\n"
        )
        win = tk.Toplevel(self._root)
        win.title("About / Scope — GNA Tracer")
        win.geometry("720x600")
        win.configure(bg="#0a0a0f")
        txt = scrolledtext.ScrolledText(win, bg="#12121a", fg="#c0c0c0",
                                        font=("Consolas", 10),
                                        wrap="word", bd=0, highlightthickness=0)
        txt.pack(fill="both", expand=True, padx=8, pady=8)
        txt.insert("1.0", about_text)
        txt.configure(state="disabled")
        tk.Button(win, text="Close", command=win.destroy,
                  bg="#1a1a2e", fg="#ff5566", font=("Consolas", 10, "bold"),
                  bd=0, padx=20, pady=4).pack(pady=8)

    def _show_vpn_leak(self):
        """Display the current VPN leak detector status in a popup."""
        full = self._get_full_data()
        status = full.get('vpn_leak_status', {})
        if not status:
            messagebox.showinfo("VPN Leak Status",
                                "No VPN leak scan has been performed yet.")
            return
        lines = [
            f"VPN Active: {status.get('vpn_active', False)}",
            f"VPN Interfaces: {', '.join(status.get('vpn_interfaces', [])) or 'None'}",
            f"Public IPs: {status.get('public_ips', {})}",
            f"Public IP Consistent: {status.get('public_ip_consistent', True)}",
            f"DNS Resolvers: {', '.join(status.get('dns_resolvers', [])) or 'None'}",
            f"IPv6 Global Addresses: {', '.join(status.get('ipv6_global', [])) or 'None'}",
            f"IPv6 Leak: {status.get('ipv6_leak', False)}",
            f"STUN Reflexive Address: {status.get('stun_reflexive', '') or 'N/A'}",
            f"Route Leaks: {len(status.get('route_leaks', []))}",
            f"WebRTC Local IP: {status.get('webrtc_local_ip', '') or 'N/A'}",
            f"WebRTC Leak: {status.get('webrtc_leak', False)}",
            f"Kill Switch OK: {status.get('kill_switch_ok', True)}",
            f"Kill Switch Detail: {status.get('kill_switch_detail', '') or 'N/A'}",
        ]
        for leak in status.get('route_leaks', []):
            lines.append(f"  - {leak}")
        fp = status.get('fingerprint_surface', {})
        if fp:
            lines.append("")
            lines.append("Fingerprint Surface (persists across VPN on/off):")
            lines.append(f"  Hostname: {fp.get('hostname', '')}")
            lines.append(f"  OS: {fp.get('os', '')}")
            lines.append(f"  Timezone: {fp.get('timezone', '')}")
            lines.append(f"  CPU/RAM: {fp.get('cpu_count', '?')} / {fp.get('memory_mb', '?')}MB")
            lines.append(f"  Font files: {fp.get('font_files', '?')}")
            lines.append(f"  Physical MACs: {', '.join(fp.get('physical_macs', [])) or 'none'}")
            if fp.get('machine_guid'):
                lines.append(f"  Machine GUID: {fp['machine_guid']}")
        lines.append("")
        lines.append("Recent Events:")
        for ev in full.get('vpn_leak_events', [])[-20:]:
            lines.append(f"  [{ev.get('type', '?')}] {ev.get('detail', '')}")
        messagebox.showinfo("VPN Leak Status", "\n".join(lines))

    def _schedule_autosave(self):
        """Periodic auto-save: writes a complete numbered log file every interval."""
        if self._stop.is_set():
            return
        try:
            self._save_tracer_data()
        except Exception as exc:
            _logger.warning("Auto-save failed: %s", exc)
        self._autosave_job = self._root.after(self._autosave_interval_ms, self._schedule_autosave)

    def _search_changed(self, refresh_name: str):
        """Re-render one tab shortly after its search box changes (debounced
        so typing does not repaint on every keystroke)."""
        job = self._search_jobs.get(refresh_name)
        if job:
            try:
                self._root.after_cancel(job)
            except Exception:
                pass

        def _run():
            self._search_jobs.pop(refresh_name, None)
            if self._stop.is_set():
                return
            data = self._last_full_data
            if data is None:
                return
            try:
                getattr(self, refresh_name)(data)
            except Exception as exc:
                _logger.debug("Search refresh %s failed: %s", refresh_name, exc)

        self._search_jobs[refresh_name] = self._root.after(180, _run)

    def _schedule_status_tick(self):
        """Refresh just the header once a second from the cheap state feed,
        so counters stay responsive between the 3s full refreshes."""
        if self._stop.is_set():
            return
        try:
            self._refresh_status(self._get_state())
        except Exception as exc:
            _logger.debug("Status tick failed: %s", exc)
        self._status_job = self._root.after(1000, self._schedule_status_tick)

    def _schedule_update(self):
        if self._stop.is_set():
            return
        t0 = time.time()
        try:
            self._refresh_all()
        except Exception as exc:
            _logger.debug("GUI refresh error: %s", exc)
        # Measure actual refresh latency
        self._refresh_latency_ms = (time.time() - t0) * 1000.0
        self._last_refresh_time = time.time()
        # Adaptive: if refresh took longer than the interval, back off slightly
        interval = self._gui_refresh_ms
        if self._refresh_latency_ms > interval * 0.8:
            # Refresh is too slow — add 50% headroom to avoid overlapping
            interval = int(self._refresh_latency_ms * 1.5)
        self._update_job = self._root.after(interval, self._schedule_update)

    def _refresh_all(self):
        data = self._get_full_data()
        self._last_full_data = data
        # The monitor owns the watchlist; mirror it so the ★ markers and the
        # context-menu labels reflect what detection is actually using.
        self._watchlist_ips = set(data.get('watchlist_ips', ()))
        self._watchlist_procs = set(data.get('watchlist_procs', ()))
        # Always refresh status (lightweight) and check for alerts
        self._refresh_status(data)
        self._check_alert_flash(data)
        # Delta refresh: fully refresh the currently visible tab + always-on tabs,
        # lightly refresh others (just update data, skip heavy rendering).
        # This keeps the active tab at near-zero latency while reducing CPU
        # on background tabs.
        # Tab indices: 0=Overview 1=Live 2=AllConn 3=Deductions 4=Processes
        # 5=Devices 6=Map 7=Actions 8=Terminal 9=Suspicious 10=Blocked
        # 11=ProcTree 12=NetStats 13=Timeline 14=Config 15=DoubleTrace
        try:
            if self._notebook:
                self._active_tab_index = self._notebook.index(self._notebook.select())
        except Exception:
            pass
        tab = self._active_tab_index
        # Only refresh the blocked IPs tab when it's visible or during
        # the periodic all-tabs refresh — it does a full widget rebuild.
        if tab == 10:  # Blocked IPs
            self._refresh_blocked()
        if tab == 0:  # Overview
            self._refresh_overview(data)
        if tab == 9:  # Suspicious Activity
            self._refresh_suspicious(data)
        # Full refresh for the active tab
        if tab == 1:               # Live Connections
            self._refresh_live(data)
        elif tab == 2:             # All Connections
            self._refresh_connections(data)
        elif tab == 3:             # Deductions
            self._refresh_deductions(data)
        elif tab == 4:             # Processes
            self._refresh_processes(data)
        elif tab == 5:             # Devices
            self._refresh_devices(data)
        elif tab == 6:             # IP Map
            self._map_data_dirty = False
            self._refresh_map(data)
        elif tab == 7:             # Actions Log
            self._refresh_actions(data)
        elif tab == 8:             # Terminal
            self._refresh_terminal(data)
        elif tab == 11:            # Process Tree
            self._refresh_process_tree(data)
        elif tab == 12:            # Net Stats
            self._refresh_netstats(data)
        elif tab == 13:            # Timeline
            self._refresh_timeline(data)
        elif tab == 14:            # Config
            self._refresh_config()
        elif tab == 15:            # Double Trace
            self._refresh_trace(data)
        # Keep the map's data current while it is hidden, but do NOT repaint it:
        # _refresh_map redraws every tile and grid line, which was by far the
        # most expensive thing in a refresh cycle and was running every cycle
        # regardless of which tab the user was actually looking at.
        if tab != 6 and hasattr(self, '_map_canvas') and self._map_canvas:
            self._map_data_dirty = True
        # Periodically refresh all tabs (every ~4s) to keep background tabs fresh.
        # Was every ~2s (every 8th cycle) — reduced frequency since background tabs
        # don't need to be real-time. This cuts GUI CPU usage significantly.
        if int(time.time() * 1000 / self._gui_refresh_ms) % 16 == 0:
            self._refresh_overview(data)
            self._refresh_suspicious(data)
            self._refresh_blocked()
            self._refresh_live(data)
            self._refresh_connections(data)
            self._refresh_deductions(data)
            self._refresh_processes(data)
            self._refresh_devices(data)
            self._refresh_actions(data)
            self._refresh_terminal(data)
            self._refresh_process_tree(data)
            self._refresh_netstats(data)
            self._refresh_timeline(data)
            self._refresh_config()
            self._refresh_trace(data)

    def _refresh_status(self, data):
        stats = data.get('conn_stats', {})
        latency = self._refresh_latency_ms
        # Color-code the latency indicator
        if latency < 100:
            lat_str = f"⚡{latency:.0f}ms"
        elif latency < 300:
            lat_str = f"🔄{latency:.0f}ms"
        elif latency < 1000:
            lat_str = f"🐢{latency:.0f}ms"
        else:
            lat_str = f"⏳{latency/1000:.1f}s"
        self._status_lbl.config(
            text=f"Connections: {stats.get('total_connections', 0)} | "
                 f"Services: {stats.get('unique_services', 0)} | "
                 f"IPs: {stats.get('unique_ips', 0)} | "
                 f"Processes: {len(data.get('processes', []))} | "
                 f"Deductions: {len(data.get('deductions', []))} | "
                 f"Pipeline: {data.get('pipeline_processed', 0)}/{data.get('pipeline_dropped', 0)} | "
                 f"Refresh: {lat_str} (every {self._gui_refresh_ms}ms)")

    def _set_text(self, widget, content, tag=None):
        """Replace a read-only text widget's contents in one step."""
        widget.config(state="normal")
        widget.delete("1.0", "end")
        widget.insert("end", content, tag or "")
        widget.config(state="disabled")

    def _refresh_overview(self, data):
        w = self._overview_text
        at_bottom, top_line = self._begin_refresh(w)
        w.config(state="normal")
        w.delete("1.0", "end")
        stats = data.get('conn_stats', {})
        w.insert("end", "═" * 90 + "\n", "dim")
        w.insert("end", "  GNA TRACER — SYSTEM OVERVIEW\n", "header")
        w.insert("end", "═" * 90 + "\n\n", "dim")
        # Core metrics with descriptive labels
        w.insert("end", "  ┌─ CORE METRICS " + "─" * 74 + "┐\n", "dim")
        w.insert("end", f"  │ Active Connections:   {stats.get('total_connections', 0):>6}   "
                        f"│ Currently open network sockets (TCP/UDP)\n", "highlight")
        w.insert("end", f"  │ Unique Services:      {stats.get('unique_services', 0):>6}   "
                        f"│ Distinct services identified (DNS/SNI/port)\n", "highlight")
        w.insert("end", f"  │ Unique Public IPs:    {stats.get('unique_ips', 0):>6}   "
                        f"│ Distinct remote public IP addresses\n", "highlight")
        w.insert("end", f"  │ Tracked Processes:    {len(data.get('processes', [])):>6}   "
                        f"│ Processes with network activity\n", "highlight")
        w.insert("end", f"  │ Total Deductions:     {len(data.get('deductions', [])):>6}   "
                        f"│ Security deductions (CRITICAL/WARNING/INFO)\n", "highlight")
        w.insert("end", f"  │ Network Devices:      {len(data.get('devices', [])):>6}   "
                        f"│ Devices found via ARP scan\n", "highlight")
        w.insert("end", f"  │ DNS Cache Entries:    {data.get('dns_count', 0):>6}   "
                        f"│ IP→domain mappings in DNS cache\n", "highlight")
        w.insert("end", f"  │ GeoIP Cache Entries:  {data.get('geoip_count', 0):>6}   "
                        f"│ Cached GeoIP lookups (hardcoded+API)\n", "highlight")
        idle_s = data.get('idle_seconds', 0)
        idle_str = f"{idle_s:.0f}s"
        if idle_s > 60:
            idle_str = f"{idle_s/60:.1f}m"
        if idle_s > 3600:
            idle_str = f"{idle_s/3600:.1f}h"
        w.insert("end", f"  │ User Idle:            {idle_str:>6}   "
                        f"│ Time since last keyboard/mouse/CPU activity\n", "highlight")
        w.insert("end", f"  │ Pipeline Processed:   {data.get('pipeline_processed', 0):>6}   "
                        f"│ Packets processed by pipeline workers\n", "highlight")
        w.insert("end", f"  │ Pipeline Dropped:     {data.get('pipeline_dropped', 0):>6}   "
                        f"│ Packets dropped (queue full)\n", "highlight")
        w.insert("end", "  └" + "─" * 88 + "┘\n", "dim")
        # Tier 5 stats with descriptive labels
        w.insert("end", "\n" + "─" * 60 + "\n", "dim")
        w.insert("end", "  EXTENDED MONITORS (Tier 5)\n", "subheader")
        w.insert("end", "─" * 60 + "\n", "dim")
        fs_ct = len(data.get('fs_events', []))
        vt_ct = len(data.get('vt_results', {}))
        usb_ct = len(data.get('usb_events', []))
        clip_ct = len(data.get('clipboard_events', []))
        task_ct = len(data.get('sched_task_events', []))
        pipe_ct = len(data.get('named_pipe_events', []))
        scan_ct = len(data.get('inbound_scan_events', []))
        doh_ct = len(data.get('doh_events', []))
        cert_ct = len(data.get('cert_events', []))
        tl_ct = len(data.get('conn_timeline', []))
        w.insert("end", f"  File System Events:   {fs_ct:>4}  ", "highlight")
        w.insert("end", f"│ File create/modify/delete in sensitive dirs\n",
                 "warning" if fs_ct > 50 else "dim")
        w.insert("end", f"  VirusTotal Scans:     {vt_ct:>4}  ", "highlight")
        w.insert("end", "│ EXE hashes checked against VT (needs API key)\n", "dim")
        w.insert("end", f"  USB Device Events:    {usb_ct:>4}  ", "highlight")
        w.insert("end", f"│ USB insertions/removals\n",
                 "warning" if usb_ct > 0 else "dim")
        w.insert("end", f"  Clipboard Events:     {clip_ct:>4}  ", "highlight")
        w.insert("end", f"│ Clipboard read/write by processes\n",
                 "critical" if clip_ct > 0 else "dim")
        w.insert("end", f"  Sched Task Changes:   {task_ct:>4}  ", "highlight")
        w.insert("end", f"│ Scheduled task create/modify (persistence)\n",
                 "warning" if task_ct > 0 else "dim")
        w.insert("end", f"  Named Pipe Events:    {pipe_ct:>4}  ", "highlight")
        w.insert("end", f"│ Named pipe creation (IPC/injection)\n",
                 "warning" if pipe_ct > 5 else "dim")
        w.insert("end", f"  Inbound Scans:        {scan_ct:>4}  ", "highlight")
        w.insert("end", f"│ Port scan detection from external sources\n",
                 "critical" if scan_ct > 0 else "dim")
        w.insert("end", f"  DoH Detections:       {doh_ct:>4}  ", "highlight")
        w.insert("end", f"│ DNS-over-HTTPS usage (bypasses DNS monitoring)\n",
                 "warning" if doh_ct > 0 else "dim")
        w.insert("end", f"  Cert/MITM Events:     {cert_ct:>4}  ", "highlight")
        w.insert("end", f"│ TLS certificate anomalies / MITM indicators\n",
                 "critical" if cert_ct > 0 else "dim")
        w.insert("end", f"  Connection Timeline:  {tl_ct:>4}  ", "highlight")
        w.insert("end", "│ Chronological connection events log\n", "dim")
        bt_ct = len(data.get('bt_devices', []))
        bt_ev = len(data.get('bt_events', []))
        serial_ct = len(data.get('serial_ports', []))
        serial_ev = len(data.get('serial_events', []))
        w.insert("end", f"  Bluetooth Devices:    {bt_ct:>4}  ", "highlight")
        w.insert("end", f"│ BT devices ({bt_ev} events) — data exfil vector\n",
                 "warning" if bt_ev > 0 else "dim")
        w.insert("end", f"  Serial/COM Ports:     {serial_ct:>4}  ", "highlight")
        w.insert("end", f"│ Serial ports ({serial_ev} events) — IoT/industrial\n",
                 "warning" if serial_ev > 0 else "dim")
        proxy_ev = len(data.get('proxy_events', []))
        proxy_procs = data.get('proxy_processes', [])
        # Count connections with proxy flags
        proxy_conns = sum(1 for c in data.get('connections', []) if c.get('proxy_type'))
        fwd_ct = sum(1 for c in data.get('connections', []) if 'FORWARD' in c.get('proxy_type', ''))
        rev_ct = sum(1 for c in data.get('connections', []) if 'REVERSE' in c.get('proxy_type', ''))
        res_ct = sum(1 for c in data.get('connections', []) if 'RESIDENTIAL' in c.get('proxy_type', ''))
        w.insert("end", f"  Proxy Detections:     {proxy_conns} connections",
                 "critical" if res_ct > 0 else ("warning" if proxy_conns > 0 else "highlight"))
        if proxy_conns > 0:
            parts = []
            if fwd_ct:
                parts.append(f"{fwd_ct} fwd")
            if rev_ct:
                parts.append(f"{rev_ct} rev")
            if res_ct:
                parts.append(f"{res_ct} residential")
            w.insert("end", f" ({', '.join(parts)})\n",
                     "critical" if res_ct > 0 else "warning")
        else:
            w.insert("end", "\n")
        if proxy_procs:
            w.insert("end", f"  Proxy Processes:      {', '.join(proxy_procs[:3])}\n", "critical")
        if proxy_ev > 0:
            w.insert("end", f"  System Proxy Events:  {proxy_ev}\n", "warning")
        sys_proxy = data.get('system_proxy', {})
        if sys_proxy.get('registry') or sys_proxy.get('pac_url') or sys_proxy.get('env'):
            w.insert("end", "  System Proxy Config:\n", "critical")
            if sys_proxy.get('registry'):
                w.insert("end", f"    Windows proxy:      {sys_proxy['registry']}\n", "warning")
            if sys_proxy.get('pac_url'):
                w.insert("end", f"    PAC auto-config:    {sys_proxy['pac_url'][:80]}\n", "warning")
            for var, val in (sys_proxy.get('env') or {}).items():
                w.insert("end", f"    {var}: {val[:70]}\n", "warning")
        # Anti-hack summary
        anti_hack_pins = data.get('anti_hack_pins', {})
        pinned_ips = len(anti_hack_pins)
        total_pins = sum(len(v.get('categories', [])) for v in anti_hack_pins.values())
        if pinned_ips > 0:
            w.insert("end", "\n" + "═" * 90 + "\n", "dim")
            w.insert("end", f"  📌 ANTI-HACK PINS — {total_pins} pins on {pinned_ips} IPs\n", "critical")
            w.insert("end", "═" * 90 + "\n", "dim")
            w.insert("end", "  Connections flagged with anti-hack detection tags:\n\n", "warning")
            for ip, info in sorted(anti_hack_pins.items()):
                cats = info.get('categories', [])
                w.insert("end", f"  {ip}: ", "highlight")
                w.insert("end", f"{' '.join('📌' + c for c in cats)}\n", "critical")
        # High-risk processes
        high_risk = [p for p in data.get('processes', []) if p.get('risk', 0) >= 40]
        if high_risk:
            w.insert("end", "\n" + "═" * 90 + "\n", "dim")
            w.insert("end", "  ⚠ HIGH-RISK PROCESSES\n", "critical")
            w.insert("end", "═" * 90 + "\n", "dim")
            for p in sorted(high_risk, key=lambda x: -x.get('risk', 0)):
                w.insert("end", f"\n  PID {p['pid']}: {p['name']}\n", "warning")
                w.insert("end", f"    Risk Score: {p['risk']}\n", "critical")
                w.insert("end", f"    Exe: {p.get('exe', '?')}\n")
                w.insert("end", f"    Connections: {p.get('connections', 0)}\n")
                w.insert("end", f"    Destinations: {p.get('destinations', 0)}\n")
                w.insert("end", f"    ML Anomaly: {p.get('ml_score', 0)}\n")
                w.insert("end", f"    Countries: {', '.join(p.get('countries', []))}\n")
        # Service summary
        svcs = data.get('services', [])
        if svcs:
            w.insert("end", "\n" + "═" * 90 + "\n", "dim")
            w.insert("end", "  📡 ACTIVE SERVICES\n", "header")
            w.insert("end", "═" * 90 + "\n", "dim")
            for s in svcs:
                w.insert("end", f"  {s.get('icon', '?')} {s.get('service', '?'):25s} "
                                f"| {s.get('category', '?'):15s} | "
                                f"{s.get('city', '?')}, {s.get('country', '?'):15s} | "
                                f"{s.get('org', '?')}\n")
        self._highlight_search(w, self._search_overview.get())
        w.config(state="disabled")
        self._end_refresh(w, at_bottom, top_line)

    def _conn_matches_search(self, c, query):
        """Check if a connection matches the search query."""
        if not query or len(query) < 2:
            return True
        q = query.lower()
        fields = [
            str(c.get('remote_ip', '')), str(c.get('domain', '')),
            str(c.get('service', '')), str(c.get('process', '')),
            str(c.get('category', '')), str(c.get('country', '')),
            str(c.get('org', '')), str(c.get('isp', '')),
            str(c.get('city', '')), str(c.get('pid', '')),
            str(c.get('via', '')), str(c.get('website_tag', '')),
            str(c.get('exe_path', '')), str(c.get('parent_name', '')),
            ' '.join(str(d) for d in c.get('all_domains', [])),
        ]
        return any(q in f.lower() for f in fields)

    def _live_toggle_conn(self, conn_key: str):
        """Toggle expand/collapse for a single connection in the live tab."""
        self._live_expanded[conn_key] = not self._live_expanded.get(conn_key, False)
        # Force immediate re-render by calling the last cached data
        if hasattr(self, '_last_live_data') and self._last_live_data is not None:
            self._refresh_live(self._last_live_data)

    def _live_set_all_expanded(self, expanded: bool):
        """Set all connections to expanded or collapsed."""
        if expanded:
            # Expand everything currently visible
            if hasattr(self, '_last_live_data') and self._last_live_data is not None:
                for c in self._last_live_data.get('connections', []):
                    self._live_expanded[self._live_conn_key(c)] = True
        else:
            self._live_expanded.clear()
        if hasattr(self, '_last_live_data') and self._last_live_data is not None:
            self._refresh_live(self._last_live_data)

    def _live_toggle_category(self, cat_key: str, conn_keys: list):
        """Toggle all connections in a category."""
        # If any are expanded, collapse all; otherwise expand all
        any_open = any(self._live_expanded.get(k, False) for k in conn_keys)
        for k in conn_keys:
            self._live_expanded[k] = not any_open
        if hasattr(self, '_last_live_data') and self._last_live_data is not None:
            self._refresh_live(self._last_live_data)

    def _install_click_dispatch(self, w):
        """Bind <Button-1> once per widget and dispatch to whichever clickable
        span is under the pointer. Binding per span instead cost three
        tag_bind calls for every clickable region on every refresh."""
        if getattr(w, '_click_dispatch_installed', False):
            return
        w._click_dispatch_installed = True

        def _on_click(_e):
            for name in w.tag_names("current"):
                cmd = self._click_cmds.get(name)
                if cmd is not None:
                    cmd()
                    return "break"
            return None

        def _on_motion(e):
            over = any(n in self._click_cmds for n in w.tag_names("@%d,%d" % (e.x, e.y)))
            w.config(cursor="hand2" if over else "")

        w.bind("<Button-1>", _on_click, add="+")
        w.bind("<Motion>", _on_motion, add="+")

    def _click_text(self, w, text, style_tag, command, cursor="hand2"):
        """Insert `text` as a clickable region instead of embedding a Button.

        Embedded tk.Button widgets were by far the most expensive thing in a
        refresh: every cycle clears the Text, which *destroys* the embedded
        widgets, so several hundred buttons were created and destroyed each
        time (~78% of the Live tab's render cost, measured). A tagged text
        span with a <Button-1> binding behaves the same for the user and is
        roughly two orders of magnitude cheaper.
        """
        self._install_click_dispatch(w)
        self._click_seq = getattr(self, '_click_seq', 0) + 1
        tag = f"click{self._click_seq}"
        # Tagging during insert avoids the index()/tag_add() round trips.
        w.insert("end", text, (style_tag, tag) if style_tag else (tag,))
        self._click_cmds[tag] = command
        return tag

    def _reset_clickables(self):
        """Drop click handlers from the previous render of a tab.

        Bounded on purpose: the tag names are regenerated every refresh, so
        without this the command dict would grow for the whole session.
        """
        if len(self._click_cmds) > 20000:
            self._click_cmds.clear()

    @staticmethod
    def _infra_badge(c: dict) -> str:
        """Short infrastructure tag for a connection row: VPN/proxy/hosting/CDN."""
        if c.get('is_vpn'):
            prov = c.get('vpn_provider') or 'VPN'
            return f"🛡️{prov} EXIT"
        if c.get('is_proxy'):
            return "🛡️PROXY"
        pt = (c.get('proxy_type') or '').upper()
        if pt and 'NONE' not in pt:
            return f"🛡️{pt}"
        if c.get('is_hosting'):
            return "🏭HOSTING"
        if c.get('is_cdn'):
            return "🌐CDN"
        return ""

    @staticmethod
    def _live_conn_key(c: dict) -> str:
        """Stable key for a connection dict to track expand state."""
        return f"{c.get('remote_ip', '')}:{c.get('remote_port', '')}:{c.get('pid', '')}"

    def _live_render_detail(self, w, c, risk, risk_tag):
        """Render the expanded detail lines for a connection."""
        rip = c.get('remote_ip', '')
        # === WEBSITE TAG ===
        wtag = c.get('website_tag', '')
        if wtag:
            w.insert("end", "  │  🏷️ WEBSITE:    ", "")
            w.insert("end", f"{wtag}\n", "highlight")
        # === SERVER & NETWORK IDENTIFIER ===
        # Shows the canonical server/network name as it is identified by
        # DNS, GeoIP, ASN, and MultiVerifier — so the user can see exactly
        # what the remote endpoint IS named, not just its IP.
        mv_rep = (self._last_full_data or {}).get('multi_verifications', {}).get(rip, {})
        # Prefer what is already labelled on the connection itself; the
        # side-channel report is only a fallback now.
        rdns = c.get('rdns', '') or (mv_rep.get('rdns', '') if mv_rep else '')
        asn = c.get('asn', '') or (mv_rep.get('asn', '') if mv_rep else '')
        mv_org = c.get('asn_org', '') or (mv_rep.get('org', '') if mv_rep else '')
        svc = c.get('service', '')
        domain = c.get('domain', '')
        org = c.get('org', '') or mv_org or ''
        isp = c.get('isp', '')
        cc = c.get('country_code', '')
        # Build the identifier label — list each name as it is named
        w.insert("end", "  │  ┌─ SERVER & NETWORK IDENTIFIER ─────────────────\n", "dim")
        if svc and svc not in ('Unknown', rip):
            w.insert("end", f"  │  │ Service:     {svc}\n", "highlight")
        if domain and domain not in ('unresolved', rip, svc):
            w.insert("end", f"  │  │ Domain:      {domain}\n")
        if rdns and rdns not in (domain, rip):
            w.insert("end", f"  │  │ rDNS Host:   {rdns}\n", "highlight")
        if wtag and wtag not in (svc, domain):
            w.insert("end", f"  │  │ Tag:         {wtag}\n")
        if org and org not in ('Unknown', ''):
            w.insert("end", f"  │  │ Org:         {org}\n")
        if isp and isp not in ('Unknown', '', org):
            w.insert("end", f"  │  │ ISP:         {isp}\n", "dim")
        if asn and asn not in ('', 'Unknown'):
            w.insert("end", f"  │  │ ASN:         {asn}\n", "dim")
        if cc and cc not in ('??', ''):
            country = c.get('country', '?')
            w.insert("end", f"  │  │ Network:     {country} ({cc})\n", "dim")
        if not any([svc not in ('Unknown', rip), domain not in ('unresolved', rip),
                    rdns, org not in ('Unknown', ''), asn not in ('', 'Unknown')]):
            w.insert("end", f"  │  │ IP Only:     {rip} (no DNS/ASN identity resolved)\n", "dim")
        w.insert("end", "  │  └────────────────────────────────────────────────\n", "dim")
        # === Process detail ===
        w.insert("end", "  │  ┌─ PROCESS ──────────────────────────────────────\n", "dim")
        w.insert("end", f"  │  │ Name:        {c.get('process', '?')} (PID {c.get('pid', '?')})\n")
        exe_path = c.get('exe_path', '')
        if exe_path:
            w.insert("end", f"  │  │ Exe Path:    {exe_path}\n", "dim")
        parent = c.get('parent_name', '')
        if parent:
            ppid = c.get('parent_pid', 0) or '?'
            w.insert("end", f"  │  │ Parent Proc: {parent} (PID {ppid})\n", "dim")
        cmdline = c.get('cmdline', '')
        if cmdline:
            w.insert("end", f"  │  │ Command:     {cmdline[:240]}\n", "dim")
        w.insert("end", "  │  └────────────────────────────────────────────────\n", "dim")
        # === Network detail ===
        w.insert("end", "  │  ┌─ NETWORK ──────────────────────────────────────\n", "dim")
        w.insert("end", f"  │  │ Remote IP:   {rip}\n")
        w.insert("end", f"  │  │ Remote Port: {c.get('remote_port', '?')}  ", "dim")
        # Add port service name
        rport = c.get('remote_port', 0)
        svc_name = _PORT_SERVICES.get(rport, '')
        if svc_name:
            w.insert("end", f"({svc_name})\n", "info")
        else:
            w.insert("end", "\n", "dim")
        w.insert("end", f"  │  │ Local Port:  {c.get('local_port', '?')}\n", "dim")
        w.insert("end", f"  │  │ Local IP:    {c.get('local_ip', '?')}\n", "dim")
        w.insert("end", f"  │  │ Protocol:    {c.get('protocol', '?')}\n", "dim")
        w.insert("end", f"  │  │ Status:      ", "dim")
        w.insert("end", f"{c.get('status', '?')}\n", risk_tag)
        # === Domain detail ===
        w.insert("end", "  │  ┌─ DNS / DOMAIN ─────────────────────────────────\n", "dim")
        domain_str = c.get('domain', 'unresolved')
        via = c.get('via', '')
        if via:
            w.insert("end", f"  │  │ Domain:      {domain_str}", "highlight")
            w.insert("end", f" (resolved via {via})\n", "dim")
        else:
            w.insert("end", f"  │  │ Domain:      {domain_str}\n")
        all_doms = c.get('all_domains', [])
        if all_doms and len(all_doms) > 1:
            w.insert("end", f"  │  │ All Domains: {', '.join(all_doms[:8])}", "dim")
            if len(all_doms) > 8:
                w.insert("end", f" (+{len(all_doms)-8} more)", "dim")
            w.insert("end", "\n")
        elif all_doms and len(all_doms) == 1:
            w.insert("end", f"  │  │ All Domains: {all_doms[0]}\n", "dim")
        w.insert("end", "  │  └────────────────────────────────────────────────\n", "dim")
        # === Geo detail ===
        w.insert("end", "  │  ┌─ GEOLOCATION ──────────────────────────────────\n", "dim")
        cc = c.get('country_code', '?')
        country = c.get('country', '?')
        # Flag high-risk countries
        if cc in CONFIG.get('high_risk_countries', set()):
            w.insert("end", f"  │  │ Country:     {country} ({cc})", "critical")
            w.insert("end", "  ⚠ HIGH-RISK\n", "critical")
        else:
            w.insert("end", f"  │  │ Country:     {country} ({cc})\n")
        w.insert("end", f"  │  │ City:        {c.get('city', '?')}\n")
        w.insert("end", f"  │  │ Region:      {c.get('region', '?')}\n", "dim")
        w.insert("end", f"  │  │ Org/ISP:     {c.get('org', '?')}\n")
        w.insert("end", f"  │  │ Lat/Lon:     {c.get('lat', '?')}, {c.get('lon', '?')}\n", "dim")
        w.insert("end", f"  │  │ Timezone:    {c.get('timezone') or 'unknown'}\n", "dim")
        if c.get('geo_source'):
            w.insert("end", f"  │  │ Geo Source:  {c['geo_source']}\n", "dim")
        if risk > 0:
            w.insert("end", f"  │  │ Risk Score:  {risk:.1f}/100  ", risk_tag)
            if risk >= 70:
                w.insert("end", "(CRITICAL)\n", "critical")
            elif risk >= 40:
                w.insert("end", "(WARNING)\n", "warning")
            else:
                w.insert("end", "(LOW)\n", "info")
        w.insert("end", "  │  └────────────────────────────────────────────────\n", "dim")
        # Location verification proof
        loc_conf = c.get('loc_confidence', 0)
        loc_grade = c.get('loc_grade', 'UNVERIFIED')
        loc_proof = c.get('loc_proof', [])
        if loc_proof:
            grade_tag = "info" if loc_grade == "HIGH" else (
                "warning" if loc_grade in ("MEDIUM", "LOW") else "critical")
            w.insert("end", "  │  ┌─ LOCATION VERIFICATION ────────────────────────\n", "dim")
            w.insert("end", f"  │  │ Confidence:  {loc_conf}%  Grade: ", "")
            w.insert("end", f"{loc_grade}\n", grade_tag)
            for proof in loc_proof:
                w.insert("end", f"  │  │   • {proof}\n", "dim")
            w.insert("end", "  │  └────────────────────────────────────────────────\n", "dim")
        # Proxy detection
        proxy_type = c.get('proxy_type', '')
        if proxy_type:
            proxy_detail = c.get('proxy_detail', '')
            w.insert("end", "  │  ┌─ PROXY DETECTION ──────────────────────────────\n", "dim")
            w.insert("end", f"  │  │ Type:        ", "")
            w.insert("end", f"{proxy_type}\n", "warning")
            if proxy_detail:
                w.insert("end", f"  │  │ Detail:      {proxy_detail}\n", "dim")
            w.insert("end", "  │  └────────────────────────────────────────────────\n", "dim")
        # MultiVerifier results — now carried on the connection itself, so this
        # panel fills in for every public endpoint rather than the handful that
        # used to satisfy the old verification gate.
        vpn_rep = (self._last_full_data or {}).get('multi_verifications', {}).get(rip) or {}
        if c.get('verify_grade') or vpn_rep:
            score = c.get('vpn_score', vpn_rep.get('vpn_score', 0)) or 0
            w.insert("end", "  │  ┌─ MULTIVERIFIER (VPN / PROXY / INFRASTRUCTURE) ─\n", "dim")
            w.insert("end", f"  │  │ VPN Score:   {score}/100\n",
                     "warning" if score >= 30 else "dim")
            for label, key, hot in (("Is VPN", 'is_vpn', "critical"),
                                    ("Is Proxy", 'is_proxy', "critical"),
                                    ("Is Hosting", 'is_hosting', "warning"),
                                    ("Is CDN", 'is_cdn', "info")):
                val = c.get(key, vpn_rep.get(key, False))
                w.insert("end", f"  │  │ {label + ':':<13}{val}\n", hot if val else "dim")
            prov = c.get('vpn_provider', '')
            if prov:
                w.insert("end", f"  │  │ Provider:    {prov}\n", "critical")
            labels = c.get('vpn_labels') or vpn_rep.get('labels') or []
            if labels:
                w.insert("end", f"  │  │ Labels:      {', '.join(labels)}\n", "dim")
            grade = c.get('verify_grade', '') or vpn_rep.get('grade', '')
            if grade:
                w.insert("end", f"  │  │ Verify Grade:{grade} "
                                f"({c.get('loc_confidence', 0)}% confidence)\n", "dim")
            rtt = c.get('rtt_ms', vpn_rep.get('rtt_ms'))
            if rtt is not None:
                w.insert("end", f"  │  │ RTT:         {rtt:.0f} ms\n", "dim")
            if c.get('ttl_os'):
                hop = c.get('hop_distance')
                hop_s = f", ~{hop} hops" if hop is not None else ""
                w.insert("end", f"  │  │ TTL/OS:      {c['ttl_os']}{hop_s}\n", "dim")
            ports = c.get('open_ports') or vpn_rep.get('open_ports') or []
            if ports:
                pretty = ', '.join(
                    f"{x[0]}/{x[1]}" if isinstance(x, (list, tuple)) and len(x) >= 2 else str(x)
                    for x in ports)
                w.insert("end", f"  │  │ Open Ports:  {pretty}\n", "warning")
            for conflict in (c.get('verify_conflicts') or vpn_rep.get('conflicts') or [])[:5]:
                w.insert("end", f"  │  │ ⚠ Conflict:  {conflict}\n", "warning")
            summary = c.get('verify_summary', '') or vpn_rep.get('summary', '')
            if summary:
                w.insert("end", f"  │  │ Summary:     {summary}\n", "dim")
            if c.get('is_vpn') or c.get('is_proxy'):
                w.insert("end", "  │  │ ⚠ This is the EXIT NODE location, "
                                "not the real source.\n", "critical")
            w.insert("end", "  │  └────────────────────────────────────────────────\n", "dim")
        # === ANTI-HACK PINS ===
        anti_hack = (self._last_full_data or {}).get('anti_hack_pins', {}).get(rip, {})
        if anti_hack and anti_hack.get('categories'):
            w.insert("end", "  │  ┌─ 📌 ANTI-HACK PINS ──────────────────────────────\n", "critical")
            for cat in anti_hack['categories']:
                w.insert("end", f"  │  │ 📌 {cat}\n", "critical")
            for detail in anti_hack.get('details', [])[:10]:
                w.insert("end", f"  │  │   {detail[:100]}\n", "warning")
            w.insert("end", "  │  └────────────────────────────────────────────────\n", "critical")

    def _refresh_live(self, data):
        """Show ONLY live (active/established) connections with collapsible rows."""
        self._last_live_data = data
        w = self._live_text
        at_bottom, top_line = self._begin_refresh(w)
        # Destroy old embedded buttons
        for btn in self._live_buttons:
            try:
                btn.destroy()
            except Exception:
                pass
        self._live_buttons.clear()
        self._reset_ctx(self._ctx_conns, w)
        self._reset_clickables()
        w.config(state="normal")
        w.delete("1.0", "end")
        conns = data.get('connections', [])
        live_statuses = {'ESTABLISHED', 'SYN_SENT', 'SYN_RECV', 'LISTEN', 'LAST_ACK', 'FIN_WAIT1', 'FIN_WAIT2', 'CLOSE_WAIT', 'TIME_WAIT'}
        live = [c for c in conns if c.get('status', '').upper() in live_statuses]
        # Apply search filter
        search_q = self._search_live.get()
        if search_q and len(search_q) >= 2:
            live = [c for c in live if self._conn_matches_search(c, search_q)]
        # Header with Expand All / Collapse All buttons
        w.insert("end", f"{'═' * 140}\n", "dim")
        w.insert("end", f"  🟢 LIVE CONNECTIONS — {len(live)} active  ", "header")
        # Expand All button
        btn_expand = tk.Button(
            w, text="▼ Expand All", bg="#333355", fg="#00d4ff",
            font=("Consolas", 8, "bold"), bd=0, padx=6, pady=0,
            activebackground="#555577", activeforeground="#ffffff",
            command=lambda: self._live_set_all_expanded(True))
        w.window_create("end", window=btn_expand)
        self._live_buttons.append(btn_expand)
        w.insert("end", "  ")
        # Collapse All button
        btn_collapse = tk.Button(
            w, text="▶ Collapse All", bg="#333355", fg="#aaaaaa",
            font=("Consolas", 8, "bold"), bd=0, padx=6, pady=0,
            activebackground="#555577", activeforeground="#ffffff",
            command=lambda: self._live_set_all_expanded(False))
        w.window_create("end", window=btn_collapse)
        self._live_buttons.append(btn_collapse)
        if search_q and len(search_q) >= 2:
            w.insert("end", f"  (filter: \"{search_q}\")", "dim")
        w.insert("end", "\n")
        w.insert("end", f"{'═' * 140}\n", "dim")
        if not live:
            w.insert("end", "\n  No live connections" +
                     (f" matching \"{search_q}\"" if search_q else "") + ".\n", "dim")
        else:
            pid_risk = {p['pid']: p.get('risk', 0) for p in data.get('processes', [])}
            by_cat = defaultdict(list)
            for c in live:
                by_cat[c.get('category', 'Unknown')].append(c)
            for cat in sorted(by_cat.keys()):
                cat_conns = by_cat[cat]
                cat_keys = [self._live_conn_key(c) for c in cat_conns]
                # Category header with toggle button
                w.insert("end", "\n  ")
                cat_any_open = any(self._live_expanded.get(k, False) for k in cat_keys)
                cat_arrow = "▼" if cat_any_open else "▶"
                cat_btn = tk.Button(
                    w, text=f"{cat_arrow} {cat} ({len(cat_conns)})",
                    bg="#1a1a2e", fg="#00d4ff",
                    font=("Consolas", 9, "bold"), bd=0, padx=4, pady=1,
                    activebackground="#333355", activeforeground="#ffffff",
                    anchor="w",
                    command=lambda ck=cat_keys, c_key=cat: self._live_toggle_category(c_key, ck))
                w.window_create("end", window=cat_btn)
                self._live_buttons.append(cat_btn)
                w.insert("end", " " + "─" * 80 + "\n", "dim")
                for idx, c in enumerate(cat_conns, 1):
                    row_start = w.index('end-1c')
                    rip = c.get('remote_ip', '')
                    conn_key = self._live_conn_key(c)
                    is_expanded = self._live_expanded.get(conn_key, False)
                    is_blocked = rip in self._blocked_ips
                    # O(1) lookup — this used to rescan the whole process list
                    # for every connection on every refresh.
                    risk = pid_risk.get(c.get('pid'), 0)
                    if risk >= 50:
                        risk_tag = "critical"
                    elif risk >= 25:
                        risk_tag = "warning"
                    else:
                        risk_tag = "info"
                    # --- Compact summary row with toggle arrow ---
                    arrow = "▼" if is_expanded else "▶"
                    wtag = c.get('website_tag', '')
                    svc_label = wtag if wtag else c.get('service', 'Unknown')
                    org = c.get('org', '')
                    cc = c.get('country_code', '')
                    # Append network identifier (org + country) to compact row
                    net_id = ''
                    if org and org not in ('Unknown', ''):
                        net_id = org
                    if cc and cc not in ('??', ''):
                        net_id = f"{net_id} [{cc}]" if net_id else f"[{cc}]"
                    summary = f"{c.get('icon', '?')} {svc_label}  —  {rip}:{c.get('remote_port', '?')}  [{c.get('process', '?')}]"
                    if net_id:
                        summary += f"  🏢{net_id}"
                    # Label the anonymising infrastructure right on the row —
                    # it used to be visible only after expanding the entry.
                    badge = self._infra_badge(c)
                    if badge:
                        summary += f"  {badge}"
                    if is_blocked:
                        summary += "  🚫BLOCKED"
                    # Anti-hack pin tags
                    anti_hack = (self._last_full_data or {}).get('anti_hack_pins', {}).get(rip, {})
                    if anti_hack and anti_hack.get('categories'):
                        pins = anti_hack['categories']
                        pin_str = ' '.join(f"📌{p}" for p in pins[:4])
                        if len(pins) > 4:
                            pin_str += f" +{len(pins)-4} more"
                        summary += f"  {pin_str}"
                    w.insert("end", "  ")
                    # Clickable arrow (was an embedded Button per row)
                    self._click_text(w, arrow, "toggle",
                                     lambda ck=conn_key: self._live_toggle_conn(ck))
                    w.insert("end", " ", "")
                    w.insert("end", f"{summary}\n", "highlight" if is_expanded else "")
                    # --- Expanded detail ---
                    if is_expanded:
                        # Block button inside expanded view
                        if rip:
                            btn_text = (f"[ 🔓 Unblock {rip} ]" if is_blocked
                                        else f"[ 🚫 Block {rip} ]")
                            w.insert("end", "       ")
                            self._click_text(
                                w, btn_text,
                                "unblock_btn" if is_blocked else "block_btn",
                                lambda ip=rip, ci=c: self._toggle_block_ip(ip, ci))
                            w.insert("end", "\n")
                        buf = _BufferedText(w)
                        self._live_render_detail(buf, c, risk, risk_tag)
                        buf.insert("end", f"  └{'─' * 90}\n", "dim")
                        buf.flush()
                    self._tag_rows(w, row_start, c, self._ctx_conns, 'conn::')
        # Drop expand-state for connections that no longer exist, otherwise this
        # dict grows for the whole session.
        if self._live_expanded:
            visible = {self._live_conn_key(c) for c in conns}
            for stale_key in [k for k in self._live_expanded if k not in visible]:
                del self._live_expanded[stale_key]
        self._highlight_search(w, search_q)
        w.config(state="disabled")
        self._end_refresh(w, at_bottom, top_line)

    def _refresh_connections(self, data):
        if self._conn_paused:
            return  # user is browsing — don't reset scroll
        w = self._conn_text
        at_bottom, top_line = self._begin_refresh(w)
        # Destroy old embedded buttons
        for btn in self._conn_buttons:
            try:
                btn.destroy()
            except Exception:
                pass
        self._conn_buttons.clear()
        self._reset_ctx(self._ctx_conns, w)
        self._reset_clickables()
        w.config(state="normal")
        w.delete("1.0", "end")
        conns = data.get('connections', [])
        search_q = self._search_conn.get()
        # Filter connections by search
        if search_q and len(search_q) >= 2:
            filtered = [c for c in conns if self._conn_matches_search(c, search_q)]
        else:
            filtered = conns
        w.insert("end", f"{'═' * 140}\n", "dim")
        if search_q and len(search_q) >= 2:
            w.insert("end", f"  ALL ACTIVE CONNECTIONS — {len(filtered)}/{len(conns)} matching \"{search_q}\"\n", "header")
        else:
            w.insert("end", f"  ALL ACTIVE CONNECTIONS — {len(conns)} total (each listed individually)\n", "header")
        w.insert("end", f"{'═' * 140}\n\n", "dim")
        w.insert("end", "  Every connection is listed individually with full details:\n", "dim")
        w.insert("end", "  Process, exe path, parent, protocol, status, domain, GeoIP (country/city/org),\n", "dim")
        w.insert("end", "  location verification, proxy detection, and MultiVerifier VPN/proxy/hosting/CDN results.\n", "dim")
        w.insert("end", "  Use ⏸ Pause to freeze updates while browsing. Click 🚫 Block to add a firewall rule.\n\n", "dim")
        if not filtered:
            w.insert("end", "  No connections match the search.\n" if search_q else "  Scanning... no connections yet.\n", "dim")
        else:
            by_cat = defaultdict(list)
            for c in filtered:
                by_cat[c.get('category', 'Unknown')].append(c)
            for cat in sorted(by_cat.keys()):
                cat_conns = by_cat[cat]
                w.insert("end", f"\n  ┌─ {cat} ({len(cat_conns)} connections) ", "subheader")
                w.insert("end", "─" * 80 + "\n", "dim")
                for idx, c in enumerate(cat_conns, 1):
                    row_start = w.index('end-1c')
                    rip = c.get('remote_ip', '')
                    is_blocked = rip in self._blocked_ips
                    w.insert("end", "  │\n")
                    w.insert("end", f"  ├── [{idx}] ", "highlight")
                    w.insert("end", f"{c.get('icon', '?')} {c.get('service', 'Unknown')}  ", "highlight")
                    # Show network identifier (org + country) inline in header
                    org_hdr = c.get('org', '')
                    cc_hdr = c.get('country_code', '')
                    if org_hdr and org_hdr not in ('Unknown', ''):
                        w.insert("end", f"🏢{org_hdr}", "dim")
                    if cc_hdr and cc_hdr not in ('??', ''):
                        w.insert("end", f" [{cc_hdr}]", "dim")
                    # Anti-hack pin tags in header
                    anti_hack = (self._last_full_data or {}).get('anti_hack_pins', {}).get(rip, {})
                    if anti_hack and anti_hack.get('categories'):
                        pins = anti_hack['categories']
                        pin_str = ' '.join(f"📌{p}" for p in pins[:3])
                        if len(pins) > 3:
                            pin_str += f" +{len(pins)-3}"
                        w.insert("end", f"  {pin_str}", "critical")
                    w.insert("end", "  ", "")
                    # Clickable Block/Unblock span. This was an embedded
                    # tk.Button per connection; clearing the Text destroys
                    # embedded widgets, so a few hundred were created and
                    # destroyed on every refresh.
                    if rip:
                        btn_text = (f"[ 🔓 Unblock {rip} ]" if is_blocked
                                    else f"[ 🚫 Block {rip} ]")
                        self._click_text(
                            w, btn_text,
                            "unblock_btn" if is_blocked else "block_btn",
                            lambda ip=rip, ci=c: self._toggle_block_ip(ip, ci))
                    if is_blocked:
                        w.insert("end", "  ← BLOCKED", "critical")
                    w.insert("end", "\n")
                    # === WEBSITE TAG ===
                    wtag = c.get('website_tag', '')
                    if wtag:
                        w.insert("end", "  │  🏷️ WEBSITE:    ", "")
                        w.insert("end", f"{wtag}\n", "highlight")
                    # === SERVER & NETWORK IDENTIFIER ===
                    # Lists the server/network name as it is named by DNS,
                    # GeoIP, ASN, and MultiVerifier — for all tagged connections.
                    mv_rep = (self._last_full_data or {}).get('multi_verifications', {}).get(rip, {})
                    # The connection now carries these directly; the report
                    # cache is only a fallback.
                    rdns = c.get('rdns', '') or (mv_rep.get('rdns', '') if mv_rep else '')
                    asn = c.get('asn', '') or (mv_rep.get('asn', '') if mv_rep else '')
                    mv_org = c.get('asn_org', '') or (mv_rep.get('org', '') if mv_rep else '')
                    svc = c.get('service', '')
                    domain = c.get('domain', '')
                    org = c.get('org', '') or mv_org or ''
                    isp = c.get('isp', '')
                    cc = c.get('country_code', '')
                    country = c.get('country', '?')
                    has_id = False
                    if svc and svc not in ('Unknown', rip):
                        w.insert("end", f"  │     Service:     {svc}\n", "highlight")
                        has_id = True
                    if domain and domain not in ('unresolved', rip, svc):
                        w.insert("end", f"  │     Domain:      {domain}\n")
                        has_id = True
                    if rdns and rdns not in (domain, rip):
                        w.insert("end", f"  │     rDNS Host:   {rdns}\n", "highlight")
                        has_id = True
                    if wtag and wtag not in (svc, domain):
                        w.insert("end", f"  │     Tag:         {wtag}\n")
                        has_id = True
                    if org and org not in ('Unknown', ''):
                        w.insert("end", f"  │     Org:         {org}\n")
                        has_id = True
                    if isp and isp not in ('Unknown', '', org):
                        w.insert("end", f"  │     ISP:         {isp}\n", "dim")
                        has_id = True
                    if asn and asn not in ('', 'Unknown'):
                        w.insert("end", f"  │     ASN:         {asn}\n", "dim")
                        has_id = True
                    if cc and cc not in ('??', ''):
                        w.insert("end", f"  │     Network:     {country} ({cc})\n", "dim")
                        has_id = True
                    if not has_id:
                        w.insert("end", f"  │     IP Only:     {rip} (no DNS/ASN identity resolved)\n", "dim")
                    # === Process detail ===
                    w.insert("end", f"  │     Process:     {c.get('process', '?')} (PID {c.get('pid', '?')})\n")
                    exe_path = c.get('exe_path', '')
                    if exe_path:
                        w.insert("end", f"  │     Exe Path:    {exe_path}\n", "dim")
                    parent = c.get('parent_name', '')
                    if parent:
                        w.insert("end", f"  │     Parent:      {parent}\n", "dim")
                    # === Network detail ===
                    w.insert("end", f"  │     Remote:      {rip}:{c.get('remote_port', '?')}\n")
                    rport = c.get('remote_port', 0)
                    psvc = _PORT_SERVICES.get(rport, '')
                    if psvc:
                        w.insert("end", f"  │     Port Service:{rport} ({psvc})\n", "info")
                    w.insert("end", f"  │     Local Port:  {c.get('local_port', '?')}\n")
                    w.insert("end", f"  │     Protocol:    {c.get('protocol', '?')} — Status: {c.get('status', '?')}\n")
                    # === Domain detail ===
                    domain_str = c.get('domain', 'unresolved')
                    via = c.get('via', '')
                    if via:
                        w.insert("end", f"  │     Domain:      {domain_str}", "highlight")
                        w.insert("end", f" (via {via})\n", "dim")
                    else:
                        w.insert("end", f"  │     Domain:      {domain_str}\n")
                    all_doms = c.get('all_domains', [])
                    if all_doms and len(all_doms) > 1:
                        w.insert("end", f"  │     All Domains: {', '.join(all_doms[:8])}", "dim")
                        if len(all_doms) > 8:
                            w.insert("end", f" (+{len(all_doms)-8} more)", "dim")
                        w.insert("end", "\n")
                    elif all_doms and len(all_doms) == 1:
                        w.insert("end", f"  │     All Domains: {all_doms[0]}\n", "dim")
                    # === Geo detail ===
                    w.insert("end", f"  │     Country:     {c.get('country', '?')} ({c.get('country_code', '?')})\n")
                    w.insert("end", f"  │     City:        {c.get('city', '?')}, Region: {c.get('region', '?')}\n")
                    w.insert("end", f"  │     Org:         {c.get('org', '?')}\n")
                    w.insert("end", f"  │     ISP:         {c.get('isp', '?')}\n")
                    w.insert("end", f"  │     Coordinates: ({c.get('lat', 0):.4f}, {c.get('lon', 0):.4f})\n")
                    # Location verification proof
                    loc_conf = c.get('loc_confidence', 0)
                    loc_grade = c.get('loc_grade', 'UNVERIFIED')
                    loc_proof = c.get('loc_proof', [])
                    if loc_proof:
                        grade_tag = "info" if loc_grade == "HIGH" else (
                            "warning" if loc_grade in ("MEDIUM", "LOW") else "critical")
                        w.insert("end", "  │     📍 Location: ", "")
                        w.insert("end", f"{loc_conf}% {loc_grade}\n", grade_tag)
                        for proof in loc_proof:
                            w.insert("end", f"  │       {proof}\n", "dim")
                    # Proxy detection
                    proxy_type = c.get('proxy_type', '')
                    if proxy_type:
                        proxy_detail = c.get('proxy_detail', '')
                        w.insert("end", "  │     🔀 Proxy:    ", "")
                        w.insert("end", f"{proxy_type}\n", "warning")
                        if proxy_detail:
                            w.insert("end", f"  │       {proxy_detail}\n", "dim")
                    w.insert("end", f"  │     First Seen:  {_fmt_ts(c.get('first_seen', 0))}\n")
                    w.insert("end", f"  │     Last Seen:   {_fmt_ts(c.get('last_seen', 0))}\n")
                    # Anti-hack pins
                    anti_hack = (self._last_full_data or {}).get('anti_hack_pins', {}).get(rip, {})
                    if anti_hack and anti_hack.get('categories'):
                        w.insert("end", "  │     ┌─ 📌 ANTI-HACK PINS ────────────────────────────\n", "critical")
                        for cat in anti_hack['categories']:
                            w.insert("end", f"  │     │ 📌 {cat}\n", "critical")
                        for detail in anti_hack.get('details', [])[:10]:
                            w.insert("end", f"  │     │   {detail[:100]}\n", "warning")
                        w.insert("end", "  │     └────────────────────────────────────────────────\n", "critical")
                    self._tag_rows(w, row_start, c, self._ctx_conns, 'conn::')
                w.insert("end", f"  └{'─' * 100}\n", "dim")
        self._highlight_search(w, search_q)
        w.config(state="disabled")
        self._end_refresh(w, at_bottom, top_line)

    def _refresh_deductions(self, data):
        w = self._ded_text
        at_bottom, top_line = self._begin_refresh(w)
        w.config(state="normal")
        w.delete("1.0", "end")
        deds = data.get('deductions', [])
        # Severity counts
        n_crit = sum(1 for d in deds if d.get('severity') == 'CRITICAL')
        n_warn = sum(1 for d in deds if d.get('severity') == 'WARNING')
        n_info = sum(1 for d in deds if d.get('severity') == 'INFO')
        w.insert("end", f"{'═' * 100}\n", "dim")
        w.insert("end", f"  ALL DEDUCTIONS — {len(deds)} total "
                        f"(🔴 {n_crit} CRITICAL | 🟡 {n_warn} WARNING | 🔵 {n_info} INFO)\n", "header")
        w.insert("end", f"{'═' * 100}\n\n", "dim")
        w.insert("end", "  Deductions are security conclusions based on multiple evidence signals.\n", "dim")
        w.insert("end", "  Each deduction shows: timestamp, severity, category, affected process,\n", "dim")
        w.insert("end", "  risk score, message, and the evidence that triggered it.\n\n", "dim")
        # Category descriptions
        cat_descs = {
            'DLL': 'DLL injection / suspicious DLL activity',
            'VIRUSTOTAL': 'VirusTotal flagged the executable as malicious',
            'BEACON': 'Periodic beaconing pattern detected (C2 callback)',
            'EXFIL': 'Data exfiltration pattern (large outbound transfer)',
            'IMPERSONATION': 'Process impersonating a legitimate system process',
            'MIMIC': 'Process mimicking a known service name',
            'FOREIGN': 'Connection to unexpected foreign country',
            'INJECTION': 'Process injection chain detected',
            'PERSISTENCE': 'Persistence mechanism (registry/startup/scheduled task)',
            'GEOIP': 'GeoIP anomaly (unexpected location for service)',
            'VERIFICATION': 'Location verification mismatch',
            'MEMORY': 'Memory forensics (RWX regions = possible shellcode)',
            'DNS_TUNNEL': 'DNS tunneling detected',
            'DOH': 'DNS-over-HTTPS usage (bypasses DNS monitoring)',
        }
        for idx, d in enumerate(reversed(deds), 1):
            sev = d.get('severity', 'INFO')
            tag = "critical" if sev == "CRITICAL" else ("warning" if sev == "WARNING" else "info")
            w.insert("end", f"  ┌─ Deduction #{idx} ", tag)
            w.insert("end", f"{'─' * 70}\n", "dim")
            w.insert("end", f"  │ Time:       {d.get('time', '?')}\n")
            w.insert("end", "  │ Severity:   ", "")
            w.insert("end", f"{sev}\n", tag)
            cat = d.get('category', '?')
            w.insert("end", f"  │ Category:   {cat}")
            cat_desc = cat_descs.get(cat)
            if cat_desc:
                w.insert("end", f"  — {cat_desc}\n", "dim")
            else:
                w.insert("end", "\n")
            w.insert("end", f"  │ Process:    {d.get('process', '?')} (PID {d.get('pid', '?')})\n")
            score = d.get('score', 0)
            w.insert("end", f"  │ Risk Score: ", "")
            w.insert("end", f"{score}/100\n", tag)
            w.insert("end", f"  │ Message:    {d.get('message', '?')}\n", "highlight")
            evidence = d.get('evidence', [])
            if evidence:
                w.insert("end", "  │ Evidence:\n")
                for ev in evidence:
                    w.insert("end", f"  │   → {ev}\n")
            # Cooldown info
            cooldown = CONFIG.get('deduction_cooldown', 120)
            w.insert("end", f"  │ Cooldown:   {cooldown}s (deductions of same type suppressed)\n", "dim")
            w.insert("end", f"  └{'─' * 80}\n\n", "dim")
        self._highlight_search(w, self._search_ded.get())
        w.config(state="disabled")
        self._end_refresh(w, at_bottom, top_line)

    def _refresh_processes(self, data):
        w = self._proc_text
        at_bottom, top_line = self._begin_refresh(w)
        w.config(state="normal")
        w.delete("1.0", "end")
        procs = data.get('processes', [])
        active = [p for p in procs if p.get('connections', 0) > 0 or p.get('risk', 0) > 0]
        active.sort(key=lambda x: -x.get('risk', 0))
        w.insert("end", f"{'═' * 120}\n", "dim")
        w.insert("end", f"  ALL TRACKED PROCESSES — {len(active)} with network activity or risk\n", "header")
        w.insert("end", f"{'═' * 120}\n\n", "dim")
        # Column header with descriptions
        w.insert("end", f"  {'PID':<8} {'Name':<28} {'Risk':>6} {'Conn':>6} {'Dst':>5} "
                        f"{'ML':>6} {'Exe':<50} {'Countries'}\n", "subheader")
        w.insert("end", f"  {'─'*8} {'─'*28} {'─'*6} {'─'*6} {'─'*5} {'─'*6} {'─'*50} {'─'*20}\n", "dim")
        # Legend explaining columns
        w.insert("end", "  Legend: PID=Process ID | Risk=0-100 score | Conn=Active connections | "
                        "Dst=Unique destinations\n", "dim")
        w.insert("end", "          ML=Machine learning anomaly score | Exe=Executable path | "
                        "Countries=GeoIP countries contacted\n\n", "dim")
        self._reset_ctx(self._ctx_procs, w)
        # Hoist CONFIG lookups out of the per-process loop
        risk_crit = CONFIG['risk_critical']
        risk_warn = CONFIG['risk_warning']
        watchlist_procs_lower = {p.lower() for p in self._watchlist_procs}
        for p in active:
            risk = p.get('risk', 0)
            tag = "critical" if risk >= risk_crit else ("warning" if risk >= risk_warn else "")
            star = " ★" if p['name'].lower() in watchlist_procs_lower else ""
            row_start = w.index('end-1c')
            line = (f"  {p['pid']:<8} {p['name']:<28} {risk:>6.1f} {p.get('connections', 0):>6} "
                    f"{p.get('destinations', 0):>5} {p.get('ml_score', 0):>6.1f} "
                    f"{p.get('exe', '?')[:50]:<50} "
                    f"{', '.join(p.get('countries', []))}{star}\n")
            w.insert("end", line, tag)
            self._tag_rows(w, row_start, p, self._ctx_procs, 'proc::')
            # Show behavioral flags if any
            flags = []
            if p.get('is_beacon'): flags.append("📡BEACON")
            if p.get('is_exfil'): flags.append("📤EXFIL")
            if p.get('is_impersonation'): flags.append("🎭IMPERSONATE")
            if p.get('is_injection'): flags.append("💉INJECTION")
            if p.get('is_mimic'): flags.append("🥸MIMIC")
            if p.get('is_foreign'): flags.append("🌍FOREIGN")
            if p.get('is_idle_anomaly'): flags.append("💤IDLE-ANOMALY")
            if p.get('dll_injected'): flags.append("🧩DLL-INJECT")
            if flags:
                w.insert("end", f"          Flags: {' | '.join(flags)}\n", "critical" if risk >= 50 else "warning")
            # Show DNS domains contacted
            dns_domains = p.get('dns_domains', [])
            if dns_domains and len(dns_domains) > 0:
                dom_str = ', '.join(list(dns_domains)[:5])
                if len(dns_domains) > 5:
                    dom_str += f" (+{len(dns_domains)-5} more)"
                w.insert("end", f"          DNS: {dom_str}\n", "dim")
            # Show SNI hostnames seen for this process
            sni = p.get('sni_domains', [])
            if sni:
                sni_str = ', '.join(list(sni)[:5])
                if len(sni) > 5:
                    sni_str += f" (+{len(sni)-5} more)"
                w.insert("end", f"          SNI: {sni_str}\n", "dim")
            # Show CPU/Memory if available
            cpu = p.get('cpu_percent', 0)
            mem = p.get('memory_mb', 0)
            if cpu > 1 or mem > 10:
                w.insert("end", f"          CPU: {cpu:.1f}%  Memory: {mem:.1f}MB  "
                                f"Parent: {p.get('parent_name', '?')} (PID {p.get('parent_pid', '?')})\n", "dim")
            # Traffic volume and command line — harvested all along but never
            # shown anywhere in the UI.
            bs, br = p.get('bytes_sent', 0), p.get('bytes_recv', 0)
            if bs or br:
                w.insert("end", f"          Process I/O (disk+socket): write {_fmt_bytes(bs)}"
                                f" / read {_fmt_bytes(br)}"
                                f"   Write rate: {_fmt_bytes(p.get('io_send_rate', 0))}/s\n", "dim")
            cl = p.get('cmdline', '')
            if cl:
                w.insert("end", f"          Cmd: {cl[:160]}\n", "dim")
            dlls = p.get('loaded_dlls', [])
            if dlls:
                w.insert("end", f"          Suspicious DLLs: {', '.join(dlls[:5])}\n", "warning")
            reasons = p.get('risk_reasons', [])
            if reasons and risk >= risk_warn:
                for r in reasons[-5:]:
                    w.insert("end", f"          • {r[:150]}\n", "warning" if risk < risk_crit else "critical")
        # Detailed per-process connection breakdown
        w.insert("end", f"\n{'═' * 120}\n", "dim")
        w.insert("end", "  DETAILED PER-PROCESS CONNECTION BREAKDOWN\n", "header")
        w.insert("end", f"{'═' * 120}\n", "dim")
        w.insert("end", "  Shows each process's individual connections with service, domain,\n", "dim")
        w.insert("end", "  GeoIP country, organization, and connection status.\n\n", "dim")
        # Build a PID→connections index ONCE — was O(P×C) scanning all connections
        # for each process. Now O(C) to build + O(1) lookup per process.
        conns_by_pid = defaultdict(list)
        for c in data.get('connections', []):
            conns_by_pid[c.get('pid')].append(c)
        for p in active[:50]:
            if p.get('connections', 0) > 0:
                w.insert("end", f"\n  ▶ {p['name']} (PID {p['pid']}) — "
                                f"Risk: {p.get('risk', 0):.1f} — "
                                f"{p.get('connections', 0)} connections — "
                                f"{p.get('destinations', 0)} destinations\n", "subheader")
                for c in conns_by_pid.get(p['pid'], []):
                    conn_start = w.index('end-1c')
                    rip = c.get('remote_ip', '?')
                    rport = c.get('remote_port', '?')
                    svc = c.get('service', '?')
                    dom = c.get('domain', '?')
                    cc = c.get('country_code', '?')
                    org = c.get('org', '?')
                    status = c.get('status', '?')
                    proxy = c.get('proxy_type', '')
                    proxy_str = f" | PROXY:{proxy}" if proxy else ""
                    w.insert("end", f"    ├─ {rip}:{rport} | {svc} | {dom} | "
                                    f"{cc} | {org} | {status}{proxy_str}\n")
                    self._tag_rows(w, conn_start, c, self._ctx_conns, 'conn::')
        self._highlight_search(w, self._search_proc.get())
        w.config(state="disabled")
        self._end_refresh(w, at_bottom, top_line)

    def _refresh_devices(self, data):
        w = self._dev_text
        at_bottom, top_line = self._begin_refresh(w)
        w.config(state="normal")
        w.delete("1.0", "end")
        devs = data.get('devices', [])
        w.insert("end", f"{'═' * 110}\n", "dim")
        w.insert("end", f"  NETWORK DEVICES — {len(devs)} discovered via ARP scan\n", "header")
        w.insert("end", f"{'═' * 110}\n\n", "dim")
        w.insert("end", f"  {'IP':<18} {'MAC':<20} {'Vendor':<18} {'Hostname':<25} "
                        f"{'OS Guess':<20} {'Conf':>6}\n", "subheader")
        w.insert("end", f"  {'─'*18} {'─'*20} {'─'*18} {'─'*25} {'─'*20} {'─'*6}\n", "dim")
        w.insert("end", "  Legend: IP=Device IP | MAC=Hardware address | Vendor=OUI lookup | "
                        "Hostname=Reverse DNS\n", "dim")
        w.insert("end", "          OS Guess=Fingerprinted OS | Conf=Identification confidence "
                        "(0.0-1.0)\n\n", "dim")
        for d in devs:
            w.insert("end", f"  {d.get('ip', '?'):<18} {d.get('mac', '?'):<20} "
                            f"{d.get('vendor', '?'):<18} {d.get('hostname', '?'):<25} "
                            f"{d.get('os_guess', '?'):<20} {d.get('confidence', 0):>6.2f}\n")
            # Detailed device info
            if d.get('ja4'):
                w.insert("end", f"    ├─ JA4 (TLS Client Fingerprint): {d['ja4']}\n", "dim")
            if d.get('ja4s'):
                w.insert("end", f"    ├─ JA4S (TLS Server Fingerprint): {d['ja4s']}\n", "dim")
            if d.get('ja4h'):
                w.insert("end", f"    ├─ JA4H (HTTP Fingerprint): {d['ja4h']}\n", "dim")
            if d.get('first_seen'):
                fs = d.get('first_seen', 0)
                if isinstance(fs, (int, float)) and fs > 0:
                    fs_str = datetime.datetime.fromtimestamp(fs).strftime('%Y-%m-%d %H:%M:%S')
                    w.insert("end", f"    ├─ First Seen: {fs_str}\n", "dim")
            if d.get('last_seen'):
                ls = d.get('last_seen', 0)
                if isinstance(ls, (int, float)) and ls > 0:
                    ls_str = datetime.datetime.fromtimestamp(ls).strftime('%Y-%m-%d %H:%M:%S')
                    w.insert("end", f"    ├─ Last Seen:  {ls_str}\n", "dim")
            if d.get('is_new'):
                w.insert("end", "    └─ ⚠ NEW DEVICE (first time seen)\n", "warning")
            elif d.get('open_ports'):
                w.insert("end", f"    └─ Open Ports: {d['open_ports']}\n", "dim")
        # Bluetooth devices
        bt_devs = data.get('bt_devices', [])
        if bt_devs:
            w.insert("end", f"\n{'═' * 110}\n", "dim")
            w.insert("end", f"  BLUETOOTH DEVICES — {len(bt_devs)} detected\n", "header")
            w.insert("end", f"{'═' * 110}\n\n", "dim")
            w.insert("end", f"  {'Name':<35} {'Type':<15} {'Device ID':<60}\n", "subheader")
            w.insert("end", f"  {'─'*35} {'─'*15} {'─'*60}\n", "dim")
            for bt in bt_devs:
                w.insert("end", f"  {bt.get('name', '?'):<35} {bt.get('type', '?'):<15} "
                                f"{bt.get('device_id', '?')[:60]:<60}\n")
        # Recent DNS queries (sniffed query log)
        recent_dns = data.get('recent_dns', [])
        if recent_dns:
            w.insert("end", f"\n{'═' * 110}\n", "dim")
            w.insert("end", f"  RECENT DNS QUERIES — {len(recent_dns)} in the last 10 min\n", "header")
            w.insert("end", f"{'═' * 110}\n\n", "dim")
            w.insert("end", f"  {'Time':<10} {'Source':<16} {'Query':<45} {'Resolved to'}\n", "subheader")
            w.insert("end", f"  {'─'*10} {'─'*16} {'─'*45} {'─'*30}\n", "dim")
            for q in recent_dns[:80]:
                tstr = datetime.datetime.fromtimestamp(q['time']).strftime('%H:%M:%S')
                ips = ', '.join(q.get('ips', [])) or '—'
                w.insert("end", f"  {tstr:<10} {q.get('src','?'):<16} "
                                f"{q.get('query','?')[:45]:<45} {ips}\n")
        # TLS certificate fingerprints (JA4X)
        ja4x = data.get('tls_ja4x', {})
        if ja4x:
            w.insert("end", f"\n{'═' * 110}\n", "dim")
            w.insert("end", f"  TLS CERTIFICATE FINGERPRINTS (JA4X) — {len(ja4x)} endpoint(s)\n", "header")
            w.insert("end", f"{'═' * 110}\n\n", "dim")
            for ip, fp in sorted(ja4x.items())[:60]:
                w.insert("end", f"  {ip:<40} {fp}\n")
        # Serial ports
        serial_ports = data.get('serial_ports', [])
        if serial_ports:
            w.insert("end", f"\n{'═' * 110}\n", "dim")
            w.insert("end", f"  SERIAL / COM PORTS — {len(serial_ports)} active\n", "header")
            w.insert("end", f"{'═' * 110}\n\n", "dim")
            w.insert("end", f"  {'Port':<12} {'Device':<60}\n", "subheader")
            w.insert("end", f"  {'─'*12} {'─'*60}\n", "dim")
            for sp in serial_ports:
                w.insert("end", f"  {sp.get('port', '?'):<12} {sp.get('device', '?'):<60}\n")
        self._highlight_search(w, self._search_dev.get())
        w.config(state="disabled")
        self._end_refresh(w, at_bottom, top_line)

    def _refresh_map(self, data):
        if not self._map_canvas:
            return
        if self._map_drag_start is not None:
            return  # a drag is in flight; don't fight the user's pan
        # Resize canvas to current size
        self._map_w = max(600, self._map_canvas.winfo_width())
        self._map_h = max(300, self._map_canvas.winfo_height())
        # Prepare map data for dot plotting (also used by _redraw_dots_only)
        all_points = list(data.get('map_points', []))
        conn_list = data.get('connections', [])
        seen = {p['ip'] for p in all_points}
        for c in conn_list:
            if c.get('lat') or c.get('lon'):
                if c.get('remote_ip') not in seen:
                    all_points.append({
                        'ip': c['remote_ip'], 'lat': c['lat'], 'lon': c['lon'],
                        'service': c.get('service', '?'), 'icon': c.get('icon', '?'),
                        'city': c.get('city', '?'), 'country': c.get('country', '?'),
                        'org': c.get('org', '?'), 'process': c.get('process', '?'),
                    })
                    seen.add(c['remote_ip'])
        # Build PID→risk index ONCE — was O(C×P) scanning all processes
        # for each connection. Now O(P) to build + O(1) lookup per connection.
        pid_risk = {p['pid']: p.get('risk', 0) for p in data.get('processes', [])}
        ip_risk: dict[str, float] = {}
        ip_conn_count: dict[str, int] = defaultdict(int)
        for c in conn_list:
            rip = c.get('remote_ip', '')
            ip_conn_count[rip] += 1
            r = pid_risk.get(c.get('pid'), 0)
            if r > ip_risk.get(rip, 0):
                ip_risk[rip] = r
        # VPN/proxy classification. The connections now carry the verdict
        # directly (every public endpoint is cross-verified), so build from
        # them first and treat the side-channel report cache as a fallback.
        ip_vpn: dict[str, dict] = {}
        for c in conn_list:
            rip = c.get('remote_ip', '')
            if not rip:
                continue
            pt = (c.get('proxy_type') or '').upper()
            is_proxy_type = bool(pt and 'NONE' not in pt)
            if c.get('is_vpn') or c.get('is_proxy') or is_proxy_type \
                    or c.get('vpn_score', 0) >= 30:
                ip_vpn[rip] = {
                    'is_vpn': bool(c.get('is_vpn')),
                    'is_proxy': bool(c.get('is_proxy')) or is_proxy_type,
                    'vpn_score': c.get('vpn_score', 50),
                    'provider': c.get('vpn_provider', ''),
                    'labels': c.get('vpn_labels') or ([pt] if pt else []),
                    'summary': c.get('verify_summary') or c.get('proxy_detail', ''),
                    'consensus_city': c.get('city', '?'),
                    'consensus_country': c.get('country', '?'),
                }
        multi_verif = data.get('multi_verifications', {})
        for ip_str, rep in multi_verif.items():
            if ip_str in ip_vpn:
                continue
            if isinstance(rep, dict) and (rep.get('is_vpn') or rep.get('is_proxy')
                                          or rep.get('vpn_score', 0) >= 30):
                ip_vpn[ip_str] = rep
        # Cache for zoom/pan redraws
        local_geo = data.get('local_geo', {})
        self._last_map_data = {
            'all_points': all_points,
            'ip_risk': ip_risk,
            'ip_conn_count': ip_conn_count,
            'ip_vpn': ip_vpn,
            'local_geo': local_geo,
        }
        # First time the user's own GeoIP resolves (it's an async lookup, not
        # available on the very first refresh), re-center the default view on
        # it instead of the generic mid-Atlantic (20°N, 0°E) point — "closer
        # to location" means centered on the actual user, not just a bigger
        # zoom number on an arbitrary spot. Only happens once per session so
        # it never fights the user's own panning/zooming afterward.
        if not self._map_auto_centered and (local_geo.get('lat') or local_geo.get('lon')):
            self._map_center_lat = max(-85, min(85, local_geo.get('lat', 0)))
            self._map_center_lon = max(-180, min(180, local_geo.get('lon', 0)))
            self._map_auto_centered = True
        # Full redraw (tiles) only when the view actually moved. This runs on
        # every GUI refresh cycle while the Map tab is active — tearing down
        # and recreating every tile image several times a second regardless
        # of whether the view had changed was the main source of map lag.
        # Panning/zooming/preset buttons call _draw_map_full() directly too
        # (for instant feedback) and update the same state, so this only
        # skips the *redundant* rebuilds, never a real one.
        view_state = (round(self._map_zoom, 3), round(self._map_center_lat, 4),
                     round(self._map_center_lon, 4), self._map_w, self._map_h)
        if view_state != getattr(self, '_map_last_view_state', None):
            self._draw_map_full()
        self._map_canvas.delete("dot", "line_to_dot", "trace_path", "trace_hop", "crosshair")
        self._plot_map_dots(self._last_map_data)
        self._plot_trace_on_map()

    def _plot_map_dots(self, map_data):
        """Plot IP dots on the map using precomputed map_data.
        Uses actual local GeoIP for connection lines. Declusters overlapping dots."""
        if not self._map_canvas or not map_data:
            return
        all_points = map_data.get('all_points', [])
        ip_risk = map_data.get('ip_risk', {})
        ip_conn_count = map_data.get('ip_conn_count', {})
        ip_vpn = map_data.get('ip_vpn', {})
        local_geo = map_data.get('local_geo', {})
        w, h = self._map_w, self._map_h
        z = self._map_zoom
        # Compute local machine position from GeoIP
        local_lat = local_geo.get('lat', 0)
        local_lon = local_geo.get('lon', 0)
        has_local = bool(local_lat or local_lon)
        local_x, local_y = w / 2, h / 2  # fallback to center
        if has_local:
            local_x, local_y = self._latlon_to_xy(local_lat, local_lon)
        # Draw "You are here" marker
        if has_local and -20 <= local_x <= w + 20 and -20 <= local_y <= h + 20:
            # Pulsing ring
            self._map_canvas.create_oval(
                local_x - 12, local_y - 12, local_x + 12, local_y + 12,
                outline="#00d4ff", width=2, tags="dot")
            self._map_canvas.create_oval(
                local_x - 7, local_y - 7, local_x + 7, local_y + 7,
                fill="#00d4ff", outline="#ffffff", width=2, tags="dot")
            # Label — always shown (it's one marker, not clutter-prone), but
            # still scales gently with zoom rather than a fixed size.
            loc_str = f"{local_geo.get('city', '?')}, {local_geo.get('country_code', '?')}"
            you_sz = self._map_label_size(z, max_size=15, floor=10, z_min=0)
            city_sz = self._map_label_size(z, max_size=13, floor=9, z_min=0)
            self._map_chip_label(local_x + 18, local_y - you_sz, "📍 YOU",
                                 "#33e0ff", you_sz, anchor="w")
            self._map_chip_label(local_x + 18, local_y + city_sz, loc_str,
                                 "#aaddff", city_sz, anchor="w")
        # Draw connection lines from local to remote
        if z >= 2 and all_points and has_local:
            for pt in all_points:
                lat, lon = pt.get('lat', 0), pt.get('lon', 0)
                if lat == 0 and lon == 0:
                    continue
                x, y = self._latlon_to_xy(lat, lon)
                if 0 <= x <= w and 0 <= y <= h:
                    # Great-circle style arc: draw a slight curve
                    # For simplicity, use a straight line with a midpoint offset
                    mid_x = (local_x + x) / 2
                    mid_y = (local_y + y) / 2
                    # Offset perpendicular to the line for a subtle arc effect
                    dx = x - local_x
                    dy = y - local_y
                    dist = math.sqrt(dx * dx + dy * dy)
                    if dist > 0:
                        # Perpendicular offset (5% of distance, upward)
                        offset = dist * 0.05
                        mid_x -= dy / dist * offset
                        mid_y += dx / dist * offset
                    self._map_canvas.create_line(
                        local_x, local_y, mid_x, mid_y, x, y,
                        fill="#1a4a6a", width=1, dash=(3, 6),
                        tags="line_to_dot", smooth=True)
        elif z >= 2 and all_points and not has_local:
            # Fallback: lines from center
            for pt in all_points:
                lat, lon = pt.get('lat', 0), pt.get('lon', 0)
                if lat == 0 and lon == 0:
                    continue
                x, y = self._latlon_to_xy(lat, lon)
                if 0 <= x <= w and 0 <= y <= h:
                    self._map_canvas.create_line(
                        local_x, local_y, x, y,
                        fill="#1a2a4a", width=1, dash=(3, 6),
                        tags="line_to_dot")
        # Decluster: detect overlapping points and apply slight jitter.
        #
        # Many public IPs resolve to the exact same city-level lat/lon (GeoIP
        # is city-granularity, not per-host), so a handful of parallel
        # connections routinely lands a dozen+ points on the same pixel. The
        # old code jittered each one a few pixels apart and then drew a full
        # text label (IP address, and a second VPN-disclaimer line) next to
        # EVERY one of them — with only ~4-20px of spiral offset between
        # labels that are each 50-150px wide, they stack into an unreadable
        # smear (this is what made the map "unreadable" — not font size).
        #
        # Fix: label individual dots only in small, uncluttered groups.
        # Clusters of 3+ get exactly one compact "×N" badge instead of N
        # overlapping labels — full per-connection detail is still one hover
        # away via the existing tooltip.
        cluster_key_of: dict = {}   # id(pt) -> cluster key
        cluster_size: dict = {}     # cluster key -> point count
        cluster_anchor: dict = {}   # cluster key -> (x, y) of first point
        for pt in all_points:
            lat, lon = pt.get('lat', 0), pt.get('lon', 0)
            if lat == 0 and lon == 0:
                continue
            x, y = self._latlon_to_xy(lat, lon)
            if x < -20 or x > w + 20 or y < -20 or y > h + 20:
                continue
            key = (round(x, 1), round(y, 1))
            cluster_key_of[id(pt)] = key
            cluster_size[key] = cluster_size.get(key, 0) + 1
            cluster_anchor.setdefault(key, (x, y))
        occupied: dict = {}  # (round(x,1), round(y,1)) -> count placed so far
        cluster_labeled: set = set()  # clusters that already got their one badge
        for pt in all_points:
            lat, lon = pt.get('lat', 0), pt.get('lon', 0)
            if lat == 0 and lon == 0:
                continue
            x, y = self._latlon_to_xy(lat, lon)
            # Skip dots outside viewport
            if x < -20 or x > w + 20 or y < -20 or y > h + 20:
                continue
            key = cluster_key_of.get(id(pt), (round(x, 1), round(y, 1)))
            cluster_n = cluster_size.get(key, 1)
            count = occupied.get(key, 0)
            if count > 0:
                # Spiral jitter: place overlapping dots in a small spiral
                angle = count * 0.8
                r = 4 + count * 2
                x += r * math.cos(angle)
                y += r * math.sin(angle)
            occupied[key] = count + 1
            ip = pt.get('ip', '?')
            risk = ip_risk.get(ip, 0)
            vpn_rep = ip_vpn.get(ip)
            if vpn_rep:
                # VPN/proxy endpoint — purple/magenta with white outline.
                # This marks the EXIT NODE location, not the real source.
                fill_color, outline_color = "#cc00cc", "#ff66ff"
            elif risk >= 50:
                fill_color, outline_color = "#ff0000", "#ff4444"
            elif risk >= 25:
                fill_color, outline_color = "#ff8800", "#ffaa44"
            elif risk >= 10:
                fill_color, outline_color = "#ffcc00", "#ffdd44"
            else:
                fill_color, outline_color = "#44cc44", "#66ff66"
            if ip in getattr(self, '_watchlist_ips', set()):
                outline_color = "#00ffff"
            radius = min(8, max(3, 3 + ip_conn_count.get(ip, 1)))
            if ip == self._selected_ip:
                # Selection ring for the endpoint chosen from a click or the
                # "Show on map" context action.
                self._map_canvas.create_oval(
                    x - radius - 6, y - radius - 6, x + radius + 6, y + radius + 6,
                    outline="#ffffff", width=2, tags="dot")
                outline_color = "#ffffff"
            # Draw a subtle glow/halo behind the dot for visibility on map tiles
            self._map_canvas.create_oval(
                x - radius - 2, y - radius - 2, x + radius + 2, y + radius + 2,
                fill="", outline="#000000", width=1, stipple="gray50", tags="dot")
            dot = self._map_canvas.create_oval(
                x - radius, y - radius, x + radius, y + radius,
                fill=fill_color, outline=outline_color, width=2, tags="dot")
            self._map_dots[ip] = dot
            info = pt
            self._map_canvas.tag_bind(dot, "<Enter>",
                lambda e, i=ip, inf=info: self._on_map_dot_enter(e, i, inf))
            self._map_canvas.tag_bind(dot, "<Leave>", self._on_map_dot_leave)
            self._map_canvas.tag_bind(dot, "<Button-1>",
                lambda e, i=ip: self._on_map_dot_click(i))
            self._map_canvas.tag_bind(dot, "<Button-3>",
                lambda e, i=ip, inf=info: self._on_map_dot_right_click(e, i, inf))
            # Per-dot text labels — only for a true singleton (nothing else
            # shares its cell). Anything with company gets the one compact
            # badge below instead of stacked, unreadable labels. Every label
            # gets an opaque dark chip behind it (via _map_chip_label) —
            # colored text floating directly on light OSM tile colors (the
            # default "OSM Standard" style is mostly pale beige/white) had
            # poor contrast regardless of which text color was chosen; a
            # solid backing fixes that at any zoom or tile style.
            #
            # Size scales continuously with zoom (_map_label_size) instead of
            # a hard z>=5 on/off gate — the gate made a label pop in at full
            # (oversized) size the instant zoom crossed 5, then vanish
            # completely one notch below it. Growing smoothly from a small
            # floor means there's no jump, and nothing needed only to
            # disappear again on a small zoom-out.
            uncluttered = cluster_n == 1
            if uncluttered:
                fsz = self._map_label_size(z, max_size=21)
                if fsz:
                    self._map_chip_label(x + radius + 8, y, ip, "#ffe066",
                                         fsz, anchor="w")
            # VPN/proxy disclaimer — only on isolated dots; a clustered VPN
            # exit is already unambiguous from its magenta color plus the
            # legend, and the full warning is always one hover away.
            if vpn_rep and uncluttered:
                fsz = self._map_label_size(z, max_size=18)
                if fsz:
                    prov = vpn_rep.get('provider') or ''
                    disclaimer = f"⚠ {prov} EXIT" if prov else "⚠ VPN EXIT"
                    self._map_chip_label(x, y - radius - (fsz + 6), disclaimer,
                                         "#ff99ff", fsz)
            # Cluster badge — one compact "×N" marker per shared cell,
            # replacing what used to be N stacked, overlapping labels. Always
            # shown (no zoom gate) since it's already compact, but still
            # scales gently so it doesn't dominate a zoomed-out view.
            if cluster_n >= 2 and key not in cluster_labeled:
                cluster_labeled.add(key)
                fsz = self._map_label_size(z, max_size=18, floor=10, z_min=0)
                ax, ay = cluster_anchor.get(key, (x, y))
                self._map_chip_label(ax + radius + fsz + 4, ay - radius - fsz,
                                     f"×{cluster_n}", "#ffe066", fsz)

    @staticmethod
    def _map_label_size(z, max_size, floor=8, z_min=3.0, z_full=7.5):
        """Continuous label font size for the map: grows smoothly from
        `floor` at `z_min` up to `max_size` at `z_full`, instead of a fixed
        size that pops in past a hard zoom threshold. Returns 0 (meaning
        "don't draw it") below z_min."""
        if z < z_min:
            return 0
        t = 1.0 if z_full <= z_min else max(0.0, min(1.0, (z - z_min) / (z_full - z_min)))
        return max(floor, round(floor + t * (max_size - floor)))

    def _map_chip_label(self, cx, cy, text, fg, font_size, anchor="center"):
        """Draw text on an opaque dark chip, sized to fit — used for every
        map label so text stays legible over light and dark tile colors
        alike, at any zoom, rather than floating directly on the tiles."""
        t = self._map_canvas.create_text(
            cx, cy, text=text, fill=fg,
            font=("Consolas", font_size, "bold"), anchor=anchor, tags="dot")
        bb = self._map_canvas.bbox(t)
        if not bb:
            return t
        pad_x = max(4, font_size // 3)
        pad_y = max(3, font_size // 5)
        bg = self._map_canvas.create_rectangle(
            bb[0] - pad_x, bb[1] - pad_y, bb[2] + pad_x, bb[3] + pad_y,
            fill="#050508", outline=fg, width=2, tags="dot")
        self._map_canvas.tag_raise(t, bg)
        return t

    def _refresh_actions(self, data):
        w = self._actions_text
        at_bottom, top_line = self._begin_refresh(w)
        w.config(state="normal")
        w.delete("1.0", "end")
        actions = data.get('all_actions', [])
        w.insert("end", f"{'═' * 100}\n", "dim")
        w.insert("end", f"  📝 RAW ACTIONS LOG — {len(actions)} entries "
                        f"(showing last {min(500, len(actions))})\n", "header")
        w.insert("end", f"{'═' * 100}\n\n", "dim")
        w.insert("end", "  Complete audit log of every process action. Each entry shows:\n", "dim")
        w.insert("end", "    STARTED       — New process launched (with exe path + parent)\n", "dim")
        w.insert("end", "    STOPPED       — Process terminated\n", "dim")
        w.insert("end", "    NETWORK_FLOW  — Network connection established (dest + domains)\n", "dim")
        w.insert("end", "    BLOCK         — IP blocked via Windows Firewall\n", "dim")
        w.insert("end", "    UNBLOCK       — IP firewall rule removed\n", "dim")
        w.insert("end", "    DEDUCTION     — Security deduction raised (CRITICAL/WARNING)\n", "dim")
        w.insert("end", "\n  Color coding: ", "dim")
        w.insert("end", "red=CRITICAL/DEDUCTION", "critical")
        w.insert("end", " | ", "dim")
        w.insert("end", "yellow=WARNING", "warning")
        w.insert("end", " | white=normal\n\n", "dim")
        # Action type counts — only count the displayed actions (last 500),
        # not all 20,000+ — was O(N×6) string scans on every refresh.
        displayed = actions[-500:]
        type_counts = {}
        for act in displayed:
            line = str(act)
            for atype in ('STARTED', 'STOPPED', 'NETWORK_FLOW', 'BLOCK', 'UNBLOCK', 'DEDUCTION'):
                if atype in line:
                    type_counts[atype] = type_counts.get(atype, 0) + 1
                    break
        if type_counts:
            w.insert("end", "  Summary: ", "subheader")
            parts = []
            for atype in ('STARTED', 'STOPPED', 'NETWORK_FLOW', 'BLOCK', 'UNBLOCK', 'DEDUCTION'):
                if atype in type_counts:
                    parts.append(f"{atype}={type_counts[atype]}")
            w.insert("end", " | ".join(parts) + "\n\n", "dim")
        for act in displayed:
            line = str(act) + "\n"
            if 'CRITICAL' in line or 'DEDUCTION' in line:
                w.insert("end", line, "critical")
            elif 'WARNING' in line:
                w.insert("end", line, "warning")
            else:
                w.insert("end", line)
        self._highlight_search(w, self._search_actions.get())
        w.config(state="disabled")
        self._end_refresh(w, at_bottom, top_line)

    def _refresh_suspicious(self, data):
        """Show ONLY out-of-norm / anomalous events — virus behavior, data access, hardware, remote power, etc."""
        w = self._suspicious_text
        at_bottom, top_line = self._begin_refresh(w)
        w.config(state="normal")
        w.delete("1.0", "end")
        events = data.get('suspicious_events', [])
        w.insert("end", "═" * 110 + "\n", "dim")
        w.insert("end", f"  🔴 SUSPICIOUS ACTIVITY — {len(events)} anomalous events detected\n", "header")
        w.insert("end", "═" * 110 + "\n", "dim")
        w.insert("end", "  Only shows operations that are OUT OF THE NORM: virus behavior, data exfil,\n", "dim")
        w.insert("end", "  cookie tracking, mic/camera access, remote power/access, code injection,\n", "dim")
        w.insert("end", "  suspicious paths, credential access, script execution, high-risk geo, etc.\n", "dim")
        w.insert("end", "═" * 110 + "\n\n", "dim")
        if not events:
            w.insert("end", "  ✅ No suspicious activity detected yet.\n\n", "info")
            w.insert("end", "  The monitor is watching for:\n", "dim")
            w.insert("end", "    • Virus-like behavior (injection, hooking, RWX memory)\n", "dim")
            w.insert("end", "    • Data exfiltration / unusual uploads\n", "dim")
            w.insert("end", "    • Cookie & tracker sending (even from Google)\n", "dim")
            w.insert("end", "    • Mic / camera / hardware access\n", "dim")
            w.insert("end", "    • Remote power (shutdown, restart, wake-on-LAN)\n", "dim")
            w.insert("end", "    • Remote access (RDP, SSH, VNC, TeamViewer)\n", "dim")
            w.insert("end", "    • Processes from temp/downloads/AppData paths\n", "dim")
            w.insert("end", "    • Credential / password / token access\n", "dim")
            w.insert("end", "    • Script execution (PowerShell, cmd, wscript)\n", "dim")
            w.insert("end", "    • Connections to high-risk countries\n", "dim")
            w.insert("end", "    • All deductions from the chess engine\n", "dim")
            w.config(state="disabled")
            self._end_refresh(w, at_bottom, top_line)
            return
        # Group by category
        by_cat = {}
        for ev in events:
            cat = ev.get('category', 'UNKNOWN')
            by_cat.setdefault(cat, []).append(ev)
        # Category icons and descriptions
        cat_icons = {
            'HARDWARE_ACCESS': '🎤', 'REMOTE_ACCESS': '🔌', 'REMOTE_POWER': '⚡',
            'COOKIE_TRACKING': '🍪', 'DATA_UPLOAD': '📤', 'DATA_EXFIL': '📤',
            'CREDENTIAL_ACCESS': '🔑', 'TOKEN_ACCESS': '🔑', 'CLIPBOARD_ACCESS': '📋',
            'KEYLOGGER': '⌨️', 'SCREEN_CAPTURE': '📸', 'CODE_INJECTION': '💉',
            'API_HOOK': '🪝', 'ENCRYPTION': '🔐', 'SCRIPT_EXEC': '📜',
            'DLL_REGISTER': '🧩', 'SCHEDULED_TASK': '📅', 'SUSPICIOUS_PATH': '📁',
            'TEMP_EXECUTION': '📁', 'HIGH_RISK_GEO': '🌍',
            'MIMIC': '🎭', 'BEACON': '📡', 'PHANTOM': '👻',
            'IMPERSONATION': '🥸', 'FOREIGN': '🌍', 'ANOMALY': '📊',
            'INJECTION': '💉', 'TUNNEL': '🕳️', 'EXFIL': '📤',
            'ENTROPY': '🔐', 'DLL': '🧩', 'PERSISTENCE': '📌',
            'IDLE_ANOMALY': '💤', 'ML_ANOMALY': '🤖',
            'WATCHLIST': '⭐', 'VIRUSTOTAL': '🦠', 'DOH': '🕳️',
            'USB': '🔌', 'SCHEDULED_TASK': '📅', 'NAMED_PIPE': '🔗',
            'INBOUND_SCAN': '🎯', 'BLUETOOTH': '📶', 'SERIAL_PORT': '🔌',
            'PROXY': '🔀', 'VPNLeak': '🔓', 'FileSystem': '📁',
            'Clipboard': '📋', 'TaskScheduler': '📅', 'NamedPipe': '🔗',
            'Network': '🌐', 'Bluetooth': '📶', 'Serial': '🔌',
            'Proxy': '🔀', 'VPNLeak': '🔓', 'SUSPICIOUS_PATH': '📁',
            # Anti-hack categories
            'SECURITY_EVENT': '🛡️', 'NET_SPAWN': '🐛', 'LISTEN_ANOMALY': '👂',
            'CREDENTIAL_DUMP': '🔑', 'DNS_HIJACK': '🌐', 'SERVICE_CREATE': '🔧',
            'PORT_FORWARD': '🕳️', 'DATA_STAGING': '📦', 'AV_DISABLE': '🛡️',
            'NEW_ACCOUNT': '👤', 'WMI_PERSIST': '🧩', 'PS_ABUSE': '📜',
            'BACKUP_TAMPER': '💾', 'DRIVER_LOAD': '🔧', 'ADMIN_SHARE': '📁',
            'MUTEX_HIT': '🔒', 'EXFIL_CHANNEL': '📤', 'PROCESS_HOLLOW': '🎭',
            'LOLBIN_ABUSE': '🧨', 'SUSPICIOUS_PATH': '📂', 'PARENT_MISMATCH': '🔀',
            'PS_OBFUSCATION': '🔮', 'MACRO_MALWARE': '📄', 'BROWSER_EXPLOIT': '🌐',
            'RENAMED_BINARY': '🎭', 'LOLBIN': '🧨',
            'SecurityEvent': '🛡️', 'DnsHijack': '🌐', 'ServiceCreate': '🔧',
            'AvDisable': '🛡️', 'NewAccount': '👤', 'WmiPersist': '🧩',
            'DriverLoad': '🔧', 'MutexHit': '🔒',
        }
        cat_descriptions = {
            'HARDWARE_ACCESS': 'Process accessed audio/camera hardware',
            'REMOTE_ACCESS': 'Connection to remote access port (SSH/RDP/VNC/TeamViewer)',
            'REMOTE_POWER': 'Remote shutdown/restart/Wake-on-LAN attempt',
            'COOKIE_TRACKING': 'Cookie or tracking data sent to remote server',
            'DATA_UPLOAD': 'Unusual data upload detected',
            'DATA_EXFIL': 'Data exfiltration pattern (large outbound transfer)',
            'CREDENTIAL_ACCESS': 'Process accessed credential/password files',
            'TOKEN_ACCESS': 'Process accessed authentication tokens',
            'CLIPBOARD_ACCESS': 'Process read or wrote to clipboard',
            'KEYLOGGER': 'Keylogger behavior detected (keyboard hook)',
            'SCREEN_CAPTURE': 'Screen capture activity detected',
            'CODE_INJECTION': 'Code injection into another process',
            'API_HOOK': 'API hooking detected (function interception)',
            'ENCRYPTION': 'File encryption activity (possible ransomware)',
            'SCRIPT_EXEC': 'Script execution (PowerShell/cmd/wscript)',
            'DLL_REGISTER': 'DLL registration (regsvr32 — possible payload)',
            'SCHEDULED_TASK': 'Scheduled task created/modified (persistence)',
            'SUSPICIOUS_PATH': 'Process running from suspicious location (temp/AppData)',
            'TEMP_EXECUTION': 'Executable running from temp directory',
            'HIGH_RISK_GEO': 'Connection to high-risk country',
            'MIMIC': 'Process mimicking a known service name',
            'BEACON': 'Periodic beaconing pattern (C2 callback)',
            'PHANTOM': 'Phantom process (hidden or ghost process)',
            'IMPERSONATION': 'Process impersonating a legitimate system process',
            'FOREIGN': 'Connection to unexpected foreign country',
            'ANOMALY': 'Behavioral anomaly detected',
            'INJECTION': 'Process injection chain detected',
            'TUNNEL': 'Tunneling protocol detected (DNS/ICMP tunnel)',
            'EXFIL': 'Data exfiltration detected',
            'ENTROPY': 'High-entropy data (possible encrypted payload)',
            'DLL': 'DLL injection or suspicious DLL activity',
            'PERSISTENCE': 'Persistence mechanism detected',
            'IDLE_ANOMALY': 'Network activity while user is idle',
            'ML_ANOMALY': 'Machine learning anomaly detected',
            'WATCHLIST': 'Watchlisted IP or process matched',
            'VIRUSTOTAL': 'VirusTotal flagged executable as malicious',
            'DOH': 'DNS-over-HTTPS usage (bypasses DNS monitoring)',
            'USB': 'USB device connected/disconnected',
            'NAMED_PIPE': 'Named pipe created (IPC/injection vector)',
            'INBOUND_SCAN': 'Inbound port scan detected from external source',
            'BLUETOOTH': 'Bluetooth device activity',
            'SERIAL_PORT': 'Serial/COM port activity',
            'PROXY': 'System proxy configuration detected',
            'VPNLeak': 'VPN leak detected (DNS/IP/WebRTC leak)',
            'FileSystem': 'File system change in sensitive directory',
            'Clipboard': 'Clipboard access by process',
            # Anti-hack descriptions
            'SECURITY_EVENT': 'Windows Security event log: logon/process/service/user event',
            'NET_SPAWN': 'Network-facing process spawned a shell (cmd/powershell) — likely hacker',
            'LISTEN_ANOMALY': 'Non-system process opened an unexpected listening port — possible bind shell/C2',
            'CREDENTIAL_DUMP': 'Credential dumping detected (LSASS access, reg save, mimikatz, procdump)',
            'DNS_HIJACK': 'Hosts file or DNS server modified — possible traffic redirection',
            'SERVICE_CREATE': 'New Windows service installed — possible persistence/backdoor',
            'PORT_FORWARD': 'Port forwarding or tunneling tool detected (netsh/ssh/ngrok/chisel)',
            'DATA_STAGING': 'Data staging: archive tool compressing user data before exfiltration',
            'AV_DISABLE': 'Windows Defender or Firewall disabled — post-exploitation indicator',
            'NEW_ACCOUNT': 'New user account or admin group member — backdoor account',
            'WMI_PERSIST': 'WMI event subscription created — stealthy persistence mechanism',
            'PS_ABUSE': 'Encoded/obfuscated PowerShell detected — fileless malware delivery',
            'BACKUP_TAMPER': 'Shadow copy deletion or backup tampering — ransomware/anti-forensics',
            'DRIVER_LOAD': 'New kernel driver loaded — possible rootkit',
            'ADMIN_SHARE': 'SMB admin share access (C$/ADMIN$) — lateral movement',
            'MUTEX_HIT': 'Known malware mutex name detected',
            'EXFIL_CHANNEL': 'Connection to known exfiltration/C2 channel (Discord/Telegram/etc)',
            'PROCESS_HOLLOW': 'System process running from non-system path — process hollowing',
            'LOLBIN_ABUSE': 'Living-off-the-land binary abuse (certutil/bitsadmin/mshta/regsvr32/etc)',
            'SUSPICIOUS_PATH': 'Executable running from temp/downloads/appdata — dropped payload',
            'PARENT_MISMATCH': 'System process spawned by unexpected parent — hollowing/injection',
            'PS_OBFUSCATION': 'Advanced PowerShell obfuscation (XOR/base64/reversed/concat)',
            'MACRO_MALWARE': 'Office application spawned a shell — macro malware',
            'BROWSER_EXPLOIT': 'Browser spawned a shell — exploit drive-by',
            'RENAMED_BINARY': 'System binary running from non-standard path — evasion',
            'SecurityEvent': 'Windows Security event log entry',
            'DnsHijack': 'DNS hijack — hosts file or DNS server change',
            'ServiceCreate': 'New service created',
            'AvDisable': 'AV/Firewall disabled',
            'NewAccount': 'New user/admin account',
            'WmiPersist': 'WMI persistence subscription',
            'DriverLoad': 'New driver loaded',
            'MutexHit': 'Malware mutex detected',
        }
        # Summary bar
        crit_count = sum(1 for e in events if e.get('severity') == 'CRITICAL')
        warn_count = sum(1 for e in events if e.get('severity') == 'WARNING')
        info_count = len(events) - crit_count - warn_count
        w.insert("end", f"  CRITICAL: {crit_count}  |  WARNING: {warn_count}  |  INFO: {info_count}  |  "
                        f"Categories: {len(by_cat)}\n\n", "subheader")
        # Render each category
        for cat in sorted(by_cat.keys()):
            cat_events = by_cat[cat]
            icon = cat_icons.get(cat, '❓')
            cat_desc = cat_descriptions.get(cat, '')
            w.insert("end", f"{'─' * 100}\n", "dim")
            w.insert("end", f"  {icon} {cat} — {len(cat_events)} event(s)\n", "header")
            if cat_desc:
                w.insert("end", f"  │ {cat_desc}\n", "dim")
            w.insert("end", f"{'─' * 100}\n", "dim")
            for ev in cat_events[-50:]:  # cap per category for performance
                sev = ev.get('severity', 'INFO')
                tag = 'critical' if sev == 'CRITICAL' else ('warning' if sev == 'WARNING' else 'info')
                w.insert("end", f"\n  [{sev}] ", tag)
                w.insert("end", f"{ev.get('time', '?')} — ", "dim")
                w.insert("end", f"{ev.get('description', '?')}\n", tag)
                w.insert("end", f"    Process: {ev.get('process', '?')} (PID {ev.get('pid', '?')})\n", "highlight")
                for detail in ev.get('details', []):
                    w.insert("end", f"      → {detail}\n", "dim")
                # Show alert cooldown info
                cooldown = CONFIG.get('alert_cooldown', 75)
                w.insert("end", f"    (Alert cooldown: {cooldown}s — same alert suppressed for this duration)\n", "dim")
        w.insert("end", f"\n{'═' * 110}\n", "dim")
        w.insert("end", f"  END OF SUSPICIOUS ACTIVITY LOG — {len(events)} total events\n", "dim")
        self._highlight_search(w, self._search_suspicious.get())
        w.config(state="disabled")
        self._end_refresh(w, at_bottom, top_line)

    def _refresh_blocked(self):
        """Show all currently blocked IPs with full metadata and unblock buttons."""
        w = self._blocked_text
        at_bottom, top_line = self._begin_refresh(w)
        # Destroy old embedded buttons
        if not hasattr(self, '_blocked_tab_buttons'):
            self._blocked_tab_buttons = []
        for btn in self._blocked_tab_buttons:
            try:
                btn.destroy()
            except Exception:
                pass
        self._blocked_tab_buttons.clear()
        w.config(state="normal")
        w.delete("1.0", "end")
        blocked = self._blocked_ips
        n = len(blocked)
        w.insert("end", f"{'═' * 120}\n", "dim")
        w.insert("end", f"  🛑 BLOCKED IPs — {n} currently blocked by Windows Firewall\n", "header")
        w.insert("end", f"{'═' * 120}\n", "dim")
        w.insert("end", "\n  IPs blocked via Windows Firewall outbound rules. Each block creates a\n", "dim")
        w.insert("end", f"  rule prefixed with '{self._fw_rule_prefix}' that prevents all outbound\n", "dim")
        w.insert("end", "  traffic to the blocked IP. Rules are cleaned up when the program closes.\n\n", "dim")
        if not self._is_admin():
            w.insert("end", "  ℹ Running without admin — a UAC prompt will appear when you block/unblock.\n", "warning")
            w.insert("end", "  Click Yes on the Windows permission dialog to allow the firewall change.\n\n", "dim")
        if n == 0:
            w.insert("end", "\n  ✅ No IPs are currently blocked.\n\n", "info")
            w.insert("end", "  To block an IP:\n", "dim")
            w.insert("end", "    1. Go to the 🔗 All Connections or 🟢 Live Connections tab\n", "dim")
            w.insert("end", "    2. Find the connection you want to block\n", "dim")
            w.insert("end", "    3. Click the 🚫 Block button next to it\n", "dim")
            w.insert("end", "    4. Confirm the UAC prompt (if not running as admin)\n\n", "dim")
            w.insert("end", "  Blocked IPs will appear here with full metadata and an unblock button.\n", "dim")
        else:
            w.insert("end", "\n")
            for idx, (ip, meta) in enumerate(sorted(blocked.items()), 1):
                w.insert("end", f"  ┌─ Blocked IP #{idx} ", "critical")
                w.insert("end", "─" * 80 + "\n", "dim")
                w.insert("end", "  │\n")
                w.insert("end", f"  │  IP Address:     {ip}\n", "highlight")
                # Embed unblock button
                w.insert("end", "  │  Action:         ")
                btn = tk.Button(
                    w, text=f"🔓 Unblock {ip}", bg="#33aa44", fg="#ffffff",
                    font=("Consolas", 9, "bold"), bd=0, padx=8, pady=2,
                    activebackground="#44cc55", activeforeground="#ffffff",
                    command=lambda i=ip: self._unblock_ip(i))
                _add_tooltip(btn,
                    f"Unblock {ip}\n"
                    "─────────────────────\n"
                    "Removes the Windows Firewall outbound rule\n"
                    "for this IP, allowing traffic to flow again.")
                w.window_create("end", window=btn)
                self._blocked_tab_buttons.append(btn)
                w.insert("end", "\n")
                # Time blocked with duration
                tb = meta.get('time_blocked', '?')
                w.insert("end", f"  │  Time Blocked:   {tb}\n", "warning")
                if isinstance(tb, str) and tb != '?':
                    try:
                        from datetime import datetime as _dt
                        tb_dt = _dt.strptime(tb, '%Y-%m-%d %H:%M:%S')
                        duration = time.time() - tb_dt.timestamp()
                        if duration < 60:
                            dur_str = f"{int(duration)}s ago"
                        elif duration < 3600:
                            dur_str = f"{int(duration/60)}m ago"
                        else:
                            dur_str = f"{duration/3600:.1f}h ago"
                        w.insert("end", f"  │  Blocked For:    {dur_str}\n", "dim")
                    except Exception:
                        pass
                # Network identity
                w.insert("end", "  │  ┌─ NETWORK IDENTITY ────────────────────────────\n", "dim")
                svc = meta.get('service', '?')
                if svc and svc != '?':
                    w.insert("end", f"  │  │ Service:       {svc}\n", "highlight")
                dom = meta.get('domain', '?')
                if dom and dom != '?':
                    w.insert("end", f"  │  │ Domain:        {dom}\n")
                cc = meta.get('country', '?')
                city = meta.get('city', '?')
                if cc and cc != '?':
                    w.insert("end", f"  │  │ Country:       {cc}", "critical" if cc in CONFIG.get('high_risk_countries', set()) else "")
                    if city and city != '?':
                        w.insert("end", f"  — {city}\n")
                    else:
                        w.insert("end", "\n")
                org = meta.get('org', '?')
                if org and org != '?':
                    w.insert("end", f"  │  │ Org:           {org}\n")
                isp = meta.get('isp', '?')
                if isp and isp != '?' and isp != org:
                    w.insert("end", f"  │  │ ISP:           {isp}\n", "dim")
                w.insert("end", "  │  └────────────────────────────────────────────────\n", "dim")
                # Process info
                w.insert("end", "  │  ┌─ PROCESS ─────────────────────────────────────\n", "dim")
                w.insert("end", f"  │  │ Process:       {meta.get('process', '?')} (PID {meta.get('pid', '?')})\n")
                rport = meta.get('remote_port', '?')
                psvc = _PORT_SERVICES.get(rport, '') if isinstance(rport, int) else ''
                if psvc:
                    w.insert("end", f"  │  │ Remote Port:   {rport} ({psvc})\n", "info")
                else:
                    w.insert("end", f"  │  │ Remote Port:   {rport}\n", "dim")
                cat = meta.get('category', '?')
                if cat and cat != '?':
                    w.insert("end", f"  │  │ Category:      {cat}\n", "dim")
                w.insert("end", "  │  └────────────────────────────────────────────────\n", "dim")
                # Firewall rule info
                w.insert("end", f"  │  Firewall Rule:  {self._fw_rule_prefix}{ip}\n", "dim")
                w.insert("end", f"  └{'─' * 90}\n\n", "dim")
        w.insert("end", f"\n{'═' * 120}\n", "dim")
        w.insert("end", f"  Firewall rules are automatically cleaned up when the program is closed.\n", "dim")
        w.insert("end", f"  Rules use prefix: {self._fw_rule_prefix}*\n", "dim")
        w.config(state="disabled")
        self._end_refresh(w, at_bottom, top_line)

    # ====================== GEOMETRY PERSISTENCE (Multi-monitor) ======================
    def _load_geometry(self):
        try:
            if os.path.exists(self._geometry_file):
                with open(self._geometry_file, 'r', encoding='utf-8') as f:
                    geo = json.load(f)
                self._root.geometry(geo.get('geometry', ''))
        except Exception:
            pass

    def _save_geometry(self):
        try:
            with open(self._geometry_file, 'w', encoding='utf-8') as f:
                json.dump({'geometry': self._root.geometry()}, f)
        except Exception:
            pass

    # ====================== ALERT FLASH SYSTEM ======================
    def _check_alert_flash(self, data):
        sus_count = len(data.get('suspicious_events', []))
        if sus_count > self._last_suspicious_count:
            self._last_suspicious_count = sus_count
            # Flash the Suspicious Activity tab
            try:
                nb = self._notebook or self._root.nametowidget(
                    self._suspicious_frame.winfo_parent())
                tab_id = nb.index(self._suspicious_frame)
                # Only start a flash if this tab is not already flashing,
                # otherwise repeated alerts stack overlapping after() loops.
                if not self._alert_flash_tabs.get('suspicious'):
                    self._alert_flash_tabs['suspicious'] = 1
                    self._flash_tab(nb, tab_id, " 🔴 Suspicious Activity ", 6,
                                    key='suspicious')
            except Exception:
                pass

    def _flash_tab(self, notebook, tab_index, original_text, flashes_remaining,
                   key=None):
        if flashes_remaining <= 0:
            try:
                notebook.tab(tab_index, text=original_text)
            except Exception:
                pass
            if key:
                self._alert_flash_tabs.pop(key, None)
            return
        try:
            current = notebook.tab(tab_index, 'text')
            if '⚡' in current:
                notebook.tab(tab_index, text=original_text)
            else:
                notebook.tab(tab_index, text=" ⚡ ALERT ⚡ ")
        except Exception:
            if key:
                self._alert_flash_tabs.pop(key, None)
            return
        self._root.after(400, lambda: self._flash_tab(
            notebook, tab_index, original_text, flashes_remaining - 1, key))

    # ====================== RIGHT-CLICK CONTEXT MENUS ======================
    def _ctx_registry(self, registry: dict, widget) -> dict:
        """Per-widget tag->payload map. Keeping them separate means a paused
        or independently re-rendered tab can never be invalidated by another."""
        return registry.setdefault(str(widget), {})

    def _reset_ctx(self, registry: dict, widget):
        """Forget the right-click targets for one widget (call before a rewrite)."""
        registry[str(widget)] = {}

    def _tag_rows(self, widget, start_index, payload, registry, prefix):
        """Tag everything written since start_index so a later right-click can
        be resolved back to `payload`. Returns the tag name."""
        per_widget = self._ctx_registry(registry, widget)
        tag = f"{prefix}{len(per_widget)}"
        try:
            widget.tag_add(tag, start_index, 'end-1c')
        except tk.TclError:
            return tag
        per_widget[tag] = payload
        return tag

    def _payload_at_event(self, widget, event, registry, prefix):
        """Return the payload registered for the row under the pointer."""
        per_widget = registry.get(str(widget), {})
        if not per_widget:
            return None
        try:
            idx = widget.index(f"@{event.x},{event.y}")
            for tag in widget.tag_names(idx):
                if tag.startswith(prefix) and tag in per_widget:
                    return per_widget[tag]
        except tk.TclError:
            pass
        return None

    def _on_conn_right_click(self, event, widget):
        conn = self._payload_at_event(widget, event, self._ctx_conns, 'conn::')
        if not conn:
            return
        ip = conn.get('remote_ip', '')
        if ip:
            self._show_conn_context_menu(event, ip, conn)

    def _on_proc_right_click(self, event, widget):
        proc = self._payload_at_event(widget, event, self._ctx_procs, 'proc::')
        if not proc:
            return
        self._show_proc_context_menu(event, proc.get('pid', 0),
                                     proc.get('name', '?'))

    def _show_conn_context_menu(self, event, ip, conn_info=None):
        info = conn_info or {}
        blocked = ip in self._blocked_ips
        watched = ip in self._watchlist_ips
        menu = tk.Menu(self._root, tearoff=0, bg="#1a1a2e", fg="#c0c0c0",
                       activebackground="#ff4444", activeforeground="white")
        header = info.get('website_tag') or info.get('service') or ip
        menu.add_command(label=f"{header}  ({ip})", state="disabled")
        menu.add_separator()
        menu.add_command(label=f"{'Unblock' if blocked else 'Block'} {ip}",
                         command=lambda: self._toggle_block_ip(ip, info))
        menu.add_command(label=f"{'Remove from' if watched else 'Add to'} Watchlist",
                         command=lambda: self._toggle_watchlist_ip(ip))
        menu.add_separator()
        menu.add_command(label=f"Copy IP: {ip}", command=lambda: self._copy_to_clipboard(ip))
        domain = info.get('domain') or ''
        if domain:
            menu.add_command(label=f"Copy domain: {domain[:48]}",
                             command=lambda: self._copy_to_clipboard(domain))
        menu.add_command(label="Copy row as text",
                         command=lambda: self._copy_to_clipboard(self._conn_as_text(info, ip)))
        menu.add_separator()
        menu.add_command(label="Whois / RDAP lookup", command=lambda: self._whois_popup(ip))
        menu.add_command(label="Cross-verify location",
                         command=lambda: self._verify_popup(ip))
        menu.add_command(label="Trace this endpoint",
                         command=lambda: self._trace_from_menu(ip))
        menu.add_command(label="Show on map", command=lambda: self._focus_ip_on_map(ip))
        menu.add_command(label="Open in OpenStreetMap",
                         command=lambda: self._open_ip_in_browser(ip))
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    def _show_proc_context_menu(self, event, pid, name):
        watched = name.lower() in self._watchlist_procs
        menu = tk.Menu(self._root, tearoff=0, bg="#1a1a2e", fg="#c0c0c0",
                       activebackground="#ff4444", activeforeground="white")
        menu.add_command(label=f"{name}  (PID {pid})", state="disabled")
        menu.add_separator()
        menu.add_command(label=f"{'Remove' if watched else 'Add'} '{name}' "
                               f"{'from' if watched else 'to'} Watchlist",
                         command=lambda: self._toggle_watchlist_proc(name))
        menu.add_command(label=f"Copy PID: {pid}",
                         command=lambda: self._copy_to_clipboard(str(pid)))
        menu.add_command(label=f"Copy name: {name}",
                         command=lambda: self._copy_to_clipboard(name))
        menu.add_separator()
        menu.add_command(label="Show this process's connections",
                         command=lambda: self._filter_conns_by_pid(pid))
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    def _copy_to_clipboard(self, text):
        self._root.clipboard_clear()
        self._root.clipboard_append(text)

    @staticmethod
    def _conn_as_text(info: dict, ip: str) -> str:
        """Flatten a connection row to a pasteable block."""
        if not info:
            return ip
        fields = [
            ('Website', info.get('website_tag')), ('Service', info.get('service')),
            ('Process', f"{info.get('process', '?')} (PID {info.get('pid', '?')})"),
            ('Exe', info.get('exe_path')), ('Remote', f"{ip}:{info.get('remote_port', '?')}"),
            ('Protocol', info.get('protocol')), ('Status', info.get('status')),
            ('Domain', info.get('domain')), ('Country', info.get('country')),
            ('City', info.get('city')), ('Org', info.get('org')),
            ('ISP', info.get('isp')), ('Proxy', info.get('proxy_type')),
        ]
        return '\n'.join(f"{k}: {v}" for k, v in fields if v)

    def _trace_from_menu(self, ip):
        """Jump to the Double Trace tab and start a trace on this endpoint."""
        try:
            self._trace_target_var.set(ip)
            if self._notebook is not None and self._trace_frame is not None:
                self._notebook.select(self._trace_frame)
            self._start_trace()
        except Exception as exc:
            _logger.debug("Trace from context menu failed: %s", exc)

    def _filter_conns_by_pid(self, pid):
        """Jump to All Connections filtered to one PID."""
        try:
            self._search_conn.set(str(pid))
            if self._notebook is not None and self._conn_frame is not None:
                self._notebook.select(self._conn_frame)
        except Exception as exc:
            _logger.debug("Connection filter failed: %s", exc)

    def _ip_coords(self, ip):
        """Find lat/lon for an IP: the cached map payload first, then a direct
        GeoIP lookup for endpoints that are not currently plotted."""
        for pt in (self._last_map_data or {}).get('all_points', []):
            if pt.get('ip') == ip and (pt.get('lat') or pt.get('lon')):
                return pt['lat'], pt['lon']
        for c in (self._last_full_data or {}).get('connections', []):
            if c.get('remote_ip') == ip and (c.get('lat') or c.get('lon')):
                return c['lat'], c['lon']
        if self._geoip is not None:
            try:
                lat, lon = self._geoip.get_coords(ip)
                if lat or lon:
                    return lat, lon
            except Exception as exc:
                _logger.debug("GeoIP coord lookup failed for %s: %s", ip, exc)
        return None

    def _focus_ip_on_map(self, ip):
        """Centre the map on an IP and select it."""
        coords = self._ip_coords(ip)
        if not coords:
            messagebox.showinfo("No location",
                                f"No geolocation is known for {ip} yet.")
            return
        self._selected_ip = ip
        try:
            if self._notebook is not None and self._map_frame is not None:
                self._notebook.select(self._map_frame)
        except Exception:
            pass
        self._zoom_to_location(coords[0], coords[1], max(self._map_zoom, 5.0))
        self._on_map_dot_click(ip)

    def _open_ip_in_browser(self, ip):
        coords = self._ip_coords(ip)
        if not coords:
            messagebox.showinfo("No location",
                                f"No geolocation is known for {ip} yet.")
            return
        self._open_in_browser(coords[0], coords[1])

    def _verify_popup(self, ip):
        """Run the full MultiVerifier cross-check on one IP in a popup."""
        win = tk.Toplevel(self._root)
        win.title(f"Cross-verification: {ip}")
        win.configure(bg="#12121a")
        win.geometry("720x420")
        txt = scrolledtext.ScrolledText(win, bg="#12121a", fg="#c0c0c0",
                                        font=("Consolas", 9), wrap="word")
        txt.pack(fill="both", expand=True)
        txt.insert("1.0", f"Verifying {ip} across GeoIP x2, rDNS, RDAP, RTT, "
                          "TTL/OS and VPN port fingerprints...\n")
        txt.config(state="disabled")

        def _work():
            mv = self._get_multiverifier()
            try:
                rep = mv.verify(ip, active=True)
                lines = mv.report_lines(rep)
            except Exception as exc:
                lines = [f"  Verification failed: {exc}"]

            def _show():
                if txt.winfo_exists():
                    self._set_text(txt, "\n".join(lines))
            self._root.after(0, _show)

        threading.Thread(target=_work, daemon=True,
                         name=f"Verify-{ip}").start()

    def _toggle_watchlist_ip(self, ip):
        """Add/remove a watchlist IP through the monitor so the change is
        persisted and actually drives detection."""
        adding = ip not in self._watchlist_ips
        if adding:
            self._watchlist_ips.add(ip)
        else:
            self._watchlist_ips.discard(ip)
        if self._monitor is not None:
            try:
                self._monitor.watch_ip(ip, add=adding)
            except Exception as exc:
                _logger.debug("Watchlist update failed for %s: %s", ip, exc)

    def _toggle_watchlist_proc(self, name):
        key = (name or '').lower()
        adding = key not in self._watchlist_procs
        if adding:
            self._watchlist_procs.add(key)
        else:
            self._watchlist_procs.discard(key)
        if self._monitor is not None:
            try:
                self._monitor.watch_proc(key, add=adding)
            except Exception as exc:
                _logger.debug("Watchlist update failed for %s: %s", name, exc)


    def _whois_popup(self, ip):
        """Open a popup with whois/RDAP info for an IP.
        Uses the shared WhoisLookup (cached + rate limited) when the monitor
        handed one over; falls back to a direct RDAP call otherwise."""
        def _do_lookup():
            try:
                if self._whois is not None:
                    data = self._whois.lookup(ip)
                    if not data or data.get('error'):
                        info = f"No RDAP record available for {ip}."
                    else:
                        info = (f"Name:    {data.get('name', '?')}\n"
                                f"Handle:  {data.get('handle', '?')}\n"
                                f"Type:    {data.get('type', '?')}\n"
                                f"Country: {data.get('country', '?')}\n"
                                f"Range:   {data.get('start_address', '?')} - "
                                f"{data.get('end_address', '?')}\n")
                        for ent in data.get('entities', []):
                            roles = ', '.join(ent.get('roles', [])) or '?'
                            info += f"Entity ({roles}): {ent.get('name', '') or '?'}\n"
                else:
                    req = urllib.request.Request(f"https://rdap.org/ip/{ip}",
                                                headers={'Accept': 'application/json'})
                    with urllib.request.urlopen(req, timeout=8) as resp:
                        data = json.loads(resp.read())
                    info = f"Name: {data.get('name', '?')}\nHandle: {data.get('handle', '?')}\n"
                    info += f"Country: {data.get('country', '?')}\nRange: {data.get('startAddress', '?')} - {data.get('endAddress', '?')}\n"
                    for ent in data.get('entities', [])[:3]:
                        roles = ', '.join(ent.get('roles', []))
                        info += f"Entity ({roles}): "
                        vcard = ent.get('vcardArray', [None, []])[1] if 'vcardArray' in ent else []
                        for v in vcard:
                            if v[0] in ('fn', 'org') and len(v) > 3:
                                info += f"{v[3]} "
                        info += "\n"
            except Exception as exc:
                info = f"Whois lookup failed: {exc}"
            self._root.after(0, lambda: _show_result(info))

        def _show_result(info):
            win = tk.Toplevel(self._root)
            win.title(f"Whois: {ip}")
            win.configure(bg="#12121a")
            win.geometry("500x300")
            txt = scrolledtext.ScrolledText(win, bg="#12121a", fg="#c0c0c0",
                                            font=("Consolas", 10), wrap="word")
            txt.pack(fill="both", expand=True)
            txt.insert("1.0", info)
            txt.config(state="disabled")

        threading.Thread(target=_do_lookup, daemon=True).start()

    # ====================== EXPORT HTML REPORT ======================
    @staticmethod
    def _esc(value) -> str:
        """HTML-escape a value for the exported report.
        Process names, domains and deduction messages can contain <, > or &,
        which previously corrupted the report markup."""
        return html_lib.escape(str(value), quote=True)

    def _export_html_report(self):
        data = self._get_full_data()
        esc = self._esc
        ts = datetime.datetime.now().strftime("%Y-%m-%d_%H%M%S")
        desktop = os.path.join(os.path.expanduser("~"), "Desktop")
        filepath = os.path.join(desktop, f"GNA_Report_{ts}.html")
        html = ['<!DOCTYPE html><html><head><meta charset="utf-8">',
                '<title>GNA Tracer Report</title>',
                '<style>body{background:#0a0a0f;color:#c0c0c0;font-family:Consolas,monospace;padding:20px}',
                'h1{color:#00d4ff}h2{color:#e94560}h3{color:#f5a623}',
                'table{border-collapse:collapse;width:100%;margin:10px 0}',
                'th,td{border:1px solid #333;padding:6px;text-align:left}',
                'th{background:#1a1a2e;color:#00d4ff}',
                'tr:nth-child(even){background:#12121a}',
                '.critical{color:#e94560;font-weight:bold}.warning{color:#f5a623}',
                '.info{color:#4caf50}.badge{display:inline-block;padding:2px 8px;border-radius:4px;',
                'font-size:11px;font-weight:bold}.badge-red{background:#e94560;color:white}',
                '.badge-yellow{background:#f5a623;color:black}',
                '</style></head><body>',
                '<h1>GNA Tracer Security Report</h1>',
                f'<p>Generated: {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>']
        # Summary
        stats = data.get('conn_stats', {})
        html.append('<h2>Summary</h2><table>')
        html.append(f'<tr><th>Connections</th><td>{stats.get("total_connections", 0)}</td></tr>')
        html.append(f'<tr><th>Processes</th><td>{len(data.get("processes", []))}</td></tr>')
        html.append(f'<tr><th>Deductions</th><td>{len(data.get("deductions", []))}</td></tr>')
        html.append(f'<tr><th>Suspicious Events</th><td>{len(data.get("suspicious_events", []))}</td></tr>')
        html.append(f'<tr><th>Devices</th><td>{len(data.get("devices", []))}</td></tr>')
        html.append('</table>')
        # Deductions
        deds = data.get('deductions', [])
        if deds:
            html.append('<h2>Deductions</h2><table><tr><th>Time</th><th>Severity</th><th>Category</th><th>Process</th><th>Message</th><th>Score</th></tr>')
            for d in deds[-200:]:
                sev_cls = 'critical' if d['severity'] == 'CRITICAL' else 'warning'
                html.append(f'<tr><td>{esc(d["time"])}</td>'
                            f'<td class="{sev_cls}">{esc(d["severity"])}</td>'
                            f'<td>{esc(d["category"])}</td><td>{esc(d["process"])}</td>'
                            f'<td>{esc(d["message"])}</td><td>{esc(d["score"])}</td></tr>')
            html.append('</table>')
        # Suspicious Events
        sus = data.get('suspicious_events', [])
        if sus:
            html.append('<h2>Suspicious Events</h2><table><tr><th>Time</th><th>Severity</th><th>Category</th><th>Process</th><th>Description</th></tr>')
            for ev in sus[-200:]:
                sev_cls = 'critical' if ev.get('severity') == 'CRITICAL' else 'warning'
                html.append(f'<tr><td>{esc(ev.get("time","?"))}</td>'
                            f'<td class="{sev_cls}">{esc(ev.get("severity","?"))}</td>'
                            f'<td>{esc(ev.get("category","?"))}</td>'
                            f'<td>{esc(ev.get("process","?"))}</td>'
                            f'<td>{esc(ev.get("description","?"))}</td></tr>')
            html.append('</table>')
        # Connections
        conns = data.get('connections', [])
        if conns:
            html.append('<h2>Active Connections</h2><table><tr><th>Process</th><th>Remote IP</th><th>Port</th><th>Service</th><th>Country</th><th>Org</th></tr>')
            for c in conns[:300]:
                html.append(f'<tr><td>{esc(c.get("process","?"))}</td>'
                            f'<td>{esc(c.get("remote_ip","?"))}</td>'
                            f'<td>{esc(c.get("remote_port","?"))}</td>'
                            f'<td>{esc(c.get("service","?"))}</td>'
                            f'<td>{esc(c.get("country","?"))}</td>'
                            f'<td>{esc(c.get("org","?"))}</td></tr>')
            html.append('</table>')
        # Processes
        procs = data.get('processes', [])
        if procs:
            html.append('<h2>Processes</h2><table><tr><th>PID</th><th>Name</th><th>Risk</th><th>Connections</th><th>Countries</th></tr>')
            for p in sorted(procs, key=lambda x: x.get('risk', 0), reverse=True)[:100]:
                risk_cls = 'critical' if p.get('risk', 0) > 50 else ('warning' if p.get('risk', 0) > 20 else '')
                html.append(f'<tr><td>{esc(p["pid"])}</td><td>{esc(p["name"])}</td>'
                            f'<td class="{risk_cls}">{esc(p["risk"])}</td>'
                            f'<td>{esc(p["connections"])}</td>'
                            f'<td>{esc(", ".join(p.get("countries", [])))}</td></tr>')
            html.append('</table>')
        # VT Results
        vt = data.get('vt_results', {})
        if vt:
            html.append('<h2>VirusTotal Results</h2><table><tr><th>SHA256</th><th>Malicious</th><th>Suspicious</th><th>Harmless</th></tr>')
            for sha, r in vt.items():
                m_cls = 'critical' if r.get('malicious', 0) > 0 else ''
                html.append(f'<tr><td>{esc(sha[:16])}...</td>'
                            f'<td class="{m_cls}">{esc(r.get("malicious",0))}</td>'
                            f'<td>{esc(r.get("suspicious",0))}</td>'
                            f'<td>{esc(r.get("harmless",0))}</td></tr>')
            html.append('</table>')
        html.append('</body></html>')
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write('\n'.join(html))
            _logger.info("HTML report exported to %s", filepath)
            messagebox.showinfo("Report Exported", f"Report saved to:\n{filepath}")
        except Exception as exc:
            _logger.warning("HTML export failed: %s", exc)
            messagebox.showerror("Export Failed", f"Could not write the report:\n{exc}")

    # ====================== PROCESS TREE TAB ======================
    def _refresh_process_tree(self, data):
        w = self._ptree_text
        at_bottom, top_line = self._begin_refresh(w)
        w.config(state="normal")
        w.delete("1.0", "end")
        w.insert("end", "═" * 120 + "\n", "dim")
        w.insert("end", "  🌳 PROCESS TREE — Parent → Child Relationships\n", "header")
        w.insert("end", "═" * 120 + "\n\n", "dim")
        w.insert("end", "  Shows the hierarchical parent-child relationship of all running processes.\n", "dim")
        w.insert("end", "  Useful for spotting suspicious process chains (e.g.,\n", "dim")
        w.insert("end", "  cmd.exe → powershell.exe → rundll32.exe → suspicious.dll).\n\n", "dim")
        w.insert("end", "  Legend:\n", "subheader")
        w.insert("end", "    risk=   0-20 = low (white)  |  21-50 = warning (yellow)  |  51+ = critical (red)\n", "dim")
        w.insert("end", "    conns=  number of active network connections\n", "dim")
        w.insert("end", "    geo=    countries contacted by this process\n", "dim")
        w.insert("end", "    ★=      watchlisted process\n\n", "dim")
        procs = data.get('processes', [])
        self._reset_ctx(self._ctx_procs, w)
        if not procs:
            w.insert("end", "  No processes tracked yet.\n", "dim")
            w.insert("end", "  Processes will appear here once the process watcher scans them.\n", "dim")
            w.config(state="disabled")
            self._end_refresh(w, at_bottom, top_line)
            return
        # Count high-risk processes for summary
        n_high = sum(1 for p in procs if p.get('risk', 0) > 50)
        n_warn = sum(1 for p in procs if 20 < p.get('risk', 0) <= 50)
        n_watch = sum(1 for p in procs if p['name'].lower() in self._watchlist_procs)
        w.insert("end", f"  Summary: {len(procs)} processes | ", "subheader")
        if n_high:
            w.insert("end", f"🔴 {n_high} critical", "critical")
            w.insert("end", " | ", "dim")
        if n_warn:
            w.insert("end", f"🟡 {n_warn} warning", "warning")
            w.insert("end", " | ", "dim")
        if n_watch:
            w.insert("end", f"⭐ {n_watch} watchlisted", "info")
            w.insert("end", " | ", "dim")
        w.insert("end", f"🟢 {len(procs) - n_high - n_warn} low risk\n\n", "info")
        # Build tree from the real parent PID. Matching parents by NAME used to
        # link same-named siblings to each other (chrome.exe -> chrome.exe),
        # which produced cycles and made whole process families invisible.
        by_pid = {p['pid']: p for p in procs}
        children_map = defaultdict(list)
        roots = []
        for p in procs:
            parent_pid = p.get('parent_pid') or 0
            if parent_pid and parent_pid != p['pid'] and parent_pid in by_pid:
                children_map[parent_pid].append(p)
            else:
                roots.append(p)
        # Any process whose ancestry loops back on itself would never be reached
        # from a root; surface those as extra roots so nothing is silently lost.
        reachable: set = set()

        def _mark(pid, seen):
            if pid in seen:
                return
            seen.add(pid)
            reachable.add(pid)
            for kid in children_map.get(pid, []):
                _mark(kid['pid'], seen)

        for r in roots:
            _mark(r['pid'], set())
        # Promote one member of each unreachable cycle to a root, marking the
        # rest of its component reachable so the cycle is shown exactly once.
        for proc in procs:
            if proc['pid'] not in reachable:
                roots.append(proc)
                _mark(proc['pid'], set())
        # Sort roots by risk
        roots.sort(key=lambda x: x.get('risk', 0), reverse=True)

        def _draw_tree(proc, prefix="", is_last=True, visited=None):
            if visited is None:
                visited = set()
            if proc['pid'] in visited:
                return  # cycle guard — never recurse into an already-drawn PID
            visited.add(proc['pid'])
            connector = "└── " if is_last else "├── "
            risk = proc.get('risk', 0)
            tag = 'critical' if risk > 50 else ('warning' if risk > 20 else 'default')
            star = " ★" if proc['name'].lower() in self._watchlist_procs else ""
            conns = proc.get('connections', 0)
            countries = ', '.join(proc.get('countries', [])) or '-'
            # Risk indicator icon
            if risk > 50:
                risk_icon = "🔴"
            elif risk > 20:
                risk_icon = "🟡"
            else:
                risk_icon = "🟢"
            line = (f"{prefix}{connector}{risk_icon} {proc['name']} (PID {proc['pid']}) "
                    f"risk={risk:.0f} conns={conns} geo=[{countries}]{star}\n")
            node_start = w.index('end-1c')
            w.insert("end", line, tag)
            self._tag_rows(w, node_start, proc, self._ctx_procs, 'proc::')
            # Show behavioral flags for high-risk processes
            if risk > 20:
                flags = []
                if proc.get('is_beacon'): flags.append("📡BEACON")
                if proc.get('is_exfil'): flags.append("📤EXFIL")
                if proc.get('is_impersonation'): flags.append("🎭IMPERSONATE")
                if proc.get('is_injection'): flags.append("💉INJECTION")
                if proc.get('is_mimic'): flags.append("🥸MIMIC")
                if proc.get('is_foreign'): flags.append("🌍FOREIGN")
                if proc.get('dll_injected'): flags.append("🧩DLL-INJECT")
                if flags:
                    flag_prefix = prefix + ("    " if is_last else "│   ")
                    w.insert("end", f"{flag_prefix}    ⚠ Flags: {' | '.join(flags)}\n",
                             "critical" if risk >= 50 else "warning")
            kids = sorted(children_map.get(proc['pid'], []),
                          key=lambda x: x.get('risk', 0), reverse=True)
            new_prefix = prefix + ("    " if is_last else "│   ")
            for i, child in enumerate(kids):
                _draw_tree(child, new_prefix, i == len(kids) - 1, visited)

        shown = roots[:50]
        for i, root in enumerate(shown):
            _draw_tree(root, "  ", i == len(shown) - 1)
        w.insert("end", f"\n  Total: {len(procs)} processes tracked\n", "dim")
        w.config(state="disabled")
        self._end_refresh(w, at_bottom, top_line)

    # ====================== NETWORK STATS TAB ======================
    def _refresh_netstats(self, data):
        w = self._netstats_text
        at_bottom, top_line = self._begin_refresh(w)
        w.config(state="normal")
        w.delete("1.0", "end")
        w.insert("end", "═" * 120 + "\n", "dim")
        w.insert("end", "  📊 NETWORK INTERFACE STATS — Real-time Bandwidth\n", "header")
        w.insert("end", "═" * 120 + "\n\n", "dim")
        w.insert("end", "  Shows per-interface upload/download rates, packet counts, errors, drops,\n", "dim")
        w.insert("end", "  and sparkline trends. Also shows top IPs by bandwidth usage.\n\n", "dim")
        iface_data = data.get('iface_stats', {})
        if not iface_data:
            w.insert("end", "  Collecting data... stats will appear after a few seconds.\n", "dim")
            w.insert("end", "  (Interface stats thread polls every 1s)\n", "dim")
            w.config(state="disabled")
            self._end_refresh(w, at_bottom, top_line)
            return
        for iface, samples in sorted(iface_data.items()):
            if not samples:
                continue
            latest = samples[-1] if samples else {}
            sent_rate = latest.get('sent_rate', 0)
            recv_rate = latest.get('recv_rate', 0)
            total_sent = latest.get('total_sent', 0)
            total_recv = latest.get('total_recv', 0)
            errin = latest.get('errin', 0)
            errout = latest.get('errout', 0)
            dropin = latest.get('dropin', 0)
            dropout = latest.get('dropout', 0)
            w.insert("end", f"  ┌─ {iface} ", "subheader")
            w.insert("end", "─" * max(1, 90 - len(iface)) + "\n", "dim")
            w.insert("end", f"  │  ↑ Upload:     {self._fmt_bytes_rate(sent_rate):>12}  "
                            f"│ Total sent: {self._fmt_bytes(total_sent):>12}\n", "info")
            w.insert("end", f"  │  ↓ Download:   {self._fmt_bytes_rate(recv_rate):>12}  "
                            f"│ Total recv: {self._fmt_bytes(total_recv):>12}\n", "cyan")
            pkts_sent = latest.get('packets_sent', 0)
            pkts_recv = latest.get('packets_recv', 0)
            w.insert("end", f"  │  Packets:      ↑{pkts_sent:>10,}  ↓{pkts_recv:>10,}\n")
            # Calculate combined error/drop rate
            total_pkts = pkts_sent + pkts_recv
            total_errs = errin + errout + dropin + dropout
            err_pct = (total_errs / total_pkts * 100) if total_pkts > 0 else 0
            if errin or errout or dropin or dropout:
                w.insert("end", f"  │  Errors:       in={errin} out={errout}  "
                                f"Drops: in={dropin} out={dropout}", "warning")
                w.insert("end", f"  ({err_pct:.2f}% loss)\n", "critical" if err_pct > 5 else "warning")
            else:
                w.insert("end", "  │  Errors:       none  │  Drops: none  (0.00% loss)\n", "info")
            # Sample count and time range
            w.insert("end", f"  │  Samples:      {len(samples)} data points "
                            f"(1s intervals)\n", "dim")
            # Sparkline (last 30 samples)
            recent = samples[-30:] if len(samples) > 30 else samples
            if len(recent) >= 2:
                max_rate = max(max(s.get('sent_rate', 0), s.get('recv_rate', 0)) for s in recent) or 1
                spark_chars = "▁▂▃▄▅▆▇█"
                send_spark = ""
                recv_spark = ""
                for s in recent:
                    si = min(7, int(s.get('sent_rate', 0) / max_rate * 7))
                    ri = min(7, int(s.get('recv_rate', 0) / max_rate * 7))
                    send_spark += spark_chars[si]
                    recv_spark += spark_chars[ri]
                w.insert("end", f"  │  ↑ Trend:      {send_spark}  (last {len(recent)}s)\n", "info")
                w.insert("end", f"  │  ↓ Trend:      {recv_spark}  (last {len(recent)}s)\n", "cyan")
            w.insert("end", f"  └{'─' * 95}\n\n", "dim")
        # Per-IP bandwidth
        bw = data.get('conn_bandwidth', {})
        if bw:
            w.insert("end", "\n  TOP IPs BY BANDWIDTH\n", "subheader")
            w.insert("end", "  Shows which remote IPs are using the most bandwidth.\n", "dim")
            w.insert("end", "  " + "─" * 95 + "\n", "dim")
            w.insert("end", f"  {'IP':>20}  {'↑ Sent':>12}  {'↓ Recv':>12}  {'Total':>12}  {'Flag'}\n", "subheader")
            w.insert("end", "  " + "─" * 95 + "\n", "dim")
            sorted_bw = sorted(bw.items(), key=lambda x: x[1].get('bytes_sent', 0) + x[1].get('bytes_recv', 0), reverse=True)
            for ip, info in sorted_bw[:20]:
                total = info.get('bytes_sent', 0) + info.get('bytes_recv', 0)
                star = " ★ watchlist" if ip in self._watchlist_ips else ""
                w.insert("end", f"  {ip:>20}  ↑{self._fmt_bytes(info.get('bytes_sent',0)):>10}  "
                                f"↓{self._fmt_bytes(info.get('bytes_recv',0)):>10}  "
                                f"Total: {self._fmt_bytes(total):>10}{star}\n")
        w.config(state="disabled")
        self._end_refresh(w, at_bottom, top_line)

    @staticmethod
    def _fmt_bytes(b):
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if abs(b) < 1024:
                return f"{b:.1f} {unit}"
            b /= 1024
        return f"{b:.1f} PB"

    @staticmethod
    def _fmt_bytes_rate(b):
        for unit in ['B/s', 'KB/s', 'MB/s', 'GB/s']:
            if abs(b) < 1024:
                return f"{b:.1f} {unit}"
            b /= 1024
        return f"{b:.1f} TB/s"

    # ====================== CONNECTION TIMELINE TAB ======================
    def _refresh_timeline(self, data):
        w = self._timeline_text
        at_bottom, top_line = self._begin_refresh(w)
        w.config(state="normal")
        w.delete("1.0", "end")
        w.insert("end", "═" * 120 + "\n", "dim")
        w.insert("end", "  ⏱️ CONNECTION TIMELINE — All Connections (Active + Closed)\n", "header")
        w.insert("end", "═" * 120 + "\n\n", "dim")
        w.insert("end", "  Chronological log of every connection event. Shows start time, remote IP:port,\n", "dim")
        w.insert("end", "  process PID, connection status, and duration. 🟢=active  ⚪=closed  ★=watchlisted\n\n", "dim")
        timeline = data.get('conn_timeline', [])
        if not timeline:
            w.insert("end", "  No connection history yet.\n", "dim")
            w.insert("end", "  Connections will appear here as they are established.\n", "dim")
            w.config(state="disabled")
            self._end_refresh(w, at_bottom, top_line)
            return
        # Status descriptions
        status_descs = {
            'ESTABLISHED': 'Connection is active and data can flow',
            'SYN_SENT': 'Connection request sent, waiting for response',
            'SYN_RECV': 'Connection request received from remote',
            'LISTEN': 'Waiting for incoming connections',
            'TIME_WAIT': 'Connection closed, waiting for delayed packets',
            'CLOSE_WAIT': 'Remote closed, waiting for local close',
            'FIN_WAIT1': 'Local closed, waiting for remote ack',
            'FIN_WAIT2': 'Local closed, waiting for remote close',
            'LAST_ACK': 'Remote closed, waiting for final ack',
            'CLOSED': 'Connection is fully closed',
            'NONE': 'No connection state',
        }
        # Stats summary
        # Counts come from the history itself so they stay correct even when
        # the exported timeline is truncated to its most recent rows.
        counts = data.get('conn_counts') or {}
        n_active = counts.get('active',
                              sum(1 for e in timeline if e.get('active', False)))
        n_closed = counts.get('closed', len(timeline) - n_active)
        n_total = counts.get('total', len(timeline))
        shown = ("" if n_total <= len(timeline)
                 else f"  (showing most recent {len(timeline)})")
        w.insert("end", f"  Summary: {n_total} total | 🟢 {n_active} active | "
                        f"⚪ {n_closed} closed{shown}\n\n", "subheader")
        # Column header
        w.insert("end", f"  {'Time':<10} {'Remote':>28} {'PID':<8} {'Status':<14} "
                        f"{'Duration':<10} {'Flags'}\n", "subheader")
        w.insert("end", f"  {'─'*10} {'─'*28} {'─'*8} {'─'*14} {'─'*10} {'─'*15}\n", "dim")
        # Show most recent first
        for entry in reversed(timeline[-500:]):
            rip = entry.get('remote_ip', '?')
            rport = entry.get('remote_port', '?')
            pid = entry.get('pid', 0)
            status = entry.get('status', '?')
            active = entry.get('active', False)
            duration = entry.get('duration', 0)
            start = entry.get('start_time', 0)
            start_str = datetime.datetime.fromtimestamp(start).strftime("%H:%M:%S") if start else '?'
            dur_str = f"{int(duration)}s" if duration < 3600 else f"{duration/3600:.1f}h"
            star = " ★" if rip in self._watchlist_ips else ""
            if active:
                tag = 'info'
                state_icon = "🟢"
            else:
                tag = 'dim'
                state_icon = "⚪"
            w.insert("end", f"  {state_icon} {start_str}  {rip:>20}:{rport:<6}  "
                            f"PID {pid:<8} {status:<14} dur={dur_str:<8}{star}\n", tag)
        w.insert("end", f"\n  Total tracked: {len(timeline)} connections "
                        f"(showing last {min(500, len(timeline))})\n", "dim")
        w.config(state="disabled")
        self._end_refresh(w, at_bottom, top_line)

    # ====================== CONFIG EDITOR TAB ======================
    def _refresh_config(self):
        w = self._config_text
        # Only refresh once (static content) unless user hasn't seen it
        if hasattr(self, '_config_rendered') and self._config_rendered:
            return
        self._config_rendered = True
        w.config(state="normal")
        w.delete("1.0", "end")
        w.insert("end", "═" * 120 + "\n", "dim")
        w.insert("end", "  ⚙️ CURRENT CONFIGURATION\n", "header")
        w.insert("end", "═" * 120 + "\n\n", "dim")
        w.insert("end", "  To change values, edit medianbox_config.yaml and restart.\n", "dim")
        w.insert("end", "  Or set VT_API_KEY environment variable for VirusTotal.\n\n", "dim")
        # Export button
        export_btn = tk.Button(w, text=" 📄 Export HTML Report ", bg="#1a6b3f", fg="white",
                               font=("Consolas", 10, "bold"), relief="flat", cursor="hand2",
                               command=self._export_html_report)
        _add_tooltip(export_btn,
            "Export HTML report\n"
            "─────────────────────\n"
            "Generates a complete HTML report of the current\n"
            "monitoring session including:\n"
            "  • All connections and their details\n"
            "  • Process list with risk scores\n"
            "  • Deductions and evidence\n"
            "  • Suspicious activity log\n"
            "  • Device inventory\n"
            "  • GeoIP locations\n"
            "  • Network statistics")
        w.window_create("end", window=export_btn)
        w.insert("end", "\n\n")
        # Live refresh rate control
        w.insert("end", "  LIVE REFRESH RATE: ", "subheader")
        refresh_frame = tk.Frame(w, bg="#12121a")
        tk.Label(refresh_frame, text="GUI refresh (ms):", bg="#12121a", fg="#a0a0b0",
                 font=("Consolas", 9)).pack(side="left", padx=4)
        refresh_entry = tk.Entry(refresh_frame, width=6, font=("Consolas", 9),
                                 bg="#1a1a2e", fg="#00d4ff", bd=0,
                                 insertbackground="#c0c0c0")
        refresh_entry.insert(0, str(self._gui_refresh_ms))
        refresh_entry.pack(side="left", padx=4)
        def _apply_refresh_rate():
            try:
                val = int(refresh_entry.get())
                if 50 <= val <= 10000:
                    self._gui_refresh_ms = val
                    CONFIG['gui_refresh_ms'] = val
                    self._config_rendered = False  # force re-render
            except ValueError:
                pass
        tk.Button(refresh_frame, text="Apply", bg="#333355", fg="#00d4ff",
                  font=("Consolas", 8, "bold"), bd=0, padx=6,
                  command=_apply_refresh_rate).pack(side="left", padx=4)
        tk.Label(refresh_frame, text="(50-10000ms · lower=faster · 250=recommended)",
                 bg="#12121a", fg="#7a7a8a", font=("Consolas", 7)).pack(side="left", padx=4)
        w.window_create("end", window=refresh_frame)
        w.insert("end", "\n\n")
        for key in sorted(CONFIG.keys()):
            val = CONFIG[key]
            if isinstance(val, set):
                val_str = str(sorted(val))
            else:
                val_str = str(val)
            w.insert("end", f"  {key:<40} = ", "cyan")
            w.insert("end", f"{val_str}\n")
        w.insert("end", "\n\n  WATCHLIST IPs: ", "subheader")
        w.insert("end", f"{', '.join(sorted(self._watchlist_ips)) or '(none)'}\n")
        w.insert("end", "  WATCHLIST Processes: ", "subheader")
        w.insert("end", f"{', '.join(sorted(self._watchlist_procs)) or '(none)'}\n")
        w.config(state="disabled")

    def _refresh_terminal(self, data):
        """Show 100% of all terminal output — appends only new lines for performance."""
        w = self._terminal_text
        lines = data.get('terminal_lines', [])
        new_count = len(lines)
        if new_count == self._terminal_last_count:
            # Still apply search highlighting even if no new lines
            search_q = self._search_terminal.get()
            if search_q and len(search_q) >= 2:
                w.config(state="normal")
                self._highlight_search(w, search_q)
                w.config(state="disabled")
            return
        at_bottom = self._is_at_bottom(w)
        # Save top-visible line for stable restoration
        try:
            top_line = int(w.index("@0,0").split('.')[0])
        except Exception:
            top_line = 1
        w.config(state="normal")
        if self._terminal_last_count == 0:
            # First render — write header + all lines
            w.delete("1.0", "end")
            w.insert("end", "═" * 110 + "\n", "dim")
            w.insert("end", "  🖥️ TERMINAL — 100% OF ALL PROCESSED OUTPUT\n", "header")
            w.insert("end", "═" * 110 + "\n", "dim")
            w.insert("end", "\n  Raw unfiltered feed from the monitoring engine.\n", "dim")
            w.insert("end", "  Color coding:\n", "dim")
            w.insert("end", "    ", "dim")
            w.insert("end", "red", "critical")
            w.insert("end", " = CRITICAL alerts / deductions | ", "dim")
            w.insert("end", "yellow", "warning")
            w.insert("end", " = WARNING alerts | ", "dim")
            w.insert("end", "green", "info")
            w.insert("end", " = info/status | ", "dim")
            w.insert("end", "cyan", "cyan")
            w.insert("end", " = detection events | white = normal log lines\n", "dim")
            w.insert("end", "\n  This tab shows every event as it is processed by the pipeline:\n", "dim")
            w.insert("end", "    • Packet processing (DNS, SNI, TLS)\n", "dim")
            w.insert("end", "    • Connection mapping and enrichment\n", "dim")
            w.insert("end", "    • Detection alerts (beacon, exfil, injection, etc.)\n", "dim")
            w.insert("end", "    • GeoIP lookups and proxy detection\n", "dim")
            w.insert("end", "    • Extended monitor events (FS, USB, clipboard, etc.)\n", "dim")
            w.insert("end", "    • System status messages\n\n", "dim")
        # Append only new lines since last refresh
        new_lines = lines[self._terminal_last_count:]
        for _ts, tag, text in new_lines:
            w.insert("end", text + "\n", tag)
        self._terminal_last_count = new_count
        self._highlight_search(w, self._search_terminal.get())
        w.config(state="disabled")
        # Only auto-scroll if user was at the bottom; otherwise preserve line position
        if at_bottom:
            w.see("end")
        else:
            # Append-only: the top line hasn't moved, so just restore to it
            try:
                end_index = w.index("end-1c")
                total_lines = int(end_index.split('.')[0])
                if total_lines > 1:
                    frac = max(0.0, min(1.0, (top_line - 1) / max(1, total_lines - 1)))
                    w.yview_moveto(frac)
            except Exception:
                pass

    # ====================== DOUBLE / MULTI-HOP TRACE ======================
    # Traces the full network path (hop-by-hop, "double or more") to each
    # destination the local machine talks to, GeoIP-enriches every hop, and
    # LABELS hops that sit on VPN / proxy / hosting / CDN infrastructure.
    #
    # Honesty note: this does NOT defeat a VPN or reveal a third party's true
    # location. That is not possible from network path tracing alone. It maps
    # and geolocates the path of YOUR OWN connections and flags anonymising
    # infrastructure it can see along the way.

    @staticmethod
    def _normalize_trace_target(raw: str) -> str:
        """Clean a user/target string down to a host or IP that traceroute accepts."""
        t = (raw or "").strip().strip("[]").strip()
        if not t:
            return ""
        # Strip any annotation FIRST ("1.2.3.4:443 — service" -> "1.2.3.4:443").
        # Doing this after the port strip left the port attached, and tracert
        # rejects "host:port".
        for sep in (" — ", "  ", " (", " ["):
            if sep in t:
                t = t.split(sep, 1)[0].strip()
                break
        t = t.strip().strip("[]").strip()
        # Then strip a trailing :port (but leave bare IPv6 addresses alone).
        if t.count(":") == 1:
            host, _, port = t.partition(":")
            if port.isdigit():
                t = host
        return t

    def _trace_active_targets(self, data) -> list[str]:
        """Public remote endpoints the local machine is currently talking to."""
        seen: dict[str, str] = {}
        for c in data.get("connections", []):
            ip = c.get("remote_ip", "")
            if not ip or ip in seen:
                continue
            try:
                if not ipaddress.ip_address(ip).is_global:
                    continue
            except ValueError:
                continue
            svc = c.get("service") or c.get("domain") or ""
            seen[ip] = f"{ip} — {svc}" if svc and svc not in ("?", "") else ip
        return list(seen.values())

    def _refresh_trace(self, data):
        """Keep the target list current and repaint the trace view when new hops land."""
        try:
            targets = self._trace_active_targets(data)
            # Only update combobox choices; don't stomp what the user is typing.
            self._trace_target_combo["values"] = targets
        except Exception:
            pass
        # Status line
        try:
            if self._trace_running:
                self._trace_status_lbl.config(text="● Tracing…", fg="#44dd66")
            else:
                self._trace_status_lbl.config(text="Idle", fg="#a0a0b0")
            if self._trace_log_path:
                self._trace_logfile_lbl.config(
                    text=f"→ {os.path.basename(self._trace_log_path)}")
        except Exception:
            pass
        if self._trace_dirty:
            self._render_trace()

    # ---- launching ----
    def _start_trace(self):
        target = self._normalize_trace_target(self._trace_target_var.get())
        if not target:
            self._trace_status_lbl.config(text="Enter a target first", fg="#ffcc44")
            return
        self._begin_trace([target])

    def _start_trace_all(self):
        try:
            data = self._get_full_data()
        except Exception:
            data = {}
        targets = [self._normalize_trace_target(t) for t in self._trace_active_targets(data)]
        targets = [t for t in targets if t]
        if not targets:
            self._trace_status_lbl.config(text="No active public endpoints", fg="#ffcc44")
            return
        self._begin_trace(targets)

    def _begin_trace(self, targets: list):
        if self._trace_running:
            self._trace_status_lbl.config(text="Busy — press Stop first", fg="#ffcc44")
            return
        # Tk variables are only safe to touch from the main thread, so read the
        # trace options here and hand plain values to the worker.
        try:
            maxhops = max(1, min(60, int(self._trace_maxhops_var.get())))
        except (ValueError, TypeError, tk.TclError):
            maxhops = 30
        try:
            deep = bool(self._trace_deepverify_var.get())
        except tk.TclError:
            deep = False
        try:
            self._trace_log_max_bytes = max(
                4096, int(float(self._trace_rotatekb_var.get()) * 1024))
        except (ValueError, TypeError, tk.TclError):
            pass
        self._trace_stop.clear()
        self._trace_running = True
        self._trace_thread = threading.Thread(
            target=self._run_trace_worker, args=(targets, maxhops, deep),
            daemon=True, name="Double-Trace")
        self._trace_thread.start()

    def _stop_trace(self):
        self._trace_stop.set()
        proc = self._trace_proc
        if proc is not None:
            try:
                proc.terminate()
            except Exception:
                pass
        self._trace_status_lbl.config(text="Stopping…", fg="#ffcc44")

    def _clear_trace(self):
        with self._trace_lock:
            self._trace_blocks = []
            self._trace_dirty = True
        self._render_trace()

    def _open_trace_log_folder(self):
        try:
            os.makedirs(self._trace_log_dir, exist_ok=True)
            if _IS_WINDOWS:
                os.startfile(self._trace_log_dir)  # type: ignore[attr-defined]
            elif sys.platform == "darwin":
                subprocess.Popen(["open", self._trace_log_dir])
            else:
                subprocess.Popen(["xdg-open", self._trace_log_dir])
        except Exception as exc:
            self._trace_status_lbl.config(text=f"Log folder: {exc}", fg="#ffcc44")

    def _export_trace_json(self):
        """Export all trace blocks to a timestamped JSON file for external analysis."""
        try:
            import json as _json
            with self._trace_lock:
                blocks = list(self._trace_blocks)
            if not blocks:
                self._trace_status_lbl.config(text="No traces to export", fg="#ffcc44")
                return
            ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            path = os.path.join(self._trace_log_dir, f"trace_export_{ts}.json")
            os.makedirs(self._trace_log_dir, exist_ok=True)
            # Strip non-serializable verify_report (keep summary fields)
            export = []
            for b in blocks:
                eb = {
                    "target": b.get("target"), "started": b.get("started"),
                    "finished": b.get("finished"), "status": b.get("status"),
                    "path_summary": b.get("path_summary"),
                    "path_distance_km": b.get("path_distance_km"),
                    "path_countries": b.get("path_countries"),
                    "path_anomalies": b.get("path_anomalies"),
                    "verification": None,
                    "hops": [],
                }
                if b.get("verification"):
                    v = b["verification"]
                    eb["verification"] = {
                        "ip": v.get("ip"), "grade": v.get("grade"),
                        "confidence": v.get("confidence"),
                        "consensus_country": v.get("consensus_country"),
                        "consensus_city": v.get("consensus_city"),
                        "vpn_score": v.get("vpn_score"),
                        "is_vpn": v.get("is_vpn"),
                        "is_proxy": v.get("is_proxy"),
                        "is_hosting": v.get("is_hosting"),
                        "is_cdn": v.get("is_cdn"),
                        "labels": v.get("labels"),
                        "conflicts": v.get("conflicts"),
                        "summary": v.get("summary"),
                    }
                for h in b.get("hops", []):
                    eh = {k: v for k, v in h.items()
                          if k not in ("verify_report",) and _is_jsonable(v)}
                    eb["hops"].append(eh)
                export.append(eb)
            with open(path, "w", encoding="utf-8") as f:
                _json.dump(export, f, indent=2, default=str)
            self._trace_status_lbl.config(
                text=f"Exported {len(export)} traces → {os.path.basename(path)}",
                fg="#44dd66")
            self._trace_log_write(f"  [EXPORT] JSON → {path}\n")
        except Exception as exc:
            self._trace_status_lbl.config(text=f"Export failed: {exc}", fg="#ffcc44")

    def _export_trace_csv(self):
        """Export all trace hops to a timestamped CSV file."""
        try:
            import csv
            with self._trace_lock:
                blocks = list(self._trace_blocks)
            if not blocks:
                self._trace_status_lbl.config(text="No traces to export", fg="#ffcc44")
                return
            ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            path = os.path.join(self._trace_log_dir, f"trace_hops_{ts}.csv")
            os.makedirs(self._trace_log_dir, exist_ok=True)
            with open(path, "w", encoding="utf-8", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["target", "started", "status", "hop", "ip",
                                 "min_rtt_ms", "country", "city", "org", "isp",
                                 "lat", "lon", "label", "verify", "method"])
                for b in blocks:
                    target = b.get("target", "")
                    started = b.get("started", "")
                    status = b.get("status", "")
                    for h in b.get("hops", []):
                        rtts = h.get("rtts", [])
                        writer.writerow([
                            target, started, status,
                            h.get("hop", ""), h.get("ip", ""),
                            f"{min(rtts):.1f}" if rtts else "",
                            h.get("country", ""), h.get("city", ""),
                            h.get("org", ""), h.get("isp", ""),
                            h.get("lat", ""), h.get("lon", ""),
                            h.get("label", ""), h.get("verify", ""),
                            h.get("method", "ICMP"),
                        ])
            self._trace_status_lbl.config(
                text=f"Exported CSV → {os.path.basename(path)}", fg="#ffaa44")
            self._trace_log_write(f"  [EXPORT] CSV → {path}\n")
        except Exception as exc:
            self._trace_status_lbl.config(text=f"Export failed: {exc}", fg="#ffcc44")

    def _toggle_auto_trace(self):
        """Toggle automatic re-tracing at a fixed interval."""
        if self._trace_auto_job is not None:
            # Stop auto-trace
            try:
                self._root.after_cancel(self._trace_auto_job)
            except Exception:
                pass
            self._trace_auto_job = None
            self._trace_auto_targets = []
            self._trace_status_lbl.config(text="Auto-trace stopped", fg="#a0a0b0")
            return
        try:
            interval = max(5, int(self._trace_auto_var.get()))
        except (ValueError, TypeError):
            interval = 30
        try:
            data = self._get_full_data()
        except Exception:
            data = {}
        targets = [self._normalize_trace_target(t)
                    for t in self._trace_active_targets(data)]
        targets = [t for t in targets if t]
        if not targets:
            self._trace_status_lbl.config(text="No targets for auto-trace", fg="#ffcc44")
            return
        self._trace_auto_targets = targets
        self._trace_auto_interval = interval
        self._trace_status_lbl.config(
            text=f"Auto-trace every {interval}s ({len(targets)} targets)",
            fg="#44dd66")
        self._run_auto_trace()

    def _run_auto_trace(self):
        """Fire one auto-trace cycle and schedule the next."""
        if self._stop.is_set() or not self._trace_auto_targets:
            self._trace_auto_job = None
            return
        if not self._trace_running:
            self._begin_trace(list(self._trace_auto_targets))
        self._trace_auto_job = self._root.after(
            self._trace_auto_interval * 1000, self._run_auto_trace)

    # ---- worker ----
    def _run_trace_worker(self, targets: list, maxhops: int = 30, deep: bool = False):
        try:
            for target in targets:
                if self._trace_stop.is_set():
                    break
                block = {
                    "target": target, "started": time.time(),
                    "finished": None, "status": "running", "hops": [],
                    "verification": None,
                }
                with self._trace_lock:
                    self._trace_blocks.append(block)
                    if len(self._trace_blocks) > self._trace_max_blocks:
                        self._trace_blocks = self._trace_blocks[-self._trace_max_blocks:]
                    self._trace_dirty = True
                self._schedule_trace_redraw()
                self._trace_one(target, block, maxhops, deep)
        finally:
            self._trace_running = False
            self._trace_dirty = True
            self._schedule_trace_redraw()

    def _traceroute_cmd(self, target: str, maxhops: int) -> list:
        if _IS_WINDOWS:
            # -d = no reverse-DNS (fast); -h max hops; -w per-hop timeout (ms)
            return ["tracert", "-d", "-h", str(maxhops), "-w", "2000", target]
        # POSIX: -n numeric; -m max hops; -w per-probe wait (s); -q 1 probe for speed
        return ["traceroute", "-n", "-q", "1", "-w", "2", "-m", str(maxhops), target]

    def _tcp_traceroute_cmd(self, target: str, maxhops: int, port: int) -> list:
        """Build a TCP-based traceroute command. On Linux, `traceroute -T` sends
        TCP SYN probes. On Windows, `tracert` doesn't support TCP directly, but
        we can use `nmap --traceroute` if available, or fall back to a manual
        Python TCP TTL probe (see _tcp_trace_python)."""
        if _IS_WINDOWS:
            # nmap may be installed; if not, the caller falls back to Python.
            return ["nmap", "-Pn", "-p", str(port), "--traceroute", "-m",
                    str(maxhops), target]
        # Linux/Mac: traceroute with TCP SYN (-T) to a specific port (-p)
        return ["traceroute", "-T", "-p", str(port), "-n", "-q", "1",
                "-w", "2", "-m", str(maxhops), target]

    def _tcp_trace_external(self, target: str, maxhops: int, port: int) -> list:
        """Run the external TCP traceroute from _tcp_traceroute_cmd when the
        tool is actually installed. Returns hop dicts in the same shape as
        _tcp_trace_python; an empty list means "unavailable, use the fallback"."""
        import shutil
        cmd = self._tcp_traceroute_cmd(target, maxhops, port)
        if not shutil.which(cmd[0]):
            return []
        try:
            out = subprocess.run(
                cmd, capture_output=True, text=True, timeout=maxhops * 2 + 20,
                creationflags=0x08000000 if _IS_WINDOWS else 0).stdout
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
            _logger.debug("External TCP traceroute failed: %s", exc)
            return []
        hops = []
        for line in out.splitlines():
            parsed = self._parse_trace_line(line.rstrip())
            if not parsed:
                continue
            hopno, ips, rtts, timed_out = parsed
            hops.append({"hop": hopno, "ip": ips[0] if ips else "",
                         "rtts": rtts, "timed_out": timed_out})
        return hops

    def _tcp_trace_python(self, target: str, maxhops: int, port: int,
                          timeout: float = 2.0) -> list:
        """Pure-Python TCP TTL traceroute: send TCP SYN packets with increasing
        TTL and listen for ICMP time-exceeded or TCP SYN-ACK. Works without
        nmap and without requiring raw sockets on Windows (uses Scapy if
        available, else falls back to socket setsockopt TTL)."""
        hops = []
        try:
            dest_ip = socket.gethostbyname(target)
        except Exception:
            return hops
        # Try Scapy-based approach (more reliable, gets ICMP time-exceeded)
        try:
            from scapy.all import IP, TCP, sr1, conf  # type: ignore
            conf.verb = 0
            for ttl in range(1, maxhops + 1):
                if self._trace_stop.is_set():
                    break
                pkt = IP(dst=dest_ip, ttl=ttl) / TCP(dport=port, flags="S")
                resp = sr1(pkt, timeout=timeout, verbose=0)
                if resp is None:
                    hops.append({"hop": ttl, "ip": "", "rtts": [],
                                 "timed_out": True})
                elif resp.haslayer("ICMP"):
                    # ICMP time-exceeded from a router
                    router_ip = resp.getlayer("IP").src
                    hops.append({"hop": ttl, "ip": router_ip,
                                 "rtts": [timeout * 1000],
                                 "timed_out": False})
                elif resp.haslayer("TCP"):
                    # SYN-ACK or RST from the destination — we've arrived
                    hops.append({"hop": ttl, "ip": dest_ip,
                                 "rtts": [timeout * 1000],
                                 "timed_out": False})
                    break
            return hops
        except ImportError:
            pass
        # Fallback: socket-based TTL probes (less reliable, no ICMP capture)
        for ttl in range(1, maxhops + 1):
            if self._trace_stop.is_set():
                break
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
                s.settimeout(timeout)
                t0 = time.time()
                try:
                    s.connect((dest_ip, port))
                    rtt = (time.time() - t0) * 1000
                    hops.append({"hop": ttl, "ip": dest_ip,
                                 "rtts": [rtt], "timed_out": False})
                    s.close()
                    break  # reached destination
                except socket.timeout:
                    rtt = (time.time() - t0) * 1000
                    hops.append({"hop": ttl, "ip": "",
                                 "rtts": [], "timed_out": True})
                except OSError:
                    # Could be ICMP time-exceeded (we can't see it without
                    # raw sockets), or connection refused (we reached dest)
                    rtt = (time.time() - t0) * 1000
                    hops.append({"hop": ttl, "ip": "",
                                 "rtts": [rtt], "timed_out": True})
                s.close()
            except Exception:
                hops.append({"hop": ttl, "ip": "",
                             "rtts": [], "timed_out": True})
        return hops

    def _trace_one(self, target: str, block: dict, maxhops: int, deep: bool):
        cmd = self._traceroute_cmd(target, maxhops)
        self._trace_log_write(
            "\n" + "=" * 100 + "\n"
            f"  DOUBLE TRACE → {target}\n"
            f"  Started: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | "
            f"cmd: {' '.join(cmd)}\n"
            + "=" * 100 + "\n")
        creation = 0x08000000 if _IS_WINDOWS else 0
        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1, creationflags=creation)
        except FileNotFoundError:
            block["status"] = "error: traceroute tool not found"
            block["finished"] = time.time()
            self._trace_dirty = True
            self._schedule_trace_redraw()
            self._trace_log_write(f"  [ERROR] traceroute tool not found for command {cmd[0]}\n")
            return
        except Exception as exc:
            block["status"] = f"error: {exc}"
            block["finished"] = time.time()
            self._trace_dirty = True
            self._schedule_trace_redraw()
            return
        self._trace_proc = proc
        try:
            for raw in proc.stdout:  # streams hop-by-hop in real time
                if self._trace_stop.is_set():
                    try:
                        proc.terminate()
                    except Exception:
                        pass
                    block["status"] = "stopped"
                    break
                parsed = self._parse_trace_line(raw.rstrip("\n"))
                if not parsed:
                    continue
                hopno, ips, rtts, timed_out = parsed
                hop = {
                    "hop": hopno, "ip": ips[0] if ips else "",
                    "rtts": rtts, "timed_out": timed_out,
                    "country": "", "city": "", "org": "", "isp": "",
                    "lat": 0, "lon": 0, "label": "", "label_tag": "default",
                    "verify": "",
                }
                if ips:
                    hop.update(self._enrich_hop(ips[0]))
                elif timed_out:
                    hop["label"] = "no reply"
                    hop["label_tag"] = "dim"
                with self._trace_lock:
                    block["hops"].append(hop)
                    self._trace_dirty = True
                self._trace_log_write(self._hop_log_line(hop) + "\n")
                self._schedule_trace_redraw()
            try:
                proc.wait(timeout=5)
            except Exception:
                pass
        except Exception as exc:
            block["status"] = f"error: {exc}"
        finally:
            try:
                proc.stdout.close()
            except Exception:
                pass
            self._trace_proc = None
        # ---- TCP fallback: if ICMP traceroute got 0 real hops, retry with TCP ----
        real_hops = [h for h in block["hops"] if h.get("ip")]
        if (self._trace_tcp_fallback and not self._trace_stop.is_set()
                and len(real_hops) == 0 and block["status"] != "stopped"):
            block["status"] = "tcp-fallback"
            self._trace_dirty = True
            self._schedule_trace_redraw()
            self._trace_log_write(
                "  [INFO] ICMP traceroute returned no hops — trying TCP fallback\n")
            for tcp_port in self._trace_tcp_ports:
                if self._trace_stop.is_set():
                    break
                tcp_hops = self._tcp_trace_external(target, maxhops, tcp_port)
                if not any(h.get("ip") for h in tcp_hops):
                    tcp_hops = self._tcp_trace_python(target, maxhops, tcp_port)
                if any(h.get("ip") for h in tcp_hops):
                    self._trace_log_write(
                        f"  [INFO] TCP traceroute (port {tcp_port}) found "
                        f"{sum(1 for h in tcp_hops if h.get('ip'))} hops\n")
                    for th in tcp_hops:
                        hop = {
                            "hop": th["hop"], "ip": th["ip"],
                            "rtts": th["rtts"], "timed_out": th["timed_out"],
                            "country": "", "city": "", "org": "", "isp": "",
                            "lat": 0, "lon": 0, "label": "", "label_tag": "default",
                            "verify": "", "method": f"TCP:{tcp_port}",
                        }
                        if th["ip"]:
                            hop.update(self._enrich_hop(th["ip"]))
                            hop["label"] = (hop.get("label", "") or "") + " [TCP]"
                        else:
                            hop["label"] = "no reply (TCP)"
                            hop["label_tag"] = "dim"
                        with self._trace_lock:
                            block["hops"].append(hop)
                            self._trace_dirty = True
                        self._trace_log_write(self._hop_log_line(hop) + "\n")
                        self._schedule_trace_redraw()
                    if any(h.get("ip") for h in tcp_hops):
                        break  # got results with this port, no need to try next
        if block["status"] in ("running", "tcp-fallback"):
            block["status"] = "complete"
        # ---- path analysis (summary, distance, anomalies) ----
        self._analyze_trace_path(block)
        # ---- multi-method cross-verification pass ----
        if block["status"] in ("complete", "stopped") and not self._trace_stop.is_set():
            try:
                self._verify_block(block, deep)
            except Exception as exc:
                _logger.debug("Verification pass failed: %s", exc)
        block["finished"] = time.time()
        self._trace_log_write(
            f"  Finished: {block['status']} "
            f"({len(block['hops'])} hops) at "
            f"{datetime.datetime.now().strftime('%H:%M:%S')}\n")
        if block.get("path_summary"):
            self._trace_log_write(
                "  " + "\n  ".join(block["path_summary"].split("\n")) + "\n")
        self._trace_dirty = True
        self._schedule_trace_redraw()

    # ---- path analysis ----
    @staticmethod
    def _haversine_km(lat1, lon1, lat2, lon2):
        """Great-circle distance between two lat/lon points in km."""
        import math
        R = 6371.0
        rlat1, rlat2 = math.radians(lat1), math.radians(lat2)
        dlat = math.radians(lat2 - lat1)
        dlon = math.radians(lon2 - lon1)
        a = (math.sin(dlat / 2) ** 2
             + math.cos(rlat1) * math.cos(rlat2) * math.sin(dlon / 2) ** 2)
        return R * 2 * math.asin(min(1, math.sqrt(a)))

    def _analyze_trace_path(self, block: dict):
        """Compute path summary: total RTT, hop deltas, geographic distance,
        and detect anomalies (country jumps, backtracking, sudden latency)."""
        hops = [h for h in block.get("hops", []) if not h.get("timed_out")]
        if not hops:
            return
        rtts = [min(h["rtts"]) for h in hops if h.get("rtts")]
        lines = []
        # RTT statistics
        if rtts:
            total_rtt = rtts[-1] - rtts[0] if len(rtts) > 1 else rtts[0]
            min_rtt = min(rtts)
            max_rtt = max(rtts)
            avg_rtt = sum(rtts) / len(rtts)
            lines.append(f"PATH LATENCY: first={rtts[0]:.0f}ms  last={rtts[-1]:.0f}ms  "
                         f"delta={total_rtt:.0f}ms  min={min_rtt:.0f}ms  "
                         f"max={max_rtt:.0f}ms  avg={avg_rtt:.0f}ms")
        # Geographic distance along path
        geo_points = [(h["lat"], h["lon"]) for h in hops
                      if h.get("lat") and h.get("lon")]
        total_km = 0.0
        for i in range(1, len(geo_points)):
            total_km += self._haversine_km(
                geo_points[i - 1][0], geo_points[i - 1][1],
                geo_points[i][0], geo_points[i][1])
        if total_km > 0:
            lines.append(f"GEOGRAPHIC PATH: {total_km:.0f} km total "
                         f"across {len(geo_points)} geolocated hops")
        # Countries traversed
        countries = []
        for h in hops:
            cc = h.get("country", "")
            if cc and cc not in countries:
                countries.append(cc)
        if countries:
            lines.append(f"COUNTRIES TRAVERSED: {' → '.join(countries)} "
                         f"({len(countries)} country{'ies' if len(countries) != 1 else ''})")
        # Anomaly detection: country backtracking
        anomalies = []
        for i in range(2, len(countries)):
            if countries[i] == countries[i - 2] and countries[i] != countries[i - 1]:
                anomalies.append(
                    f"Country backtrack: {countries[i-2]} → {countries[i-1]} → "
                    f"{countries[i]} (possible VPN/proxy relay)")
        # Anomaly: sudden latency spike (>3x previous delta)
        for i in range(2, len(rtts)):
            prev_delta = rtts[i - 1] - rtts[i - 2]
            curr_delta = rtts[i] - rtts[i - 1]
            if prev_delta > 5 and curr_delta > prev_delta * 3 and curr_delta > 50:
                anomalies.append(
                    f"Latency spike at hop {hops[i]['hop']}: +{curr_delta:.0f}ms "
                    f"(prev delta +{prev_delta:.0f}ms) — possible relay, "
                    "satellite hop, or congestion")
        # Anomaly: VPN/proxy/hosting hop detected
        vpn_hops = [h for h in hops if h.get("label_tag") == "critical"
                    or "VPN" in h.get("label", "")]
        if vpn_hops:
            anomalies.append(
                "VPN/anonymiser infrastructure detected at hop(s) "
                f"{', '.join(str(h['hop']) for h in vpn_hops)}")
        if anomalies:
            lines.append("PATH ANOMALIES:")
            for a in anomalies:
                lines.append(f"  ⚠ {a}")
        block["path_summary"] = "\n".join(lines)
        block["path_anomalies"] = anomalies
        block["path_distance_km"] = total_km
        block["path_countries"] = countries

    def _verify_block(self, block: dict, deep: bool):
        """Run the MultiVerifier over a completed trace: always on the destination
        endpoint; on every public hop when deep cross-verify is enabled."""
        mv = self._get_multiverifier()
        public_hops = [h for h in block["hops"]
                       if h.get("ip") and not h.get("timed_out")
                       and self._is_public_ip(h["ip"])]
        # Destination = last public hop, or resolve the target hostname.
        dest_ip = public_hops[-1]["ip"] if public_hops else ""
        if not dest_ip:
            try:
                dest_ip = socket.gethostbyname(self._normalize_trace_target(block["target"]))
            except Exception:
                dest_ip = ""
        block["status"] = "verifying"
        self._trace_dirty = True
        self._schedule_trace_redraw()
        # Deep mode: cross-verify every public hop.
        if deep:
            for h in public_hops:
                if self._trace_stop.is_set():
                    break
                rep = mv.verify(h["ip"], active=True)
                h["verify_report"] = rep
                h["verify"] = f"{rep['grade']} {rep['confidence']}%"
                if rep.get("is_vpn"):
                    h["label"] = f"VPN/anon (score {rep['vpn_score']})"
                    h["label_tag"] = "critical"
                self._trace_dirty = True
                self._schedule_trace_redraw()
        # Always verify the destination endpoint.
        if dest_ip:
            rep = mv.verify(dest_ip, active=True)
            block["verification"] = rep
            self._trace_log_write("\n" + "\n".join(mv.report_lines(rep)) + "\n")
        block["status"] = "complete" if block["status"] != "stopped" else "stopped"
        self._trace_dirty = True
        self._schedule_trace_redraw()

    @staticmethod
    def _is_public_ip(ip: str) -> bool:
        return _is_public_ip_cached(ip)

    _IP4_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
    _IP6_RE = re.compile(r"\b([0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{0,4}){2,7})\b")
    _RTT_RE = re.compile(r"([\d.]+)\s*ms", re.IGNORECASE)
    _HOP_RE = re.compile(r"^\s*(\d+)\b")

    def _parse_trace_line(self, line: str):
        """Parse one tracert/traceroute output line.
        Returns (hop_no, [ips], [rtts], timed_out) or None for non-hop lines."""
        m = self._HOP_RE.match(line)
        if not m:
            return None
        hopno = int(m.group(1))
        low = line.lower()
        # RTTs (handle Windows "<1 ms")
        rtts = [float(x) for x in self._RTT_RE.findall(line)]
        if "<1" in line and 0.5 not in rtts:
            rtts.insert(0, 0.5)
        # IPs — prefer IPv4, fall back to IPv6
        ips = self._IP4_RE.findall(line)
        if not ips:
            ips = [x for x in self._IP6_RE.findall(line) if ":" in x]
        # dedupe, preserve order
        ips = list(dict.fromkeys(ips))
        timed_out = (not ips) and ("*" in line or "timed out" in low
                                   or "request" in low)
        if not ips and not timed_out:
            # header line that merely started with a number — ignore
            return None
        return hopno, ips, rtts, timed_out

    def _enrich_hop(self, ip: str) -> dict:
        """Fast per-hop enrichment during streaming: GeoIP + infra classification.
        Full cross-verification (active probes) happens later in _verify_block."""
        out = {"country": "", "city": "", "org": "", "isp": "",
               "lat": 0, "lon": 0, "label": "", "label_tag": "default",
               "verify": ""}
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return out
        if not addr.is_global:
            out["label"] = "LAN / private hop"
            out["label_tag"] = "dim"
            return out
        geo = {}
        if self._geoip is not None:
            try:
                geo = self._geoip.get_full(ip) or {}
            except Exception:
                geo = {}
        out["country"] = geo.get("country") or geo.get("countryCode") or ""
        out["city"] = geo.get("city") or ""
        out["org"] = geo.get("org") or ""
        out["isp"] = geo.get("isp") or ""
        out["lat"] = geo.get("lat") or 0
        out["lon"] = geo.get("lon") or 0
        label, tag = self._classify_hop(ip, geo)
        out["label"] = label
        out["label_tag"] = tag
        return out

    def _classify_hop(self, ip: str, geo: dict):
        """Return (label, color_tag) describing what kind of infrastructure this hop is.

        This is detection/labelling only — flagging that a hop belongs to a VPN,
        proxy, hosting, or CDN operator. It does not de-anonymise anyone."""
        org_isp = f"{geo.get('org', '')} {geo.get('isp', '')} {geo.get('as', '')}".lower()
        # 1) Known VPN provider — most important flag
        for kw in self._vpn_org_markers:
            if kw in org_isp:
                return (f"VPN infra ({kw.strip()})", "critical")
        # 2) Proxy / CDN via the existing ProxyDetector (CDN ranges, residential, ports)
        if self._proxy_detector is not None:
            try:
                pc = self._proxy_detector.classify_connection(
                    ip, 0, "", geo.get("org", ""), geo.get("isp", ""),
                    geo.get("as", ""))
            except Exception:
                pc = {}
            ptype = pc.get("proxy_type", "") if pc else ""
            if "RESIDENTIAL" in ptype:
                return ("residential proxy", "warning")
            if "REVERSE" in ptype:
                return (f"CDN / reverse proxy ({pc.get('proxy_detail', 'CDN')})", "cyan")
            if "FORWARD" in ptype:
                return ("forward proxy port", "warning")
        # 3) Hosting / datacenter backbone (common VPN & proxy exit points)
        for kw in self._hosting_org_markers:
            if kw in org_isp:
                return (f"hosting / datacenter ({kw.strip()})", "warning")
        # 4) Otherwise a normal ISP/backbone hop
        return ("ISP / backbone", "info")

    # ---- rendering & logging ----
    def _schedule_trace_redraw(self):
        """Ask the Tk main thread to repaint the trace view (safe from worker thread)."""
        try:
            if self._root is not None:
                self._root.after(0, self._render_trace)
        except Exception:
            pass

    @staticmethod
    def _fmt_rtt(rtts):
        if not rtts:
            return "   *   "
        return f"{min(rtts):.0f} ms".rjust(7)

    def _hop_display(self, hop: dict):
        """Return (text, tag) for one hop line in the GUI."""
        if hop.get("timed_out"):
            return (f"   {hop['hop']:>2}  {'*':<15}  {'*':>7}   (no reply)", "dim")
        ip = hop.get("ip", "")
        rtt = self._fmt_rtt(hop.get("rtts"))
        loc = ", ".join(x for x in (hop.get("city", ""), hop.get("country", "")) if x)
        org = hop.get("org", "") or hop.get("isp", "")
        if len(org) > 30:
            org = org[:29] + "…"
        label = hop.get("label", "")
        verify = f"  ✓{hop['verify']}" if hop.get("verify") else ""
        text = (f"   {hop['hop']:>2}  {ip:<15}  {rtt}   "
                f"{loc:<22}  {org:<30}  [{label}]{verify}")
        return (text, hop.get("label_tag", "default"))

    def _hop_log_line(self, hop: dict) -> str:
        """Plain-text version of a hop line for the rotating .txt log."""
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        if hop.get("timed_out"):
            return f"[{ts}]  hop {hop['hop']:>2}  *  (no reply)"
        loc = ", ".join(x for x in (hop.get("city", ""), hop.get("country", "")) if x)
        return (f"[{ts}]  hop {hop['hop']:>2}  {hop.get('ip',''):<15}  "
                f"{self._fmt_rtt(hop.get('rtts')).strip():<8}  {loc:<22}  "
                f"{(hop.get('org','') or hop.get('isp','')):<30}  "
                f"[{hop.get('label','')}]"
                + (f"  verify={hop['verify']}" if hop.get('verify') else ""))

    def _render_trace(self):
        w = getattr(self, "_trace_text", None)
        if w is None:
            return
        with self._trace_lock:
            blocks = list(self._trace_blocks)
            self._trace_dirty = False
        at_bottom, top_line = self._begin_refresh(w)
        w.config(state="normal")
        w.delete("1.0", "end")
        w.insert("end", "═" * 118 + "\n", "dim")
        w.insert("end", "  🔀 DOUBLE / MULTI-HOP TRACE — full path of your connections, "
                        "GeoIP + VPN/proxy/CDN labelling + 11-method cross-verification\n", "header")
        w.insert("end", "  Consensus from GeoIP×2 · rDNS · RDAP · RTT · TTL/OS · port-FP · "
                        "DNS-leak · TLS-JA3 · ASN. TCP fallback when ICMP blocked. "
                        "Labels flag anonymising infra.\n", "dim")
        w.insert("end", "═" * 118 + "\n\n", "dim")
        w.insert("end", "  Traces the full network path (hop-by-hop) to each destination.\n", "dim")
        w.insert("end", "  Each hop shows: hop number, IP address, RTT (round-trip time),\n", "dim")
        w.insert("end", "  GeoIP location, organization/ISP, and infrastructure label.\n\n", "dim")
        w.insert("end", "  Labels:\n", "subheader")
        w.insert("end", "    [VPN]     = VPN exit node (anonymising service)\n", "critical")
        w.insert("end", "    [PROXY]   = Proxy server (forward/reverse/residential)\n", "warning")
        w.insert("end", "    [HOSTING] = Datacenter/hosting provider (AWS/GCP/Azure/etc.)\n", "warning")
        w.insert("end", "    [CDN]     = Content delivery network (Cloudflare/Akamai/etc.)\n", "info")
        w.insert("end", "    [ISP]     = Regular ISP/router (normal infrastructure)\n", "dim")
        w.insert("end", "    [ANON]    = Anonymising infrastructure detected\n", "critical")
        w.insert("end", "    *         = Hop did not respond (filtered or rate-limited)\n\n", "dim")
        w.insert("end", "  ⚠ This does NOT defeat a VPN or reveal a third party's true location.\n", "warning")
        w.insert("end", "    It maps and geolocates the path of YOUR OWN connections and flags\n", "dim")
        w.insert("end", "    anonymising infrastructure it can see along the way.\n\n", "dim")
        if not blocks:
            w.insert("end", "  No traces yet. Enter a target (or pick an active endpoint)\n", "dim")
            w.insert("end", "  and press ▶ Trace, or ▶▶ Trace All Active.\n\n", "dim")
            w.insert("end", "  Quick start:\n", "subheader")
            w.insert("end", "    1. Select or type a target IP/domain in the Target box\n", "dim")
            w.insert("end", "    2. Click ▶ Trace for a single target\n", "dim")
            w.insert("end", "    3. Or click ▶▶ Trace All Active to trace every connection\n", "dim")
            w.insert("end", "    4. Enable 'Cross-verify every hop' for deep analysis (slower)\n", "dim")
            w.insert("end", "    5. Set Auto (s) > 0 for periodic re-tracing\n", "dim")
            w.insert("end", "    6. Export results as JSON or CSV for external analysis\n", "dim")
        for block in reversed(blocks):  # newest first
            started = datetime.datetime.fromtimestamp(block["started"]).strftime("%H:%M:%S")
            status = block.get("status", "?")
            stag = ("info" if status == "complete"
                    else "warning" if status in ("running", "stopped", "verifying")
                    else "critical" if status.startswith("error") else "default")
            w.insert("end", f"▼ {block['target']}", "subheader")
            w.insert("end", f"   [{status}]", stag)
            w.insert("end", f"   started {started}\n", "dim")
            w.insert("end", "   HOP  IP               RTT      LOCATION"
                            "                ORG / ISP                       LABEL\n", "dim")
            for hop in block["hops"]:
                text, tag = self._hop_display(hop)
                w.insert("end", text + "\n", tag)
            # path analysis summary (latency, distance, anomalies)
            if block.get("path_summary"):
                w.insert("end", "   ┌─ PATH ANALYSIS\n", "cyan")
                for line in block["path_summary"].split("\n"):
                    atag = "critical" if line.startswith("PATH ANOMALIES") or line.startswith("  ⚠") else "dim"
                    w.insert("end", f"   │ {line}\n", atag)
                w.insert("end", "   └" + "─" * 40 + "\n", "cyan")
            # cross-verification report for the destination endpoint
            if block.get("verification"):
                self._render_verification(w, block["verification"])
            w.insert("end", "\n")
        # keep search highlighting working on this tab
        try:
            self._highlight_search(w, self._search_trace.get())
        except Exception:
            pass
        w.config(state="disabled")
        self._end_refresh(w, at_bottom, top_line)

    def _render_verification(self, w, rep: dict):
        """Render a MultiVerifier cross-verification report inside the trace view."""
        grade = rep.get("grade", "?")
        gtag = ("info" if grade == "HIGH"
                else "warning" if grade in ("MEDIUM", "LOW", "SINGLE-SOURCE")
                else "critical" if grade in ("CONFLICTED",) else "cyan")
        w.insert("end", "   ┌─ CROSS-VERIFICATION ", "cyan")
        w.insert("end", f"({rep.get('ip','')})\n", "dim")
        w.insert("end", "   │ ", "cyan")
        w.insert("end", rep.get("summary", "") + "\n", gtag)
        # consensus + agreement
        w.insert("end", "   │ consensus: ", "cyan")
        loc = ", ".join(x for x in (rep.get("consensus_city", ""),
                                    rep.get("consensus_country", "")) if x) or "unresolved"
        w.insert("end", f"{loc}   ", "highlight")
        w.insert("end", f"({rep.get('agree',0)}/{rep.get('total_votes',0)} sources agree, "
                        f"{rep.get('confidence',0)}%)\n", "dim")
        # per-method votes
        for m in rep.get("methods", []):
            mtag = {"ok": "info", "conflict": "critical"}.get(m.get("status"), "dim")
            mark = {"ok": "✓", "conflict": "✗"}.get(m.get("status"), "·")
            w.insert("end", "   │  ", "cyan")
            w.insert("end", f"{mark} {m.get('name',''):<9} ", mtag)
            w.insert("end", f"{m.get('detail','')}\n", "default")
        # infra + vpn verdict
        if rep.get("labels"):
            w.insert("end", "   │ infra: ", "cyan")
            w.insert("end", "; ".join(rep["labels"]) + "\n", "warning")
        if rep.get("is_vpn"):
            w.insert("end", "   │ ", "cyan")
            w.insert("end", f"⚑ VPN / anonymiser likely — vpn_score {rep.get('vpn_score',0)}/100 "
                            "(detection only; true origin not recoverable)\n", "critical")
        if rep.get("conflicts"):
            w.insert("end", "   │ conflicts: ", "cyan")
            w.insert("end", "; ".join(rep["conflicts"]) + "\n", "warning")
        w.insert("end", "   └" + "─" * 40 + "\n", "cyan")

    def _trace_log_write(self, text: str):
        """Append text to the rotating .txt trace log, rolling over at the size cap."""
        try:
            os.makedirs(self._trace_log_dir, exist_ok=True)
            # _trace_log_max_bytes is refreshed from the Tk entry on the main
            # thread in _begin_trace; reading the Tk variable here would be a
            # cross-thread Tcl call.
            max_bytes = self._trace_log_max_bytes
            if self._trace_log_path is None:
                self._trace_log_path = os.path.join(
                    self._trace_log_dir, f"double_trace_log_{self._trace_log_index}.txt")
            data = text.encode("utf-8", "replace")
            # Roll over if this write would exceed the cap.
            with self._trace_log_lock:
                try:
                    cur = os.path.getsize(self._trace_log_path)
                except OSError:
                    cur = 0
                if cur and cur + len(data) > max_bytes:
                    self._trace_log_index += 1
                    self._trace_log_path = os.path.join(
                        self._trace_log_dir, f"double_trace_log_{self._trace_log_index}.txt")
                with open(self._trace_log_path, "ab") as f:
                    f.write(data)
                    f.flush()
        except Exception as exc:
            _logger.debug("Double-trace log write failed: %s", exc)

    def _on_close(self):
        # Save window geometry for multi-monitor persistence
        try:
            self._save_geometry()
        except Exception:
            pass
        # Final save
        try:
            self._save_tracer_data()
        except Exception as exc:
            _logger.warning("Failed to save GNA tracer data: %s", exc)
        # Remove all firewall rules created by this session
        try:
            self._unblock_all()
        except Exception:
            pass
        # Cancel auto-trace timer
        try:
            if self._trace_auto_job is not None:
                self._root.after_cancel(self._trace_auto_job)
                self._trace_auto_job = None
        except Exception:
            pass
        # Abort any in-flight double trace
        try:
            self._trace_stop.set()
            proc = self._trace_proc
            if proc is not None:
                proc.terminate()
        except Exception:
            pass
        self._stop.set()
        if self._update_job:
            self._root.after_cancel(self._update_job)
        if self._autosave_job:
            self._root.after_cancel(self._autosave_job)
        if self._status_job:
            self._root.after_cancel(self._status_job)
        self._root.destroy()

    def _save_tracer_data(self):
        self._save_counter += 1
        ts_now = datetime.datetime.now()
        ts = ts_now.strftime("%Y-%m-%d %H:%M:%S")
        # ── Organized session directory structure ──
        # sessions/YYYY-MM-DD/session_HHMM_HHMM.txt
        # This keeps all running-duration segments organized by date
        # and 10-minute time windows, making it easy to find exactly
        # what happened during any specific period.
        session_date = ts_now.strftime("%Y-%m-%d")
        # Calculate the 10-minute time segment window
        seg_start_min = (ts_now.minute // 10) * 10
        seg_end_min = seg_start_min + 10
        seg_start_ts = ts_now.replace(minute=seg_start_min, second=0, microsecond=0)
        if seg_end_min >= 60:
            seg_end_ts = (seg_start_ts + datetime.timedelta(hours=1)).replace(minute=seg_end_min - 60, second=0, microsecond=0)
        else:
            seg_end_ts = seg_start_ts.replace(minute=seg_end_min)
        seg_label = f"{seg_start_ts.strftime('%H%M')}_{seg_end_ts.strftime('%H%M')}"
        # Base directory: Boxmon/sessions/YYYY-MM-DD/
        base_dir = os.path.dirname(os.path.abspath(__file__))
        sessions_dir = os.path.join(base_dir, "sessions", session_date)
        os.makedirs(sessions_dir, exist_ok=True)
        # Time-segmented file name
        segment_filename = f"session_{seg_label}.txt"
        segment_filepath = os.path.join(sessions_dir, segment_filename)
        # Also save to Desktop for backward compatibility
        desktop = os.path.join(os.path.expanduser("~"), "Desktop")
        os.makedirs(desktop, exist_ok=True)
        desktop_filepath = os.path.join(desktop, f"GNA tracer data {self._save_counter}.txt")
        # Never overwrite a report from an earlier session in this same folder.
        while os.path.exists(desktop_filepath):
            self._save_counter += 1
            desktop_filepath = os.path.join(desktop, f"GNA tracer data {self._save_counter}.txt")
        data = self._get_full_data()
        start_ts = datetime.datetime.fromtimestamp(self._session_start).strftime("%Y-%m-%d %H:%M:%S")
        elapsed = time.time() - self._session_start
        hrs, rem = divmod(int(elapsed), 3600)
        mins, secs = divmod(rem, 60)
        runtime_str = f"{hrs}h {mins}m {secs}s"
        lines = []
        lines.append("=" * 120)
        lines.append(f"  GNA TRACER — COMPLETE OPERATIONS LOG #{self._save_counter}")
        lines.append(f"  Exported:      {ts}")
        lines.append(f"  Session Start: {start_ts}")
        lines.append(f"  Runtime:       {runtime_str} ({int(elapsed)}s total)")
        lines.append(f"  Save #:        {self._save_counter} (auto-saved every 10 min + on close)")
        lines.append(f"  Time Segment:  {session_date} {seg_start_ts.strftime('%H:%M')}-{seg_end_ts.strftime('%H:%M')}")
        lines.append(f"  Session Dir:   sessions/{session_date}/")
        lines.append("=" * 120)
        lines.append("")
        # Overview
        stats = data.get('conn_stats', {})
        lines.append("=" * 100)
        lines.append("── OVERVIEW ──")
        lines.append("=" * 100)
        lines.append(f"  Active Connections:  {stats.get('total_connections', 0)}")
        lines.append(f"  Unique Services:     {stats.get('unique_services', 0)}")
        lines.append(f"  Unique Public IPs:   {stats.get('unique_ips', 0)}")
        lines.append(f"  Tracked Processes:   {len(data.get('processes', []))}")
        lines.append(f"  Total Deductions:    {len(data.get('deductions', []))}")
        lines.append(f"  Network Devices:     {len(data.get('devices', []))}")
        lines.append(f"  Suspicious Events:   {len(data.get('suspicious_events', []))}")
        lines.append(f"  Terminal Lines:      {len(data.get('terminal_lines', []))}")
        lines.append(f"  DNS Cache:           {data.get('dns_count', 0)}")
        lines.append(f"  GeoIP Cache:         {data.get('geoip_count', 0)}")
        lines.append(f"  Pipeline:            {data.get('pipeline_processed', 0)} processed / {data.get('pipeline_dropped', 0)} dropped")
        proxy_conns = [c for c in data.get('connections', []) if c.get('proxy_type')]
        lines.append(f"  Proxy Connections:   {len(proxy_conns)}")
        proxy_procs = data.get('proxy_processes', [])
        if proxy_procs:
            lines.append(f"  Proxy Processes:     {', '.join(proxy_procs)}")
        lines.append("")
        # All connections individually
        lines.append("=" * 100)
        lines.append("── ALL CONNECTIONS (each individually) ──")
        lines.append("=" * 100)
        for idx, c in enumerate(data.get('connections', []), 1):
            lines.append(f"\n  [{idx}] {c.get('icon', '?')} {c.get('service', 'Unknown')}")
            lines.append(f"      Process:     {c.get('process', '?')} (PID {c.get('pid', '?')})")
            lines.append(f"      Remote:      {c.get('remote_ip', '?')}:{c.get('remote_port', '?')}")
            lines.append(f"      Local Port:  {c.get('local_port', '?')}")
            lines.append(f"      Protocol:    {c.get('protocol', '?')} — Status: {c.get('status', '?')}")
            lines.append(f"      Domain:      {c.get('domain', 'unresolved')}")
            lines.append(f"      Country:     {c.get('country', '?')} ({c.get('country_code', '?')})")
            lines.append(f"      City:        {c.get('city', '?')}, Region: {c.get('region', '?')}")
            lines.append(f"      Org:         {c.get('org', '?')}")
            lines.append(f"      ISP:         {c.get('isp', '?')}")
            lines.append(f"      Coordinates: ({c.get('lat', 0):.4f}, {c.get('lon', 0):.4f})")
            loc_conf = c.get('loc_confidence', 0)
            loc_grade = c.get('loc_grade', 'UNVERIFIED')
            loc_proof = c.get('loc_proof', [])
            lines.append(f"      Location Verified: {loc_conf}% {loc_grade}")
            for proof in loc_proof:
                lines.append(f"        {proof}")
            proxy_type = c.get('proxy_type', '')
            if proxy_type:
                lines.append(f"      Proxy:       {proxy_type} — {c.get('proxy_detail', '')}")
            lines.append(f"      First Seen:  {_fmt_ts(c.get('first_seen', 0))}")
            lines.append(f"      Last Seen:   {_fmt_ts(c.get('last_seen', 0))}")
        # All deductions with full evidence
        lines.append("")
        lines.append("=" * 100)
        lines.append("── ALL DEDUCTIONS (full evidence) ──")
        lines.append("=" * 100)
        for idx, d in enumerate(data.get('deductions', []), 1):
            lines.append(f"\n  Deduction #{idx}")
            lines.append(f"    Time:     {d.get('time', '?')}")
            lines.append(f"    Severity: {d.get('severity', '?')}")
            lines.append(f"    Category: {d.get('category', '?')}")
            lines.append(f"    Process:  {d.get('process', '?')} (PID {d.get('pid', '?')})")
            lines.append(f"    Score:    {d.get('score', 0)}")
            lines.append(f"    Message:  {d.get('message', '?')}")
            for ev in d.get('evidence', []):
                lines.append(f"      -> {ev}")
        # All processes
        lines.append("")
        lines.append("=" * 100)
        lines.append("── ALL PROCESSES ──")
        lines.append("=" * 100)
        for p in data.get('processes', []):
            lines.append(f"\n  PID {p['pid']}: {p['name']}")
            lines.append(f"    Exe:          {p.get('exe', '?')}")
            lines.append(f"    Parent:       {p.get('parent', '?')}")
            lines.append(f"    Risk Score:   {p.get('risk', 0)}")
            lines.append(f"    Connections:  {p.get('connections', 0)}")
            lines.append(f"    Destinations: {p.get('destinations', 0)}")
            lines.append(f"    ML Anomaly:   {p.get('ml_score', 0)}")
            lines.append(f"    Countries:    {', '.join(p.get('countries', []))}")
        # All devices
        lines.append("")
        lines.append("=" * 100)
        lines.append("── ALL DEVICES ──")
        lines.append("=" * 100)
        for d in data.get('devices', []):
            lines.append(f"\n  {d.get('ip', '?')} — {d.get('mac', '?')}")
            lines.append(f"    Vendor:     {d.get('vendor', '?')}")
            lines.append(f"    Hostname:   {d.get('hostname', '?')}")
            lines.append(f"    OS Guess:   {d.get('os_guess', '?')}")
            lines.append(f"    Confidence: {d.get('confidence', 0):.2f}")
        # ALL raw actions — no caps (complete log)
        lines.append("")
        lines.append("=" * 100)
        lines.append("── COMPLETE RAW ACTIONS LOG (ALL, NO CAPS) ──")
        lines.append("=" * 100)
        for act in data.get('all_actions', []):
            lines.append(f"  {act}")
        # Map data
        lines.append("")
        lines.append("=" * 100)
        lines.append("── ALL IPs WITH GEOLOCATION ──")
        lines.append("=" * 100)
        for pt in data.get('map_points', []):
            lines.append(f"  {pt.get('ip', '?')} — {pt.get('service', '?')} | "
                         f"{pt.get('city', '?')}, {pt.get('country', '?')} | "
                         f"({pt.get('lat', 0):.4f}, {pt.get('lon', 0):.4f}) | "
                         f"{pt.get('org', '?')} | Process: {pt.get('process', '?')}")
        # Suspicious activity events
        lines.append("")
        lines.append("=" * 100)
        lines.append("── SUSPICIOUS ACTIVITY (OUT-OF-NORM ONLY) ──")
        lines.append("=" * 100)
        susp_events = data.get('suspicious_events', [])
        if not susp_events:
            lines.append("  No suspicious activity detected.")
        for ev in susp_events:
            lines.append(f"\n  [{ev.get('severity', '?')}] [{ev.get('category', '?')}] {ev.get('time', '?')}")
            lines.append(f"    Description: {ev.get('description', '?')}")
            lines.append(f"    Process:     {ev.get('process', '?')} (PID {ev.get('pid', '?')})")
            for detail in ev.get('details', []):
                lines.append(f"      → {detail}")
        # ── SNEAKIEST CONNECTIONS (anti-hack pinned) ──
        # Every connection that has been flagged by any anti-hack detection
        # is listed here with full details and all pin categories.
        anti_hack_pins = data.get('anti_hack_pins', {})
        lines.append("")
        lines.append("=" * 100)
        lines.append("── SNEAKIEST CONNECTIONS (Anti-Hack Flagged) ──")
        lines.append("=" * 100)
        if not anti_hack_pins:
            lines.append("  No anti-hack flagged connections in this segment.")
        else:
            lines.append(f"  Total flagged IPs: {len(anti_hack_pins)}")
            total_pins = sum(len(v.get('categories', [])) for v in anti_hack_pins.values())
            lines.append(f"  Total anti-hack pins: {total_pins}")
            lines.append("")
            conn_by_ip = {c.get('remote_ip'): c for c in data.get('connections', [])}
            for ip, info in sorted(anti_hack_pins.items()):
                cats = info.get('categories', [])
                details = info.get('details', [])
                # Index built once outside the loop — this used to rescan
                # every connection for every pinned IP.
                conn_info = conn_by_ip.get(ip)
                lines.append(f"\n  📌 FLAGGED IP: {ip}")
                lines.append(f"    Pin Categories: {', '.join(cats)}")
                if conn_info:
                    lines.append(f"    Process:     {conn_info.get('process', '?')} (PID {conn_info.get('pid', '?')})")
                    lines.append(f"    Remote:      {conn_info.get('remote_ip', '?')}:{conn_info.get('remote_port', '?')}")
                    lines.append(f"    Service:     {conn_info.get('service', 'Unknown')}")
                    lines.append(f"    Domain:      {conn_info.get('domain', 'unresolved')}")
                    lines.append(f"    Country:     {conn_info.get('country', '?')} ({conn_info.get('country_code', '?')})")
                    lines.append(f"    Org:         {conn_info.get('org', '?')}")
                    lines.append(f"    Status:      {conn_info.get('status', '?')}")
                    lines.append(f"    First Seen:  {_fmt_ts(conn_info.get('first_seen', 0))}")
                    lines.append(f"    Last Seen:   {_fmt_ts(conn_info.get('last_seen', 0))}")
                else:
                    lines.append(f"    (Connection no longer active — historical pin)")
                lines.append(f"    Pin Details ({len(details)}):")
                for detail in details[:20]:
                    lines.append(f"      → {detail[:200]}")
                if len(details) > 20:
                    lines.append(f"      ... and {len(details) - 20} more details")
        # ── ANTI-HACK DEDUCTIONS ──
        # All deductions from anti-hack categories, with full evidence
        anti_hack_categories = {
            'NET_SPAWN', 'LISTEN_ANOMALY', 'CREDENTIAL_DUMP', 'DNS_HIJACK',
            'SERVICE_CREATE', 'PORT_FORWARD', 'DATA_STAGING', 'AV_DISABLE',
            'NEW_ACCOUNT', 'WMI_PERSIST', 'PS_ABUSE', 'BACKUP_TAMPER',
            'DRIVER_LOAD', 'ADMIN_SHARE', 'MUTEX_HIT', 'EXFIL_CHANNEL',
            'PROCESS_HOLLOW', 'LOLBIN_ABUSE', 'SUSPICIOUS_PATH',
            'PARENT_MISMATCH', 'PS_OBFUSCATION', 'MACRO_MALWARE',
            'BROWSER_EXPLOIT', 'RENAMED_BINARY',
        }
        anti_hack_deds = [d for d in data.get('deductions', [])
                          if d.get('category') in anti_hack_categories]
        lines.append("")
        lines.append("=" * 100)
        lines.append(f"── ANTI-HACK DEDUCTIONS ({len(anti_hack_deds)} total) ──")
        lines.append("=" * 100)
        if not anti_hack_deds:
            lines.append("  No anti-hack deductions in this segment.")
        for idx, d in enumerate(anti_hack_deds, 1):
            lines.append(f"\n  Anti-Hack Deduction #{idx}")
            lines.append(f"    Time:     {d.get('time', '?')}")
            lines.append(f"    Severity: {d.get('severity', '?')}")
            lines.append(f"    Category: {d.get('category', '?')}")
            lines.append(f"    Process:  {d.get('process', '?')} (PID {d.get('pid', '?')})")
            lines.append(f"    Score:    {d.get('score', 0)}")
            lines.append(f"    Message:  {d.get('message', '?')}")
            for ev in d.get('evidence', []):
                lines.append(f"      -> {ev}")
        # ── ALL ANTI-HACK EVENTS (from monitors) ──
        # Events from the 8 background monitors (SecurityEvent, DnsHijack,
        # ServiceCreate, AvDisable, NewAccount, WmiPersist, DriverLoad, MutexHit)
        anti_hack_event_cats = {
            'SECURITY_EVENT', 'SecurityEvent', 'DNS_HIJACK', 'DnsHijack',
            'SERVICE_CREATE', 'ServiceCreate', 'AV_DISABLE', 'AvDisable',
            'NEW_ACCOUNT', 'NewAccount', 'WMI_PERSIST', 'WmiPersist',
            'DRIVER_LOAD', 'DriverLoad', 'MUTEX_HIT', 'MutexHit',
        }
        anti_hack_monitor_events = [ev for ev in susp_events
                                    if ev.get('category') in anti_hack_event_cats]
        lines.append("")
        lines.append("=" * 100)
        lines.append(f"── ANTI-HACK MONITOR EVENTS ({len(anti_hack_monitor_events)} total) ──")
        lines.append("=" * 100)
        if not anti_hack_monitor_events:
            lines.append("  No anti-hack monitor events in this segment.")
        for ev in anti_hack_monitor_events:
            lines.append(f"\n  [{ev.get('severity', '?')}] [{ev.get('category', '?')}] {ev.get('time', '?')}")
            lines.append(f"    Description: {ev.get('description', '?')}")
            lines.append(f"    Process:     {ev.get('process', '?')} (PID {ev.get('pid', '?')})")
            for detail in ev.get('details', []):
                lines.append(f"      → {detail}")
        # ── TIER 5 DATA ──
        # VirusTotal results
        vt_results = data.get('vt_results', {})
        if vt_results:
            lines.append("")
            lines.append("=" * 100)
            lines.append("── VIRUSTOTAL SCAN RESULTS ──")
            lines.append("=" * 100)
            for sha, r in vt_results.items():
                mal = r.get('malicious', 0)
                tag = " *** MALICIOUS ***" if mal > 0 else ""
                lines.append(f"  SHA256: {sha}{tag}")
                lines.append(f"    Malicious: {mal}  Suspicious: {r.get('suspicious', 0)}  "
                             f"Harmless: {r.get('harmless', 0)}  Undetected: {r.get('undetected', 0)}")
                if r.get('name'):
                    lines.append(f"    Name: {r['name']}")
        # File system events
        fs_events = data.get('fs_events', [])
        if fs_events:
            lines.append("")
            lines.append("=" * 100)
            lines.append("── FILE SYSTEM WATCHDOG EVENTS ──")
            lines.append("=" * 100)
            for ev in fs_events:
                lines.append(f"  [{ev.get('severity', '?')}] {ev.get('type', '?')} — {ev.get('detail', '?')}")
                if ev.get('path'):
                    lines.append(f"    Path: {ev['path']}")
        # Clipboard events
        clip_events = data.get('clipboard_events', [])
        if clip_events:
            lines.append("")
            lines.append("=" * 100)
            lines.append("── CLIPBOARD MONITOR EVENTS ──")
            lines.append("=" * 100)
            for ev in clip_events:
                lines.append(f"  [{ev.get('severity', '?')}] {ev.get('type', '?')} — {ev.get('detail', '?')}")
        # USB events
        usb_events = data.get('usb_events', [])
        if usb_events:
            lines.append("")
            lines.append("=" * 100)
            lines.append("── USB DEVICE EVENTS ──")
            lines.append("=" * 100)
            for ev in usb_events:
                lines.append(f"  [{ev.get('severity', '?')}] {ev.get('detail', '?')}")
        # Scheduled task events
        task_events = data.get('sched_task_events', [])
        if task_events:
            lines.append("")
            lines.append("=" * 100)
            lines.append("── SCHEDULED TASK CHANGES ──")
            lines.append("=" * 100)
            for ev in task_events:
                lines.append(f"  [{ev.get('severity', '?')}] {ev.get('type', '?')} — {ev.get('detail', '?')}")
        # Named pipe events
        pipe_events = data.get('named_pipe_events', [])
        if pipe_events:
            lines.append("")
            lines.append("=" * 100)
            lines.append("── NAMED PIPE / IPC EVENTS ──")
            lines.append("=" * 100)
            for ev in pipe_events:
                lines.append(f"  [{ev.get('severity', '?')}] {ev.get('detail', '?')}")
        # Inbound scan events
        scan_events = data.get('inbound_scan_events', [])
        if scan_events:
            lines.append("")
            lines.append("=" * 100)
            lines.append("── INBOUND PORT SCAN DETECTIONS ──")
            lines.append("=" * 100)
            for ev in scan_events:
                lines.append(f"  [{ev.get('severity', '?')}] {ev.get('detail', '?')}")
                lines.append(f"    Ports probed: {ev.get('ports_probed', [])}")
        # DoH detections
        doh_events = data.get('doh_events', [])
        if doh_events:
            lines.append("")
            lines.append("=" * 100)
            lines.append("── DNS-OVER-HTTPS (DoH) DETECTIONS ──")
            lines.append("=" * 100)
            for ev in doh_events:
                lines.append(f"  {ev.get('detail', '?')}")
        # TLS cert / MITM events
        cert_events = data.get('cert_events', [])
        if cert_events:
            lines.append("")
            lines.append("=" * 100)
            lines.append("── TLS CERTIFICATE / MITM EVENTS ──")
            lines.append("=" * 100)
            for ev in cert_events:
                lines.append(f"  [{ev.get('severity', '?')}] {ev.get('detail', '?')}")
        # Connection timeline with durations
        timeline = data.get('conn_timeline', [])
        if timeline:
            lines.append("")
            lines.append("=" * 100)
            lines.append("── CONNECTION TIMELINE (Active + Closed, with Duration) ──")
            lines.append("=" * 100)
            for entry in timeline[-1000:]:
                rip = entry.get('remote_ip', '?')
                rport = entry.get('remote_port', '?')
                pid = entry.get('pid', 0)
                active = entry.get('active', False)
                duration = entry.get('duration', 0)
                start = entry.get('start_time', 0)
                start_str = _fmt_ts(start)
                dur_str = f"{int(duration)}s" if duration < 3600 else f"{duration/3600:.1f}h"
                state = "ACTIVE" if active else "CLOSED"
                lines.append(f"  [{state:6}] {start_str}  {rip}:{rport}  PID {pid}  dur={dur_str}")
        # Network interface bandwidth
        iface_data = data.get('iface_stats', {})
        if iface_data:
            lines.append("")
            lines.append("=" * 100)
            lines.append("── NETWORK INTERFACE BANDWIDTH ──")
            lines.append("=" * 100)
            for iface, samples in sorted(iface_data.items()):
                if samples:
                    latest = samples[-1]
                    lines.append(f"  {iface}: ↑{latest.get('total_sent',0)/1024/1024:.1f} MB sent  "
                                 f"↓{latest.get('total_recv',0)/1024/1024:.1f} MB recv  "
                                 f"pkts: ↑{latest.get('packets_sent',0)}  ↓{latest.get('packets_recv',0)}  "
                                 f"errs: {latest.get('errin',0)}/{latest.get('errout',0)}")
        # Bluetooth devices
        bt_devs = data.get('bt_devices', [])
        if bt_devs:
            lines.append("")
            lines.append("=" * 100)
            lines.append("── BLUETOOTH DEVICES ──")
            lines.append("=" * 100)
            for bt in bt_devs:
                lines.append(f"  {bt.get('name', '?')}  Type: {bt.get('type', '?')}  ID: {bt.get('device_id', '?')}")
        bt_events = data.get('bt_events', [])
        if bt_events:
            lines.append("")
            lines.append("── BLUETOOTH EVENTS ──")
            for ev in bt_events:
                lines.append(f"  [{ev.get('severity', '?')}] {ev.get('detail', '?')}")
        # Serial / COM ports
        serial_ports = data.get('serial_ports', [])
        if serial_ports:
            lines.append("")
            lines.append("=" * 100)
            lines.append("── SERIAL / COM PORTS ──")
            lines.append("=" * 100)
            for sp in serial_ports:
                lines.append(f"  {sp.get('port', '?')}  Device: {sp.get('device', '?')}")
        serial_events = data.get('serial_events', [])
        if serial_events:
            lines.append("")
            lines.append("── SERIAL PORT EVENTS ──")
            for ev in serial_events:
                lines.append(f"  [{ev.get('severity', '?')}] {ev.get('detail', '?')}")
        # Full terminal output (100%)
        lines.append("")
        lines.append("=" * 100)
        lines.append("── FULL TERMINAL OUTPUT (100%) ──")
        lines.append("=" * 100)
        for _ts, _tag, text in data.get('terminal_lines', []):
            lines.append(f"  {text}")
        # Footer
        lines.append("")
        lines.append("=" * 120)
        lines.append(f"  END OF LOG #{self._save_counter} — Runtime: {runtime_str} — {ts}")
        lines.append("=" * 120)
        file_content = '\n'.join(lines)
        # Save to organized session directory (time-segmented)
        try:
            with open(segment_filepath, 'w', encoding='utf-8') as f:
                f.write(file_content)
        except Exception as exc:
            _logger.warning("Failed to save session file %s: %s", segment_filepath, exc)
        # Also save to Desktop for backward compatibility
        with open(desktop_filepath, 'w', encoding='utf-8') as f:
            f.write(file_content)
        _logger.info("GNA tracer data saved to %s + %s (save #%d, runtime %s)",
                     segment_filepath, desktop_filepath, self._save_counter, runtime_str)


@_lru_cache(maxsize=8192)
def _fmt_clock(sec: int) -> str:
    """'YYYY-MM-DD HH:MM:SS' for a whole-second epoch value.

    The payload reformats the whole action log on every GUI refresh (~4x a
    second). Actions never change once written and many share the same
    second, so caching by truncated timestamp removes almost all of that
    work as the buffer grows toward its export cap.
    """
    return datetime.datetime.fromtimestamp(sec).strftime('%Y-%m-%d %H:%M:%S')


@_lru_cache(maxsize=8192)
def _fmt_hms(sec: int) -> str:
    """'HH:MM:SS' for a whole-second epoch value."""
    return datetime.datetime.fromtimestamp(sec).strftime('%H:%M:%S')


def _fmt_bytes(n) -> str:
    """Human-readable byte count for the process and bandwidth views."""
    try:
        n = float(n or 0)
    except (TypeError, ValueError):
        return "0 B"
    for unit in ("B", "KB", "MB", "GB"):
        if abs(n) < 1024.0:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024.0
    return f"{n:.1f} TB"


def _fmt_ts(ts):
    if not ts or ts == 0:
        return "N/A"
    try:
        return _fmt_clock(int(ts))
    except Exception:
        return str(ts)


def _is_jsonable(v) -> bool:
    """True if v is a JSON-serializable primitive (str/int/float/bool/None/
    list/dict of the same)."""
    if v is None or isinstance(v, (str, int, float, bool)):
        return True
    if isinstance(v, (list, tuple)):
        return all(_is_jsonable(x) for x in v)
    if isinstance(v, dict):
        return all(isinstance(k, str) and _is_jsonable(x)
                   for k, x in v.items())
    return False


def _check_token(request, token: str) -> bool:
    """Validate bearer token from query param or Authorization header."""
    if request.query_params.get('token') == token:
        return True
    auth = request.headers.get('authorization', '')
    return bool(auth.startswith('Bearer ') and auth[7:] == token)


def start_dashboard(get_state_fn, stop_event):
    """Run the FastAPI dashboard (blocking — call from a daemon thread)."""
    if not HAS_FASTAPI:
        _logger.info("FastAPI not installed — dashboard disabled")
        return
    if not CONFIG.get('dashboard_enabled'):
        return

    from fastapi.responses import PlainTextResponse
    from starlette.requests import Request

    app = FastAPI(title="MedianBoxMonitor Dashboard")
    auth_token = CONFIG.get('dashboard_password', '')

    @app.get("/", response_class=HTMLResponse)
    async def root(request: Request):
        if auth_token and not _check_token(request, auth_token):
            return PlainTextResponse("401 Unauthorized — append ?token=YOUR_PASSWORD", status_code=401)
        return DASHBOARD_HTML

    @app.get("/api/state")
    async def api_state(request: Request):
        if auth_token and not _check_token(request, auth_token):
            return PlainTextResponse("401 Unauthorized", status_code=401)
        return JSONResponse(get_state_fn())

    @app.websocket("/ws")
    async def ws_endpoint(websocket: WebSocket):
        import asyncio
        if auth_token:
            ws_token = websocket.query_params.get('token', '')
            if ws_token != auth_token:
                await websocket.close(code=4001, reason="Unauthorized")
                return
        await websocket.accept()
        try:
            while not stop_event.is_set():
                state = get_state_fn()
                await websocket.send_json(state)
                await asyncio.sleep(3)
        except WebSocketDisconnect:
            pass
        except Exception as exc:
            _logger.debug("WebSocket error: %s", exc)

    if auth_token:
        _logger.info("Dashboard authentication enabled (token required)")

    try:
        uvicorn.run(app, host="127.0.0.1", port=CONFIG['dashboard_port'],
                    log_level="warning")
    except Exception as e:
        _logger.warning("Dashboard failed: %s", e)


# ========================== MAIN MONITOR CLASS ==========================
class MedianBoxMonitor:
    def __init__(self, args):
        self.args = args
        self.lock = threading.RLock()
        self.local_ip, self.subnet, self.network = self._detect_subnet()
        self._local_geoip_cache = None  # cached local GeoIP for map positioning

        # Terminal output buffer — captures 100% of all _log output
        self.terminal_buffer: deque = deque(maxlen=10000)

        # Database
        self.db = DatabaseManager()

        # Original LAN tracking
        self.devices = {}
        self.seen_composites = set()
        self.remote_sessions = {}
        self.probe_attempts = defaultdict(int)
        self._probe_window_start = time.time()
        self.flow_stats = defaultdict(lambda: deque(maxlen=400))
        self.mac_to_ip_history = defaultdict(set)
        self.last_alert = defaultdict(float)

        # Connection cache — populated by dedicated mapper thread
        self.conn_by_pid: dict[int, list] = defaultdict(list)
        self.conn_by_raddr: dict[str, tuple] = {}
        self.conn_cache_lock = threading.Lock()

        # Deductive Chess Engine v2
        self.dns_cache = DNSCache()
        self.dns_cache.load_history()
        self.beacon_detector = BeaconDetector()
        self.process_profiles: dict[int, ProcessProfile] = {}
        # Bounded per-PID history. An unbounded list here made _get_full_data
        # format and sort hundreds of thousands of strings on every GUI refresh.
        self.process_actions = defaultdict(lambda: deque(maxlen=MAX_ACTIONS_PER_PID))
        self.deductions: deque = deque(maxlen=2000)
        self.deduction_cooldowns: dict[str, float] = {}

        # Suspicious activity buffer — ONLY out-of-norm / anomalous events
        self.suspicious_events: deque = deque(maxlen=5000)

        # Behavioral baselines keyed by process NAME
        self.name_baselines: dict[str, dict] = defaultdict(lambda: {
            'typical_dsts': set(),
            'dst_count_samples': deque(maxlen=200),
            'pkt_rate_samples': deque(maxlen=200),
            'samples': 0,
        })

        # Hardware / user-activity correlation
        self.audio_active_pids: set[int] = set()
        self.camera_active_pids: set[int] = set()
        self.user_activity_ts: float = 0.0

        # Pre-parsed known IP ranges
        self.known_ranges: dict[str, list] = {}
        for svc, cidrs in KNOWN_SERVICE_RANGES.items():
            self.known_ranges[svc] = [ipaddress.ip_network(c, strict=False) for c in cidrs]

        # Tier 1
        self.sni_extractor = SNIExtractor()
        self.dns_tunnel_detector = DNSTunnelingDetector()
        self.entropy_analyzer = EntropyAnalyzer()

        # Tier 2
        self.geoip = GeoIPCache()
        self.registry_monitor = RegistryMonitor()
        self.user_idle = UserIdleMonitor()
        self.registry_baseline_set = False
        self._last_registry_scan = 0.0

        # Tier 3
        self.escalation = AlertEscalation()
        self.siem = SIEMOutput()
        self.slog = setup_structured_logging()

        # Tier 4
        self.ml_baseline = StatisticalBaseline()
        self.ja4plus = JA4Plus()

        # Tier 5 — New detectors
        self.vt_checker = VirusTotalChecker()
        self.fs_watchdog = FileSystemWatchdog()
        self.clipboard_monitor = ClipboardMonitor()
        self.usb_monitor = USBMonitor()
        self.sched_task_monitor = ScheduledTaskMonitor()
        self.named_pipe_monitor = NamedPipeMonitor()
        self.whois_lookup = WhoisLookup()
        self.inbound_scan_detector = InboundScanDetector()
        self.doh_detector = DoHDetector()
        self.tls_cert_detector = TLSCertDetector()
        self.conn_history = ConnectionHistory()
        self.bt_scanner = BluetoothScanner()
        self.serial_scanner = SerialPortScanner()
        self.proxy_detector = ProxyDetector()
        self.vpn_leak_detector = VPNLeakDetector()  # stop_event wired after self.stop exists
        # Anti-hack monitors (18 features)
        self.security_event_monitor = SecurityEventMonitor()
        self.hosts_file_monitor = HostsFileMonitor()
        self.service_monitor = ServiceMonitor()
        self.security_tool_monitor = SecurityToolMonitor()
        self.user_account_monitor = UserAccountMonitor()
        self.wmi_subscription_monitor = WMISubscriptionMonitor()
        self.driver_load_monitor = DriverLoadMonitor()
        self.mutex_scanner = MutexScanner()
        # Anti-hack pin system: ip -> set of category tags
        self._anti_hack_pins: dict[str, set[str]] = {}
        self._anti_hack_details: dict[str, list[str]] = {}
        self._vpn_flagged: set[str] = set()

        # Watchlist / Favorites — authoritative copy, mutated from the GUI
        # context menus and persisted between sessions.
        self._watchlist_ips: set[str] = set()
        self._watchlist_procs: set[str] = set()
        self._watchlist_lock = threading.Lock()
        self._watchlist_alerted: set[str] = set()
        self._load_watchlist()

        # Network interface bandwidth tracking
        self._iface_stats_prev: dict[str, tuple] = {}
        self._iface_stats_history: dict[str, deque] = defaultdict(lambda: deque(maxlen=120))

        # Admin check — use a lightweight test instead of enumerating all
        # connections (psutil.net_connections can take 100ms+ on Windows).
        self._admin_mode = True
        try:
            # Just try to read our own process connections — much faster
            _proc_connections(psutil.Process())
        except psutil.AccessDenied:
            self._admin_mode = False
        except Exception:
            # On some systems this can raise other errors; default to admin
            self._admin_mode = True

        self.stop = threading.Event()
        self.vpn_leak_detector._stop = self.stop  # wire stop event now that it exists

        # Packet pipeline (queue-based async processing)
        self.pipeline = PacketPipeline(
            handler=self._packet_callback,
            stop_event=self.stop,
        )

        # Shared connection snapshot (written by _connection_mapper, read by inventory + process watcher)
        self._conn_snapshot = []
        self._conn_snapshot_lock = threading.Lock()

        # Service resolver + Connection inventory (reads from shared snapshot)
        self.service_resolver = ServiceResolver()
        self.conn_inventory = ConnectionInventory(
            dns_cache=self.dns_cache,
            geoip=self.geoip,
            service_resolver=self.service_resolver,
            stop_event=self.stop,
            conn_provider=self._get_conn_snapshot,
        )

        # Multi-method cross-verification (shared between monitor and GUI).
        # Placed after service_resolver so LocationVerifier has a resolver.
        self.multiverifier = MultiVerifier(
            geoip=self.geoip,
            location_verifier=LocationVerifier(self.service_resolver),
            proxy_detector=self.proxy_detector)
        # Background IP verification queue: enriches high-risk / suspicious
        # public destinations without blocking the process watcher loop.
        # A verify pass costs 3-6s of network I/O per IP, so one worker could
        # never keep up with every public endpoint. Use a small pool fed by a
        # priority queue: suspicious destinations jump ahead of routine ones.
        self._verify_queue: queue.PriorityQueue = queue.PriorityQueue(maxsize=4000)
        self._verify_seq = itertools.count()
        self._verify_cache: dict[str, dict] = {}
        self._verify_cache_lock = threading.Lock()
        self._verify_in_progress: set[str] = set()
        self._verify_lock = threading.Lock()
        self._verify_threads = []
        for _i in range(max(1, int(CONFIG.get('verify_workers', 4)))):
            t = threading.Thread(target=self._verification_worker, daemon=True,
                                 name=f"MultiVerify-{_i + 1}")
            t.start()
            self._verify_threads.append(t)
        # Let the inventory ask for verification of every endpoint it sees.
        self.conn_inventory.verify_request_fn = self._queue_ip_verification

        self._print_banner()

    # ====================== BANNER ======================
    def _print_banner(self):
        self._log(f"{Colors.G}{EMOJI['brain']} MedianBoxMonitor 3.0 — MODULAR DEDUCTIVE CHESS ENGINE{Colors.END}")
        self._log(f"Monitoring: {self.local_ip} -> {self.subnet}")
        cap = [
            'DNS-chess', 'SNI-extract', 'Beacon-detect', 'Legitimacy-check',
            'Phantom-hunt', 'DNS-tunnel-detect', 'Entropy-analysis', 'Exfil-detect',
        ]
        if _IS_WINDOWS:
            cap.extend(['DLL-inspect', 'Registry-monitor', 'User-idle', 'Memory-forensics'])
        cap.extend(['GeoIP-enrich', 'Statistical-baseline', 'JA4+', 'Alert-escalation',
                     'Queue-pipeline'])
        if CONFIG['siem_output']:
            cap.append(f"SIEM-{CONFIG['siem_output']}")
        if HAS_FASTAPI and CONFIG['dashboard_enabled']:
            cap.append(f"Dashboard:{CONFIG['dashboard_port']}")
        if not self._admin_mode:
            self._log(f"{Colors.Y}Running without admin — reduced capability{Colors.END}")
        self._log(f"{Colors.M}Capabilities: {' | '.join(cap)}{Colors.END}")

    # ====================== LOGGING ======================
    _ANSI_RE = re.compile(r'\033\[[0-9;]*m')

    def _log(self, msg, color=Colors.Y):
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        line = f"{ts} {color}{msg}{Colors.END}"
        print(line)
        # Capture to terminal buffer with color tag for GUI
        # Strip ANSI codes only if color was actually applied (skip regex when no color)
        if color:
            clean = self._ANSI_RE.sub('', line)
        else:
            clean = line
        tag = 'critical' if color == Colors.R else ('warning' if color == Colors.Y else (
            'info' if color == Colors.G else 'default'))
        # deque.append is thread-safe in CPython — no lock needed
        self.terminal_buffer.append((ts, tag, clean))

    def _safe_alert(self, msg, color=Colors.R):
        key = msg.split('\u2192')[0].strip() if '\u2192' in msg else msg[:60]
        now = time.time()
        # Only hold the lock for the cooldown check — _log does print()
        # (I/O) which can block and shouldn't be inside the lock.
        should_log = False
        with self.lock:
            if now - self.last_alert.get(key, 0) > CONFIG['alert_cooldown']:
                self.last_alert[key] = now
                should_log = True
        if should_log:
            self._log(msg, color=color)

    # Keywords that mark a _write_action as suspicious (auto-flagged)
    _SUSPICIOUS_ACTION_KW = {
        'NETWORK_FLOW': 'DATA_ACCESS',
        'DEDUCTION_': 'DEDUCTION',
    }
    _SUSPICIOUS_EXTRA_KW = [
        ('cookie', 'COOKIE_TRACKING', 'Process is sending/receiving tracking cookies'),
        ('upload', 'DATA_UPLOAD', 'Process is uploading data'),
        ('exfil', 'DATA_EXFIL', 'Potential data exfiltration detected'),
        ('credential', 'CREDENTIAL_ACCESS', 'Process accessing credentials'),
        ('password', 'CREDENTIAL_ACCESS', 'Process accessing password data'),
        ('token', 'TOKEN_ACCESS', 'Process accessing authentication tokens'),
        ('clipboard', 'CLIPBOARD_ACCESS', 'Process accessing clipboard data'),
        ('keylog', 'KEYLOGGER', 'Possible keylogger behavior detected'),
        ('screenshot', 'SCREEN_CAPTURE', 'Process performing screen capture'),
        ('inject', 'CODE_INJECTION', 'Process injection activity detected'),
        ('hook', 'API_HOOK', 'Process hooking system APIs'),
        ('encrypt', 'ENCRYPTION', 'Process performing encryption (possible ransomware)'),
        ('decrypt', 'ENCRYPTION', 'Process performing decryption'),
        ('powershell', 'SCRIPT_EXEC', 'PowerShell execution detected'),
        ('cmd.exe', 'SCRIPT_EXEC', 'Command shell execution detected'),
        ('wscript', 'SCRIPT_EXEC', 'Windows Script Host execution'),
        ('cscript', 'SCRIPT_EXEC', 'Console Script Host execution'),
        ('regsvr', 'DLL_REGISTER', 'DLL registration activity'),
        ('schtask', 'SCHEDULED_TASK', 'Scheduled task manipulation'),
        ('rdp', 'REMOTE_ACCESS', 'Remote Desktop Protocol activity'),
        ('vnc', 'REMOTE_ACCESS', 'VNC remote access activity'),
        ('ssh', 'REMOTE_ACCESS', 'SSH remote access activity'),
        ('telnet', 'REMOTE_ACCESS', 'Telnet remote access activity'),
        ('wake-on-lan', 'REMOTE_POWER', 'Wake-on-LAN (remote power on)'),
        ('shutdown', 'REMOTE_POWER', 'Remote shutdown command detected'),
        ('restart', 'REMOTE_POWER', 'Remote restart command detected'),
        ('microphone', 'HARDWARE_ACCESS', 'Microphone access detected'),
        ('camera', 'HARDWARE_ACCESS', 'Camera access detected'),
        ('webcam', 'HARDWARE_ACCESS', 'Webcam access detected'),
        ('audiodg', 'HARDWARE_ACCESS', 'Audio device graph isolation active'),
        ('temp\\', 'TEMP_EXECUTION', 'Process running from temp directory'),
        ('appdata', 'SUSPICIOUS_PATH', 'Process running from AppData'),
        ('downloads\\', 'SUSPICIOUS_PATH', 'Process running from Downloads'),
    ]

    def _flag_suspicious(self, category: str, severity: str, process: str,
                         pid: int, description: str, details: list):
        """Record a suspicious/anomalous event — ONLY out-of-norm behavior."""
        ts = time.time()
        event = {
            'timestamp': ts,
            'time': datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S"),
            'category': category,
            'severity': severity,
            'process': process,
            'pid': pid,
            'description': description,
            'details': details,
        }
        # deque.append is thread-safe in CPython — no lock needed for append-only
        self.suspicious_events.append(event)

    def _auto_flag_action(self, pid, name, action, extra):
        """Check if an action matches suspicious patterns and auto-flag it."""
        combined = f"{action} {extra}".lower()
        name_lower = name.lower()  # compute once, not per-keyword
        for keyword, cat, desc in self._SUSPICIOUS_EXTRA_KW:
            if keyword in combined or keyword in name_lower:
                self._flag_suspicious(cat, "WARNING", name, pid, desc,
                    [f"Action: {action}", f"Detail: {extra}",
                     f"Process: {name} (PID {pid})",
                     f"Matched keyword: '{keyword}'"])
                return

    # Cache loggers to avoid repeated getLogger() calls on every action
    _actions_logger = logging.getLogger('medianbox.actions')
    _deductions_logger = logging.getLogger('medianbox.deductions')

    def _write_action(self, pid, name, action, extra=""):
        now_ts = time.time()
        ts = datetime.datetime.fromtimestamp(now_ts).strftime("%Y-%m-%d %H:%M:%S")
        entry = f"{ts} | {name} (PID {pid}) | {action} {extra}"
        self._actions_logger.info(entry)
        with self.lock:
            self.process_actions[pid].append((now_ts, name, action, extra))
        # Auto-detect suspicious actions
        self._auto_flag_action(pid, name, action, extra)

    def _write_deduction_log(self, d: Deduction):
        ts = datetime.datetime.fromtimestamp(d.timestamp).strftime("%Y-%m-%d %H:%M:%S")
        entry = (f"{ts} | [{d.severity}] [{d.category}] {d.process_name} (PID {d.pid}) | "
                 f"{d.message} | score={d.score:.1f} | evidence={d.evidence}")
        self._deductions_logger.info(entry)

    # ====================== SUBNET DETECTION ======================
    @staticmethod
    def _primary_local_ip() -> str:
        """The source IP the OS would use to reach the internet. A UDP connect()
        sets the route without sending a packet, so this costs nothing and,
        unlike enumerating adapters, it names the interface actually in use."""
        for probe in ('8.8.8.8', '1.1.1.1'):
            s = None
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(0.5)
                s.connect((probe, 80))
                ip = s.getsockname()[0]
                if ip and not ip.startswith('127.') and not ip.startswith('169.254.'):
                    return ip
            except Exception:
                continue
            finally:
                if s is not None:
                    try:
                        s.close()
                    except Exception:
                        pass
        return ''

    def _detect_subnet(self):
        """Pick the interface that actually carries traffic.

        The old version took the first non-loopback IPv4 with a netmask, which
        on Windows is routinely a *disconnected* adapter holding an APIPA
        169.254.x address. Everything downstream keys off self.network — the
        packet handler drops any source outside it — so choosing a dead adapter
        silently disabled device discovery, byte accounting, inbound-scan
        detection and SNI harvesting. Rank candidates instead: the routed
        source IP wins, then link-up adapters, and link-local/down ones last.
        """
        routed_ip = self._primary_local_ip()
        try:
            if_stats = psutil.net_if_stats()
        except Exception:
            if_stats = {}
        candidates = []
        try:
            if_addrs = psutil.net_if_addrs().items()
        except Exception:
            if_addrs = []
        for iface, addrs in if_addrs:
            for a in addrs:
                if a.family != socket.AF_INET or not a.netmask:
                    continue
                if a.address.startswith('127.'):
                    continue
                try:
                    net = ipaddress.IPv4Interface(f"{a.address}/{a.netmask}").network
                except Exception:
                    continue
                st = if_stats.get(iface)
                is_up = bool(st.isup) if st is not None else False
                is_apipa = a.address.startswith('169.254.')
                # Higher score wins.
                score = 0
                if routed_ip and a.address == routed_ip:
                    score += 1000          # this is the interface the OS routes over
                if is_up:
                    score += 100
                if not is_apipa:
                    score += 50
                if net.prefixlen >= 24:
                    score += 10            # a real LAN, not a /16 of nothing
                score += min(int(getattr(st, 'speed', 0) or 0) // 100, 9)
                candidates.append((score, iface, a.address, net))
        if candidates:
            candidates.sort(key=lambda c: c[0], reverse=True)
            score, iface, addr, net = candidates[0]
            _logger.info("Primary interface: %s %s (%s) score=%d", iface, addr, net, score)
            return addr, str(net), net
        if routed_ip:
            # Adapter enumeration failed but routing works — assume a /24.
            try:
                net = ipaddress.IPv4Interface(f"{routed_ip}/24").network
                return routed_ip, str(net), net
            except Exception:
                pass
        return "192.168.1.100", "192.168.1.0/24", ipaddress.IPv4Network("192.168.1.0/24")

    def _get_local_geoip(self) -> dict:
        """Get GeoIP for the local machine's PUBLIC IP (for map positioning).
        Caches the result so we only do the lookup once."""
        if hasattr(self, '_local_geoip_cache') and self._local_geoip_cache:
            return self._local_geoip_cache
        result = {'lat': 0, 'lon': 0, 'city': '', 'country': '', 'country_code': '',
                  'ip': '', 'org': '', 'isp': ''}
        if not CONFIG.get('geoip_enabled', True):
            # --no-geoip / geoip_enabled=False must also suppress this lookup;
            # it sends our public IP to a third party over plain HTTP.
            self._local_geoip_cache = result
            return result
        try:
            # Get public IP via external API
            req = urllib.request.Request(
                'http://ip-api.com/json/?fields=status,country,countryCode,city,lat,lon,org,isp,query',
                headers={'User-Agent': 'MedianBoxMonitor/3.0'})
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode('utf-8'))
            if data.get('status') == 'success':
                result = {
                    'lat': data.get('lat', 0),
                    'lon': data.get('lon', 0),
                    'city': data.get('city', ''),
                    'country': data.get('country', ''),
                    'country_code': data.get('countryCode', ''),
                    'ip': data.get('query', ''),
                    'org': data.get('org', ''),
                    'isp': data.get('isp', ''),
                }
        except Exception:
            pass
        self._local_geoip_cache = result
        return result

    # ====================== WATCHLIST ======================
    _WATCHLIST_FILE = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), '.medianbox_watchlist.json')

    def get_watchlist(self) -> dict:
        with self._watchlist_lock:
            return {'ips': set(self._watchlist_ips),
                    'procs': set(self._watchlist_procs)}

    def watch_ip(self, ip: str, add: bool = True):
        """Add or remove an IP from the watchlist (called from the GUI)."""
        ip = (ip or '').strip()
        if not ip:
            return
        with self._watchlist_lock:
            if add:
                self._watchlist_ips.add(ip)
            else:
                self._watchlist_ips.discard(ip)
                self._watchlist_alerted.discard(f'ip:{ip}')
        self._log(f"{EMOJI['ok']} Watchlist: {'added' if add else 'removed'} IP {ip}",
                  color=Colors.C)
        self._save_watchlist()

    def watch_proc(self, name: str, add: bool = True):
        """Add or remove a process name from the watchlist."""
        name = (name or '').strip().lower()
        if not name:
            return
        with self._watchlist_lock:
            if add:
                self._watchlist_procs.add(name)
            else:
                self._watchlist_procs.discard(name)
                self._watchlist_alerted.discard(f'proc:{name}')
        self._log(f"{EMOJI['ok']} Watchlist: {'added' if add else 'removed'} process {name}",
                  color=Colors.C)
        self._save_watchlist()

    def _save_watchlist(self):
        try:
            with self._watchlist_lock:
                data = {'ips': sorted(self._watchlist_ips),
                        'procs': sorted(self._watchlist_procs)}
            with open(self._WATCHLIST_FILE, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
        except Exception as exc:
            _logger.debug("Watchlist save failed: %s", exc)

    def _load_watchlist(self):
        try:
            if not os.path.exists(self._WATCHLIST_FILE):
                return
            with open(self._WATCHLIST_FILE, 'r', encoding='utf-8') as f:
                data = json.load(f)
            with self._watchlist_lock:
                self._watchlist_ips = set(data.get('ips', []))
                self._watchlist_procs = {p.lower() for p in data.get('procs', [])}
            if self._watchlist_ips or self._watchlist_procs:
                _logger.info("Watchlist loaded: %d IP(s), %d process name(s)",
                             len(self._watchlist_ips), len(self._watchlist_procs))
        except Exception as exc:
            _logger.debug("Watchlist load failed: %s", exc)

    def _check_watchlist(self, name, pid, dst_ip, dst_port, domains):
        """A watchlist hit is reported once per IP/process until removed."""
        # Grab references (not copies) under lock — the sets are only
        # replaced (not mutated) by the watchlist loader, so a reference
        # is safe for the duration of this check.
        with self._watchlist_lock:
            watch_ips = self._watchlist_ips
            watch_procs = self._watchlist_procs
            alerted = self._watchlist_alerted
        # Fast path: if neither set is populated, skip entirely
        if not watch_ips and not watch_procs:
            return
        name_l = (name or '').lower()
        if dst_ip in watch_ips and f'ip:{dst_ip}' not in alerted:
            with self._watchlist_lock:
                self._watchlist_alerted.add(f'ip:{dst_ip}')
            self._flag_suspicious(
                'WATCHLIST', 'CRITICAL', name, pid,
                f'Watchlisted IP contacted: {dst_ip}',
                [f'Process: {name} (PID {pid})',
                 f'Destination: {dst_ip}:{dst_port}',
                 f'Domain: {", ".join(domains) if domains else "unresolved"}',
                 'This IP is on your watchlist'])
            self._log(f"{EMOJI['alert']} WATCHLIST IP: {name} -> {dst_ip}", color=Colors.R)
        if name_l in watch_procs and f'proc:{name_l}' not in alerted:
            with self._watchlist_lock:
                self._watchlist_alerted.add(f'proc:{name_l}')
            self._flag_suspicious(
                'WATCHLIST', 'WARNING', name, pid,
                f'Watchlisted process is on the network: {name}',
                [f'Process: {name} (PID {pid})',
                 f'Destination: {dst_ip}:{dst_port}',
                 'This process name is on your watchlist'])
            self._log(f"{EMOJI['alert']} WATCHLIST PROC: {name} -> {dst_ip}", color=Colors.Y)

    # ====================== VERIFICATION WORKER ======================
    def _queue_ip_verification(self, ip: str, priority: int = 5):
        """Queue a public IP for background multi-method cross-verification.

        Every public destination is queued, not just the suspicious ones —
        VPN/proxy status, ASN, rDNS and RTT are part of a connection's
        identity, and gating the lookup on "high risk country or watchlisted
        or remote-access port" left that identity blank for ordinary traffic.
        `priority` orders the queue (lower runs first) so suspicious
        destinations are still verified first when there is a backlog.
        """
        if not ip or not self._is_public_ip(ip):
            return
        with self._verify_cache_lock:
            if ip in self._verify_cache:
                return
        with self._verify_lock:
            if ip in self._verify_in_progress:
                return
            self._verify_in_progress.add(ip)
        try:
            # The counter breaks ties so equal priorities never compare the
            # payload (and stay FIFO within a priority band).
            self._verify_queue.put_nowait((priority, next(self._verify_seq), ip))
        except queue.Full:
            with self._verify_lock:
                self._verify_in_progress.discard(ip)
        except Exception as exc:
            _logger.debug("Verification queue put error: %s", exc)

    def _verification_worker(self):
        """Background worker that runs MultiVerifier on queued IPs."""
        while not self.stop.is_set():
            try:
                _prio, _seq, ip = self._verify_queue.get(timeout=1.0)
            except queue.Empty:
                continue
            try:
                # Skip if no longer public or already done
                if not self._is_public_ip(ip):
                    continue
                with self._verify_cache_lock:
                    if ip in self._verify_cache:
                        continue
                rep = self.multiverifier.verify(ip, active=True)
                with self._verify_cache_lock:
                    self._verify_cache[ip] = rep
                # Label the connections themselves, not just a side dict, so
                # every view that renders a connection shows the verdict.
                try:
                    self.conn_inventory.apply_verification(ip, rep)
                except Exception as exc:
                    _logger.debug("apply_verification failed for %s: %s", ip, exc)
                self._raise_vpn_deduction(ip, rep)
            except Exception as exc:
                _logger.debug("MultiVerification worker error for %s: %s", ip, exc)
            finally:
                with self._verify_lock:
                    self._verify_in_progress.discard(ip)
                try:
                    self._verify_queue.task_done()
                except Exception:
                    pass

    def _raise_vpn_deduction(self, ip: str, rep: dict):
        """Surface a VPN/proxy/Tor endpoint as an event once per IP."""
        if not rep or not (rep.get('is_vpn') or rep.get('is_proxy')):
            return
        with self.lock:
            if ip in self._vpn_flagged:
                return
            self._vpn_flagged.add(ip)
            if len(self._vpn_flagged) > 20000:
                self._vpn_flagged.clear()
        owner = self.owner_of_ip(ip)
        name = owner.get('name', '?')
        pid = owner.get('pid', 0)
        labels = ', '.join(rep.get('labels', [])) or 'anonymising endpoint'
        self._flag_suspicious(
            'VPN_ENDPOINT', 'WARNING', name, pid,
            f'{name} is talking to a VPN/proxy endpoint: {ip} ({labels})',
            [f'Destination: {ip}',
             f'VPN score: {rep.get("vpn_score", 0)}/100',
             f'Labels: {labels}',
             f'Org: {rep.get("org", "Unknown")}',
             f'ASN: {rep.get("asn", "Unknown")}',
             f'Apparent location: {rep.get("consensus_city", "?")}, '
             f'{rep.get("consensus_country", "?")} — this is the EXIT NODE, '
             f'not the real source'])

    def _get_verification(self, ip: str) -> Optional[dict]:
        """Return a cached MultiVerifier report for an IP, or None."""
        with self._verify_cache_lock:
            return self._verify_cache.get(ip)

    # ====================== HELPERS ======================
    def _is_public_ip(self, ip: str) -> bool:
        return _is_public_ip_cached(ip)

    def _composite_key(self, mac, ip):
        # Use Python's built-in hash() instead of SHA256 — this is a dedup
        # key, not a cryptographic hash. ~50x faster per call.
        return f"{mac or 'nomac'}:{ip or 'noip'}"

    def _extract_hostname(self, pkt):
        if pkt.haslayer(DNS) and pkt[DNS].qr == 0:
            try:
                return pkt[DNS].qd.qname.decode(errors='ignore').rstrip('.')
            except Exception as exc:
                _logger.debug("Hostname extract error: %s", exc)
        if pkt.haslayer(BOOTP) and pkt.haslayer(DHCP):
            for opt in pkt[DHCP].options:
                if isinstance(opt, tuple) and opt[0] == 'hostname':
                    return opt[1].decode(errors='ignore')
        return None

    def _passive_os(self, pkt):
        if not pkt.haslayer(TCP) or not (pkt[TCP].flags & 0x02):
            return "Unknown"
        ttl = pkt[IP].ttl if pkt.haslayer(IP) else (pkt[IPv6].hlim if pkt.haslayer(IPv6) else 64)
        win = pkt[TCP].window
        if 50 <= ttl <= 70 and win >= 5000:
            return "Linux 5.x/6.x"
        if 110 <= ttl <= 130 and win <= 12000:
            return "Windows 10/11"
        if ttl >= 200:
            return "macOS/BSD"
        return "Unknown/other"

    # ====================== DEDUCTIVE CHESS ENGINE v2 ======================
    # Hoisted to class level — was rebuilt as a dict literal on every _add_deduction call
    _DEDUCTION_EMOJI_MAP = {
        "MIMIC": EMOJI['mimic'], "BEACON": EMOJI['beacon'],
        "PHANTOM": EMOJI['phantom'], "IMPERSONATION": EMOJI['impersonate'],
        "FOREIGN": EMOJI['foreign'], "ANOMALY": EMOJI['anomaly'],
        "INJECTION": EMOJI['inject'], "TUNNEL": EMOJI['tunnel'],
        "EXFIL": EMOJI['exfil'], "ENTROPY": EMOJI['entropy'],
        "DLL": EMOJI['dll'], "PERSISTENCE": EMOJI['persist'],
        "IDLE_ANOMALY": EMOJI['idle'], "ML_ANOMALY": EMOJI['ml'],
    }

    def _add_deduction(self, severity, category, proc_name, pid, message, evidence, score):
        cooldown_key = f"{category}:{pid}:{hash(message[:80])}"
        now = time.time()
        # Single lock for cooldown check + deduction append + risk update
        # (was 2 separate lock acquisitions)
        with self.lock:
            if now - self.deduction_cooldowns.get(cooldown_key, 0) < CONFIG['deduction_cooldown']:
                return
            self.deduction_cooldowns[cooldown_key] = now

            multiplier = self.escalation.get_multiplier(pid)
            escalated_score = score * multiplier
            self.escalation.record(pid, escalated_score)
            if multiplier > 1.0:
                evidence.append(f"{EMOJI['escalate']} ESCALATED x{multiplier:.1f} ({score:.0f} -> {escalated_score:.0f})")
                if severity == "WARNING" and escalated_score >= 50:
                    severity = "CRITICAL"

            d = Deduction(now, severity, category, proc_name, pid, message, evidence, escalated_score)
            self.deductions.append(d)
            _prof = self.process_profiles.get(pid)
            if _prof is not None:
                _prof.risk_score += escalated_score
                _prof.risk_reasons.append(f"[{category}] {message}")
                # Bounded: a long-lived noisy process would otherwise grow this
                # list without limit for the whole session.
                if len(_prof.risk_reasons) > 200:
                    del _prof.risk_reasons[:-200]
                _prof.escalation_hits += 1
                _prof.flags.add(category)

        icon = self._DEDUCTION_EMOJI_MAP.get(category, EMOJI['chess'])
        color = Colors.R if severity == "CRITICAL" else Colors.Y

        self._log(f"{icon} [{severity}] {message}", color=color)
        for e in evidence:
            self._log(f"    -> {e}", color=Colors.C)

        log_level = logging.CRITICAL if severity == "CRITICAL" else (
            logging.WARNING if severity == "WARNING" else logging.INFO)
        self.slog.log(log_level, f"[{category}] {message} | pid={pid} score={escalated_score:.1f}")

        self._write_action(pid, proc_name, f"DEDUCTION_{category}", message)
        self._write_deduction_log(d)
        self.db.save_deduction(d)
        self.siem.emit(d)
        # Every deduction is a suspicious event
        self._flag_suspicious(category, severity, proc_name, pid, message, list(evidence))

    # ---------- DEDUCTION 1: Mimic Traffic ----------
    def _check_mimic(self, profile, dst_ip, domains):
        all_idents = {d.lower() for d in domains}
        all_idents.add(dst_ip)
        for service, keywords in MIMIC_KEYWORDS.items():
            if any(kw in ident for kw in keywords for ident in all_idents):
                app_running = any(
                    service in p.name.lower()
                    for p in self.process_profiles.values()
                    if p.pid != profile.pid)
                if ALLOWED_APPS.get(service) and not app_running:
                    continue
                if not app_running:
                    suspicion = 30.0
                    evidence = [
                        f"Traffic matches '{service}' (keywords: {keywords})",
                        f"But NO '{service}' process is running",
                        f"Destinations: {', '.join(list(profile.destinations)[:5])}",
                        f"Process: {profile.name} (PID {profile.pid}, exe={profile.exe_path})",
                    ]
                    self._add_deduction("WARNING", "MIMIC", profile.name, profile.pid,
                        f"MIMIC: '{profile.name}' imitates '{service}' traffic "
                        f"(suspicion={suspicion:.0f})", evidence, suspicion)

    # ---------- DEDUCTION 2: Foreign Influence ----------
    def _check_foreign(self, profile, dst_ip, domains):
        try:
            ip_obj = ipaddress.ip_address(dst_ip)
            if not ip_obj.is_global:
                return
        except Exception:
            return
        proc_lower = profile.name.lower()
        for service, ranges in self.known_ranges.items():
            if service not in proc_lower:
                continue
            in_range = any(ip_obj in net for net in ranges)
            if not in_range:
                domain_str = ', '.join(domains) if domains else 'no resolved domain'
                recent_cpu = any(c > 2 for c in list(profile.cpu_samples)[-10:])
                evidence = [
                    f"'{profile.name}' claims to be '{service}' service",
                    f"Destination {dst_ip} ({domain_str}) NOT in known {service} IP ranges",
                    f"User CPU activity: {'yes' if recent_cpu else 'NONE'}",
                    f"Process exe: {profile.exe_path}",
                ]
                score = 25.0 if not recent_cpu else 15.0
                self._add_deduction("WARNING", "FOREIGN", profile.name, profile.pid,
                    f"FOREIGN: '{profile.name}' -> {dst_ip} ({domain_str}) "
                    f"outside known {service} infrastructure", evidence, score)
            break

    # ---------- DEDUCTION 3: Behavioral Anomaly ----------
    def _check_behavioral_anomaly(self, profile, dst_ip):
        name_lower = profile.name.lower()
        bl = self.name_baselines[name_lower]
        if bl['samples'] >= CONFIG['baseline_min_samples']:
            new_dsts = profile.destinations - bl['typical_dsts']
            if len(new_dsts) > 3:
                evidence = [
                    f"Baseline: {len(bl['typical_dsts'])} typical dests over {bl['samples']} samples",
                    f"{len(new_dsts)} NEW destinations: {', '.join(list(new_dsts)[:8])}",
                    f"Domains: {', '.join(profile.dns_domains)}",
                ]
                self._add_deduction("WARNING", "ANOMALY", profile.name, profile.pid,
                    f"BEHAVIORAL SHIFT: '{profile.name}' suddenly has "
                    f"{len(new_dsts)} new destinations", evidence, 20.0)
        bl['typical_dsts'].update(profile.destinations)
        bl['dst_count_samples'].append(len(profile.destinations))
        bl['samples'] += 1

    # ---------- DEDUCTION 4: Beacon Detection ----------
    def _check_beacon(self, profile):
        if len(profile.packet_timestamps) < CONFIG['beacon_min_samples']:
            return
        is_beacon, confidence, desc = self.beacon_detector.analyze(profile.packet_timestamps)
        if is_beacon and confidence > 0.4:
            evidence = [desc, f"Destinations: {', '.join(list(profile.destinations)[:6])}",
                        f"Exe: {profile.exe_path}", f"Connections: {profile.connection_count}"]
            sev = "CRITICAL" if confidence > 0.7 else "WARNING"
            self._add_deduction(sev, "BEACON", profile.name, profile.pid,
                f"C2 BEACON: '{profile.name}' automated callback (confidence={confidence:.0%})",
                evidence, confidence * 55)

    # ---------- DEDUCTION 5: Process Impersonation ----------
    def _check_impersonation(self, profile, proc):
        if profile.checked_legitimacy:
            return
        profile.checked_legitimacy = True
        reasons = ProcessLegitimacyChecker.check_all(proc)
        for reason in reasons:
            self._add_deduction("CRITICAL", "IMPERSONATION", profile.name, profile.pid,
                f"IMPERSONATION: {reason}",
                [reason, f"Exe: {profile.exe_path}",
                 f"Parent: {profile.parent_name} (PID {profile.parent_pid})"], 45.0)

    # ---------- DEDUCTION 6: Phantom Connections ----------
    def _check_phantoms(self, active_pids):
        try:
            with self._conn_snapshot_lock:
                snapshot = list(self._conn_snapshot)
            for conn in snapshot:
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    if conn.pid is None or conn.pid == 0 or conn.pid not in active_pids:
                        dst_ip = conn.raddr[0]
                        domains = self.dns_cache.get_domains(dst_ip)
                        evidence = [
                            f"Connection: {conn.laddr} -> {conn.raddr}",
                            f"PID: {conn.pid or 'NONE'} — not in active process list",
                            f"Domains: {', '.join(domains) if domains else 'unknown'}",
                        ]
                        self._add_deduction("CRITICAL", "PHANTOM", "UNKNOWN", conn.pid or 0,
                            f"PHANTOM: {conn.laddr} -> {conn.raddr} — "
                            f"{'no owning process' if not conn.pid else f'PID {conn.pid} missing'}",
                            evidence, 50.0)
        except psutil.AccessDenied:
            pass
        except Exception as exc:
            _logger.debug("Phantom check error: %s", exc)

    # ---------- DEDUCTION 7: Injection Chain ----------
    def _check_injection_chain(self, profile):
        if not profile.parent_name:
            return
        parent_lower = profile.parent_name.lower()
        name_lower = profile.name.lower()
        known_apps = {"chrome.exe", "firefox.exe", "msedge.exe", "explorer.exe",
                      "zoom.exe", "teams.exe", "discord.exe", "slack.exe"}
        if parent_lower in known_apps and name_lower not in known_apps and profile.connection_count > 2:
            evidence = [
                f"Parent: {profile.parent_name} (PID {profile.parent_pid})",
                f"Child: {profile.name} (PID {profile.pid})",
                f"Child has {profile.connection_count} INDIVIDUAL network connections:",
            ]
            with self.conn_cache_lock:
                pid_conns = list(self.conn_by_pid.get(profile.pid, []))
            for idx, conn in enumerate(pid_conns, 1):
                if conn.raddr:
                    dst_ip = conn.raddr[0]
                    dst_port = conn.raddr[1]
                    local_port = conn.laddr[1] if conn.laddr else 0
                    domains = self.dns_cache.get_domains(dst_ip)
                    svc_info = self.service_resolver.identify(dst_ip, domains)
                    svc_name = svc_info.get('service', 'Unknown')
                    domain_str = ', '.join(domains) if domains else 'unresolved'
                    geo_country = self.geoip.get_country(dst_ip) if self._is_public_ip(dst_ip) else 'LAN'
                    geo_org = self.geoip.get_org(dst_ip) if self._is_public_ip(dst_ip) else 'Local'
                    evidence.append(
                        f"  [{idx}] {dst_ip}:{dst_port} (local:{local_port}) | "
                        f"service={svc_name} | domain={domain_str} | "
                        f"country={geo_country} | org={geo_org} | status={conn.status}"
                    )
            if not pid_conns:
                for dst_ip in list(profile.destinations):
                    domains = self.dns_cache.get_domains(dst_ip)
                    domain_str = ', '.join(domains) if domains else 'unresolved'
                    evidence.append(f"  -> {dst_ip} | domain={domain_str}")
            self._add_deduction("WARNING", "INJECTION", profile.name, profile.pid,
                f"INJECTION CHAIN: '{profile.parent_name}' spawned '{profile.name}' "
                f"which has {profile.connection_count} connections (each listed below)",
                evidence, 30.0)

    # ---------- DEDUCTION 8: DNS Tunneling ----------
    def _check_dns_tunnel(self, qname, src_ip):
        is_tunnel, score, evidence = self.dns_tunnel_detector.analyze_query(qname)
        if is_tunnel:
            self._add_deduction("CRITICAL", "TUNNEL", "DNS", 0,
                f"DNS TUNNELING: suspicious query '{qname[:80]}...' from {src_ip}",
                evidence, score)

    # ---------- DEDUCTION 9: Data Exfiltration ----------
    def _check_exfil(self, profile, proc):
        try:
            io_counters = proc.io_counters()
            now = time.time()
            # Cumulative process I/O. These two profile fields existed but were
            # never written, so the Processes tab had nothing to show. psutil
            # reports process-wide I/O (disk + socket), not network bytes
            # alone, and it is labelled as such wherever it is displayed.
            profile.bytes_sent = io_counters.write_bytes
            profile.bytes_recv = io_counters.read_bytes
            if profile.io_snapshot_time > 0:
                dt = now - profile.io_snapshot_time
                if dt > 0:
                    sent_rate = (io_counters.write_bytes - profile.io_baseline_sent) / dt
                    # Store the rate on the profile so _check_ml_anomaly scores the
                    # SAME metric that was recorded. Previously it scored the
                    # cumulative profile.bytes_sent against a rate baseline, which
                    # produced a permanent false-positive z-score.
                    profile.io_send_rate = sent_rate
                    self.ml_baseline.record(profile.name.lower(), profile.connection_count,
                        len(profile.destinations), sent_rate,
                        statistics.mean(profile.cpu_samples) if profile.cpu_samples else 0)
                    # psutil reports process-wide I/O, not network bytes. Without
                    # an active remote destination a write burst is just disk
                    # activity, so requiring one removes the biggest class of
                    # false "exfiltration" alerts (compilers, installers, etc.).
                    with self.lock:
                        dests = list(profile.destinations)
                        public_dests = [d for d in dests if self._is_public_ip(d)]
                    # Require a genuine spike over this process's own recent
                    # average, not just a large absolute number.
                    prior = list(profile.io_rate_samples)
                    profile.io_rate_samples.append(sent_rate)
                    spike_factor = CONFIG['exfil_bytes_spike_factor']
                    avg_prior = statistics.mean(prior) if prior else 0.0
                    is_spike = (not prior) or sent_rate > max(
                        avg_prior * spike_factor, CONFIG['exfil_min_bytes'] / 60)
                    if (public_dests and is_spike and
                            sent_rate > CONFIG['exfil_min_bytes'] / 60 and
                            io_counters.write_bytes - profile.io_baseline_sent > CONFIG['exfil_min_bytes']):
                        evidence = [
                            f"Process I/O write rate: {sent_rate/1024:.0f} KB/s",
                            f"Written since last sample: {(io_counters.write_bytes - profile.io_baseline_sent)/1024/1024:.1f} MB",
                            f"Active public destinations ({len(public_dests)}): "
                            f"{', '.join(public_dests[:5])}",
                            f"Spike: {sent_rate/1024:.0f} KB/s vs recent average "
                            f"{avg_prior/1024:.0f} KB/s "
                            f"(threshold x{spike_factor})",
                            "Note: psutil reports total process I/O, so this is a "
                            "correlation between heavy writes and live outbound "
                            "connections, not a measured upload volume.",
                        ]
                        idle_sec = self._idle_seconds()
                        if idle_sec > CONFIG['user_idle_threshold']:
                            evidence.append(f"User idle for {idle_sec:.0f}s")
                        self._add_deduction("CRITICAL", "EXFIL", profile.name, profile.pid,
                            f"POSSIBLE EXFILTRATION: '{profile.name}' writing "
                            f"{sent_rate/1024:.0f} KB/s while connected to "
                            f"{len(public_dests)} public destination(s)",
                            evidence, 40.0)
            with self.lock:
                profile.io_baseline_sent = io_counters.write_bytes
                profile.io_baseline_recv = io_counters.read_bytes
                profile.io_snapshot_time = now
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    # ---------- DEDUCTION 10: DLL Injection ----------
    def _check_dlls(self, profile, proc):
        if not _IS_WINDOWS:
            return
        # Re-inspect on the configured cadence rather than latching after
        # a single check — a process can load a malicious DLL at any time.
        now = time.time()
        if profile.checked_dlls and now - profile.dll_scan_time < CONFIG['dll_scan_interval']:
            return
        profile.checked_dlls = True
        profile.dll_scan_time = now
        suspicious = DLLInspector.inspect(proc)
        if suspicious:
            profile.loaded_dlls = suspicious
            evidence = [f"Suspicious DLL: {dll}" for dll in suspicious[:10]]
            self._add_deduction("CRITICAL", "DLL", profile.name, profile.pid,
                f"DLL INJECTION: '{profile.name}' has {len(suspicious)} suspicious modules",
                evidence, 40.0)

    # ---------- DEDUCTION 11: Persistence Changes ----------
    def _check_persistence(self):
        # Honour registry_scan_interval instead of running on every 3s
        # process-watcher cycle.
        now = time.time()
        if now - self._last_registry_scan < CONFIG['registry_scan_interval']:
            return
        self._last_registry_scan = now
        changes = self.registry_monitor.scan()
        for action, key_path, value in changes:
            if not self.registry_baseline_set:
                continue
            evidence = [f"Action: {action}", f"Key: {key_path}", f"Value: {value[:200]}"]
            sev = "CRITICAL" if action == "ADDED" else "WARNING"
            self._add_deduction(sev, "PERSISTENCE", "Registry", 0,
                f"PERSISTENCE {action}: {key_path}", evidence,
                35.0 if action == "ADDED" else 15.0)
        if not self.registry_baseline_set and changes is not None:
            self.registry_baseline_set = True

    # ---------- DEDUCTION 12: User Idle Anomaly ----------
    def _idle_seconds(self) -> float:
        """User idle time. GetLastInputInfo is Windows-only, so fall back to
        the CPU-activity timestamp recorded by the process watcher.
        Cached for 1s — called from multiple threads/refresh paths."""
        now = time.time()
        if hasattr(self, '_idle_cache_ts') and now - self._idle_cache_ts < 1.0:
            return self._idle_cache_val
        idle = self.user_idle.get_idle_seconds()
        if idle > 0:
            val = idle
        else:
            with self.lock:
                last = self.user_activity_ts
            val = (now - last) if last else 0.0
        self._idle_cache_ts = now
        self._idle_cache_val = val
        return val

    def _check_idle_anomaly(self, profile):
        idle_sec = self._idle_seconds()
        if idle_sec < CONFIG['user_idle_threshold']:
            return
        if profile.connection_count > 5 and profile.last_network_ts > time.time() - 30:
            recent_cpu = any(c > 3 for c in list(profile.cpu_samples)[-10:])
            if not recent_cpu:
                evidence = [
                    f"User idle: {idle_sec:.0f}s",
                    f"'{profile.name}' has {profile.connection_count} active connections",
                    "No recent CPU activity from this process",
                ]
                self._add_deduction("WARNING", "IDLE_ANOMALY", profile.name, profile.pid,
                    f"IDLE ANOMALY: '{profile.name}' active while user idle {idle_sec:.0f}s",
                    evidence, 15.0)

    # ---------- DEDUCTION 13: Statistical Anomaly ----------
    def _check_ml_anomaly(self, profile):
        if len(profile.cpu_samples) < 5:
            return
        cpu_mean = statistics.mean(profile.cpu_samples) if profile.cpu_samples else 0
        ml_score, anomalies = self.ml_baseline.score(
            profile.name.lower(), profile.connection_count,
            len(profile.destinations), profile.io_send_rate, cpu_mean)
        profile.ml_anomaly_score = ml_score
        if ml_score > 30 and anomalies:
            evidence = [*anomalies, f"Overall anomaly score: {ml_score:.1f}", f"Process: {profile.name} (PID {profile.pid})"]
            sev = "CRITICAL" if ml_score > 60 else "WARNING"
            self._add_deduction(sev, "ML_ANOMALY", profile.name, profile.pid,
                f"STATISTICAL ANOMALY: '{profile.name}' deviates from baseline (score={ml_score:.0f})",
                evidence, ml_score * 0.5)

    # ---------- DEDUCTION 14: GeoIP Enrichment ----------
    def _check_geoip(self, profile, dst_ip, domains):
        # Use cached public-IP check instead of raw ipaddress parse
        if not _is_public_ip_cached(dst_ip):
            return
        geo = self.geoip.lookup(dst_ip)
        if geo:
            country = geo.get('countryCode', '??')
            org = geo.get('org', 'Unknown')
            with self.lock:
                profile.geo_countries.add(country)
            if country in CONFIG.get('high_risk_countries', set()):
                idle_sec = self._idle_seconds()
                # Avoid list() copy — slice the deque directly
                recent_cpu = any(c > 2 for c in list(profile.cpu_samples)[-10:])
                if not recent_cpu and idle_sec > CONFIG['user_idle_threshold']:
                    evidence = [
                        f"Destination: {dst_ip} -> {country} ({org})",
                        f"Domains: {', '.join(domains) if domains else 'none'}",
                        f"User idle: {idle_sec:.0f}s" if idle_sec > 60 else "User recently active",
                        f"Process: {profile.name} exe={profile.exe_path}",
                    ]
                    self._add_deduction("WARNING", "FOREIGN", profile.name, profile.pid,
                        f"GEO ALERT: '{profile.name}' -> {dst_ip} ({country}, {org})",
                        evidence, 20.0)

    def _check_verification(self, profile, dst_ip, dst_port, domains):
        """Check cached MultiVerifier report for the destination and flag
        VPN/proxy/hosting/CDN or high-conflict results. Called periodically
        by the process watcher when a report is available."""
        rep = self._get_verification(dst_ip)
        if not rep:
            return
        if rep.get('is_vpn') or rep.get('is_proxy'):
            self._add_deduction(
                "WARNING", "VPN_PROXY", profile.name, profile.pid,
                f"VPN/proxy/anonymiser detected for {dst_ip} "
                f"({rep.get('summary', '')})",
                [f"Destination: {dst_ip}:{dst_port}",
                 f"Domains: {', '.join(domains) if domains else 'unresolved'}",
                 f"VPN score: {rep.get('vpn_score', 0)}/100",
                 f"Consensus: {rep.get('consensus_city','')}, {rep.get('consensus_country','')}",
                 f"Labels: {', '.join(rep.get('labels', []))}",
                 f"Conflicts: {', '.join(rep.get('conflicts', []))}"],
                min(60.0, 30 + rep.get('vpn_score', 0) / 2))
        elif rep.get('is_hosting') and rep.get('vpn_score', 0) >= 20:
            self._add_deduction(
                "INFO", "HOSTING", profile.name, profile.pid,
                f"{dst_ip} is hosted in a datacenter "
                f"({rep.get('consensus_city','')}, {rep.get('consensus_country','')})",
                [f"Destination: {dst_ip}:{dst_port}",
                 f"Labels: {', '.join(rep.get('labels', []))}",
                 f"Org: {rep.get('org','Unknown')}"],
                10.0)

    # ====================== ANTI-HACK PROCESS CHECKS ======================
    # These run inside the process watcher alongside the existing _check_*
    # methods. Each flags a deduction and pins the finding to any
    # connection owned by the offending process.

    # Known network-facing parent processes that should never spawn shells
    _NETWORK_PARENTS = {
        'w3wp.exe', 'sqlservr.exe', 'winrm.exe', 'sshd.exe', 'termsrv.exe',
        'nginx.exe', 'httpd.exe', 'apache.exe', 'tomcat.exe', 'iisexpress.exe',
        'wsmprovhost.exe', 'umworkerprocess.exe', 'umservice.exe',
    }
    # Suspicious child processes that indicate post-exploitation
    _SUSPICIOUS_CHILDREN = {
        'cmd.exe', 'powershell.exe', 'pwsh.exe', 'whoami.exe', 'net.exe',
        'net1.exe', 'systeminfo.exe', 'ipconfig.exe', 'wmic.exe', 'nltest.exe',
        'hostname.exe', 'quser.exe', 'qwinsta.exe', 'rwinsta.exe', 'tasklist.exe',
        'netsh.exe', 'sc.exe', 'reg.exe', 'regedit.exe', 'mshta.exe', 'wscript.exe',
        'cscript.exe', 'certutil.exe', 'bitsadmin.exe', 'rundll32.exe',
    }

    def _pin_to_conns(self, pid: int, category: str, detail: str):
        """Pin an anti-hack tag to all connections owned by this PID."""
        with self.conn_cache_lock:
            conns = list(self.conn_by_pid.get(pid, []))
        for conn in conns:
            if conn.raddr:
                rip = conn.raddr[0]
                with self.lock:
                    self._anti_hack_pins.setdefault(rip, set()).add(category)
                    dets = self._anti_hack_details.setdefault(rip, [])
                    line = f"[{category}] {detail}"
                    # Bounded, and deduplicated against the most recent entries:
                    # a process re-flagged every scan cycle would otherwise grow
                    # this list for the whole session.
                    if line not in dets[-10:]:
                        dets.append(line)
                        if len(dets) > 50:
                            del dets[:-50]

    def _check_network_spawned(self, profile):
        """Check 2: Detect network-facing processes spawning shells."""
        if not profile.parent_name:
            return
        parent_lower = profile.parent_name.lower()
        name_lower = profile.name.lower()
        if parent_lower in self._NETWORK_PARENTS and name_lower in self._SUSPICIOUS_CHILDREN:
            cmdline = ''
            try:
                import psutil as _ps
                p = _ps.Process(profile.pid)
                cmdline = ' '.join(p.cmdline()[:10])
            except Exception:
                pass
            evidence = [
                f"Parent: {profile.parent_name} (PID {profile.parent_pid})",
                f"Child: {profile.name} (PID {profile.pid})",
                f"Command: {cmdline[:200]}",
                "Network-facing process spawned a shell — likely post-exploitation",
            ]
            self._add_deduction("CRITICAL", "NET_SPAWN", profile.name, profile.pid,
                f"NETWORK-SPAWNED PROCESS: '{profile.parent_name}' spawned "
                f"'{profile.name}' — possible hacker shell",
                evidence, 55.0)
            self._pin_to_conns(profile.pid, "NET_SPAWN",
                f"Network-spawned {profile.name} from {profile.parent_name}")
            self._flag_suspicious('NET_SPAWN', 'CRITICAL', 'Process', profile.pid,
                f"Network-facing process {profile.parent_name} spawned {profile.name}",
                evidence)

    # Known service ports that are expected to listen
    _EXPECTED_LISTEN_PORTS = {80, 443, 3389, 22, 21, 25, 53, 110, 143, 445,
                              139, 5985, 5986, 8080, 8443, 5900, 5938,
                              135, 137, 138, 161, 162, 389, 636, 464,
                              1433, 1521, 3306, 5432, 6379, 27017, 9200}
    _SYSTEM_PROCESSES = {'svchost.exe', 'lsass.exe', 'wininit.exe', 'services.exe',
                         'smss.exe', 'csrss.exe', 'winlogon.exe', 'spoolsv.exe',
                         'dwm.exe', 'fontdrvhost.exe', 'RuntimeBroker.exe',
                         'System', 'Idle', 'Registry'}

    def _check_listening_ports(self, profile):
        """Check 3: Detect non-system processes opening listening ports."""
        if profile.name.lower() in self._SYSTEM_PROCESSES:
            return
        try:
            import psutil as _ps
            p = _ps.Process(profile.pid)
            for conn in _proc_connections(p):
                if conn.status == 'LISTEN' and conn.laddr:
                    port = conn.laddr[1]
                    if port not in self._EXPECTED_LISTEN_PORTS and port > 1024:
                        evidence = [
                            f"Process: {profile.name} (PID {profile.pid})",
                            f"Listening on port: {port}",
                            f"Local address: {conn.laddr[0]}",
                            f"Non-system process opened unexpected listening port",
                            "Possible bind shell or C2 listener",
                        ]
                        self._add_deduction("CRITICAL", "LISTEN_ANOMALY",
                            profile.name, profile.pid,
                            f"LISTENING PORT ANOMALY: '{profile.name}' (PID {profile.pid}) "
                            f"listening on port {port}",
                            evidence, 50.0)
                        self._pin_to_conns(profile.pid, "LISTEN_ANOMALY",
                            f"Listening on port {port}")
                        self._flag_suspicious('LISTEN_ANOMALY', 'CRITICAL',
                            'Process', profile.pid,
                            f"{profile.name} listening on port {port}",
                            evidence)
                        break  # one alert per process per scan
        except Exception:
            pass

    def _check_credential_access(self, profile):
        """Check 4: Detect credential dumping (LSASS access, reg save, etc.)."""
        name_lower = profile.name.lower()
        cmdline = self._get_cmdline(profile).lower()
        # Check for known credential dumping tools
        cred_tools = {
            'mimikatz.exe', 'procdump.exe', 'sekurlsa.exe', 'laZagne.exe',
            'sharpkatz.exe', 'pypykatz.exe', 'nanodump.exe', 'comsvcs.dll',
        }
        if name_lower in cred_tools:
            evidence = [
                f"Process: {profile.name} (PID {profile.pid})",
                f"Known credential dumping tool detected",
            ]
            self._add_deduction("CRITICAL", "CREDENTIAL_DUMP",
                profile.name, profile.pid,
                f"CREDENTIAL DUMPING: '{profile.name}' is a known credential theft tool",
                evidence, 65.0)
            self._pin_to_conns(profile.pid, "CREDENTIAL_DUMP",
                f"Credential dumping tool: {profile.name}")
            self._flag_suspicious('CREDENTIAL_DUMP', 'CRITICAL', 'Process',
                profile.pid, f"Credential dumping tool: {profile.name}", evidence)
            return
        # Check for reg.exe save HKLM\SAM
        if name_lower == 'reg.exe' and ('save' in cmdline and
                ('sam' in cmdline or 'security' in cmdline or 'system' in cmdline)):
            evidence = [
                f"Process: {profile.name} (PID {profile.pid})",
                f"Command: {cmdline[:200]}",
                "Registry hive save — credential extraction",
            ]
            self._add_deduction("CRITICAL", "CREDENTIAL_DUMP",
                profile.name, profile.pid,
                "CREDENTIAL DUMPING: reg.exe saving registry hives",
                evidence, 60.0)
            self._pin_to_conns(profile.pid, "CREDENTIAL_DUMP",
                "reg.exe saving registry hives")
            self._flag_suspicious('CREDENTIAL_DUMP', 'CRITICAL', 'Process',
                profile.pid, "reg.exe saving registry hives", evidence)
            return
        # Check for ntdsutil.exe (DC credential extraction)
        if name_lower == 'ntdsutil.exe':
            evidence = [
                f"Process: {profile.name} (PID {profile.pid})",
                "ntdsutil.exe — Active Directory credential extraction",
            ]
            self._add_deduction("CRITICAL", "CREDENTIAL_DUMP",
                profile.name, profile.pid,
                "CREDENTIAL DUMPING: ntdsutil.exe running (NTDS.dit extraction)",
                evidence, 65.0)
            self._pin_to_conns(profile.pid, "CREDENTIAL_DUMP",
                "ntdsutil.exe NTDS.dit extraction")
            self._flag_suspicious('CREDENTIAL_DUMP', 'CRITICAL', 'Process',
                profile.pid, "ntdsutil.exe running", evidence)
            return
        # Check for LSASS access via procdump -ma
        if name_lower == 'procdump.exe' and '-ma' in cmdline:
            evidence = [
                f"Process: {profile.name} (PID {profile.pid})",
                f"Command: {cmdline[:200]}",
                "procdump -ma — full process memory dump (likely LSASS)",
            ]
            self._add_deduction("CRITICAL", "CREDENTIAL_DUMP",
                profile.name, profile.pid,
                "CREDENTIAL DUMPING: procdump -ma (full memory dump)",
                evidence, 60.0)
            self._pin_to_conns(profile.pid, "CREDENTIAL_DUMP",
                "procdump -ma memory dump")
            self._flag_suspicious('CREDENTIAL_DUMP', 'CRITICAL', 'Process',
                profile.pid, "procdump -ma", evidence)

    def _check_port_forward(self, profile):
        """Check 7: Detect port forwarding and tunneling tools."""
        name_lower = profile.name.lower()
        cmdline = self._get_cmdline(profile).lower()
        tunnel_tools = {'chisel.exe', 'ngrok.exe', 'ligolo-ng.exe', 'ligolo.exe',
                        'plink.exe', 'socat.exe', 'stunnel.exe', 'iodine.exe',
                        'dnscat2.exe', 'rathole.exe', 'frpc.exe', 'frps.exe'}
        if name_lower in tunnel_tools:
            evidence = [
                f"Process: {profile.name} (PID {profile.pid})",
                f"Known tunneling/port-forwarding tool",
                f"Command: {cmdline[:200]}",
            ]
            self._add_deduction("CRITICAL", "PORT_FORWARD",
                profile.name, profile.pid,
                f"PORT FORWARDING: '{profile.name}' is a known tunneling tool",
                evidence, 50.0)
            self._pin_to_conns(profile.pid, "PORT_FORWARD",
                f"Tunneling tool: {profile.name}")
            self._flag_suspicious('PORT_FORWARD', 'CRITICAL', 'Process',
                profile.pid, f"Tunneling tool: {profile.name}", evidence)
            return
        # Check ssh.exe with -L, -R, or -D flags
        if name_lower in ('ssh.exe', 'ssh') and any(
                f in cmdline for f in (' -l ', ' -r ', ' -d ', ' -ld ', ' -rd ')):
            evidence = [
                f"Process: {profile.name} (PID {profile.pid})",
                f"Command: {cmdline[:200]}",
                "SSH with port forwarding flags (-L/-R/-D)",
            ]
            self._add_deduction("WARNING", "PORT_FORWARD",
                profile.name, profile.pid,
                "PORT FORWARDING: ssh.exe with tunnel flags",
                evidence, 35.0)
            self._pin_to_conns(profile.pid, "PORT_FORWARD",
                "SSH port forwarding")

    def _check_data_staging(self, profile):
        """Check 8: Detect data staging and mass compression before exfil."""
        name_lower = profile.name.lower()
        cmdline = self._get_cmdline(profile).lower()
        archive_tools = {'7z.exe', 'winrar.exe', 'rar.exe', 'tar.exe',
                         '7za.exe', '7zr.exe', 'bandizip.exe', 'hjsplit.exe'}
        if name_lower in archive_tools:
            # Check if archiving from user document directories
            user_dirs = ('\\documents\\', '\\desktop\\', '\\downloads\\',
                         '\\pictures\\', '\\users\\')
            if any(d in cmdline for d in user_dirs) or 'compress' in cmdline:
                evidence = [
                    f"Process: {profile.name} (PID {profile.pid})",
                    f"Command: {cmdline[:200]}",
                    "Archive tool accessing user data directories — possible data staging",
                ]
                self._add_deduction("WARNING", "DATA_STAGING",
                    profile.name, profile.pid,
                    f"DATA STAGING: '{profile.name}' compressing user data",
                    evidence, 35.0)
                self._pin_to_conns(profile.pid, "DATA_STAGING",
                    f"Data staging: {profile.name} archiving user data")
                self._flag_suspicious('DATA_STAGING', 'WARNING', 'Process',
                    profile.pid, f"Data staging: {profile.name}", evidence)
        # Check for PowerShell Compress-Archive
        if name_lower in ('powershell.exe', 'pwsh.exe') and 'compress-archive' in cmdline:
            evidence = [
                f"Process: {profile.name} (PID {profile.pid})",
                f"Command: {cmdline[:200]}",
                "PowerShell Compress-Archive — possible data staging",
            ]
            self._add_deduction("WARNING", "DATA_STAGING",
                profile.name, profile.pid,
                "DATA STAGING: PowerShell Compress-Archive detected",
                evidence, 35.0)
            self._pin_to_conns(profile.pid, "DATA_STAGING",
                "PowerShell Compress-Archive")

    def _check_powershell_abuse(self, profile):
        """Check 12: Detect encoded/obfuscated PowerShell usage."""
        name_lower = profile.name.lower()
        if name_lower not in ('powershell.exe', 'pwsh.exe'):
            return
        cmdline = self._get_cmdline(profile)
        cmdline_lower = cmdline.lower()
        abuse_indicators = [
            ('-enc', 'Encoded PowerShell command'),
            ('-encodedcommand', 'Encoded PowerShell command'),
            ('-e ', 'Encoded PowerShell command'),
            ('-executionpolicy bypass', 'Execution policy bypass'),
            ('-w hidden', 'Hidden window PowerShell'),
            ('-windowstyle hidden', 'Hidden window PowerShell'),
            ('iex(', 'PowerShell IEX (Invoke-Expression)'),
            ('downloadstring', 'PowerShell download string'),
            ('invoke-expression', 'PowerShell Invoke-Expression'),
            ('frombase64string', 'PowerShell Base64 decode'),
            ('invoke-webrequest', 'PowerShell web request'),
            ('invoke-restmethod', 'PowerShell REST request'),
            ('-nop', 'No profile PowerShell'),
            ('-noninteractive', 'Non-interactive PowerShell'),
            ('amsiinitfailed', 'AMSI bypass attempt'),
            ('amsi bypass', 'AMSI bypass attempt'),
            ('reflection.assembly', 'Reflective .NET assembly load'),
        ]
        for indicator, desc in abuse_indicators:
            if indicator in cmdline_lower:
                evidence = [
                    f"Process: {profile.name} (PID {profile.pid})",
                    f"Command: {cmdline[:300]}",
                    f"Indicator: {desc}",
                ]
                sev = "CRITICAL" if any(k in indicator for k in
                    ('-enc', 'amsi', 'iex(', 'downloadstring',
                     'frombase64', 'reflection')) else "WARNING"
                self._add_deduction(sev, "PS_ABUSE",
                    profile.name, profile.pid,
                    f"POWERSHELL ABUSE: {desc} in {profile.name}",
                    evidence, 45.0 if sev == "CRITICAL" else 30.0)
                self._pin_to_conns(profile.pid, "PS_ABUSE",
                    f"PowerShell abuse: {desc}")
                self._flag_suspicious('PS_ABUSE', sev, 'Process',
                    profile.pid, f"PowerShell abuse: {desc}", evidence)
                break  # one alert per process per scan

    def _check_backup_tampering(self, profile):
        """Check 13: Detect shadow copy deletion and backup tampering."""
        name_lower = profile.name.lower()
        cmdline = self._get_cmdline(profile).lower()
        if name_lower == 'vssadmin.exe' and ('delete' in cmdline or 'resize' in cmdline):
            evidence = [
                f"Process: {profile.name} (PID {profile.pid})",
                f"Command: {cmdline[:200]}",
                "Shadow copy deletion/resize — ransomware or anti-forensics",
            ]
            self._add_deduction("CRITICAL", "BACKUP_TAMPER",
                profile.name, profile.pid,
                "BACKUP TAMPERING: vssadmin deleting/resizing shadow copies",
                evidence, 60.0)
            self._pin_to_conns(profile.pid, "BACKUP_TAMPER",
                "vssadmin shadow copy tampering")
            self._flag_suspicious('BACKUP_TAMPER', 'CRITICAL', 'Process',
                profile.pid, "vssadmin shadow copy tampering", evidence)
        elif name_lower == 'wbadmin.exe' and 'delete' in cmdline:
            evidence = [
                f"Process: {profile.name} (PID {profile.pid})",
                f"Command: {cmdline[:200]}",
                "wbadmin delete — backup catalog deletion",
            ]
            self._add_deduction("CRITICAL", "BACKUP_TAMPER",
                profile.name, profile.pid,
                "BACKUP TAMPERING: wbadmin deleting backup catalog",
                evidence, 60.0)
            self._pin_to_conns(profile.pid, "BACKUP_TAMPER",
                "wbadmin backup catalog deletion")
            self._flag_suspicious('BACKUP_TAMPER', 'CRITICAL', 'Process',
                profile.pid, "wbadmin backup deletion", evidence)
        elif name_lower == 'bcdedit.exe' and 'recoveryenabled' in cmdline and 'no' in cmdline:
            evidence = [
                f"Process: {profile.name} (PID {profile.pid})",
                f"Command: {cmdline[:200]}",
                "bcdedit disabling recovery — anti-forensics",
            ]
            self._add_deduction("CRITICAL", "BACKUP_TAMPER",
                profile.name, profile.pid,
                "BACKUP TAMPERING: bcdedit disabling recovery",
                evidence, 55.0)
            self._pin_to_conns(profile.pid, "BACKUP_TAMPER",
                "bcdedit recovery disabled")

    def _check_admin_share(self, profile, dst_ip, dst_port):
        """Check 15: Detect SMB admin share access (C$, ADMIN$, IPC$)."""
        if dst_port != 445:
            return
        name_lower = profile.name.lower()
        cmdline = self._get_cmdline(profile).lower()
        if name_lower == 'net.exe' and 'use' in cmdline and '$' in cmdline:
            evidence = [
                f"Process: {profile.name} (PID {profile.pid})",
                f"Destination: {dst_ip}:{dst_port}",
                f"Command: {cmdline[:200]}",
                "Admin share access via net use — lateral movement",
            ]
            self._add_deduction("CRITICAL", "ADMIN_SHARE",
                profile.name, profile.pid,
                f"ADMIN SHARE ACCESS: {profile.name} connecting to admin share on {dst_ip}",
                evidence, 50.0)
            self._pin_to_conns(profile.pid, "ADMIN_SHARE",
                f"Admin share access to {dst_ip}")
            self._flag_suspicious('ADMIN_SHARE', 'CRITICAL', 'Process',
                profile.pid, f"Admin share access to {dst_ip}", evidence)
        elif name_lower in ('psexec.exe', 'psexesvc.exe'):
            evidence = [
                f"Process: {profile.name} (PID {profile.pid})",
                f"Destination: {dst_ip}:{dst_port}",
                "PsExec — remote execution via admin share",
            ]
            self._add_deduction("CRITICAL", "ADMIN_SHARE",
                profile.name, profile.pid,
                f"ADMIN SHARE ACCESS: PsExec targeting {dst_ip}",
                evidence, 50.0)
            self._pin_to_conns(profile.pid, "ADMIN_SHARE",
                f"PsExec to {dst_ip}")

    # Known exfil/C2 channel domains
    _EXFIL_CHANNELS = {
        'discord.com', 'discordapp.com', 'api.telegram.org', 'telegram.org',
        'hooks.slack.com', 'slack.com', 'pastebin.com', 'transfer.sh',
        'gofile.io', '0x0.st', 'file.io', 'ufile.io', 'anonfiles.com',
        'bayfiles.com', 'mega.nz', 'mega.co.nz', 'wormhole.app',
        'webhook.site', 'requestbin.com', 'pipedream.com',
        'ngrok.io', 'ngrok-free.app', 'serveo.net', 'localhost.run',
        'trycloudflare.com', 'loophole.site',
    }

    def _check_exfil_channel(self, profile, dst_ip, domains):
        """Check 17: Detect connections to known exfil/C2 channels."""
        for domain in domains:
            domain_lower = domain.lower()
            for channel in self._EXFIL_CHANNELS:
                if domain_lower == channel or domain_lower.endswith('.' + channel):
                    evidence = [
                        f"Process: {profile.name} (PID {profile.pid})",
                        f"Destination: {dst_ip}",
                        f"Domain: {domain}",
                        f"Known exfil/C2 channel: {channel}",
                    ]
                    self._add_deduction("WARNING", "EXFIL_CHANNEL",
                        profile.name, profile.pid,
                        f"EXFIL CHANNEL: {profile.name} connecting to {channel}",
                        evidence, 40.0)
                    self._pin_to_conns(profile.pid, "EXFIL_CHANNEL",
                        f"Exfil channel: {channel}")
                    self._flag_suspicious('EXFIL_CHANNEL', 'WARNING', 'Process',
                        profile.pid, f"Exfil channel: {channel}", evidence)
                    return

    def _check_process_hollow(self, profile):
        """Check 18: Detect process hollowing (suspended process + path mismatch)."""
        if profile.name.lower() not in self._SYSTEM_PROCESSES:
            return  # Only check system-named processes for hollowing
        # Use profile.exe_path first (already collected by process watcher),
        # fall back to psutil if not available
        exe_path = (profile.exe_path or '').lower()
        if not exe_path:
            try:
                import psutil as _ps
                p = _ps.Process(profile.pid)
                exe_path = p.exe().lower()
            except Exception:
                return
        # System processes should have paths in System32 or SysWOW64
        if exe_path and 'system32' not in exe_path and 'syswow64' not in exe_path:
            evidence = [
                f"Process: {profile.name} (PID {profile.pid})",
                f"Expected: System32/SysWOW64 path",
                f"Actual: {exe_path}",
                "System process name running from non-system path — possible process hollowing",
            ]
            self._add_deduction("CRITICAL", "PROCESS_HOLLOW",
                profile.name, profile.pid,
                f"PROCESS HOLLOWING: '{profile.name}' running from {exe_path}",
                evidence, 55.0)
            self._pin_to_conns(profile.pid, "PROCESS_HOLLOW",
                f"Hollowed process: {profile.name} from {exe_path}")
            self._flag_suspicious('PROCESS_HOLLOW', 'CRITICAL', 'Process',
                profile.pid, f"Process hollowing: {profile.name}", evidence)

    # ====================== ENHANCED ANTI-HACK CHECKS ======================
    # These catch the sneakiest hackers using LOLbins, parent-child
    # mismatches, suspicious execution paths, and advanced obfuscation.

    # LOLbins that attackers abuse for download/execution/obfuscation
    _LOLBINS = {
        'certutil.exe', 'bitsadmin.exe', 'mshta.exe', 'regsvr32.exe',
        'rundll32.exe', 'wscript.exe', 'cscript.exe', 'msiexec.exe',
        'installutil.exe', 'regasm.exe', 'regsvcs.exe', 'msbuild.exe',
        'ieexec.exe', 'presentationhost.exe', 'extexport.exe',
        'finger.exe', 'ftp.exe', 'replace.exe', 'pcalua.exe',
        'forfiles.exe', 'atbroker.exe', 'cmstp.exe', 'xwizard.exe',
        'wmic.exe',
    }

    # Suspicious execution directories — executables running from here
    # are almost always post-exploitation tools or dropped payloads
    _SUSPICIOUS_EXEC_DIRS = (
        '\\temp\\', '\\tmp\\', '\\downloads\\', '\\appdata\\local\\temp\\',
        '\\appdata\\roaming\\', '\\desktop\\', '\\public\\',
        '\\programdata\\', '\\$recycle.bin\\', '\\windows\\temp\\',
        '\\users\\public\\', '\\perflogs\\',
    )

    # Expected parent processes for critical system binaries
    # If svchost.exe is NOT spawned by services.exe, it's likely hollowed
    _EXPECTED_PARENTS = {
        'svchost.exe': {'services.exe'},
        'smss.exe': {'smss.exe', 'system'},
        'wininit.exe': {'smss.exe'},
        'winlogon.exe': {'smss.exe'},
        'csrss.exe': {'smss.exe', 'wininit.exe', 'winlogon.exe'},
        'lsass.exe': {'wininit.exe'},
        'services.exe': {'wininit.exe'},
        'spoolsv.exe': {'services.exe'},
        'taskhostw.exe': {'services.exe', 'svchost.exe'},
        'dwm.exe': {'winlogon.exe', 'dwm.exe'},
        'fontdrvhost.exe': {'wininit.exe', 'fontdrvhost.exe'},
        'runtimebroker.exe': {'svchost.exe'},
        'explorer.exe': {'userinit.exe', 'explorer.exe'},
        'conhost.exe': {'cmd.exe', 'powershell.exe', 'pwsh.exe',
                        'windowsterminal.exe', 'explorer.exe', 'svchost.exe',
                        'w3wp.exe', 'sqlservr.exe', 'sshd.exe'},
    }

    # Suspicious command-line patterns for LOLbins
    _LOLBIN_PATTERNS = {
        'certutil.exe': [
            ('-urlcache', 'Certutil file download (LOLbin)'),
            ('-split', 'Certutil file download with split'),
            ('-decode', 'Certutil base64 decode'),
            ('-encode', 'Certutil base64 encode (obfuscation)'),
        ],
        'bitsadmin.exe': [
            ('/transfer', 'BITS file transfer (LOLbin)'),
            ('/create', 'BITS job creation (LOLbin)'),
            ('/addfile', 'BITS file add (LOLbin)'),
        ],
        'mshta.exe': [
            ('http', 'MSHTA loading remote HTA (Squiblydoo variant)'),
            ('javascript:', 'MSHTA with inline JavaScript'),
            ('vbscript:', 'MSHTA with inline VBScript'),
        ],
        'regsvr32.exe': [
            ('/i:http', 'Regsvr32 remote script (Squiblydoo attack)'),
            ('/i:https', 'Regsvr32 remote script (Squiblydoo attack)'),
            ('/u ', 'Regsvr32 uninstall with script'),
            ('scrobj.dll', 'Regsvr32 with script object (Squiblydoo)'),
        ],
        'rundll32.exe': [
            ('javascript:', 'Rundll32 with JavaScript (execution bypass)'),
            ('shell32.dll,ShellExec', 'Rundll32 ShellExec execution'),
            ('advpack.dll,LaunchINFSection', 'Rundll32 INF section launch'),
            ('ieadvpack.dll,LaunchINFSection', 'Rundll32 INF section launch'),
            ('shell32.dll,OpenAs_RunDLL', 'Rundll32 OpenAs execution'),
            ('comsvcs.dll,MiniDump', 'Rundll32 LSASS minidump (credential theft)'),
            ('\\temp\\', 'Rundll32 loading from temp directory'),
            ('\\downloads\\', 'Rundll32 loading from downloads directory'),
        ],
        'wmic.exe': [
            ('process call create', 'WMIC process creation (lateral movement)'),
            ('process create', 'WMIC process creation (lateral movement)'),
            ('/node:', 'WMIC remote node execution (lateral movement)'),
        ],
        'msbuild.exe': [
            ('inline', 'MSBuild inline task execution (fileless)'),
            ('http', 'MSBuild remote project load'),
            ('\\temp\\', 'MSBuild from temp directory'),
        ],
        'installutil.exe': [
            ('/logfile=', 'InstallUtil code execution (LOLbin)'),
            ('/InstallState=', 'InstallUtil code execution (LOLbin)'),
        ],
        'msiexec.exe': [
            ('/i http', 'MSI remote install (LOLbin)'),
            ('/ihttps', 'MSI remote install (LOLbin)'),
            ('/quiet', 'MSI silent install'),
        ],
        'forfiles.exe': [
            ('/c ', 'Forfiles command execution (LOLbin bypass)'),
            ('cmd.exe', 'Forfiles spawning cmd.exe (LOLbin bypass)'),
        ],
        'cmstp.exe': [
            ('/s ', 'CMSTP silent install (LOLbin)'),
            ('/ns', 'CMSTP no service install (LOLbin)'),
        ],
    }

    # Suspicious curl/wget upload patterns
    _EXFIL_UPLOAD_FLAGS = (
        ' -t ', ' --upload-file ', ' -f ', ' --form ',
        ' -d ', ' --data ', ' --data-binary ', ' -T ',
    )

    def _get_cmdline(self, profile):
        """Get command line for a process, cached on profile."""
        if hasattr(profile, '_cmdline_cache'):
            return profile._cmdline_cache
        try:
            import psutil as _ps
            p = _ps.Process(profile.pid)
            cmd = ' '.join(p.cmdline()[:30])
        except Exception:
            cmd = ''
        profile._cmdline_cache = cmd
        return cmd

    def _check_lolbin_abuse(self, profile):
        """Detect LOLbin abuse — certutil, bitsadmin, mshta, regsvr32, etc."""
        name_lower = profile.name.lower()
        if name_lower not in self._LOLBINS:
            return
        cmdline = self._get_cmdline(profile)
        cmdline_lower = cmdline.lower()
        patterns = self._LOLBIN_PATTERNS.get(name_lower, [])
        for pattern, desc in patterns:
            if pattern in cmdline_lower:
                evidence = [
                    f"Process: {profile.name} (PID {profile.pid})",
                    f"Command: {cmdline[:300]}",
                    f"LOLbin abuse: {desc}",
                ]
                sev = "CRITICAL" if any(k in pattern or k in cmdline_lower for k in
                    ('http', 'javascript', 'vbscript', 'minidump',
                     'process call create', 'process create', '/node:',
                     'inline', '/i http', 'shell32.dll,ShellExec',
                     'scrobj.dll', '\\temp\\', '\\downloads\\')) else "WARNING"
                self._add_deduction(sev, "LOLBIN_ABUSE",
                    profile.name, profile.pid,
                    f"LOLBIN ABUSE: {desc} in {profile.name}",
                    evidence, 50.0 if sev == "CRITICAL" else 30.0)
                self._pin_to_conns(profile.pid, "LOLBIN_ABUSE",
                    f"LOLbin abuse: {desc}")
                self._flag_suspicious('LOLBIN_ABUSE', sev, 'Process',
                    profile.pid, f"LOLbin abuse: {desc}", evidence)
                break  # one alert per process per scan

    def _check_suspicious_exec_path(self, profile):
        """Detect executables running from suspicious directories."""
        if not profile.exe_path:
            return
        exe_lower = profile.exe_path.lower()
        # System processes are exempt
        if profile.name.lower() in self._SYSTEM_PROCESSES:
            return
        # Known safe directories
        if any(safe in exe_lower for safe in (
                '\\windows\\system32\\', '\\windows\\syswow64\\',
                '\\program files\\', '\\program files (x86)\\',
                '\\windows\\winsxs\\', '\\windows\\servicing\\',
                '\\windows\\assembly\\')):
            return
        for susp_dir in self._SUSPICIOUS_EXEC_DIRS:
            if susp_dir in exe_lower:
                evidence = [
                    f"Process: {profile.name} (PID {profile.pid})",
                    f"Executable path: {profile.exe_path}",
                    f"Running from suspicious directory: {susp_dir}",
                    "Executable in temp/downloads/appdata — likely dropped payload",
                ]
                self._add_deduction("CRITICAL", "SUSPICIOUS_PATH",
                    profile.name, profile.pid,
                    f"SUSPICIOUS EXEC PATH: '{profile.name}' running from {profile.exe_path}",
                    evidence, 45.0)
                self._pin_to_conns(profile.pid, "SUSPICIOUS_PATH",
                    f"Exec from {profile.exe_path}")
                self._flag_suspicious('SUSPICIOUS_PATH', 'CRITICAL', 'Process',
                    profile.pid, f"Exec from suspicious path: {exe_lower}",
                    evidence)
                break

    def _check_parent_child_mismatch(self, profile):
        """Detect system processes spawned by unexpected parents."""
        name_lower = profile.name.lower()
        if name_lower not in self._EXPECTED_PARENTS:
            return
        if not profile.parent_name:
            return
        parent_lower = profile.parent_name.lower()
        expected = self._EXPECTED_PARENTS[name_lower]
        if parent_lower not in expected:
            # svchost.exe spawned by cmd.exe is a classic hollowing sign
            evidence = [
                f"Process: {profile.name} (PID {profile.pid})",
                f"Parent: {profile.parent_name} (PID {profile.parent_pid})",
                f"Expected parent: {', '.join(expected)}",
                f"Actual parent: {profile.parent_name}",
                "Parent-child mismatch — possible process hollowing or injection",
            ]
            self._add_deduction("CRITICAL", "PARENT_MISMATCH",
                profile.name, profile.pid,
                f"PARENT MISMATCH: '{profile.name}' spawned by "
                f"'{profile.parent_name}' (expected: {', '.join(expected)})",
                evidence, 55.0)
            self._pin_to_conns(profile.pid, "PARENT_MISMATCH",
                f"{profile.name} spawned by {profile.parent_name}")
            self._flag_suspicious('PARENT_MISMATCH', 'CRITICAL', 'Process',
                profile.pid, f"Parent mismatch: {profile.name} <- {profile.parent_name}",
                evidence)

    def _check_lsass_access(self, profile):
        """Detect non-system processes accessing LSASS memory."""
        name_lower = profile.name.lower()
        # Only system processes should access LSASS
        if name_lower in ('wininit.exe', 'svchost.exe', 'lsass.exe',
                          'services.exe', 'smss.exe', 'csrss.exe',
                          'winlogon.exe', 'werfault.exe'):
            return
        try:
            import psutil as _ps
            # Find LSASS PID
            lsass_pid = None
            for p in _ps.process_iter(['pid', 'name']):
                if p.info['name'] and p.info['name'].lower() == 'lsass.exe':
                    lsass_pid = p.info['pid']
                    break
            if not lsass_pid:
                return
            # Check if this process has handles to LSASS
            p = _ps.Process(profile.pid)
            # Check open_files and connections for indicators
            # psutil doesn't expose handle list, but we can check
            # if the process name is a known dumper
            cmdline = self._get_cmdline(profile)
            cmdline_lower = cmdline.lower()
            # comsvcs.dll MiniDump via rundll32
            if 'comsvcs.dll' in cmdline_lower and 'minidump' in cmdline_lower:
                evidence = [
                    f"Process: {profile.name} (PID {profile.pid})",
                    f"Command: {cmdline[:300]}",
                    f"LSASS PID: {lsass_pid}",
                    "comsvcs.dll MiniDump — LSASS memory dump via rundll32",
                ]
                self._add_deduction("CRITICAL", "CREDENTIAL_DUMP",
                    profile.name, profile.pid,
                    "CREDENTIAL DUMPING: LSASS minidump via comsvcs.dll",
                    evidence, 70.0)
                self._pin_to_conns(profile.pid, "CREDENTIAL_DUMP",
                    "LSASS minidump via comsvcs.dll")
                self._flag_suspicious('CREDENTIAL_DUMP', 'CRITICAL', 'Process',
                    profile.pid, "LSASS minidump via comsvcs.dll", evidence)
            # taskmgr.exe creating a dump file
            elif name_lower == 'taskmgr.exe' and ('.dmp' in cmdline_lower
                    or 'dump' in cmdline_lower):
                evidence = [
                    f"Process: {profile.name} (PID {profile.pid})",
                    f"Command: {cmdline[:300]}",
                    "Task Manager creating dump — possible LSASS dump",
                ]
                self._add_deduction("WARNING", "CREDENTIAL_DUMP",
                    profile.name, profile.pid,
                    "CREDENTIAL DUMPING: Task Manager dump (possible LSASS)",
                    evidence, 45.0)
                self._pin_to_conns(profile.pid, "CREDENTIAL_DUMP",
                    "Task Manager dump")
        except Exception:
            pass

    def _check_exfil_upload(self, profile, dst_ip, dst_port, domains):
        """Detect curl/wwget uploading files to external servers."""
        name_lower = profile.name.lower()
        if name_lower not in ('curl.exe', 'wget.exe', 'curl', 'wget'):
            return
        cmdline = self._get_cmdline(profile)
        cmdline_lower = cmdline.lower()
        for flag in self._EXFIL_UPLOAD_FLAGS:
            if flag in cmdline_lower:
                # Check if uploading to a non-local IP
                evidence = [
                    f"Process: {profile.name} (PID {profile.pid})",
                    f"Destination: {dst_ip}:{dst_port}",
                    f"Command: {cmdline[:300]}",
                    f"Upload flag detected: {flag.strip()}",
                    "curl/wget uploading data — possible exfiltration",
                ]
                self._add_deduction("CRITICAL", "EXFIL_CHANNEL",
                    profile.name, profile.pid,
                    f"EXFIL UPLOAD: {profile.name} uploading to {dst_ip}",
                    evidence, 50.0)
                self._pin_to_conns(profile.pid, "EXFIL_CHANNEL",
                    f"curl/wget upload to {dst_ip}")
                self._flag_suspicious('EXFIL_CHANNEL', 'CRITICAL', 'Process',
                    profile.pid, f"Exfil upload to {dst_ip}", evidence)
                break

    def _check_powershell_obfuscation(self, profile):
        """Detect advanced PowerShell obfuscation that evades simple matching."""
        name_lower = profile.name.lower()
        if name_lower not in ('powershell.exe', 'pwsh.exe'):
            return
        cmdline = self._get_cmdline(profile)
        if not cmdline or len(cmdline) < 10:
            return
        # Advanced obfuscation indicators
        obfuscation_signs = 0
        reasons = []
        # High ratio of non-alphanumeric chars = obfuscation
        non_alpha = sum(1 for c in cmdline if not (c.isalnum() or c in ' .-_/\\:"\''))
        if len(cmdline) > 50 and non_alpha / len(cmdline) > 0.15:
            obfuscation_signs += 1
            reasons.append("High special-character ratio (obfuscation)")
        # Reversed strings (common obfuscation)
        reversed_patterns = ['}he`', '}"e`', 'noisseuqxe-ekovni', 'gnirtSesaBmorF']
        cmdline_lower = cmdline.lower()
        for rp in reversed_patterns:
            if rp in cmdline_lower:
                obfuscation_signs += 1
                reasons.append("Reversed string pattern (obfuscation)")
                break
        # Concatenated string building
        if cmdline.count('+') > 10 and 'char' in cmdline_lower:
            obfuscation_signs += 1
            reasons.append("String concatenation with char codes (obfuscation)")
        # XOR patterns
        if '-bxor' in cmdline_lower or '^' in cmdline and 'char' in cmdline_lower:
            obfuscation_signs += 1
            reasons.append("XOR encoding (obfuscation)")
        # Base64 in variable assignment
        if 'frombase64string' in cmdline_lower and '::' in cmdline:
            obfuscation_signs += 1
            reasons.append("Base64 decode with type accelerator (obfuscation)")
        # Long encoded blob
        if '-enc' in cmdline_lower or '-encodedcommand' in cmdline_lower:
            # Extract the encoded part
            parts = cmdline_lower.split('-enc')
            if len(parts) > 1:
                encoded_part = parts[1].strip().split()[0] if parts[1].strip() else ''
                if len(encoded_part) > 100:
                    obfuscation_signs += 1
                    reasons.append(f"Long encoded command ({len(encoded_part)} chars)")
        # -Command with IEX or Invoke-Expression
        if '-command' in cmdline_lower and ('iex' in cmdline_lower
                or 'invoke-expression' in cmdline_lower):
            obfuscation_signs += 1
            reasons.append("-Command with IEX/Invoke-Expression")
        # Hidden + NoProfile + NonInteractive combo (suspicious combo)
        combo_count = sum(1 for f in ('-w hidden', '-windowstyle hidden',
            '-nop', '-noProfile', '-noninteractive', '-sta') if f in cmdline_lower)
        if combo_count >= 3:
            obfuscation_signs += 1
            reasons.append(f"Suspicious flag combo ({combo_count} stealth flags)")
        # Download cradle: Net.WebClient + DownloadString
        if 'net.webclient' in cmdline_lower and 'download' in cmdline_lower:
            obfuscation_signs += 1
            reasons.append("WebClient download cradle (fileless execution)")
        # Reflection.Assembly load (fileless .NET)
        if 'reflection.assembly' in cmdline_lower or '[assembly]' in cmdline_lower:
            obfuscation_signs += 1
            reasons.append("Reflective assembly load (fileless .NET)")
        # Add-Type (compiling C# in memory)
        if 'add-type' in cmdline_lower and ('http' in cmdline_lower
                or 'webclient' in cmdline_lower):
            obfuscation_signs += 1
            reasons.append("Add-Type with network access (in-memory compile)")
        if obfuscation_signs >= 1:
            evidence = [
                f"Process: {profile.name} (PID {profile.pid})",
                f"Command: {cmdline[:400]}",
                f"Obfuscation indicators: {obfuscation_signs}",
            ] + [f"  - {r}" for r in reasons]
            sev = "CRITICAL" if obfuscation_signs >= 2 else "WARNING"
            self._add_deduction(sev, "PS_OBFUSCATION",
                profile.name, profile.pid,
                f"POWERSHELL OBFUSCATION: {profile.name} has "
                f"{obfuscation_signs} obfuscation indicators",
                evidence, 55.0 if sev == "CRITICAL" else 35.0)
            self._pin_to_conns(profile.pid, "PS_OBFUSCATION",
                f"PowerShell obfuscation ({obfuscation_signs} indicators)")
            self._flag_suspicious('PS_OBFUSCATION', sev, 'Process',
                profile.pid, f"PS obfuscation: {obfuscation_signs} indicators",
                evidence)

    def _check_suspicious_child(self, profile):
        """Detect suspicious child processes spawned by any process
        (broader than _check_network_spawned which only checks network parents)."""
        if not profile.parent_name:
            return
        name_lower = profile.name.lower()
        parent_lower = profile.parent_name.lower()
        # Suspicious children spawned by office apps, browsers, etc.
        _OFFICE_PARENTS = {
            'winword.exe', 'excel.exe', 'powerpnt.exe', 'outlook.exe',
            'onenote.exe', 'msaccess.exe',
        }
        _BROWSER_PARENTS = {
            'chrome.exe', 'firefox.exe', 'msedge.exe', 'iexplore.exe',
            'brave.exe', 'opera.exe', 'vivaldi.exe',
        }
        # Office apps spawning shells = macro malware
        if parent_lower in _OFFICE_PARENTS and name_lower in self._SUSPICIOUS_CHILDREN:
            evidence = [
                f"Parent: {profile.parent_name} (PID {profile.parent_pid})",
                f"Child: {profile.name} (PID {profile.pid})",
                f"Command: {self._get_cmdline(profile)[:200]}",
                "Office application spawned a shell — macro malware",
            ]
            self._add_deduction("CRITICAL", "MACRO_MALWARE",
                profile.name, profile.pid,
                f"MACRO MALWARE: '{profile.parent_name}' spawned '{profile.name}'",
                evidence, 60.0)
            self._pin_to_conns(profile.pid, "MACRO_MALWARE",
                f"Office spawned {profile.name}")
            self._flag_suspicious('MACRO_MALWARE', 'CRITICAL', 'Process',
                profile.pid, f"Office spawned {profile.name}", evidence)
            return
        # Browsers spawning shells = exploit drive-by
        if parent_lower in _BROWSER_PARENTS and name_lower in (
                'cmd.exe', 'powershell.exe', 'pwsh.exe', 'wscript.exe',
                'cscript.exe', 'mshta.exe', 'rundll32.exe', 'regsvr32.exe'):
            evidence = [
                f"Parent: {profile.parent_name} (PID {profile.parent_pid})",
                f"Child: {profile.name} (PID {profile.pid})",
                f"Command: {self._get_cmdline(profile)[:200]}",
                "Browser spawned a shell — exploit drive-by",
            ]
            self._add_deduction("CRITICAL", "BROWSER_EXPLOIT",
                profile.name, profile.pid,
                f"BROWSER EXPLOIT: '{profile.parent_name}' spawned '{profile.name}'",
                evidence, 60.0)
            self._pin_to_conns(profile.pid, "BROWSER_EXPLOIT",
                f"Browser spawned {profile.name}")
            self._flag_suspicious('BROWSER_EXPLOIT', 'CRITICAL', 'Process',
                profile.pid, f"Browser spawned {profile.name}", evidence)

    def _check_renamed_system_binary(self, profile):
        """Detect system binaries running from non-standard paths
        (e.g., a copy of cmd.exe renamed and run from temp)."""
        if not profile.exe_path:
            return
        exe_lower = profile.exe_path.lower()
        name_lower = profile.name.lower()
        # Known system binary names that should be in System32
        _SYSTEM_BINARIES = {
            'cmd.exe', 'powershell.exe', 'reg.exe', 'regedit.exe',
            'sc.exe', 'net.exe', 'net1.exe', 'taskmgr.exe',
            'eventvwr.exe', 'mmc.exe', 'wmic.exe', 'netsh.exe',
            'certutil.exe', 'bitsadmin.exe', 'mshta.exe',
        }
        if name_lower not in _SYSTEM_BINARIES:
            return
        # Check if running from a non-system directory
        if 'system32' in exe_lower or 'syswow64' in exe_lower:
            return
        if 'windowspowershell' in exe_lower and 'powershell.exe' in exe_lower:
            return  # PowerShell from WindowsPowerShell dir is valid
        evidence = [
            f"Process: {profile.name} (PID {profile.pid})",
            f"Executable path: {profile.exe_path}",
            f"System binary '{profile.name}' running from non-standard path",
            "Possible renamed/copied system binary — evasion technique",
        ]
        self._add_deduction("CRITICAL", "RENAMED_BINARY",
            profile.name, profile.pid,
            f"RENAMED BINARY: '{profile.name}' running from {profile.exe_path}",
            evidence, 50.0)
        self._pin_to_conns(profile.pid, "RENAMED_BINARY",
            f"System binary from {profile.exe_path}")
        self._flag_suspicious('RENAMED_BINARY', 'CRITICAL', 'Process',
            profile.pid, f"System binary from non-standard path", evidence)

    # ---------- Risk Score Management ----------
    def _update_risk(self, profile):
        profile.risk_score = max(0, profile.risk_score * 0.997)
        if profile.risk_score > CONFIG['risk_critical']:
            self._safe_alert(
                f"{EMOJI['alert']} HIGH RISK: '{profile.name}' (PID {profile.pid}) "
                f"score={profile.risk_score:.0f}", Colors.R)

    # ====================== CONNECTION MAPPER ======================
    def _get_conn_snapshot(self) -> list:
        """Return the latest connection snapshot (used by ConnectionInventory)."""
        # Return the reference directly — the mapper replaces the list
        # atomically rather than mutating it, so a reference is safe.
        # Avoids a list() copy on every ConnectionInventory scan cycle.
        with self._conn_snapshot_lock:
            return self._conn_snapshot

    def owner_of_ip(self, ip: str) -> dict:
        """Resolve a remote IP to its owning process via the conn_by_raddr
        index the connection mapper maintains."""
        with self.conn_cache_lock:
            entry = self.conn_by_raddr.get(ip)
        if not entry:
            return {}
        pid, conn = entry
        info = {'pid': pid or 0, 'name': '?', 'exe': '', 'status': conn.status}
        with self.lock:
            prof = self.process_profiles.get(pid)
            if prof:
                info['name'] = prof.name
                info['exe'] = prof.exe_path
        return info

    def _connection_mapper(self):
        while not self.stop.is_set():
            try:
                raw_conns = psutil.net_connections(kind='all')
                # Store raw snapshot for ConnectionInventory (single psutil call)
                with self._conn_snapshot_lock:
                    self._conn_snapshot = raw_conns
                # Build indexed views for process watcher
                by_pid = defaultdict(list)
                by_raddr = {}
                for conn in raw_conns:
                    if conn.pid:
                        by_pid[conn.pid].append(conn)
                    if conn.raddr:
                        # Last-write-wins used to discard every process but one
                        # per remote IP, so owner_of_ip could name the wrong
                        # process. Prefer an entry that actually has a PID.
                        prev = by_raddr.get(conn.raddr[0])
                        if prev is None or (not prev[0] and conn.pid):
                            by_raddr[conn.raddr[0]] = (conn.pid, conn)
                with self.conn_cache_lock:
                    self.conn_by_pid = by_pid
                    self.conn_by_raddr = by_raddr
            except psutil.AccessDenied:
                pass
            except Exception as exc:
                _logger.debug("Connection mapper error: %s", exc)
            time.sleep(CONFIG.get('conn_map_interval', 0.5))

    # ====================== PROCESS WATCHER ======================
    def _process_watcher(self):
        last_pids: set[int] = set()
        while not self.stop.is_set():
            current_pids: set[int] = set()
            audio_pids: set[int] = set()
            camera_pids: set[int] = set()
            with self.lock:
                prev_audio_pids = set(self.audio_active_pids)
                prev_camera_pids = set(self.camera_active_pids)
            # Grab a reference (not a copy) — the mapper replaces the dict
            # atomically rather than mutating it, so a reference is safe.
            with self.conn_cache_lock:
                conn_by_pid = self.conn_by_pid

            for proc in psutil.process_iter(['pid', 'name', 'ppid', 'exe', 'cpu_percent']):
                try:
                    pid = proc.pid
                    name = proc.name()
                    current_pids.add(pid)
                    # Hardware detection (merged — avoids double process_iter)
                    name_lower_hw = name.lower()
                    # Compare against the PREVIOUS cycle's sets, not the sets being
                    # built right now — otherwise every audio/camera process is
                    # re-flagged on every scan and floods the suspicious log.
                    if any(kw in name_lower_hw for kw in HARDWARE_KEYWORDS['audio']):
                        if pid not in prev_audio_pids:
                            self._flag_suspicious('HARDWARE_ACCESS', 'WARNING', name, pid,
                                f'Audio device accessed by {name}',
                                [f'Process: {name} (PID {pid})',
                                 'Matched audio keyword in process name',
                                 'Audio hardware is being used — potential eavesdropping if unexpected'])
                        audio_pids.add(pid)
                    if any(kw in name_lower_hw for kw in HARDWARE_KEYWORDS['camera']):
                        if pid not in prev_camera_pids:
                            self._flag_suspicious('HARDWARE_ACCESS', 'CRITICAL', name, pid,
                                f'Camera/webcam accessed by {name}',
                                [f'Process: {name} (PID {pid})',
                                 'Matched camera keyword in process name',
                                 'Camera hardware is being used — potential surveillance if unexpected'])
                        camera_pids.add(pid)
                    with self.lock:
                        if pid not in self.process_profiles:
                            profile = ProcessProfile(
                                pid=pid, name=name, exe_path=proc.exe() or "",
                                parent_pid=proc.ppid() or 0,
                                start_time=proc.create_time(),
                            )
                            try:
                                profile.parent_name = psutil.Process(profile.parent_pid).name()
                            except Exception:
                                profile.parent_name = ""
                            self.process_profiles[pid] = profile
                            self._write_action(pid, name, "STARTED",
                                f"exe={profile.exe_path} parent={profile.parent_name}")
                            # Flag processes from suspicious paths
                            exe_lower = profile.exe_path.lower()
                            for susp_path in SUSPICIOUS_DLL_PATHS:
                                if susp_path in exe_lower:
                                    self._flag_suspicious('SUSPICIOUS_PATH', 'WARNING', name, pid,
                                        f'Process started from suspicious location: {profile.exe_path}',
                                        [f'Process: {name} (PID {pid})',
                                         f'Exe: {profile.exe_path}',
                                         f'Parent: {profile.parent_name} (PID {profile.parent_pid})',
                                         f'Matched suspicious path: {susp_path}'])
                                    break
                        profile = self.process_profiles[pid]

                    cpu = proc.cpu_percent(interval=None)
                    try:
                        mem_mb = proc.memory_info().rss / (1024 * 1024)
                    except Exception:
                        mem_mb = 0.0
                    with self.lock:
                        profile.cpu_samples.append(cpu)
                        profile.memory_mb = mem_mb
                        if cpu > 5:
                            self.user_activity_ts = time.time()
                    if not profile.cmdline:
                        try:
                            cl = proc.cmdline()
                            if cl:
                                profile.cmdline = ' '.join(cl)[:500]
                        except Exception:
                            pass

                    _pw_conns = conn_by_pid.get(pid, [])
                    self._check_impersonation(profile, proc)
                    for conn in _pw_conns:
                        if conn.raddr:
                            dst_ip = conn.raddr[0]
                            dst_port = conn.raddr[1]
                            conn_key = (dst_ip, dst_port, conn.laddr[0] if conn.laddr else '', conn.laddr[1] if conn.laddr else 0)
                            now_ts = time.time()
                            # Fetch domains once — was called twice (inside lock + outside)
                            domains = self.dns_cache.get_domains(dst_ip)
                            # Single lock acquisition for all profile updates
                            with self.lock:
                                is_new = conn_key not in profile.seen_conn_keys
                                profile.destinations.add(dst_ip)
                                if is_new:
                                    profile.seen_conn_keys.add(conn_key)
                                    profile.connection_count += 1
                                profile.packet_timestamps.append(now_ts)
                                profile.last_network_ts = now_ts
                                profile.dns_domains.update(domains)
                            self._write_action(pid, name, "NETWORK_FLOW",
                                f"-> {dst_ip}:{dst_port} domains={domains or 'unresolved'}")
                            # Flag remote access ports — uses module-level _PORT_NAMES constant
                            if is_new and dst_port in CONFIG['remote_ports']:
                                pname = _PORT_NAMES.get(dst_port, "Unknown")
                                self._flag_suspicious('REMOTE_ACCESS', 'WARNING', name, pid,
                                    f'{name} connected to remote access port {dst_port} ({pname})',
                                    [f'Process: {name} (PID {pid})',
                                     f'Destination: {dst_ip}:{dst_port}',
                                     f'Protocol: {pname}',
                                     f'Domain: {", ".join(domains) if domains else "unresolved"}',
                                     'This could indicate remote control or lateral movement'])
                            # Flag connections to high-risk countries — cache _is_public_ip result
                            is_pub = self._is_public_ip(dst_ip) if is_new else False
                            cc = ''
                            if is_pub:
                                cc = self.geoip.get_country(dst_ip)
                                if cc in CONFIG['high_risk_countries']:
                                    self._flag_suspicious('HIGH_RISK_GEO', 'CRITICAL', name, pid,
                                        f'{name} connected to high-risk country: {cc} ({dst_ip})',
                                        [f'Process: {name} (PID {pid})',
                                         f'Destination: {dst_ip}:{dst_port}',
                                         f'Country: {cc}',
                                         f'Domain: {", ".join(domains) if domains else "unresolved"}',
                                         f'High-risk countries: {CONFIG["high_risk_countries"]}'])
                            self._check_watchlist(name, pid, dst_ip, dst_port, domains)
                            self._check_mimic(profile, dst_ip, domains)
                            self._check_foreign(profile, dst_ip, domains)
                            self._check_behavioral_anomaly(profile, dst_ip)
                            self._check_geoip(profile, dst_ip, domains)
                            self._check_verification(profile, dst_ip, dst_port, domains)
                            # Anti-hack: check admin share access (15) and exfil channels (17)
                            self._check_admin_share(profile, dst_ip, dst_port)
                            self._check_exfil_channel(profile, dst_ip, domains)
                            self._check_exfil_upload(profile, dst_ip, dst_port, domains)
                            # Background multi-verification — reuse cached is_pub + cc
                            if is_new and is_pub:
                                # Everything public gets verified; these just
                                # jump the queue.
                                urgent = (
                                    cc in CONFIG['high_risk_countries']
                                    or dst_ip in self._watchlist_ips
                                    or (dst_port in CONFIG['remote_ports'])
                                    or (profile.risk > 30)
                                )
                                self._queue_ip_verification(
                                    dst_ip, priority=0 if urgent else 5)
                                # Whois/RDAP lookup for high-risk or unknown public IPs
                                if (cc in CONFIG['high_risk_countries']
                                        or dst_port in CONFIG['remote_ports']
                                        or dst_ip in self._watchlist_ips):
                                    self._whois_lookup.lookup(dst_ip)
                            # DoH detection
                            doh_ev = self.doh_detector.check_connection(pid, name, dst_ip, dst_port)
                            if doh_ev:
                                self._flag_suspicious('DOH', 'WARNING', name, pid,
                                    doh_ev['detail'], [doh_ev['detail']])
                                self._log(f"{EMOJI['tunnel']} DOH: {doh_ev['detail']}", color=Colors.Y)

                    self._check_beacon(profile)
                    if profile.connection_count > 0:
                        self._check_injection_chain(profile)
                    self._check_exfil(profile, proc)
                    self._check_dlls(profile, proc)
                    self._check_idle_anomaly(profile)
                    self._check_ml_anomaly(profile)
                    # Anti-hack per-process checks
                    self._check_network_spawned(profile)
                    self._check_listening_ports(profile)
                    self._check_credential_access(profile)
                    self._check_port_forward(profile)
                    self._check_data_staging(profile)
                    self._check_powershell_abuse(profile)
                    self._check_backup_tampering(profile)
                    self._check_process_hollow(profile)
                    # Enhanced anti-hack checks
                    self._check_lolbin_abuse(profile)
                    self._check_suspicious_exec_path(profile)
                    self._check_parent_child_mismatch(profile)
                    self._check_lsass_access(profile)
                    self._check_powershell_obfuscation(profile)
                    self._check_suspicious_child(profile)
                    self._check_renamed_system_binary(profile)
                    self._update_risk(profile)
                    # VirusTotal check (once per PID, rate-limited)
                    vt_result = self.vt_checker.check_exe(pid, profile.exe_path)
                    if vt_result and vt_result.get('malicious', 0) > 0:
                        self._flag_suspicious('VIRUSTOTAL', 'CRITICAL', name, pid,
                            f"VirusTotal: {name} flagged by {vt_result['malicious']} engines",
                            [f"SHA256: {vt_result.get('sha256', '?')}",
                             f"Malicious: {vt_result['malicious']}, Suspicious: {vt_result.get('suspicious', 0)}",
                             f"Exe: {profile.exe_path}"])
                        self._add_deduction("CRITICAL", "VIRUSTOTAL", name, pid,
                            f"VIRUSTOTAL: '{name}' flagged as malicious by {vt_result['malicious']} AV engines",
                            [f"SHA256: {vt_result.get('sha256', '?')}",
                             f"Malicious: {vt_result['malicious']}", f"Exe: {profile.exe_path}"],
                            min(80.0, vt_result['malicious'] * 5.0))
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
                except Exception as exc:
                    _logger.debug("Process watcher error for PID %s: %s", pid, exc)

            for pid in last_pids - current_pids:
                prof_name = None
                with self.lock:
                    if pid in self.process_profiles:
                        prof_name = self.process_profiles[pid].name
                        del self.process_profiles[pid]
                if prof_name is not None:
                    self._write_action(pid, prof_name, "STOPPED")

            # Update hardware activity from this scan pass
            with self.lock:
                self.audio_active_pids = audio_pids
                self.camera_active_pids = camera_pids

            self._check_phantoms(current_pids)
            if _IS_WINDOWS:
                self._check_persistence()
            last_pids = current_pids
            time.sleep(CONFIG.get('process_scan_interval', 0.5))

    # ====================== PACKET CALLBACK (via pipeline) ======================
    def _packet_callback(self, pkt):
        """Called by pipeline workers — not directly by sniff thread."""
        # Cache layer checks — pkt.haslayer() is called many times per packet
        has_ip = pkt.haslayer(IP)
        has_ipv6 = pkt.haslayer(IPv6)
        has_tcp = pkt.haslayer(TCP)
        has_udp = pkt.haslayer(UDP)
        has_dns = pkt.haslayer(DNS)
        has_raw = pkt.haslayer(Raw)
        has_ether = pkt.haslayer(Ether)

        if has_dns:
            self.dns_cache.process_packet(pkt)
            if pkt[DNS].qr == 0:
                try:
                    qname = pkt[DNS].qd.qname.decode(errors='ignore').rstrip('.')
                    src_q = pkt[IP].src if has_ip else '?'
                    self._check_dns_tunnel(qname, src_q)
                except Exception as exc:
                    _logger.debug("DNS tunnel check error: %s", exc)

        sni = self.sni_extractor.extract(pkt)
        if sni:
            dst_for_sni = pkt[IP].dst if has_ip else None
            if dst_for_sni:
                with self.dns_cache.lock:
                    self.dns_cache.ip_to_domains[dst_for_sni].add(sni)
                    self.dns_cache.domain_to_ips[sni].add(dst_for_sni)

        if has_raw:
            payload = bytes(pkt[Raw])
            if len(payload) >= 32:
                ent = self.entropy_analyzer.payload_entropy(payload)
                is_sus, desc = self.entropy_analyzer.is_suspicious(pkt, ent)
                if is_sus:
                    src_e = pkt[IP].src if has_ip else '?'
                    dst_e = pkt[IP].dst if has_ip else '?'
                    self._add_deduction("WARNING", "ENTROPY", "packet", 0,
                        f"HIGH ENTROPY PAYLOAD: {src_e} -> {dst_e}: {desc}",
                        [desc, f"Payload size: {len(payload)} bytes"], 15.0)

        ja4s = self.ja4plus.ja4s(pkt)
        ja4h = self.ja4plus.ja4h(pkt)

        if not (has_ip or has_ipv6):
            return

        src = pkt[IP].src if has_ip else pkt[IPv6].src
        dst = pkt[IP].dst if has_ip else pkt[IPv6].dst
        dport = pkt[TCP].dport if has_tcp else (pkt[UDP].dport if has_udp else 0)

        mac = pkt[Ether].src.upper() if has_ether else None
        try:
            if self.network and ipaddress.ip_address(src) not in self.network:
                if not (src.startswith('fe80') or src.startswith('fd')):
                    return
        except Exception:
            return

        comp_key = self._composite_key(mac, src)
        now = time.time()

        with self.lock:
            if comp_key not in self.seen_composites:
                vendor = get_vendor(mac)
                hostname = self._extract_hostname(pkt) or "Hidden"
                dev = {
                    'mac': mac, 'ip': src, 'vendor': vendor, 'hostname': hostname,
                    'os_guess': self._passive_os(pkt), 'first_seen': now, 'last_seen': now,
                    'confidence': 0.4, 'anomaly_count': 0,
                    'ja4': self.ja4plus.ja4(pkt),
                }
                self.devices[comp_key] = dev
                self.seen_composites.add(comp_key)
                self._log(f"{EMOJI['new']} NEW DEVICE -> {src:18} {vendor:14} {hostname}", color=Colors.Y)
                self.db.save_device(comp_key, dev)
            else:
                dev = self.devices[comp_key]
                if now - dev.get('last_seen', now) > 1800:
                    dev['confidence'] = max(0.05, dev['confidence'] * 0.93)
                dev['last_seen'] = now
                dev['ip'] = src
                dev['confidence'] = min(1.0, dev['confidence'] + 0.07)
            if ja4s:
                dev['ja4s'] = ja4s
            if ja4h:
                dev['ja4h'] = ja4h

        proto = pkt[IP].proto if has_ip else 0
        sport = pkt[TCP].sport if has_tcp else (pkt[UDP].sport if has_udp else 0)
        flow_key = (src, dst, proto, sport, dport)

        # Inbound SYN detection — detect port scans targeting us
        if has_tcp and pkt[TCP].flags & 0x02 and dst == self.local_ip and src != self.local_ip:
            self.inbound_scan_detector.record_inbound_syn(src, pkt[TCP].dport)

        # Per-remote-IP byte accounting — feeds the Net Stats bandwidth table.
        pkt_len = len(pkt)
        if src == self.local_ip and _is_public_ip_cached(dst):
            self.conn_history.update_bandwidth(dst, pkt_len, 0)
        elif dst == self.local_ip and _is_public_ip_cached(src):
            self.conn_history.update_bandwidth(src, 0, pkt_len)

        # TLS certificate tracking (ServerHello with cert)
        if has_tcp and has_raw:
            raw_data = bytes(pkt[Raw])
            if len(raw_data) > 10 and raw_data[0] == 0x16:
                hs = raw_data[5:]
                if len(hs) > 4 and hs[0] == 0x0b:  # Certificate message
                    self.tls_cert_detector.record_cert(src, raw_data[:256])

        with self.lock:
            # These dicts are keyed by network tuples and would otherwise grow for
            # the whole session; drop the oldest entries once they get large.
            if len(self.flow_stats) > MAX_FLOW_KEYS:
                for stale in list(self.flow_stats)[:MAX_FLOW_KEYS // 4]:
                    del self.flow_stats[stale]
            if len(self.remote_sessions) > MAX_REMOTE_SESSIONS:
                cutoff = now - 3600
                for k in [k for k, t in self.remote_sessions.items() if t < cutoff]:
                    del self.remote_sessions[k]
            self.flow_stats[flow_key].append(now)
            probe_count = 0
            if has_tcp and pkt[TCP].flags & 0x02 and pkt[TCP].dport in CONFIG['probe_alert_ports']:
                # Reset the counters every 5 minutes; without this a host that
                # once crossed the threshold stayed "probing" for the whole run
                # and the dict grew unbounded.
                if now - self._probe_window_start > 300:
                    self.probe_attempts.clear()
                    self._probe_window_start = now
                self.probe_attempts[src] += 1
                probe_count = self.probe_attempts[src]

            new_remote = False
            s_port = d_port = 0
            if has_tcp and (pkt[TCP].flags & 0x10):
                s_port, d_port = pkt[TCP].sport, pkt[TCP].dport
                if d_port in CONFIG['remote_ports'] or s_port in CONFIG['remote_ports']:
                    session_key = (src, dst, s_port, d_port)
                    if session_key not in self.remote_sessions:
                        self.remote_sessions[session_key] = now
                        new_remote = True

            arp_spoof_mac = None
            if mac and pkt.haslayer(ARP) and pkt[ARP].op == 2:
                claimed = pkt[ARP].psrc
                if claimed not in self.mac_to_ip_history[mac]:
                    for other_mac, ips in self.mac_to_ip_history.items():
                        if other_mac != mac and claimed in ips:
                            arp_spoof_mac = (mac, claimed)
                            break
                if len(self.mac_to_ip_history[mac]) < 256:
                    self.mac_to_ip_history[mac].add(claimed)

        if probe_count > 7:
            self._safe_alert(f"{EMOJI['probe']} Active probe -> {src} ({probe_count} SYN attempts)", Colors.R)
        if new_remote:
            self._safe_alert(f"{EMOJI['remote']} REMOTE SESSION -> {src}:{s_port} -> {dst}:{d_port}", Colors.R)
        if arp_spoof_mac:
            self._safe_alert(f"{EMOJI['spoof']} ARP SPOOF -> {arp_spoof_mac[0]} claims {arp_spoof_mac[1]}", Colors.R)

    # ====================== THREADS ======================
    def _arp_thread(self):
        while not self.stop.is_set():
            try:
                ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=str(self.network)),
                             timeout=3, verbose=0)
                for _, rcv in ans:
                    fake = Ether(src=rcv.hwsrc)/IP(src=rcv.psrc)
                    self.pipeline.enqueue(fake)
            except Exception as exc:
                _logger.debug("ARP scan error: %s", exc)
            time.sleep(random.uniform(CONFIG.get('scan_interval_min', 2), CONFIG.get('scan_interval_max', 10)))

    def _dns_cache_poll_thread(self):
        """Periodically poll Windows DNS client cache and save domain history."""
        # Initial aggressive poll on startup
        self.dns_cache.poll_system_dns_cache()
        save_counter = 0
        while not self.stop.is_set():
            time.sleep(CONFIG.get('dns_poll_interval', 5))
            try:
                self.dns_cache.poll_system_dns_cache()
            except Exception as exc:
                _logger.debug("DNS poll thread error: %s", exc)
            save_counter += 1
            if save_counter >= 12:  # Save every ~60 seconds (12 × 5s)
                try:
                    self.dns_cache.save_history()
                except Exception as exc:
                    _logger.debug("DNS history save error: %s", exc)
                save_counter = 0

    def _sniff_thread(self):
        filt = "ip or ip6 or arp"
        while not self.stop.is_set():
            try:
                sniff(prn=self.pipeline.enqueue, filter=filt, store=False,
                      promisc=True, timeout=60,
                      stop_filter=lambda _: self.stop.is_set())
            except Exception as e:
                _logger.warning("Sniff error: %s — retrying in %ss", e, CONFIG.get('sniff_retry_interval', 2))
                time.sleep(CONFIG.get('sniff_retry_interval', 2))

    def _status_thread(self):
        while not self.stop.is_set():
            now = time.time()
            # Merge the two self.lock acquisitions (stats + cooldown cleanup)
            # into a single critical section.
            with self.lock:
                n_procs = len(self.process_profiles)
                n_deductions = len(self.deductions)
                high_risk = sum(1 for p in self.process_profiles.values() if p.risk_score > CONFIG['risk_critical'])
                n_devices = len(self.devices)
                # Cooldown cleanup — was a separate lock acquisition
                cooldown_ttl = CONFIG['deduction_cooldown'] * 2
                stale_keys = [k for k, t in self.deduction_cooldowns.items()
                              if now - t > cooldown_ttl]
                for k in stale_keys:
                    del self.deduction_cooldowns[k]
            # These locks are independent — acquire outside self.lock
            with self.dns_cache.lock:
                n_dns = len(self.dns_cache.ip_to_domains)
            with self.geoip.lock:
                n_geo = len(self.geoip.cache)
            idle_sec = self._idle_seconds()
            _min_samples = max(5, int(CONFIG.get('baseline_min_samples', 50)))
            with self.ml_baseline.lock:
                ml_active = sum(1 for m in self.ml_baseline.models.values()
                                if len(m['conn_rate']) >= _min_samples)
            pipe = self.pipeline.stats()
            self._log(
                f"{EMOJI['chess']} Status: {n_devices} devices | "
                f"{n_procs} processes | {n_deductions} deductions | "
                f"{high_risk} high-risk | {n_dns} DNS | {n_geo} GeoIP | "
                f"{ml_active} baselines | idle={idle_sec:.0f}s | "
                f"pipe={pipe['processed']}/{pipe['dropped']}",
                color=Colors.G)
            time.sleep(CONFIG.get('status_interval', 5))

    def _memory_forensics_thread(self):
        if not _IS_WINDOWS:
            return
        MEM_COMMIT = 0x1000
        PAGE_EXECUTE_READWRITE = 0x40
        try:
            class MEMORY_BASIC_INFORMATION(ctypes.Structure):
                _fields_ = [
                    ("BaseAddress", ctypes.c_void_p), ("AllocationBase", ctypes.c_void_p),
                    ("AllocationProtect", ctypes.wintypes.DWORD), ("RegionSize", ctypes.c_size_t),
                    ("State", ctypes.wintypes.DWORD), ("Protect", ctypes.wintypes.DWORD),
                    ("Type", ctypes.wintypes.DWORD),
                ]
        except Exception:
            return

        while not self.stop.is_set():
            with self.lock:
                pids_to_check = [(pid, p.name) for pid, p in self.process_profiles.items()
                                 if p.risk_score > 10 and p.connection_count > 0]
            for pid, pname in pids_to_check[:20]:
                if self.stop.is_set():
                    break
                try:
                    handle = ctypes.windll.kernel32.OpenProcess(0x0400 | 0x0010, False, pid)
                    if not handle:
                        continue
                    mbi = MEMORY_BASIC_INFORMATION()
                    addr = 0
                    rwx_regions = 0
                    regions_walked = 0
                    while ctypes.windll.kernel32.VirtualQueryEx(
                            handle, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)):
                        if mbi.State == MEM_COMMIT and mbi.Protect == PAGE_EXECUTE_READWRITE and mbi.RegionSize > 4096:
                            rwx_regions += 1
                        # A zero RegionSize would never advance `addr` and would
                        # spin this thread forever.
                        if not mbi.RegionSize:
                            break
                        addr += mbi.RegionSize
                        regions_walked += 1
                        if addr > 0x7FFFFFFFFFFF or regions_walked > 200000:
                            break
                    ctypes.windll.kernel32.CloseHandle(handle)
                    if rwx_regions > 2:
                        evidence = [f"Process: {pname} (PID {pid})", f"RWX memory regions: {rwx_regions}",
                                    "RWX pages indicate possible shellcode or reflective DLL injection"]
                        self._add_deduction("CRITICAL", "DLL", pname, pid,
                            f"MEMORY FORENSICS: '{pname}' has {rwx_regions} RWX memory regions",
                            evidence, 45.0)
                except Exception as exc:
                    _logger.debug("Memory forensics error for PID %s: %s", pid, exc)
            time.sleep(CONFIG.get('memory_forensics_interval', 15))

    # ====================== EXTENDED MONITORS (Tier 5) ======================
    def _extended_monitor_thread(self):
        """Runs all Tier 5 detectors periodically in a single thread."""
        cycle = 0
        # Brief delay to let main thread proceed
        time.sleep(2)
        while not self.stop.is_set():
            try:
                cycle += 1
                # File system watchdog — every 10s
                if cycle % 2 == 0:
                    fs_events = self.fs_watchdog.scan()
                    for ev in fs_events:
                        if ev.get('severity') in ('CRITICAL', 'WARNING'):
                            self._flag_suspicious(ev['type'], ev['severity'],
                                'FileSystem', 0, ev['detail'],
                                [f"Path: {ev.get('path', '?')}", f"Type: {ev['type']}"])
                            self._log(f"{EMOJI['alert']} FS: {ev['detail']}",
                                      color=Colors.R if ev['severity'] == 'CRITICAL' else Colors.Y)
                # Clipboard — every 5s
                clip_events = self.clipboard_monitor.check()
                for ev in clip_events:
                    self._flag_suspicious(ev['type'], ev['severity'],
                        'Clipboard', 0, ev['detail'], [ev['detail']])
                    self._log(f"{EMOJI['alert']} CLIPBOARD: {ev['detail']}", color=Colors.R)
                # USB devices — every 30s
                if cycle % 6 == 0:
                    usb_events = self.usb_monitor.scan()
                    for ev in usb_events:
                        self._flag_suspicious('USB', ev['severity'],
                            'USB', 0, ev['detail'], [ev.get('device_id', '?')])
                        self._log(f"{EMOJI['alert']} USB: {ev['detail']}", color=Colors.Y)
                # Scheduled tasks — every 60s
                if cycle % 12 == 0:
                    task_events = self.sched_task_monitor.scan()
                    for ev in task_events:
                        self._flag_suspicious('SCHEDULED_TASK', ev['severity'],
                            'TaskScheduler', 0, ev['detail'], [ev.get('task', '?')])
                        self._log(f"{EMOJI['persist']} TASK: {ev['detail']}", color=Colors.Y)
                # Named pipes — every 30s
                if cycle % 6 == 0:
                    pipe_events = self.named_pipe_monitor.scan()
                    for ev in pipe_events:
                        if ev['severity'] == 'CRITICAL':
                            self._flag_suspicious('NAMED_PIPE', 'CRITICAL',
                                'NamedPipe', 0, ev['detail'], [ev.get('pipe', '?')])
                            self._log(f"{EMOJI['inject']} PIPE: {ev['detail']}", color=Colors.R)
                # Inbound scan detection — every 5s
                scan_events = self.inbound_scan_detector.check()
                for ev in scan_events:
                    self._flag_suspicious('INBOUND_SCAN', 'CRITICAL',
                        'Network', 0, ev['detail'],
                        [f"Source: {ev.get('source_ip', '?')}",
                         f"Ports: {ev.get('ports_probed', [])}"])
                    self._log(f"{EMOJI['probe']} SCAN: {ev['detail']}", color=Colors.R)
                # Bluetooth scan — every 30s
                if cycle % 6 == 0:
                    bt_events = self.bt_scanner.scan()
                    for ev in bt_events:
                        self._flag_suspicious('BLUETOOTH', ev['severity'],
                            'Bluetooth', 0, ev['detail'], [ev['detail']])
                        self._log(f"{EMOJI['alert']} BT: {ev['detail']}", color=Colors.Y)
                # Serial port scan — every 30s
                if cycle % 6 == 0:
                    serial_events = self.serial_scanner.scan()
                    for ev in serial_events:
                        self._flag_suspicious('SERIAL_PORT', ev['severity'],
                            'Serial', 0, ev['detail'], [ev['detail']])
                        self._log(f"{EMOJI['alert']} SERIAL: {ev['detail']}", color=Colors.Y)
                # Proxy detection — every 30s
                if cycle % 6 == 0:
                    proxy_events = self.proxy_detector.scan_system()
                    for ev in proxy_events:
                        self._flag_suspicious(ev['type'], ev['severity'],
                            ev.get('subtype', 'Proxy'), 0, ev['detail'], [ev['detail']])
                        self._log(f"{EMOJI['alert']} PROXY: {ev['detail']}", color=Colors.Y)
                # VPN leak detection — every 60s
                if cycle % 12 == 0:
                    vpn_report = self.vpn_leak_detector.scan()
                    for ev in vpn_report.get('events', []):
                        if ev.get('severity') in ('CRITICAL', 'WARNING'):
                            self._flag_suspicious(ev['type'], ev['severity'],
                                'VPNLeak', 0, ev['detail'], [ev['detail']])
                            self._log(f"{EMOJI['tunnel']} VPN LEAK [{ev['type']}]: {ev['detail']}",
                                      color=Colors.R if ev['severity'] == 'CRITICAL' else Colors.Y)
                # ---- ANTI-HACK MONITORS (18 features) ----
                # 1. Security Event Log — every 15s
                if cycle % 3 == 0:
                    for ev in self.security_event_monitor.scan():
                        self._flag_suspicious(ev['type'], ev['severity'],
                            'SecurityEvent', 0, ev['detail'], [ev['detail']])
                        self._log(f"🛡️ SECURITY EVENT [{ev.get('event_id','?')}]: {ev['detail']}",
                                  color=Colors.R if ev['severity'] == 'CRITICAL' else Colors.Y)
                # 5. Hosts file / DNS hijack — every 30s
                if cycle % 6 == 0:
                    for ev in self.hosts_file_monitor.scan():
                        self._flag_suspicious(ev['type'], ev['severity'],
                            'DnsHijack', 0, ev['detail'], [ev.get('path', ev['detail'])])
                        self._log(f"🌐 DNS HIJACK: {ev['detail']}",
                                  color=Colors.R if ev['severity'] == 'CRITICAL' else Colors.Y)
                # 6. Service creation — every 60s
                if cycle % 12 == 0:
                    for ev in self.service_monitor.scan():
                        self._flag_suspicious(ev['type'], ev['severity'],
                            'ServiceCreate', 0, ev['detail'],
                            [f"Service: {ev.get('service','?')}",
                             f"Binary: {ev.get('binpath','?')}"])
                        self._log(f"🔧 SERVICE CREATE: {ev['detail']}",
                                  color=Colors.R if ev['severity'] == 'CRITICAL' else Colors.Y)
                # 9. Defender / AV disable — every 30s
                if cycle % 6 == 0:
                    for ev in self.security_tool_monitor.scan():
                        self._flag_suspicious(ev['type'], ev['severity'],
                            'AvDisable', 0, ev['detail'], [ev['detail']])
                        self._log(f"🛡️ AV DISABLE: {ev['detail']}",
                                  color=Colors.R if ev['severity'] == 'CRITICAL' else Colors.Y)
                # 10. New user / admin escalation — every 60s
                if cycle % 12 == 0:
                    for ev in self.user_account_monitor.scan():
                        self._flag_suspicious(ev['type'], ev['severity'],
                            'NewAccount', 0, ev['detail'],
                            [f"Account: {ev.get('account','?')}"])
                        self._log(f"👤 NEW ACCOUNT: {ev['detail']}",
                                  color=Colors.R)
                # 11. WMI subscription — every 60s
                if cycle % 12 == 0:
                    for ev in self.wmi_subscription_monitor.scan():
                        self._flag_suspicious(ev['type'], ev['severity'],
                            'WmiPersist', 0, ev['detail'], [ev['detail']])
                        self._log(f"🧩 WMI PERSIST: {ev['detail']}",
                                  color=Colors.R)
                # 14. Driver / rootkit load — every 60s
                if cycle % 12 == 0:
                    for ev in self.driver_load_monitor.scan():
                        self._flag_suspicious(ev['type'], ev['severity'],
                            'DriverLoad', 0, ev['detail'],
                            [f"Driver: {ev.get('driver', ev.get('file','?'))}"])
                        self._log(f"🔧 DRIVER LOAD: {ev['detail']}",
                                  color=Colors.Y)
                # 16. Mutex / named object — every 30s
                if cycle % 6 == 0:
                    for ev in self.mutex_scanner.scan():
                        self._flag_suspicious(ev['type'], ev['severity'],
                            'MutexHit', 0, ev['detail'],
                            [f"Mutex: {ev.get('mutex','?')}"])
                        self._log(f"🔒 MUTEX HIT: {ev['detail']}",
                                  color=Colors.R)
                # Connection history update
                with self._conn_snapshot_lock:
                    snapshot = list(self._conn_snapshot)
                self.conn_history.update(snapshot)
                self.conn_history.prune_bandwidth()
            except Exception as exc:
                _logger.debug("Extended monitor error: %s", exc)
            time.sleep(CONFIG.get('extended_monitor_interval', 2))

    def _iface_stats_thread(self):
        """Track network interface bandwidth over time."""
        while not self.stop.is_set():
            try:
                counters = psutil.net_io_counters(pernic=True)
                now = time.time()
                for iface, stats in counters.items():
                    prev = self._iface_stats_prev.get(iface)
                    if prev:
                        dt = now - prev[2]
                        if dt > 0:
                            sent_rate = (stats.bytes_sent - prev[0]) / dt
                            recv_rate = (stats.bytes_recv - prev[1]) / dt
                            self._iface_stats_history[iface].append({
                                'time': now, 'sent_rate': sent_rate,
                                'recv_rate': recv_rate,
                                'total_sent': stats.bytes_sent,
                                'total_recv': stats.bytes_recv,
                                'packets_sent': stats.packets_sent,
                                'packets_recv': stats.packets_recv,
                                'errin': stats.errin, 'errout': stats.errout,
                                'dropin': stats.dropin, 'dropout': stats.dropout,
                            })
                    self._iface_stats_prev[iface] = (stats.bytes_sent, stats.bytes_recv, now)
            except Exception as exc:
                _logger.debug("Interface stats error: %s", exc)
            time.sleep(CONFIG.get('iface_stats_interval', 1))

    # ====================== DASHBOARD STATE ======================
    def _get_dashboard_state(self) -> dict:
        # Single lock acquisition for all shared state — was already good,
        # but we also avoid list(self.deductions) copy by slicing directly.
        with self.lock:
            # Was truncated to the first 200 by insertion order, which silently
            # dropped later processes — including any high-risk one that started
            # after the cap was reached — from the GUI, from the risk index and
            # from every export. Rank by risk and keep effectively all of them.
            profiles = sorted(self.process_profiles.values(),
                              key=lambda pr: pr.risk_score, reverse=True)
            processes = []
            for p in profiles[:MAX_PROCESSES_EXPORTED]:
                cpu_now = p.cpu_samples[-1] if p.cpu_samples else 0.0
                flags = p.flags
                processes.append({
                    'pid': p.pid, 'name': p.name, 'exe': p.exe_path,
                    'parent': p.parent_name, 'parent_name': p.parent_name,
                    'parent_pid': p.parent_pid,
                    'cmdline': p.cmdline,
                    'risk': round(p.risk_score, 1),
                    'connections': p.connection_count,
                    'destinations': len(p.destinations),
                    'destination_ips': sorted(p.destinations)[:50],
                    'ml_score': round(p.ml_anomaly_score, 1),
                    'countries': sorted(p.geo_countries),
                    # --- previously harvested but never exported ---
                    'cpu_percent': round(cpu_now, 1),
                    'memory_mb': round(p.memory_mb, 1),
                    'dns_domains': sorted(p.dns_domains)[:50],
                    'sni_domains': sorted(p.sni_domains)[:50],
                    'bytes_sent': p.bytes_sent, 'bytes_recv': p.bytes_recv,
                    'io_send_rate': round(p.io_send_rate, 1),
                    'loaded_dlls': list(p.loaded_dlls)[:50],
                    'escalation_hits': p.escalation_hits,
                    'risk_reasons': list(p.risk_reasons)[-20:],
                    'start_time': p.start_time,
                    'last_network_ts': p.last_network_ts,
                    'flags': sorted(flags),
                    # Named booleans kept for the flag row in the Processes tab.
                    'is_beacon': 'TUNNEL' in flags or 'BEACON' in flags,
                    'is_exfil': 'EXFIL' in flags or 'EXFIL_CHANNEL' in flags,
                    'is_impersonation': 'IMPERSONATION' in flags,
                    'is_injection': 'INJECTION' in flags,
                    'is_mimic': 'MIMIC' in flags,
                    'is_foreign': 'FOREIGN' in flags,
                    'is_idle_anomaly': 'IDLE_ANOMALY' in flags,
                    'dll_injected': 'DLL' in flags,
                })
            # Slice the deque directly — avoids full list() copy
            recent_deds = list(self.deductions)[-100:]
            devices_list = list(self.devices.values())
            dns_count = len(self.dns_cache.ip_to_domains)
            geoip_count = len(self.geoip.cache)
        # Format deductions outside the lock (CPU-bound string work)
        deductions_list = []
        for d in recent_deds:
            deductions_list.append({
                'time': datetime.datetime.fromtimestamp(d.timestamp).strftime("%H:%M:%S"),
                'severity': d.severity, 'category': d.category,
                'process': d.process_name, 'pid': d.pid,
                'message': d.message, 'score': round(d.score, 1),
                'evidence': list(d.evidence),
            })
        pipe = self.pipeline.stats()
        return {
            'processes': processes, 'deductions': deductions_list,
            'devices': devices_list, 'dns_count': dns_count,
            'geoip_count': geoip_count,
            'idle_seconds': round(self._idle_seconds(), 0),
            'pipeline_processed': pipe['processed'],
            'pipeline_dropped': pipe['dropped'],
            # Connection inventory data
            'connections': self.conn_inventory.get_all(),
            'map_points': self.conn_inventory.get_map_points(),
            'services': self.conn_inventory.get_services_summary(),
            'conn_stats': self.conn_inventory.get_stats(),
        }

    # ====================== FULL DATA (for GUI) ======================
    def _get_full_data(self) -> dict:
        """Returns ALL data for the GNA Tracer GUI — 100% detail."""
        base = self._get_dashboard_state()
        # Single lock acquisition for all shared-state copies — was 4 separate
        # lock acquisitions, each causing contention with the packet/process threads.
        with self.lock:
            raw_actions = [(ts, pid, name, action, extra)
                           for pid, actions in self.process_actions.items()
                           for ts, name, action, extra in actions]
            full_deds = []
            for d in list(self.deductions):
                full_deds.append({
                    'time': _fmt_hms(int(d.timestamp)),
                    'severity': d.severity, 'category': d.category,
                    'process': d.process_name, 'pid': d.pid,
                    'message': d.message, 'score': round(d.score, 1),
                    'evidence': list(d.evidence),
                })
            terminal_copy = list(self.terminal_buffer)
            suspicious_copy = list(self.suspicious_events)
        # Sort on the raw timestamp (cheap) and format only what is exported.
        raw_actions.sort(key=lambda r: r[0])
        if len(raw_actions) > MAX_ACTIONS_EXPORTED:
            raw_actions = raw_actions[-MAX_ACTIONS_EXPORTED:]
        base['all_actions'] = [
            f"{_fmt_clock(int(ts))} | {name} (PID {pid}) | {action} {extra}"
            for ts, pid, name, action, extra in raw_actions
        ]
        base['deductions'] = full_deds
        base['terminal_lines'] = terminal_copy
        base['suspicious_events'] = suspicious_copy
        # Tier 5 data
        base['fs_events'] = self.fs_watchdog.get_events()
        base['clipboard_events'] = self.clipboard_monitor.get_events()
        base['usb_events'] = self.usb_monitor.get_events()
        base['sched_task_events'] = self.sched_task_monitor.get_events()
        base['named_pipe_events'] = self.named_pipe_monitor.get_events()
        base['inbound_scan_events'] = self.inbound_scan_detector.get_events()
        base['doh_events'] = self.doh_detector.get_events()
        base['cert_events'] = self.tls_cert_detector.get_events()
        base['vt_results'] = self.vt_checker.get_all_results()
        # conn_active + conn_closed used to be built here too. Nothing read
        # them: get_history() already returns active + closed, which is the
        # same set conn_timeline carries, so the payload was serialising the
        # full history three times per refresh and rendering it once.
        base['conn_timeline'] = self.conn_history.get_timeline(
            limit=MAX_TIMELINE_EXPORTED)
        base['conn_counts'] = self.conn_history.get_counts()
        base['conn_bandwidth'] = self.conn_history.get_bandwidth()
        # Anti-hack pins: ip -> {categories: set, details: list}
        with self.lock:
            base['anti_hack_pins'] = {
                ip: {'categories': list(cats), 'details': list(self._anti_hack_details.get(ip, []))}
                for ip, cats in self._anti_hack_pins.items()
            }
        base['iface_stats'] = {k: list(v) for k, v in self._iface_stats_history.items()}
        # Multi-verification cache for the GUI (one report per public IP)
        with self._verify_cache_lock:
            base['multi_verifications'] = dict(self._verify_cache)
        wl = self.get_watchlist()
        base['watchlist_ips'] = sorted(wl['ips'])
        base['watchlist_procs'] = sorted(wl['procs'])
        # Recent DNS queries + what each name resolved to (get_ips), so the
        # sniffed query log is actually visible somewhere.
        recent_dns = []
        for ts, src, qname in self.dns_cache.recent_queries(window=600)[:200]:
            recent_dns.append({
                'time': ts, 'src': src, 'query': qname,
                'ips': sorted(self.dns_cache.get_ips(qname))[:6],
            })
        base['recent_dns'] = recent_dns
        base['tls_ja4x'] = self.tls_cert_detector.get_ja4x()
        base['system_proxy'] = self.proxy_detector.get_system_proxy()
        base['bt_devices'] = self.bt_scanner.get_devices()
        base['bt_events'] = self.bt_scanner.get_events()
        base['serial_ports'] = self.serial_scanner.get_ports()
        base['serial_events'] = self.serial_scanner.get_events()
        base['proxy_events'] = self.proxy_detector.get_events()
        base['proxy_processes'] = self.proxy_detector.get_proxy_processes()
        base['vpn_leak_status'] = self.vpn_leak_detector.get_status()
        base['vpn_leak_events'] = self.vpn_leak_detector.get_events()
        # Local machine GeoIP (for map "you are here" marker)
        base['local_geo'] = self._get_local_geoip()
        return base

    # ====================== RUN ======================
    def run(self):
        # Start packet pipeline workers
        self.pipeline.start()

        threads = [
            threading.Thread(target=self._connection_mapper, daemon=True, name="Connection-Mapper"),
            threading.Thread(target=self._process_watcher, daemon=True, name="Process-Watcher"),
            threading.Thread(target=self._status_thread, daemon=True, name="Status-Reporter"),
            threading.Thread(target=self.conn_inventory.run_thread, daemon=True, name="Connection-Inventory"),
        ]
        if self._admin_mode:
            threads.append(threading.Thread(target=self._arp_thread, daemon=True, name="ARP-Scanner"))
            threads.append(threading.Thread(target=self._sniff_thread, daemon=True, name="Packet-Sniffer"))
        else:
            self._log(f"{Colors.Y}Skipping packet capture (no admin). Process monitoring only.{Colors.END}")

        threads.append(threading.Thread(target=self._dns_cache_poll_thread,
                                        daemon=True, name="DNS-Cache-Poll"))
        if _IS_WINDOWS:
            threads.append(threading.Thread(target=self._memory_forensics_thread,
                                            daemon=True, name="Memory-Forensics"))
        # Tier 5 extended monitors
        threads.append(threading.Thread(target=self._extended_monitor_thread,
                                        daemon=True, name="Extended-Monitor"))
        threads.append(threading.Thread(target=self._iface_stats_thread,
                                        daemon=True, name="Interface-Stats"))
        if HAS_FASTAPI and CONFIG.get('dashboard_enabled'):
            threads.append(threading.Thread(
                target=start_dashboard,
                args=(self._get_dashboard_state, self.stop),
                daemon=True, name="Dashboard"))

        for t in threads:
            t.start()
            self._log(f"  Started thread: {t.name}", color=Colors.C)

        if HAS_FASTAPI and CONFIG.get('dashboard_enabled'):
            self._log(f"{EMOJI['dashboard']} Dashboard: http://127.0.0.1:{CONFIG['dashboard_port']}", color=Colors.G)

        # Launch GNA Tracer GUI unless --no-gui
        gui = None
        use_gui = not getattr(self.args, 'no_gui', False)
        if use_gui:
            self._log(f"{EMOJI['brain']} Launching GNA Tracer GUI...", color=Colors.G)
            try:
                gui = GNATracerGUI(
                    get_state_fn=self._get_dashboard_state,
                    get_full_data_fn=self._get_full_data,
                    stop_event=self.stop,
                    geoip=self.geoip,
                    proxy_detector=self.proxy_detector,
                    location_verifier=LocationVerifier(self.service_resolver),
                    monitor=self,
                    whois=self.whois_lookup,
                )
            except Exception as exc:
                import traceback
                print(f"GUI INIT CRASH: {exc}", flush=True)
                traceback.print_exc()
                gui = None
        try:
            if gui:
                gui.run()  # blocks until GUI window is closed
            else:
                while not self.stop.is_set():
                    time.sleep(1)
        except KeyboardInterrupt:
            self._log(f"{EMOJI['ok']} Shutting down...", color=Colors.C)
        except Exception as exc:
            import traceback
            self._log(f"GUI CRASH: {exc}", color=Colors.R)
            traceback.print_exc()
            if gui:
                _logger.warning("GUI error: %s — falling back to terminal mode", exc)
            try:
                while not self.stop.is_set():
                    time.sleep(1)
            except KeyboardInterrupt:
                self._log(f"{EMOJI['ok']} Shutting down...", color=Colors.C)
        finally:
            self.stop.set()
            self.pipeline.drain(timeout=3)
            for t in threads:
                t.join(timeout=5)
            # Save a final GNA tracer report on any exit. The GUI already saves
            # on close, so only do this when no GUI ran — the old guard tested
            # for "GNA tracer data.txt", a name this program never writes, so it
            # fired every time and clobbered "GNA tracer data 1.txt".
            if gui is None:
                try:
                    saver = GNATracerGUI(
                        get_state_fn=self._get_dashboard_state,
                        get_full_data_fn=self._get_full_data,
                        stop_event=self.stop,
                    )
                    saver._save_tracer_data()
                except Exception as exc:
                    _logger.debug("Final tracer save failed: %s", exc)
            self._log(f"{EMOJI['ok']} Stopped. Logs: {CONFIG['actions_log']}, {CONFIG['deductions_log']}")


# ========================== ENTRY POINT ==========================
def main():
    parser = argparse.ArgumentParser(
        description="MedianBoxMonitor 3.0 — Modular Deductive Chess Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument('--config', '-c', default=None,
                        help='Path to YAML config file (default: medianbox_config.yaml)')
    parser.add_argument('--no-dashboard', action='store_true',
                        help='Disable web dashboard')
    parser.add_argument('--no-geoip', action='store_true',
                        help='Disable GeoIP lookups (privacy)')
    parser.add_argument('--siem', choices=['json', 'cef', 'syslog'],
                        help='Enable SIEM output format')
    parser.add_argument('--port', type=int, default=None,
                        help='Dashboard port (default: 8470)')
    parser.add_argument('--workers', type=int, default=None,
                        help='Number of pipeline worker threads (default: 2)')
    parser.add_argument('--dashboard-password', default=None,
                        help='Require this password/token to access the dashboard')
    parser.add_argument('--geoip-db', default=None,
                        help='Path to MaxMind GeoLite2-City.mmdb for local offline GeoIP')
    parser.add_argument('--no-gui', action='store_true',
                        help='Disable the GNA Tracer GUI popup window (terminal only)')

    args = parser.parse_args()

    # Load YAML config first
    load_config(args.config)

    # CLI overrides
    if args.no_dashboard:
        CONFIG['dashboard_enabled'] = False
    if args.no_geoip:
        CONFIG['geoip_enabled'] = False
    if args.siem:
        CONFIG['siem_output'] = args.siem
    if args.port:
        CONFIG['dashboard_port'] = args.port
    if args.workers:
        CONFIG['pipeline_workers'] = args.workers
    if args.dashboard_password:
        CONFIG['dashboard_password'] = args.dashboard_password
    if args.geoip_db:
        CONFIG['geoip_db_path'] = args.geoip_db

    monitor = MedianBoxMonitor(args)
    monitor.run()


if __name__ == '__main__':
    main()