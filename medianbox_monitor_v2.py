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
import contextlib
import datetime
import hashlib
import ipaddress
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
import struct
import threading
import time
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
CONFIG = {
    'remote_ports': {22, 3389, 5900, 5938, 445, 139, 5985, 5986},
    'probe_alert_ports': {21, 23, 80, 443, 445, 22, 3389, 5900},
    'alert_cooldown': 75,
    'deduction_cooldown': 120,
    'db_file': 'medianbox_ultimate.db',
    'log_file': 'medianbox_ultimate.log',
    'actions_log': 'medianbox_full_actions.log',
    'deductions_log': 'medianbox_deductions.log',
    'process_scan_interval': 3,
    'scan_interval_min': 5,
    'scan_interval_max': 55,
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
    'pipeline_workers': 2,
    'pipeline_queue_size': 5000,
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
    'process_scan_interval':      {'type': (int, float), 'min': 0.5, 'max': 60},
    'scan_interval_min':          {'type': (int, float), 'min': 1},
    'scan_interval_max':          {'type': (int, float), 'min': 1},
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
    io_baseline_sent: int = 0
    io_baseline_recv: int = 0
    io_snapshot_time: float = 0.0
    geo_countries: set[str] = field(default_factory=set)
    loaded_dlls: list[str] = field(default_factory=list)
    escalation_hits: int = 0
    ml_anomaly_score: float = 0.0


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
            return set(self.ip_to_domains.get(ip, set()))

    def get_ips(self, domain: str) -> set[str]:
        with self.lock:
            return set(self.domain_to_ips.get(domain, set()))

    def recent_queries(self, keyword: str, window: float = 120) -> list[tuple]:
        cutoff = time.time() - window
        with self.lock:
            return [(t, s, d) for t, s, d in self.query_log
                    if t > cutoff and keyword in d.lower()]


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
        })
        self.lock = threading.Lock()

    def record(self, proc_name: str, conn_rate: float, dst_count: int,
               bytes_rate: float, cpu_mean: float):
        with self.lock:
            m = self.models[proc_name]
            m['conn_rate'].append(conn_rate)
            m['dst_count'].append(dst_count)
            m['bytes_rate'].append(bytes_rate)
            m['cpu_mean'].append(cpu_mean)

    def score(self, proc_name: str, conn_rate: float, dst_count: int,
              bytes_rate: float, cpu_mean: float) -> tuple[float, list[str]]:
        anomalies = []
        total_z = 0.0
        with self.lock:
            m = self.models.get(proc_name)
            if not m or len(m['conn_rate']) < 30:
                return 0.0, []
            for metric_name, current_val in [('conn_rate', conn_rate), ('dst_count', dst_count),
                                              ('bytes_rate', bytes_rate), ('cpu_mean', cpu_mean)]:
                samples = list(m[metric_name])
                if len(samples) < 10:
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
        if not self.api_key or not exe_path or pid in self._checked_pids:
            return None
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
        except Exception:
            with self.lock:
                self.cache[ip] = {'name': '?', 'error': True}
            return None


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
                self._window_start = now
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
        self._events: deque = deque(maxlen=500)
        self._cert_change_count: dict[str, int] = defaultdict(int)

    def record_cert(self, dst_ip: str, cert_data: bytes) -> Optional[dict]:
        if not cert_data:
            return None
        cert_hash = hashlib.sha256(cert_data).hexdigest()[:16]
        with self.lock:
            prev = self._cert_cache.get(dst_ip)
            self._cert_cache[dst_ip] = cert_hash
            if prev and prev != cert_hash:
                self._cert_change_count[dst_ip] += 1
                if self._cert_change_count[dst_ip] >= 3:
                    ev = {'type': 'CERT_CHANGE', 'ip': dst_ip,
                          'time': time.time(), 'severity': 'CRITICAL',
                          'old_hash': prev, 'new_hash': cert_hash,
                          'detail': f"TLS cert changed {self._cert_change_count[dst_ip]}x for {dst_ip} — possible MITM"}
                    self._events.append(ev)
                    return ev
        return None

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
            return dict(self._bandwidth)

    def get_timeline(self) -> list[dict]:
        """Return all connections sorted by start_time for timeline display."""
        with self.lock:
            all_conns = list(self._history) + [dict(v) for v in self._active.values()]
        all_conns.sort(key=lambda c: c.get('start_time', 0))
        return all_conns


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


class GeoIPCache:
    """Thread-safe GeoIP lookup with caching, rate limiting, optional local DB, and HTTPS fallback."""
    _PRIVACY_WARNED = False
    _EMPTY: dict[str, object] = {'country': '??', 'countryCode': '??', 'city': '??',
                                 'org': 'Unknown', 'isp': 'Unknown', 'lat': 0, 'lon': 0}

    def __init__(self, maxmind_db_path: Optional[str] = None):
        self.cache: dict[str, dict] = {}
        self.lock = threading.Lock()
        self._api_url = ("http://ip-api.com/json/{ip}?fields="
                        "status,country,countryCode,org,as,isp,lat,lon,city,regionName,timezone")
        self._rate_limiter = TokenBucket(rate=40.0, capacity=45.0)
        self._rate_limited_count = 0
        self._rate_lock = threading.Lock()
        self._local_reader = None
        db_path = maxmind_db_path or CONFIG.get('geoip_db_path')
        if db_path and HAS_GEOIP2:
            try:
                self._local_reader = _geoip2_db.Reader(db_path)
                _logger.info("GeoIP: using local MaxMind DB at %s", db_path)
            except Exception as exc:
                _logger.warning("GeoIP: failed to open MaxMind DB '%s': %s — falling back to API", db_path, exc)

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
                data['_source'] = 'api'
                return data
        except Exception as exc:
            _logger.debug("GeoIP API lookup failed for %s: %s", ip, exc)
        return None

    def lookup(self, ip: str) -> Optional[dict]:
        if not CONFIG.get('geoip_enabled', True):
            return None
        if not GeoIPCache._PRIVACY_WARNED and not self._local_reader:
            _logger.warning(
                "GeoIP enabled: destination IPs will be sent to ip-api.com over HTTP. "
                "Set geoip_enabled=False or configure geoip_db_path for local lookups."
            )
            GeoIPCache._PRIVACY_WARNED = True
        with self.lock:
            cached = self.cache.get(ip)
            if cached and time.time() - cached.get('_ts', 0) < CONFIG['geoip_cache_ttl']:
                return cached
        data = self._lookup_local(ip) or self._lookup_api(ip)
        if data:
            with self.lock:
                self.cache[ip] = data
            return data
        return None

    def get_country(self, ip: str) -> str:
        info = self.lookup(ip)
        return info.get('countryCode', '??') if info else '??'

    def get_org(self, ip: str) -> str:
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
        try:
            hostname = socket.gethostbyaddr(ip)[0].lower()
        except (socket.herror, socket.gaierror, OSError):
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
                                for field in item:
                                    if isinstance(field, list) and len(field) >= 4:
                                        if field[0] == 'adr' and isinstance(field[3], dict):
                                            cc = field[3].get('cc', '')
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

        # 2. Check Windows registry proxy settings
        if _IS_WINDOWS:
            try:
                import winreg
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
                try:
                    pac_url, _ = winreg.QueryValueEx(key, "AutoConfigURL")
                    if pac_url:
                        ev = {'type': 'FORWARD_PROXY', 'subtype': 'PAC',
                              'severity': 'WARNING',
                              'detail': f"PAC auto-config URL: {pac_url[:150]}"}
                        events.append(ev)
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
            with self._lock:
                self._proxy_processes = proxy_procs
            ev = {'type': 'FORWARD_PROXY', 'subtype': 'PROCESS',
                  'severity': 'WARNING',
                  'detail': f"Proxy software running: {', '.join(proxy_procs[:5])}"}
            events.append(ev)
        else:
            with self._lock:
                self._proxy_processes = []

        with self._lock:
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

        # --- Residential Proxy: check domain/org for known proxy services ---
        check_str = f"{domain} {org} {isp}".lower()
        for rp_kw in _RESIDENTIAL_PROXY_DOMAINS:
            if rp_kw in check_str:
                results.append('RESIDENTIAL')
                detail_parts.append(f"matches residential proxy service '{rp_kw}'")
                break

        if not results:
            return {}

        proxy_type = '/'.join(sorted(set(results)))
        return {
            'proxy_type': proxy_type,
            'proxy_detail': '; '.join(detail_parts),
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


# ========================== LOGGING SETUP ==========================
def setup_structured_logging():
    """Configure Python logging with rotation for main, actions, and deductions logs."""
    logger = logging.getLogger('medianbox')
    if not logger.handlers:
        logger.setLevel(logging.DEBUG)
        fmt = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
        fh = RotatingFileHandler('medianbox_structured.log', maxBytes=50_000_000, backupCount=5,
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
        with self.lock:
            self.history[pid].append((time.time(), score))

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
        while not self._stop.is_set():
            try:
                pkt = self._queue.get(timeout=1.0)
            except queue.Empty:
                continue
            try:
                self._handler(pkt)
                with self._lock:
                    self._processed += 1
            except Exception as exc:
                _logger.debug("Pipeline worker %d error: %s", worker_id, exc)
            finally:
                self._queue.task_done()
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
    (r'youtube|googlevideo|ytimg|yt\d', 'YouTube', 'Streaming', '🎬'),
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
    (r'google\.com|googleapis|gstatic|goog\b|google-analytics|googleusercontent', 'Google', 'Tech', '🔍'),
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


class ServiceResolver:
    """Resolves IPs and domains to human-readable service names with caching."""
    def __init__(self):
        self._rdns_cache: dict[str, str] = {}
        self._service_cache: dict[str, dict] = {}
        self.lock = threading.Lock()

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
            hostname = socket.gethostbyaddr(ip)[0]
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
                return cached
        if domains:
            for d in domains:
                result = self.resolve_domain(d)
                if result['service'] != d.lower():
                    result['domain'] = d
                    with self.lock:
                        self._service_cache[ip] = result
                    return result
            first_domain = next(iter(domains))
            result = {'service': first_domain, 'category': 'Other', 'icon': '🌐',
                      'domain': first_domain}
            with self.lock:
                self._service_cache[ip] = result
            return result
        rdns = self.reverse_dns(ip)
        if rdns:
            result = self.resolve_domain(rdns)
            result['domain'] = rdns
            with self.lock:
                self._service_cache[ip] = result
            return result
        if ip in ('1.1.1.1', '1.0.0.1'):
            result = {'service': 'Cloudflare DNS', 'category': 'DNS', 'icon': '🌐', 'domain': ip}
        elif ip.startswith('8.8.'):
            result = {'service': 'Google DNS', 'category': 'DNS', 'icon': '🌐', 'domain': ip}
        elif ip == '9.9.9.9':
            result = {'service': 'Quad9 DNS', 'category': 'DNS', 'icon': '🌐', 'domain': ip}
        else:
            result = {'service': ip, 'category': 'Unknown', 'icon': '❓', 'domain': ip}
        with self.lock:
            self._service_cache[ip] = result
        return result


# ========================== CONNECTION INVENTORY ==========================
class ConnectionEntry:
    """Single tracked connection with full metadata."""
    __slots__ = (
        'category', 'city', 'country', 'country_code', 'domain',
        'first_seen', 'icon', 'isp', 'last_seen', 'lat', 'local_port',
        'loc_confidence', 'loc_grade', 'loc_proof',
        'lon', 'org', 'pid', 'process_name', 'protocol', 'proxy_detail',
        'proxy_type', 'region', 'remote_ip', 'remote_port', 'service', 'status',
    )

    def __init__(self):
        self.pid = 0
        self.process_name = ''
        self.remote_ip = ''
        self.remote_port = 0
        self.local_port = 0
        self.protocol = 'TCP'
        self.status = ''
        self.service = 'Unknown'
        self.category = 'Unknown'
        self.icon = '❓'
        self.domain = ''
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

    def to_dict(self) -> dict:
        return {
            'pid': self.pid, 'process': self.process_name,
            'remote_ip': self.remote_ip, 'remote_port': self.remote_port,
            'local_port': self.local_port, 'protocol': self.protocol,
            'status': self.status, 'service': self.service,
            'category': self.category, 'icon': self.icon, 'domain': self.domain,
            'country': self.country, 'country_code': self.country_code,
            'city': self.city, 'region': self.region,
            'org': self.org, 'isp': self.isp,
            'lat': self.lat, 'lon': self.lon,
            'first_seen': self.first_seen, 'last_seen': self.last_seen,
            'loc_confidence': self.loc_confidence, 'loc_grade': self.loc_grade,
            'loc_proof': list(self.loc_proof),
            'proxy_type': self.proxy_type, 'proxy_detail': self.proxy_detail,
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
        self.total_unique_ips: set[str] = set()
        self.scan_count = 0

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

    def scan(self):
        now = time.time()
        active_keys = set()
        pid_names = {}
        for proc in psutil.process_iter(['pid', 'name']):
            with contextlib.suppress(psutil.NoSuchProcess, psutil.AccessDenied):
                pid_names[proc.pid] = proc.name()
        conns = self._get_connections()
        for conn in conns:
            if not conn.raddr:
                continue
            remote_ip = conn.raddr[0]
            remote_port = conn.raddr[1]
            pid = conn.pid or 0
            key = (remote_ip, remote_port, pid)
            active_keys.add(key)
            with self.lock:
                if key in self.connections:
                    self.connections[key].last_seen = now
                    self.connections[key].status = conn.status
                    continue
            entry = ConnectionEntry()
            entry.pid = pid
            entry.process_name = pid_names.get(pid, f'PID:{pid}')
            entry.remote_ip = remote_ip
            entry.remote_port = remote_port
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
            if self._is_public(remote_ip):
                geo = self.geoip.get_full(remote_ip)
                entry.country = geo.get('country', '??')
                entry.country_code = geo.get('countryCode', '??')
                entry.city = geo.get('city', '??')
                entry.region = geo.get('regionName', '')
                entry.org = geo.get('org', 'Unknown')
                entry.isp = geo.get('isp', 'Unknown')
                entry.lat = geo.get('lat', 0.0)
                entry.lon = geo.get('lon', 0.0)
                # Run location verification in background to avoid blocking
                try:
                    vr = self.loc_verifier.verify(remote_ip, geo)
                    entry.loc_confidence = vr.get('confidence', 0)
                    entry.loc_grade = vr.get('grade', 'UNVERIFIED')
                    entry.loc_proof = vr.get('proof', [])
                except Exception:
                    pass
            # Proxy detection per-connection
            try:
                proxy_info = self.proxy_detector.classify_connection(
                    remote_ip, remote_port, entry.domain, entry.org, entry.isp)
                if proxy_info:
                    entry.proxy_type = proxy_info.get('proxy_type', '')
                    entry.proxy_detail = proxy_info.get('proxy_detail', '')
            except Exception:
                pass
            with self.lock:
                if self._is_public(remote_ip):
                    self.total_unique_ips.add(remote_ip)
                self.connections[key] = entry
                self.services_seen[entry.service] = {
                    'category': entry.category, 'icon': entry.icon,
                    'country': entry.country, 'city': entry.city,
                    'org': entry.org, 'lat': entry.lat, 'lon': entry.lon,
                    'last_seen': now,
                }
        with self.lock:
            stale = [k for k, v in self.connections.items() if k not in active_keys
                     and now - v.last_seen > 60]
            for k in stale:
                del self.connections[k]
        with self.lock:
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
                        'city': entry.city, 'country': entry.country,
                        'org': entry.org, 'process': entry.process_name,
                        'loc_confidence': entry.loc_confidence,
                        'loc_grade': entry.loc_grade,
                        'loc_proof': list(entry.loc_proof),
                        'proxy_type': entry.proxy_type,
                        'proxy_detail': entry.proxy_detail,
                    }
        return list(seen_ips.values())

    def get_services_summary(self) -> list[dict]:
        with self.lock:
            return [{'service': name, **info} for name, info in self.services_seen.items()]

    def get_stats(self) -> dict:
        with self.lock:
            n_conns = len(self.connections)
            n_services = len(self.services_seen)
        return {
            'total_connections': n_conns,
            'unique_services': n_services,
            'unique_ips': len(self.total_unique_ips),
            'scans': self.scan_count,
        }

    def format_terminal_line(self, entry: ConnectionEntry) -> str:
        geo = f"{entry.city}, {entry.country_code}" if entry.city != '??' else entry.country_code
        coords = f"({entry.lat:.2f}, {entry.lon:.2f})" if entry.lat or entry.lon else ""
        return (f"  {entry.icon} {entry.service:20s} | {entry.process_name:20s} | "
                f"{entry.remote_ip:15s}:{entry.remote_port:<5d} | "
                f"{geo:20s} {coords} | {entry.org}")

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
                geo = f"{c['city']}, {c['country_code']}" if c['city'] != '??' else c['country_code']
                coords = f"({c['lat']:.2f}, {c['lon']:.2f})" if c['lat'] or c['lon'] else ""
                print(f"    {c['icon']} {c['service']:20s} | {c['process']:18s} | "
                      f"{c['remote_ip']:15s}:{c['remote_port']:<5d} | "
                      f"{geo:20s} {coords}")
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
  const b1=document.createElement('b');b1.textContent=p.service+' '+p.icon;d.appendChild(b1);
  d.appendChild(document.createElement('br'));
  const t1=document.createTextNode(p.ip+' ('+p.process+')');d.appendChild(t1);
  d.appendChild(document.createElement('br'));
  const t2=document.createTextNode(p.city+', '+p.country);d.appendChild(t2);
  d.appendChild(document.createElement('br'));
  const sm=document.createElement('small');sm.textContent=p.org+' | '+p.lat.toFixed(4)+', '+p.lon.toFixed(4);d.appendChild(sm);
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
      const svc=document.createElement('span');svc.className='conn-svc';svc.textContent=c.service;
      const proc=document.createElement('span');proc.className='conn-proc';proc.textContent=c.process;
      const ip=document.createElement('span');ip.className='conn-ip';ip.textContent=c.remote_ip+':'+c.remote_port;
      const geo=document.createElement('span');geo.className='conn-geo';
      geo.textContent=(c.city&&c.city!=='??')?c.city+', '+c.country_code:c.country_code;
      const coords=document.createElement('span');coords.className='conn-coords';
      coords.textContent=(c.lat||c.lon)?'('+c.lat.toFixed(2)+', '+c.lon.toFixed(2)+')':'';
      const org=document.createElement('span');org.className='conn-org';org.textContent=c.org||'';
      row.appendChild(icon);row.appendChild(svc);row.appendChild(proc);row.appendChild(ip);
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
# Simplified world coastline points (lat, lon) for equirectangular map projection
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


class GNATracerGUI:
    """Full-detail popup window for GNA Tracer — shows 100% of all data."""

    def __init__(self, get_state_fn, get_full_data_fn, stop_event: threading.Event):
        self._get_state = get_state_fn
        self._get_full_data = get_full_data_fn
        self._stop = stop_event
        self._root = None
        self._map_canvas = None
        self._map_dots = {}  # ip -> canvas item id
        self._map_w = 900
        self._map_h = 460
        self._tooltip = None
        self._tooltip_id = None
        self._selected_ip = None
        # Zoom / pan state for atlas map
        self._map_zoom = 1.0
        self._map_center_lat = 20.0   # initial center latitude
        self._map_center_lon = 0.0    # initial center longitude
        self._map_drag_start = None   # (x, y) when drag starts
        self._map_min_zoom = 1.0
        self._map_max_zoom = 20.0
        self._ip_actions_text = None
        self._update_job = None
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
        with open(bat_path, 'w') as f:
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
                # Get exit code
                exit_code = ctypes.wintypes.DWORD()
                ctypes.windll.kernel32.GetExitCodeProcess(
                    sei.hProcess, ctypes.byref(exit_code))
                ctypes.windll.kernel32.CloseHandle(sei.hProcess)
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
        rule_name = f'{self._fw_rule_prefix}{ip.replace(".", "_")}'
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
        rule_name = f'{self._fw_rule_prefix}{ip.replace(".", "_")}'
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
        for ip in list(self._blocked_ips):
            self._unblock_ip(ip)

    def _update_blocked_label(self):
        if hasattr(self, '_blocked_lbl'):
            n = len(self._blocked_ips)
            if n:
                ip_list = ', '.join(sorted(self._blocked_ips.keys()))
                self._blocked_lbl.config(
                    text=f'🚫 Blocked ({n}): {ip_list}',
                    fg='#e94560')
            else:
                self._blocked_lbl.config(
                    text='No IPs blocked',
                    fg='#666666')

    # ─── Scroll-aware refresh helpers ───
    def _is_at_bottom(self, widget):
        """Return True if the scrollbar is near the bottom (auto-scroll zone)."""
        return widget.yview()[1] >= 0.95

    def _begin_refresh(self, widget):
        """Save scroll state before a full rewrite. Returns (was_at_bottom, scroll_frac)."""
        at_bottom = self._is_at_bottom(widget)
        frac = widget.yview()[0]
        return at_bottom, frac

    def _end_refresh(self, widget, at_bottom, frac):
        """Restore scroll: auto-scroll to end if was at bottom, else restore position."""
        if at_bottom:
            widget.see("end")
        else:
            widget.yview_moveto(frac)

    # ─── Search infrastructure ───
    def _make_search_bar(self, parent, search_var):
        """Create a search toolbar frame with entry + clear button. Returns the frame."""
        bar = tk.Frame(parent, bg="#1a1a2e", height=28)
        bar.pack(fill="x", side="top")
        bar.pack_propagate(False)
        tk.Label(bar, text="🔍", bg="#1a1a2e", fg="#666666",
                 font=("Consolas", 10)).pack(side="left", padx=(8, 2))
        entry = tk.Entry(bar, textvariable=search_var, bg="#222233", fg="#00d4ff",
                         insertbackground="#00d4ff", font=("Consolas", 9),
                         bd=0, highlightthickness=1, highlightcolor="#333366")
        entry.pack(side="left", fill="x", expand=True, padx=4, pady=3)
        clear_btn = tk.Button(bar, text="✕", bg="#1a1a2e", fg="#666666",
                              font=("Consolas", 9), bd=0, padx=4,
                              command=lambda: search_var.set(""))
        clear_btn.pack(side="right", padx=4)
        return bar

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
        """Convert lat/lon to canvas x/y using current zoom and center."""
        z = self._map_zoom
        cx, cy = self._map_center_lon, self._map_center_lat
        w, h = self._map_w, self._map_h
        x = w / 2 + (lon - cx) * (w / 360) * z
        y = h / 2 - (lat - cy) * (h / 180) * z
        return x, y

    def _xy_to_latlon(self, x, y):
        """Convert canvas x/y back to lat/lon."""
        z = self._map_zoom
        cx, cy = self._map_center_lon, self._map_center_lat
        w, h = self._map_w, self._map_h
        lon = cx + (x - w / 2) / (w / 360 * z)
        lat = cy - (y - h / 2) / (h / 180 * z)
        return lat, lon

    def _draw_map_full(self):
        """Redraw the entire map: grid, coastlines, labels."""
        if not self._map_canvas:
            return
        self._map_canvas.delete("grid", "coastline", "label", "city")
        self._draw_grid()
        self._draw_coastline()
        self._draw_labels()
        self._zoom_lbl.config(text=f"Zoom: {self._map_zoom:.1f}x")

    def _draw_grid(self):
        """Draw lat/lon grid lines that adapt to zoom level."""
        if not self._map_canvas:
            return
        z = self._map_zoom
        w, h = self._map_w, self._map_h
        # Choose grid spacing based on zoom
        if z >= 10:
            spacing = 5
        elif z >= 5:
            spacing = 10
        elif z >= 2:
            spacing = 15
        else:
            spacing = 30
        # Latitude lines
        for lat in range(-90, 91, spacing):
            _, y = self._latlon_to_xy(lat, 0)
            if 0 <= y <= h:
                self._map_canvas.create_line(0, y, w, y, fill="#1a2a2a",
                                             width=1, tags="grid", dash=(2, 4))
                if z >= 1.5:
                    self._map_canvas.create_text(
                        4, y - 2, text=f"{lat}°", fill="#334444",
                        font=("Consolas", 7), anchor="sw", tags="grid")
        # Longitude lines
        for lon in range(-180, 181, spacing):
            x, _ = self._latlon_to_xy(0, lon)
            if 0 <= x <= w:
                self._map_canvas.create_line(x, 0, x, h, fill="#1a2a2a",
                                             width=1, tags="grid", dash=(2, 4))
                if z >= 1.5:
                    self._map_canvas.create_text(
                        x + 2, h - 2, text=f"{lon}°", fill="#334444",
                        font=("Consolas", 7), anchor="se", tags="grid")
        # Equator + prime meridian highlighted
        _, eq_y = self._latlon_to_xy(0, 0)
        pm_x, _ = self._latlon_to_xy(0, 0)
        if 0 <= eq_y <= h:
            self._map_canvas.create_line(0, eq_y, w, eq_y, fill="#2a3a3a",
                                         width=1, tags="grid")
        if 0 <= pm_x <= w:
            self._map_canvas.create_line(pm_x, 0, pm_x, h, fill="#2a3a3a",
                                         width=1, tags="grid")

    def _draw_coastline(self):
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
                # Skip points far outside viewport for performance
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
        """Draw country and city labels based on zoom level."""
        if not self._map_canvas:
            return
        z = self._map_zoom
        w, h = self._map_w, self._map_h
        # Country labels at zoom >= 1.5
        if z >= 1.5:
            font_size = max(7, min(11, int(7 + z)))
            for lat, lon, name in _COUNTRY_LABELS:
                x, y = self._latlon_to_xy(lat, lon)
                if 0 <= x <= w and 0 <= y <= h:
                    self._map_canvas.create_text(
                        x, y, text=name, fill="#3a5a5a",
                        font=("Consolas", font_size, "bold"),
                        tags="label")
        # Tier 1 cities at zoom >= 3
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
        """Zoom the map by a factor, optionally centered on mouse position."""
        old_zoom = self._map_zoom
        self._map_zoom = max(self._map_min_zoom,
                             min(self._map_max_zoom, self._map_zoom * factor))
        if event and old_zoom != self._map_zoom:
            # Zoom toward the mouse cursor position
            lat, lon = self._xy_to_latlon(event.x, event.y)
            # Shift center partially toward the cursor
            t = 0.3
            self._map_center_lat += (lat - self._map_center_lat) * t
            self._map_center_lon += (lon - self._map_center_lon) * t
        self._draw_map_full()
        self._redraw_dots_only()

    def _map_reset_view(self):
        """Reset map to default view."""
        self._map_zoom = 1.0
        self._map_center_lat = 20.0
        self._map_center_lon = 0.0
        self._draw_map_full()
        self._redraw_dots_only()

    def _on_map_scroll(self, event):
        """Mouse wheel zoom."""
        if event.delta > 0:
            self._map_zoom_by(1.3, event)
        else:
            self._map_zoom_by(1 / 1.3, event)

    def _on_map_drag_start(self, event):
        self._map_drag_start = (event.x, event.y)

    def _on_map_drag(self, event):
        if not self._map_drag_start:
            return
        dx = event.x - self._map_drag_start[0]
        dy = event.y - self._map_drag_start[1]
        z = self._map_zoom
        w, h = self._map_w, self._map_h
        self._map_center_lon -= dx / (w / 360 * z)
        self._map_center_lat += dy / (h / 180 * z)
        # Clamp
        self._map_center_lat = max(-85, min(85, self._map_center_lat))
        self._map_center_lon = max(-180, min(180, self._map_center_lon))
        self._map_drag_start = (event.x, event.y)
        self._draw_map_full()
        self._redraw_dots_only()

    def _on_map_drag_end(self, event):
        self._map_drag_start = None

    def _on_map_mouse_move(self, event):
        """Show lat/lon coordinates under cursor."""
        lat, lon = self._xy_to_latlon(event.x, event.y)
        if hasattr(self, '_coords_lbl'):
            self._coords_lbl.config(text=f"Lat: {lat:.2f}° Lon: {lon:.2f}°")

    def _redraw_dots_only(self):
        """Quick redraw of just the connection dots without full data refresh."""
        if not self._map_canvas:
            return
        self._map_canvas.delete("dot", "line_to_dot")
        if hasattr(self, '_last_map_data') and self._last_map_data:
            self._plot_map_dots(self._last_map_data)

    def _show_tooltip(self, event, text):
        self._hide_tooltip()
        x, y = event.x_root + 15, event.y_root + 10
        self._tooltip = tk.Toplevel(self._root)
        self._tooltip.wm_overrideredirect(True)
        self._tooltip.wm_geometry(f"+{x}+{y}")
        self._tooltip.attributes("-topmost", True)
        frame = tk.Frame(self._tooltip, bg="#1a1a2e", bd=1, relief="solid")
        frame.pack()
        lbl = tk.Label(frame, text=text, bg="#1a1a2e", fg="#00d4ff",
                       font=("Consolas", 9), justify="left", padx=6, pady=4)
        lbl.pack()

    def _hide_tooltip(self):
        if self._tooltip:
            self._tooltip.destroy()
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
        text = (f"IP: {ip}\n"
                f"Service: {info.get('service', '?')}\n"
                f"Process: {info.get('process', '?')}\n"
                f"City: {info.get('city', '?')}, {info.get('country', '?')}\n"
                f"Org: {info.get('org', '?')}\n"
                f"Lat: {info.get('lat', 0):.4f}, Lon: {info.get('lon', 0):.4f}"
                f"{loc_line}{proof_lines}{proxy_line}\n"
                f"[Click for full action log]")
        self._show_tooltip(event, text)

    def _on_map_dot_leave(self, event):
        self._hide_tooltip()

    def _on_map_dot_click(self, ip):
        self._selected_ip = ip
        if self._ip_actions_text:
            self._ip_actions_text.config(state="normal")
            self._ip_actions_text.delete("1.0", "end")
            data = self._get_full_data()
            lines = [f"=== FULL ACTION LOG FOR IP: {ip} ===\n"]
            # Find all connections for this IP
            for conn in data.get('connections', []):
                if conn.get('remote_ip') == ip:
                    lines.append(f"Connection: {conn.get('process', '?')} (PID {conn.get('pid', '?')})")
                    lines.append(f"  Remote: {ip}:{conn.get('remote_port', '?')}")
                    lines.append(f"  Local Port: {conn.get('local_port', '?')}")
                    lines.append(f"  Protocol: {conn.get('protocol', '?')}")
                    lines.append(f"  Status: {conn.get('status', '?')}")
                    lines.append(f"  Service: {conn.get('service', '?')} ({conn.get('category', '?')})")
                    lines.append(f"  Domain: {conn.get('domain', '?')}")
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
        style.configure("Treeview.Heading", background="#1a1a2e", foreground="#e94560",
                        font=("Consolas", 9, "bold"))
        style.map("Treeview", background=[("selected", "#0f3460")])

        # Header
        hdr = tk.Frame(self._root, bg="#1a1a2e", height=40)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)
        tk.Label(hdr, text="♟ GNA TRACER — FULL NETWORK INTELLIGENCE",
                 bg="#1a1a2e", fg="#e94560", font=("Consolas", 14, "bold")).pack(side="left", padx=16)
        self._status_lbl = tk.Label(hdr, text="Initializing...", bg="#1a1a2e", fg="#00d4ff",
                                    font=("Consolas", 10))
        self._status_lbl.pack(side="right", padx=16)

        # Notebook
        nb = ttk.Notebook(self._root)
        nb.pack(fill="both", expand=True, padx=4, pady=4)

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

        # === TAB 1: Overview ===
        self._overview_frame = ttk.Frame(nb)
        nb.add(self._overview_frame, text=" 📊 Overview ")
        self._make_search_bar(self._overview_frame, self._search_overview)
        self._overview_text = scrolledtext.ScrolledText(
            self._overview_frame, bg="#12121a", fg="#c0c0c0",
            font=("Consolas", 10), insertbackground="#c0c0c0", state="disabled",
            wrap="word", bd=0, highlightthickness=0)
        self._overview_text.pack(fill="both", expand=True)

        # === TAB 2: Live Connections (only active/established) ===
        self._live_frame = ttk.Frame(nb)
        nb.add(self._live_frame, text=" 🟢 Live Connections ")
        self._make_search_bar(self._live_frame, self._search_live)
        self._live_text = scrolledtext.ScrolledText(
            self._live_frame, bg="#12121a", fg="#c0c0c0",
            font=("Consolas", 9), insertbackground="#c0c0c0", state="disabled",
            wrap="none", bd=0, highlightthickness=0)
        self._live_text.pack(fill="both", expand=True)
        self._live_buttons: list = []

        # === TAB 3: All Connections (each individually) ===
        self._conn_frame = ttk.Frame(nb)
        nb.add(self._conn_frame, text=" 🔗 All Connections ")
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
        self._blocked_lbl = tk.Label(
            conn_toolbar, text="No IPs blocked", bg="#1a1a2e", fg="#666666",
            font=("Consolas", 9))
        self._blocked_lbl.pack(side="left", padx=12)
        unblock_all_btn = tk.Button(
            conn_toolbar, text="🔓 Unblock All", bg="#333344", fg="#f5a623",
            font=("Consolas", 9), bd=0, padx=8, pady=2,
            activebackground="#444466", activeforeground="#f5a623",
            command=self._unblock_all)
        unblock_all_btn.pack(side="right", padx=8, pady=4)
        tk.Label(conn_toolbar, text="Click [Block] next to any connection to add a firewall rule",
                 bg="#1a1a2e", fg="#555555", font=("Consolas", 8)).pack(side="right", padx=8)
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
        self._make_search_bar(self._ded_frame, self._search_ded)
        self._ded_text = scrolledtext.ScrolledText(
            self._ded_frame, bg="#12121a", fg="#c0c0c0",
            font=("Consolas", 9), insertbackground="#c0c0c0", state="disabled",
            wrap="word", bd=0, highlightthickness=0)
        self._ded_text.pack(fill="both", expand=True)

        # === TAB 4: Processes ===
        self._proc_frame = ttk.Frame(nb)
        nb.add(self._proc_frame, text=" 📈 Processes ")
        self._make_search_bar(self._proc_frame, self._search_proc)
        self._proc_text = scrolledtext.ScrolledText(
            self._proc_frame, bg="#12121a", fg="#c0c0c0",
            font=("Consolas", 9), insertbackground="#c0c0c0", state="disabled",
            wrap="none", bd=0, highlightthickness=0)
        self._proc_text.pack(fill="both", expand=True)

        # === TAB 5: Devices ===
        self._dev_frame = ttk.Frame(nb)
        nb.add(self._dev_frame, text=" 📱 Devices ")
        self._make_search_bar(self._dev_frame, self._search_dev)
        self._dev_text = scrolledtext.ScrolledText(
            self._dev_frame, bg="#12121a", fg="#c0c0c0",
            font=("Consolas", 9), insertbackground="#c0c0c0", state="disabled",
            wrap="none", bd=0, highlightthickness=0)
        self._dev_text.pack(fill="both", expand=True)

        # === TAB 6: IP Map (Atlas with zoom/pan) ===
        self._map_frame = ttk.Frame(nb)
        nb.add(self._map_frame, text=" 🗺️ IP Map ")
        # Controls bar
        map_ctrl = tk.Frame(self._map_frame, bg="#1a1a2e", height=32)
        map_ctrl.pack(fill="x")
        map_ctrl.pack_propagate(False)
        tk.Button(map_ctrl, text="➕ Zoom In", bg="#333344", fg="#c0c0c0",
                  font=("Consolas", 9, "bold"), bd=0, padx=6,
                  command=lambda: self._map_zoom_by(1.5)).pack(side="left", padx=4, pady=2)
        tk.Button(map_ctrl, text="➖ Zoom Out", bg="#333344", fg="#c0c0c0",
                  font=("Consolas", 9, "bold"), bd=0, padx=6,
                  command=lambda: self._map_zoom_by(1/1.5)).pack(side="left", padx=4, pady=2)
        tk.Button(map_ctrl, text="🏠 Reset", bg="#333344", fg="#c0c0c0",
                  font=("Consolas", 9, "bold"), bd=0, padx=6,
                  command=self._map_reset_view).pack(side="left", padx=4, pady=2)
        self._zoom_lbl = tk.Label(map_ctrl, text="Zoom: 1.0x", bg="#1a1a2e",
                                  fg="#00d4ff", font=("Consolas", 9))
        self._zoom_lbl.pack(side="left", padx=12)
        self._coords_lbl = tk.Label(map_ctrl, text="", bg="#1a1a2e",
                                    fg="#888888", font=("Consolas", 9))
        self._coords_lbl.pack(side="right", padx=12)
        # Legend
        legend_f = tk.Frame(map_ctrl, bg="#1a1a2e")
        legend_f.pack(side="right", padx=8)
        for color, label in [("#44cc44", "Low"), ("#ffcc00", "Med"),
                              ("#ff8800", "High"), ("#ff0000", "Crit")]:
            tk.Canvas(legend_f, bg=color, width=10, height=10,
                      highlightthickness=0).pack(side="left", padx=1)
            tk.Label(legend_f, text=label, bg="#1a1a2e", fg="#888888",
                     font=("Consolas", 7)).pack(side="left", padx=(0, 6))
        # Map canvas
        map_top = tk.Frame(self._map_frame, bg="#0a0a0f")
        map_top.pack(fill="both", expand=True)
        self._map_canvas = tk.Canvas(map_top, bg="#0d1117", width=self._map_w,
                                     height=self._map_h, highlightthickness=0)
        self._map_canvas.pack(fill="both", expand=True, padx=4, pady=4)
        # Bind zoom (mouse wheel) and pan (click-drag)
        self._map_canvas.bind("<MouseWheel>", self._on_map_scroll)
        self._map_canvas.bind("<Button-4>", lambda e: self._map_zoom_by(1.3, e))
        self._map_canvas.bind("<Button-5>", lambda e: self._map_zoom_by(1/1.3, e))
        self._map_canvas.bind("<ButtonPress-3>", self._on_map_drag_start)
        self._map_canvas.bind("<B3-Motion>", self._on_map_drag)
        self._map_canvas.bind("<ButtonRelease-3>", self._on_map_drag_end)
        self._map_canvas.bind("<Motion>", self._on_map_mouse_move)
        self._draw_map_full()
        # Action log below map
        map_bottom = tk.Frame(self._map_frame, bg="#0a0a0f", height=220)
        map_bottom.pack(fill="both", expand=True)
        map_bottom.pack_propagate(False)
        tk.Label(map_bottom, text="IP ACTION LOG (click a dot · scroll to zoom · right-drag to pan)",
                 bg="#1a1a2e", fg="#e94560", font=("Consolas", 10, "bold")).pack(fill="x")
        self._ip_actions_text = scrolledtext.ScrolledText(
            map_bottom, bg="#12121a", fg="#c0c0c0",
            font=("Consolas", 9), insertbackground="#c0c0c0", state="disabled",
            wrap="word", bd=0, highlightthickness=0)
        self._ip_actions_text.pack(fill="both", expand=True)

        # === TAB 7: Raw Actions Log ===
        self._actions_frame = ttk.Frame(nb)
        nb.add(self._actions_frame, text=" 📝 Actions Log ")
        self._make_search_bar(self._actions_frame, self._search_actions)
        self._actions_text = scrolledtext.ScrolledText(
            self._actions_frame, bg="#12121a", fg="#c0c0c0",
            font=("Consolas", 9), insertbackground="#c0c0c0", state="disabled",
            wrap="none", bd=0, highlightthickness=0)
        self._actions_text.pack(fill="both", expand=True)

        # === TAB 8: Terminal (100% of all processed output) ===
        self._terminal_frame = ttk.Frame(nb)
        nb.add(self._terminal_frame, text=" 🖥️ Terminal ")
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
        self._make_search_bar(self._suspicious_frame, self._search_suspicious)
        self._suspicious_text = scrolledtext.ScrolledText(
            self._suspicious_frame, bg="#12121a", fg="#c0c0c0",
            font=("Consolas", 9), insertbackground="#c0c0c0", state="disabled",
            wrap="word", bd=0, highlightthickness=0)
        self._suspicious_text.pack(fill="both", expand=True)

        # === TAB 10: Blocked IPs ===
        self._blocked_frame = ttk.Frame(nb)
        nb.add(self._blocked_frame, text=" 🛑 Blocked IPs ")
        self._blocked_text = scrolledtext.ScrolledText(
            self._blocked_frame, bg="#12121a", fg="#c0c0c0",
            font=("Consolas", 9), insertbackground="#c0c0c0", state="disabled",
            wrap="none", bd=0, highlightthickness=0)
        self._blocked_text.pack(fill="both", expand=True)

        # === TAB 11: Process Tree ===
        self._ptree_frame = ttk.Frame(nb)
        nb.add(self._ptree_frame, text=" 🌳 Process Tree ")
        self._ptree_text = scrolledtext.ScrolledText(
            self._ptree_frame, bg="#12121a", fg="#c0c0c0",
            font=("Consolas", 9), insertbackground="#c0c0c0", state="disabled",
            wrap="none", bd=0, highlightthickness=0)
        self._ptree_text.pack(fill="both", expand=True)

        # === TAB 12: Network Stats ===
        self._netstats_frame = ttk.Frame(nb)
        nb.add(self._netstats_frame, text=" 📊 Net Stats ")
        self._netstats_text = scrolledtext.ScrolledText(
            self._netstats_frame, bg="#12121a", fg="#c0c0c0",
            font=("Consolas", 9), insertbackground="#c0c0c0", state="disabled",
            wrap="none", bd=0, highlightthickness=0)
        self._netstats_text.pack(fill="both", expand=True)

        # === TAB 13: Connection Timeline ===
        self._timeline_frame = ttk.Frame(nb)
        nb.add(self._timeline_frame, text=" ⏱️ Timeline ")
        self._timeline_text = scrolledtext.ScrolledText(
            self._timeline_frame, bg="#12121a", fg="#c0c0c0",
            font=("Consolas", 9), insertbackground="#c0c0c0", state="disabled",
            wrap="none", bd=0, highlightthickness=0)
        self._timeline_text.pack(fill="both", expand=True)

        # === TAB 14: Config Editor ===
        self._config_frame = ttk.Frame(nb)
        nb.add(self._config_frame, text=" ⚙️ Config ")
        self._config_text = scrolledtext.ScrolledText(
            self._config_frame, bg="#12121a", fg="#c0c0c0",
            font=("Consolas", 9), insertbackground="#c0c0c0", state="disabled",
            wrap="none", bd=0, highlightthickness=0)
        self._config_text.pack(fill="both", expand=True)

        # Alert flash tracking
        self._alert_flash_tabs: dict[str, int] = {}
        self._last_suspicious_count = 0

        # Watchlist sets (synced from monitor)
        self._watchlist_ips: set[str] = set()
        self._watchlist_procs: set[str] = set()

        # Window geometry persistence
        self._geometry_file = os.path.join(os.path.expanduser("~"), ".gna_tracer_geometry.json")
        self._load_geometry()

        # Configure text tags for coloring
        for widget in [self._overview_text, self._live_text, self._conn_text,
                       self._ded_text, self._proc_text, self._dev_text,
                       self._actions_text, self._terminal_text,
                       self._suspicious_text, self._blocked_text,
                       self._ptree_text, self._netstats_text,
                       self._timeline_text, self._config_text]:
            widget.tag_configure("critical", foreground="#e94560", font=("Consolas", 10, "bold"))
            widget.tag_configure("warning", foreground="#f5a623")
            widget.tag_configure("info", foreground="#4caf50")
            widget.tag_configure("header", foreground="#00d4ff", font=("Consolas", 11, "bold"))
            widget.tag_configure("subheader", foreground="#e94560", font=("Consolas", 10, "bold"))
            widget.tag_configure("dim", foreground="#666666")
            widget.tag_configure("highlight", foreground="#ffffff")
            widget.tag_configure("default", foreground="#c0c0c0")
            widget.tag_configure("cyan", foreground="#00d4ff")
            widget.tag_configure("search_match", background="#f5a623", foreground="#000000",
                                 font=("Consolas", 10, "bold"))

        self._schedule_update()
        self._schedule_autosave()
        self._root.mainloop()

    def _schedule_autosave(self):
        """Periodic auto-save: writes a complete numbered log file every interval."""
        if self._stop.is_set():
            return
        try:
            self._save_tracer_data()
        except Exception as exc:
            _logger.warning("Auto-save failed: %s", exc)
        self._autosave_job = self._root.after(self._autosave_interval_ms, self._schedule_autosave)

    def _schedule_update(self):
        if self._stop.is_set():
            return
        try:
            self._refresh_all()
        except Exception as exc:
            _logger.debug("GUI refresh error: %s", exc)
        self._update_job = self._root.after(3000, self._schedule_update)

    def _refresh_all(self):
        data = self._get_full_data()
        self._refresh_status(data)
        self._refresh_overview(data)
        self._refresh_live(data)
        self._refresh_connections(data)
        self._refresh_deductions(data)
        self._refresh_processes(data)
        self._refresh_devices(data)
        self._refresh_map(data)
        self._refresh_actions(data)
        self._refresh_terminal(data)
        self._refresh_suspicious(data)
        self._refresh_blocked()
        self._refresh_process_tree(data)
        self._refresh_netstats(data)
        self._refresh_timeline(data)
        self._refresh_config()
        self._check_alert_flash(data)

    def _refresh_status(self, data):
        stats = data.get('conn_stats', {})
        self._status_lbl.config(
            text=f"Connections: {stats.get('total_connections', 0)} | "
                 f"Services: {stats.get('unique_services', 0)} | "
                 f"IPs: {stats.get('unique_ips', 0)} | "
                 f"Processes: {len(data.get('processes', []))} | "
                 f"Deductions: {len(data.get('deductions', []))} | "
                 f"Pipeline: {data.get('pipeline_processed', 0)}/{data.get('pipeline_dropped', 0)}")

    def _set_text(self, widget, content):
        widget.config(state="normal")
        widget.delete("1.0", "end")
        widget.insert("end", content)
        widget.config(state="disabled")

    def _refresh_overview(self, data):
        w = self._overview_text
        at_bottom, frac = self._begin_refresh(w)
        w.config(state="normal")
        w.delete("1.0", "end")
        stats = data.get('conn_stats', {})
        w.insert("end", "═" * 90 + "\n", "dim")
        w.insert("end", "  GNA TRACER — SYSTEM OVERVIEW\n", "header")
        w.insert("end", "═" * 90 + "\n\n", "dim")
        w.insert("end", f"  Active Connections:   {stats.get('total_connections', 0)}\n", "highlight")
        w.insert("end", f"  Unique Services:      {stats.get('unique_services', 0)}\n", "highlight")
        w.insert("end", f"  Unique Public IPs:    {stats.get('unique_ips', 0)}\n", "highlight")
        w.insert("end", f"  Tracked Processes:    {len(data.get('processes', []))}\n", "highlight")
        w.insert("end", f"  Total Deductions:     {len(data.get('deductions', []))}\n", "highlight")
        w.insert("end", f"  Network Devices:      {len(data.get('devices', []))}\n", "highlight")
        w.insert("end", f"  DNS Cache Entries:    {data.get('dns_count', 0)}\n", "highlight")
        w.insert("end", f"  GeoIP Cache Entries:  {data.get('geoip_count', 0)}\n", "highlight")
        w.insert("end", f"  User Idle:            {data.get('idle_seconds', 0):.0f}s\n", "highlight")
        w.insert("end", f"  Pipeline Processed:   {data.get('pipeline_processed', 0)}\n", "highlight")
        w.insert("end", f"  Pipeline Dropped:     {data.get('pipeline_dropped', 0)}\n", "highlight")
        # Tier 5 stats
        w.insert("end", "\n" + "─" * 60 + "\n", "dim")
        w.insert("end", "  EXTENDED MONITORS\n", "subheader")
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
        w.insert("end", f"  File System Events:   {fs_ct}\n",
                 "warning" if fs_ct > 50 else "highlight")
        w.insert("end", f"  VirusTotal Scans:     {vt_ct}\n", "highlight")
        w.insert("end", f"  USB Device Events:    {usb_ct}\n",
                 "warning" if usb_ct > 0 else "highlight")
        w.insert("end", f"  Clipboard Events:     {clip_ct}\n",
                 "critical" if clip_ct > 0 else "highlight")
        w.insert("end", f"  Sched Task Changes:   {task_ct}\n",
                 "warning" if task_ct > 0 else "highlight")
        w.insert("end", f"  Named Pipe Events:    {pipe_ct}\n",
                 "warning" if pipe_ct > 5 else "highlight")
        w.insert("end", f"  Inbound Scans:        {scan_ct}\n",
                 "critical" if scan_ct > 0 else "highlight")
        w.insert("end", f"  DoH Detections:       {doh_ct}\n",
                 "warning" if doh_ct > 0 else "highlight")
        w.insert("end", f"  Cert/MITM Events:     {cert_ct}\n",
                 "critical" if cert_ct > 0 else "highlight")
        w.insert("end", f"  Connection Timeline:  {tl_ct}\n", "highlight")
        bt_ct = len(data.get('bt_devices', []))
        bt_ev = len(data.get('bt_events', []))
        serial_ct = len(data.get('serial_ports', []))
        serial_ev = len(data.get('serial_events', []))
        w.insert("end", f"  Bluetooth Devices:    {bt_ct} ({bt_ev} events)\n",
                 "warning" if bt_ev > 0 else "highlight")
        w.insert("end", f"  Serial/COM Ports:     {serial_ct} ({serial_ev} events)\n",
                 "warning" if serial_ev > 0 else "highlight")
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
        self._end_refresh(w, at_bottom, frac)

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
        ]
        return any(q in f.lower() for f in fields)

    def _refresh_live(self, data):
        """Show ONLY live (active/established) connections — drops vanish instantly."""
        w = self._live_text
        at_bottom, frac = self._begin_refresh(w)
        # Destroy old embedded buttons
        for btn in self._live_buttons:
            try:
                btn.destroy()
            except Exception:
                pass
        self._live_buttons.clear()
        w.config(state="normal")
        w.delete("1.0", "end")
        conns = data.get('connections', [])
        # Filter to only ESTABLISHED / SYN_SENT / SYN_RECV (truly live)
        live_statuses = {'ESTABLISHED', 'SYN_SENT', 'SYN_RECV', 'LISTEN', 'LAST_ACK', 'FIN_WAIT1', 'FIN_WAIT2'}
        live = [c for c in conns if c.get('status', '').upper() in live_statuses]
        # Apply search filter
        search_q = self._search_live.get()
        if search_q and len(search_q) >= 2:
            live = [c for c in live if self._conn_matches_search(c, search_q)]
        w.insert("end", f"{'═' * 140}\n", "dim")
        w.insert("end", f"  🟢 LIVE CONNECTIONS — {len(live)} active right now", "header")
        if search_q and len(search_q) >= 2:
            w.insert("end", f"  (filter: \"{search_q}\")", "dim")
        w.insert("end", "\n")
        w.insert("end", f"{'═' * 140}\n\n", "dim")
        if not live:
            w.insert("end", "  No live connections" +
                     (f" matching \"{search_q}\"" if search_q else "") + ".\n", "dim")
        else:
            by_cat = defaultdict(list)
            for c in live:
                by_cat[c.get('category', 'Unknown')].append(c)
            for cat in sorted(by_cat.keys()):
                cat_conns = by_cat[cat]
                w.insert("end", f"\n  ┌─ {cat} ({len(cat_conns)} live) ", "subheader")
                w.insert("end", "─" * 80 + "\n", "dim")
                for idx, c in enumerate(cat_conns, 1):
                    rip = c.get('remote_ip', '')
                    is_blocked = rip in self._blocked_ips
                    risk = 0
                    for p in data.get('processes', []):
                        if p['pid'] == c.get('pid'):
                            risk = p.get('risk', 0)
                            break
                    if risk >= 50:
                        risk_tag = "critical"
                    elif risk >= 25:
                        risk_tag = "warning"
                    else:
                        risk_tag = "info"
                    w.insert("end", f"  │\n")
                    w.insert("end", f"  ├── [{idx}] ", "highlight")
                    w.insert("end", f"{c.get('icon', '?')} {c.get('service', 'Unknown')}  ", "highlight")
                    # Block button
                    if rip:
                        btn_text = f"🔓 Unblock {rip}" if is_blocked else f"🚫 Block {rip}"
                        btn_bg = "#4caf50" if is_blocked else "#8b0000"
                        btn = tk.Button(
                            w, text=btn_text, bg=btn_bg, fg="#ffffff",
                            font=("Consolas", 8, "bold"), bd=0, padx=6, pady=0,
                            activebackground="#555555", activeforeground="#ffffff",
                            command=lambda ip=rip, ci=c: self._toggle_block_ip(ip, ci))
                        w.window_create("end", window=btn)
                        self._live_buttons.append(btn)
                    if is_blocked:
                        w.insert("end", "  ← BLOCKED", "critical")
                    w.insert("end", "\n")
                    w.insert("end", f"  │     Process:     {c.get('process', '?')} (PID {c.get('pid', '?')})\n")
                    w.insert("end", f"  │     Remote:      {rip}:{c.get('remote_port', '?')}\n")
                    w.insert("end", f"  │     Local Port:  {c.get('local_port', '?')}\n")
                    w.insert("end", f"  │     Protocol:    {c.get('protocol', '?')} — Status: ", "")
                    w.insert("end", f"{c.get('status', '?')}\n", risk_tag)
                    w.insert("end", f"  │     Domain:      {c.get('domain', 'unresolved')}\n")
                    w.insert("end", f"  │     Country:     {c.get('country', '?')} ({c.get('country_code', '?')})\n")
                    w.insert("end", f"  │     City:        {c.get('city', '?')}\n")
                    w.insert("end", f"  │     Org:         {c.get('org', '?')}\n")
                    if risk > 0:
                        w.insert("end", f"  │     Risk:        {risk:.1f}\n", risk_tag)
                    # Location verification proof
                    loc_conf = c.get('loc_confidence', 0)
                    loc_grade = c.get('loc_grade', 'UNVERIFIED')
                    loc_proof = c.get('loc_proof', [])
                    if loc_proof:
                        grade_tag = "info" if loc_grade == "HIGH" else (
                            "warning" if loc_grade in ("MEDIUM", "LOW") else "critical")
                        w.insert("end", f"  │     📍 Location: ", "")
                        w.insert("end", f"{loc_conf}% {loc_grade}\n", grade_tag)
                        for proof in loc_proof:
                            w.insert("end", f"  │       {proof}\n", "dim")
                    # Proxy detection
                    proxy_type = c.get('proxy_type', '')
                    if proxy_type:
                        proxy_detail = c.get('proxy_detail', '')
                        w.insert("end", f"  │     🔀 Proxy:    ", "")
                        w.insert("end", f"{proxy_type}\n", "warning")
                        if proxy_detail:
                            w.insert("end", f"  │       {proxy_detail}\n", "dim")
                w.insert("end", f"  └{'─' * 100}\n", "dim")
        self._highlight_search(w, search_q)
        w.config(state="disabled")
        self._end_refresh(w, at_bottom, frac)

    def _refresh_connections(self, data):
        if self._conn_paused:
            return  # user is browsing — don't reset scroll
        w = self._conn_text
        at_bottom, frac = self._begin_refresh(w)
        # Destroy old embedded buttons
        for btn in self._conn_buttons:
            try:
                btn.destroy()
            except Exception:
                pass
        self._conn_buttons.clear()
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
                    rip = c.get('remote_ip', '')
                    is_blocked = rip in self._blocked_ips
                    w.insert("end", f"  │\n")
                    w.insert("end", f"  ├── [{idx}] ", "highlight")
                    w.insert("end", f"{c.get('icon', '?')} {c.get('service', 'Unknown')}  ", "highlight")
                    # Embed Block/Unblock button
                    if rip:
                        btn_text = f"🔓 Unblock {rip}" if is_blocked else f"🚫 Block {rip}"
                        btn_bg = "#4caf50" if is_blocked else "#8b0000"
                        btn_fg = "#ffffff"
                        btn = tk.Button(
                            w, text=btn_text, bg=btn_bg, fg=btn_fg,
                            font=("Consolas", 8, "bold"), bd=0, padx=6, pady=0,
                            activebackground="#555555", activeforeground="#ffffff",
                            command=lambda ip=rip, ci=c: self._toggle_block_ip(ip, ci))
                        w.window_create("end", window=btn)
                        self._conn_buttons.append(btn)
                    if is_blocked:
                        w.insert("end", "  ← BLOCKED", "critical")
                    w.insert("end", "\n")
                    w.insert("end", f"  │     Process:     {c.get('process', '?')} (PID {c.get('pid', '?')})\n")
                    w.insert("end", f"  │     Remote:      {rip}:{c.get('remote_port', '?')}\n")
                    w.insert("end", f"  │     Local Port:  {c.get('local_port', '?')}\n")
                    w.insert("end", f"  │     Protocol:    {c.get('protocol', '?')} — Status: {c.get('status', '?')}\n")
                    w.insert("end", f"  │     Domain:      {c.get('domain', 'unresolved')}\n")
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
                        w.insert("end", f"  │     📍 Location: ", "")
                        w.insert("end", f"{loc_conf}% {loc_grade}\n", grade_tag)
                        for proof in loc_proof:
                            w.insert("end", f"  │       {proof}\n", "dim")
                    # Proxy detection
                    proxy_type = c.get('proxy_type', '')
                    if proxy_type:
                        proxy_detail = c.get('proxy_detail', '')
                        w.insert("end", f"  │     🔀 Proxy:    ", "")
                        w.insert("end", f"{proxy_type}\n", "warning")
                        if proxy_detail:
                            w.insert("end", f"  │       {proxy_detail}\n", "dim")
                    w.insert("end", f"  │     First Seen:  {_fmt_ts(c.get('first_seen', 0))}\n")
                    w.insert("end", f"  │     Last Seen:   {_fmt_ts(c.get('last_seen', 0))}\n")
                w.insert("end", f"  └{'─' * 100}\n", "dim")
        self._highlight_search(w, search_q)
        w.config(state="disabled")
        self._end_refresh(w, at_bottom, frac)

    def _refresh_deductions(self, data):
        w = self._ded_text
        at_bottom, frac = self._begin_refresh(w)
        w.config(state="normal")
        w.delete("1.0", "end")
        deds = data.get('deductions', [])
        w.insert("end", f"{'═' * 100}\n", "dim")
        w.insert("end", f"  ALL DEDUCTIONS — {len(deds)} total (full evidence)\n", "header")
        w.insert("end", f"{'═' * 100}\n\n", "dim")
        for idx, d in enumerate(reversed(deds), 1):
            sev = d.get('severity', 'INFO')
            tag = "critical" if sev == "CRITICAL" else ("warning" if sev == "WARNING" else "info")
            w.insert("end", f"  ┌─ Deduction #{idx} ", tag)
            w.insert("end", f"{'─' * 70}\n", "dim")
            w.insert("end", f"  │ Time:     {d.get('time', '?')}\n")
            w.insert("end", f"  │ Severity: ", "")
            w.insert("end", f"{sev}\n", tag)
            w.insert("end", f"  │ Category: {d.get('category', '?')}\n")
            w.insert("end", f"  │ Process:  {d.get('process', '?')} (PID {d.get('pid', '?')})\n")
            w.insert("end", f"  │ Score:    {d.get('score', 0)}\n", tag)
            w.insert("end", f"  │ Message:  {d.get('message', '?')}\n", "highlight")
            evidence = d.get('evidence', [])
            if evidence:
                w.insert("end", f"  │ Evidence:\n")
                for ev in evidence:
                    w.insert("end", f"  │   → {ev}\n")
            w.insert("end", f"  └{'─' * 80}\n\n", "dim")
        self._highlight_search(w, self._search_ded.get())
        w.config(state="disabled")
        self._end_refresh(w, at_bottom, frac)

    def _refresh_processes(self, data):
        w = self._proc_text
        at_bottom, frac = self._begin_refresh(w)
        w.config(state="normal")
        w.delete("1.0", "end")
        procs = data.get('processes', [])
        active = [p for p in procs if p.get('connections', 0) > 0 or p.get('risk', 0) > 0]
        active.sort(key=lambda x: -x.get('risk', 0))
        w.insert("end", f"{'═' * 120}\n", "dim")
        w.insert("end", f"  ALL TRACKED PROCESSES — {len(active)} with network activity or risk\n", "header")
        w.insert("end", f"{'═' * 120}\n\n", "dim")
        w.insert("end", f"  {'PID':<8} {'Name':<28} {'Risk':>6} {'Conn':>6} {'Dst':>5} "
                        f"{'ML':>6} {'Exe':<50} {'Countries'}\n", "subheader")
        w.insert("end", f"  {'─'*8} {'─'*28} {'─'*6} {'─'*6} {'─'*5} {'─'*6} {'─'*50} {'─'*20}\n", "dim")
        for p in active:
            risk = p.get('risk', 0)
            tag = "critical" if risk >= 70 else ("warning" if risk >= 40 else "")
            line = (f"  {p['pid']:<8} {p['name']:<28} {risk:>6.1f} {p.get('connections', 0):>6} "
                    f"{p.get('destinations', 0):>5} {p.get('ml_score', 0):>6.1f} "
                    f"{p.get('exe', '?')[:50]:<50} {', '.join(p.get('countries', []))}\n")
            w.insert("end", line, tag)
        # Also show detailed per-process connection breakdown
        w.insert("end", f"\n{'═' * 120}\n", "dim")
        w.insert("end", f"  DETAILED PER-PROCESS CONNECTION BREAKDOWN\n", "header")
        w.insert("end", f"{'═' * 120}\n", "dim")
        for p in active[:50]:
            if p.get('connections', 0) > 0:
                w.insert("end", f"\n  ▶ {p['name']} (PID {p['pid']}) — "
                                f"Risk: {p.get('risk', 0):.1f} — "
                                f"{p.get('connections', 0)} connections\n", "subheader")
                # Pull individual connections for this PID
                for c in data.get('connections', []):
                    if c.get('pid') == p['pid']:
                        w.insert("end", f"    ├─ {c.get('remote_ip', '?')}:{c.get('remote_port', '?')} | "
                                        f"{c.get('service', '?')} | {c.get('domain', '?')} | "
                                        f"{c.get('country_code', '?')} | {c.get('org', '?')} | "
                                        f"{c.get('status', '?')}\n")
        self._highlight_search(w, self._search_proc.get())
        w.config(state="disabled")
        self._end_refresh(w, at_bottom, frac)

    def _refresh_devices(self, data):
        w = self._dev_text
        at_bottom, frac = self._begin_refresh(w)
        w.config(state="normal")
        w.delete("1.0", "end")
        devs = data.get('devices', [])
        w.insert("end", f"{'═' * 110}\n", "dim")
        w.insert("end", f"  NETWORK DEVICES — {len(devs)} discovered\n", "header")
        w.insert("end", f"{'═' * 110}\n\n", "dim")
        w.insert("end", f"  {'IP':<18} {'MAC':<20} {'Vendor':<18} {'Hostname':<25} "
                        f"{'OS Guess':<20} {'Conf':>6}\n", "subheader")
        w.insert("end", f"  {'─'*18} {'─'*20} {'─'*18} {'─'*25} {'─'*20} {'─'*6}\n", "dim")
        for d in devs:
            w.insert("end", f"  {d.get('ip', '?'):<18} {d.get('mac', '?'):<20} "
                            f"{d.get('vendor', '?'):<18} {d.get('hostname', '?'):<25} "
                            f"{d.get('os_guess', '?'):<20} {d.get('confidence', 0):>6.2f}\n")
            if d.get('ja4'):
                w.insert("end", f"    JA4: {d['ja4']}\n", "dim")
            if d.get('ja4s'):
                w.insert("end", f"    JA4S: {d['ja4s']}\n", "dim")
            if d.get('ja4h'):
                w.insert("end", f"    JA4H: {d['ja4h']}\n", "dim")
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
        self._end_refresh(w, at_bottom, frac)

    def _refresh_map(self, data):
        if not self._map_canvas:
            return
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
        ip_risk: dict[str, float] = {}
        for c in conn_list:
            rip = c.get('remote_ip', '')
            for p in data.get('processes', []):
                if p['pid'] == c.get('pid'):
                    ip_risk[rip] = max(ip_risk.get(rip, 0), p.get('risk', 0))
                    break
        ip_conn_count: dict[str, int] = defaultdict(int)
        for c in conn_list:
            ip_conn_count[c.get('remote_ip', '')] += 1
        # Cache for zoom/pan redraws
        self._last_map_data = {
            'all_points': all_points,
            'ip_risk': ip_risk,
            'ip_conn_count': ip_conn_count,
        }
        # Full redraw: grid + coastline + labels + dots
        self._draw_map_full()
        self._map_canvas.delete("dot", "line_to_dot")
        self._plot_map_dots(self._last_map_data)

    def _plot_map_dots(self, map_data):
        """Plot IP dots on the map using precomputed map_data."""
        if not self._map_canvas or not map_data:
            return
        all_points = map_data.get('all_points', [])
        ip_risk = map_data.get('ip_risk', {})
        ip_conn_count = map_data.get('ip_conn_count', {})
        w, h = self._map_w, self._map_h
        z = self._map_zoom
        # Draw connection lines from local to remote at higher zoom
        if z >= 2 and all_points:
            local_x, local_y = w / 2, h / 2  # approximate local position
            for pt in all_points:
                lat, lon = pt.get('lat', 0), pt.get('lon', 0)
                if lat == 0 and lon == 0:
                    continue
                x, y = self._latlon_to_xy(lat, lon)
                if 0 <= x <= w and 0 <= y <= h:
                    self._map_canvas.create_line(
                        local_x, local_y, x, y,
                        fill="#1a2a3a", width=1, dash=(3, 6),
                        tags="line_to_dot")
        for pt in all_points:
            lat, lon = pt.get('lat', 0), pt.get('lon', 0)
            if lat == 0 and lon == 0:
                continue
            x, y = self._latlon_to_xy(lat, lon)
            # Skip dots outside viewport
            if x < -20 or x > w + 20 or y < -20 or y > h + 20:
                continue
            ip = pt.get('ip', '?')
            risk = ip_risk.get(ip, 0)
            if risk >= 50:
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
            dot = self._map_canvas.create_oval(
                x - radius, y - radius, x + radius, y + radius,
                fill=fill_color, outline=outline_color, width=1, tags="dot")
            info = pt
            self._map_canvas.tag_bind(dot, "<Enter>",
                lambda e, i=ip, inf=info: self._on_map_dot_enter(e, i, inf))
            self._map_canvas.tag_bind(dot, "<Leave>", self._on_map_dot_leave)
            self._map_canvas.tag_bind(dot, "<Button-1>",
                lambda e, i=ip: self._on_map_dot_click(i))
            # Show IP label when zoomed in enough
            if z >= 4:
                self._map_canvas.create_text(
                    x + radius + 3, y, text=ip, fill="#88aaaa",
                    font=("Consolas", max(7, min(9, int(6 + z * 0.3)))),
                    anchor="w", tags="dot")

    def _refresh_actions(self, data):
        w = self._actions_text
        at_bottom, frac = self._begin_refresh(w)
        w.config(state="normal")
        w.delete("1.0", "end")
        actions = data.get('all_actions', [])
        w.insert("end", f"{'═' * 100}\n", "dim")
        w.insert("end", f"  RAW ACTIONS LOG — {len(actions)} entries\n", "header")
        w.insert("end", f"{'═' * 100}\n\n", "dim")
        for act in actions[-500:]:
            line = str(act) + "\n"
            if 'CRITICAL' in line or 'DEDUCTION' in line:
                w.insert("end", line, "critical")
            elif 'WARNING' in line:
                w.insert("end", line, "warning")
            else:
                w.insert("end", line)
        self._highlight_search(w, self._search_actions.get())
        w.config(state="disabled")
        self._end_refresh(w, at_bottom, frac)

    def _refresh_suspicious(self, data):
        """Show ONLY out-of-norm / anomalous events — virus behavior, data access, hardware, remote power, etc."""
        w = self._suspicious_text
        at_bottom, frac = self._begin_refresh(w)
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
            self._end_refresh(w, at_bottom, frac)
            return
        # Group by category
        by_cat = {}
        for ev in events:
            cat = ev.get('category', 'UNKNOWN')
            by_cat.setdefault(cat, []).append(ev)
        # Category icons
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
            w.insert("end", f"{'─' * 100}\n", "dim")
            w.insert("end", f"  {icon} {cat} — {len(cat_events)} event(s)\n", "header")
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
        w.insert("end", f"\n{'═' * 110}\n", "dim")
        w.insert("end", f"  END OF SUSPICIOUS ACTIVITY LOG — {len(events)} total events\n", "dim")
        self._highlight_search(w, self._search_suspicious.get())
        w.config(state="disabled")
        self._end_refresh(w, at_bottom, frac)

    def _refresh_blocked(self):
        """Show all currently blocked IPs with full metadata and unblock buttons."""
        w = self._blocked_text
        at_bottom, frac = self._begin_refresh(w)
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
        if not self._is_admin():
            w.insert("end", "\n  ℹ Running without admin — a UAC prompt will appear when you block/unblock.\n", "warning")
            w.insert("end", "  Click Yes on the Windows permission dialog to allow the firewall change.\n\n", "dim")
        if n == 0:
            w.insert("end", "\n  No IPs are currently blocked.\n\n", "dim")
            w.insert("end", "  To block an IP, go to the All Connections tab and click the\n", "dim")
            w.insert("end", "  🚫 Block button next to any connection.\n", "dim")
        else:
            w.insert("end", "\n")
            for idx, (ip, meta) in enumerate(sorted(blocked.items()), 1):
                w.insert("end", f"  ┌─ Blocked IP #{idx} ", "critical")
                w.insert("end", "─" * 80 + "\n", "dim")
                w.insert("end", f"  │\n")
                w.insert("end", f"  │  IP:           {ip}\n", "highlight")
                # Embed unblock button
                w.insert("end", f"  │  Action:       ")
                btn = tk.Button(
                    w, text=f"🔓 Unblock {ip}", bg="#4caf50", fg="#ffffff",
                    font=("Consolas", 9, "bold"), bd=0, padx=8, pady=2,
                    activebackground="#66bb6a", activeforeground="#ffffff",
                    command=lambda i=ip: self._unblock_ip(i))
                w.window_create("end", window=btn)
                self._blocked_tab_buttons.append(btn)
                w.insert("end", "\n")
                w.insert("end", f"  │  Time Blocked: {meta.get('time_blocked', '?')}\n", "warning")
                w.insert("end", f"  │  Service:      {meta.get('service', '?')}\n")
                w.insert("end", f"  │  Domain:       {meta.get('domain', '?')}\n")
                w.insert("end", f"  │  Process:      {meta.get('process', '?')} (PID {meta.get('pid', '?')})\n")
                w.insert("end", f"  │  Country:      {meta.get('country', '?')}\n")
                w.insert("end", f"  │  City:         {meta.get('city', '?')}\n")
                w.insert("end", f"  │  Org:          {meta.get('org', '?')}\n")
                w.insert("end", f"  │  ISP:          {meta.get('isp', '?')}\n")
                w.insert("end", f"  │  Port:         {meta.get('remote_port', '?')}\n")
                w.insert("end", f"  │  Category:     {meta.get('category', '?')}\n")
                w.insert("end", f"  └{'─' * 90}\n\n", "dim")
        w.insert("end", f"\n{'═' * 120}\n", "dim")
        w.insert("end", f"  Firewall rules are automatically cleaned up when the program is closed.\n", "dim")
        w.insert("end", f"  Rules use prefix: {self._fw_rule_prefix}*\n", "dim")
        w.config(state="disabled")
        self._end_refresh(w, at_bottom, frac)

    # ====================== GEOMETRY PERSISTENCE (Multi-monitor) ======================
    def _load_geometry(self):
        try:
            if os.path.exists(self._geometry_file):
                with open(self._geometry_file, 'r') as f:
                    geo = json.load(f)
                self._root.geometry(geo.get('geometry', ''))
        except Exception:
            pass

    def _save_geometry(self):
        try:
            with open(self._geometry_file, 'w') as f:
                json.dump({'geometry': self._root.geometry()}, f)
        except Exception:
            pass

    # ====================== ALERT FLASH SYSTEM ======================
    def _check_alert_flash(self, data):
        sus_count = len(data.get('suspicious_events', []))
        if sus_count > self._last_suspicious_count:
            new_alerts = sus_count - self._last_suspicious_count
            self._last_suspicious_count = sus_count
            # Flash the Suspicious Activity tab
            try:
                nb = self._root.nametowidget(self._suspicious_frame.winfo_parent())
                tab_id = nb.index(self._suspicious_frame)
                self._flash_tab(nb, tab_id, " 🔴 Suspicious Activity ", 6)
            except Exception:
                pass

    def _flash_tab(self, notebook, tab_index, original_text, flashes_remaining):
        if flashes_remaining <= 0:
            try:
                notebook.tab(tab_index, text=original_text)
            except Exception:
                pass
            return
        try:
            current = notebook.tab(tab_index, 'text')
            if '⚡' in current:
                notebook.tab(tab_index, text=original_text)
            else:
                notebook.tab(tab_index, text=" ⚡ ALERT ⚡ ")
        except Exception:
            return
        self._root.after(400, lambda: self._flash_tab(notebook, tab_index,
                                                        original_text, flashes_remaining - 1))

    # ====================== RIGHT-CLICK CONTEXT MENUS ======================
    def _show_conn_context_menu(self, event, ip, conn_info=None):
        menu = tk.Menu(self._root, tearoff=0, bg="#1a1a2e", fg="#c0c0c0",
                       activebackground="#e94560", activeforeground="white")
        menu.add_command(label=f"Block {ip}", command=lambda: self._toggle_block_ip(ip, conn_info))
        menu.add_command(label=f"Copy IP: {ip}", command=lambda: self._copy_to_clipboard(ip))
        menu.add_command(label=f"Add to Watchlist", command=lambda: self._add_to_watchlist_ip(ip))
        menu.add_command(label=f"Remove from Watchlist", command=lambda: self._watchlist_ips.discard(ip))
        menu.add_separator()
        menu.add_command(label=f"Whois Lookup", command=lambda: self._whois_popup(ip))
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    def _show_proc_context_menu(self, event, pid, name):
        menu = tk.Menu(self._root, tearoff=0, bg="#1a1a2e", fg="#c0c0c0",
                       activebackground="#e94560", activeforeground="white")
        menu.add_command(label=f"Add '{name}' to Watchlist",
                         command=lambda: self._watchlist_procs.add(name.lower()))
        menu.add_command(label=f"Remove '{name}' from Watchlist",
                         command=lambda: self._watchlist_procs.discard(name.lower()))
        menu.add_command(label=f"Copy PID: {pid}", command=lambda: self._copy_to_clipboard(str(pid)))
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    def _copy_to_clipboard(self, text):
        self._root.clipboard_clear()
        self._root.clipboard_append(text)

    def _add_to_watchlist_ip(self, ip):
        self._watchlist_ips.add(ip)

    def _whois_popup(self, ip):
        """Open a popup with whois info for an IP."""
        def _do_lookup():
            try:
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
    def _export_html_report(self):
        data = self._get_full_data()
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
                f'<h1>GNA Tracer Security Report</h1>',
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
                html.append(f'<tr><td>{d["time"]}</td><td class="{sev_cls}">{d["severity"]}</td>'
                            f'<td>{d["category"]}</td><td>{d["process"]}</td>'
                            f'<td>{d["message"]}</td><td>{d["score"]}</td></tr>')
            html.append('</table>')
        # Suspicious Events
        sus = data.get('suspicious_events', [])
        if sus:
            html.append('<h2>Suspicious Events</h2><table><tr><th>Time</th><th>Severity</th><th>Category</th><th>Process</th><th>Description</th></tr>')
            for ev in sus[-200:]:
                sev_cls = 'critical' if ev.get('severity') == 'CRITICAL' else 'warning'
                html.append(f'<tr><td>{ev.get("time","?")}</td><td class="{sev_cls}">{ev.get("severity","?")}</td>'
                            f'<td>{ev.get("category","?")}</td><td>{ev.get("process","?")}</td>'
                            f'<td>{ev.get("description","?")}</td></tr>')
            html.append('</table>')
        # Connections
        conns = data.get('connections', [])
        if conns:
            html.append('<h2>Active Connections</h2><table><tr><th>Process</th><th>Remote IP</th><th>Port</th><th>Service</th><th>Country</th><th>Org</th></tr>')
            for c in conns[:300]:
                html.append(f'<tr><td>{c.get("process","?")}</td><td>{c.get("remote_ip","?")}</td>'
                            f'<td>{c.get("remote_port","?")}</td><td>{c.get("service","?")}</td>'
                            f'<td>{c.get("country","?")}</td><td>{c.get("org","?")}</td></tr>')
            html.append('</table>')
        # Processes
        procs = data.get('processes', [])
        if procs:
            html.append('<h2>Processes</h2><table><tr><th>PID</th><th>Name</th><th>Risk</th><th>Connections</th><th>Countries</th></tr>')
            for p in sorted(procs, key=lambda x: x.get('risk', 0), reverse=True)[:100]:
                risk_cls = 'critical' if p.get('risk', 0) > 50 else ('warning' if p.get('risk', 0) > 20 else '')
                html.append(f'<tr><td>{p["pid"]}</td><td>{p["name"]}</td>'
                            f'<td class="{risk_cls}">{p["risk"]}</td><td>{p["connections"]}</td>'
                            f'<td>{", ".join(p.get("countries", []))}</td></tr>')
            html.append('</table>')
        # VT Results
        vt = data.get('vt_results', {})
        if vt:
            html.append('<h2>VirusTotal Results</h2><table><tr><th>SHA256</th><th>Malicious</th><th>Suspicious</th><th>Harmless</th></tr>')
            for sha, r in vt.items():
                m_cls = 'critical' if r.get('malicious', 0) > 0 else ''
                html.append(f'<tr><td>{sha[:16]}...</td><td class="{m_cls}">{r.get("malicious",0)}</td>'
                            f'<td>{r.get("suspicious",0)}</td><td>{r.get("harmless",0)}</td></tr>')
            html.append('</table>')
        html.append('</body></html>')
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write('\n'.join(html))
            _logger.info("HTML report exported to %s", filepath)
            from tkinter import messagebox
            messagebox.showinfo("Report Exported", f"Report saved to:\n{filepath}")
        except Exception as exc:
            _logger.warning("HTML export failed: %s", exc)

    # ====================== PROCESS TREE TAB ======================
    def _refresh_process_tree(self, data):
        w = self._ptree_text
        at_bottom = self._is_at_bottom(w)
        frac = w.yview()[0]
        w.config(state="normal")
        w.delete("1.0", "end")
        w.insert("end", "═" * 120 + "\n", "dim")
        w.insert("end", "  🌳 PROCESS TREE — Parent → Child Relationships\n", "header")
        w.insert("end", "═" * 120 + "\n\n", "dim")
        procs = data.get('processes', [])
        if not procs:
            w.insert("end", "  No processes tracked yet.\n", "dim")
            w.config(state="disabled")
            return
        # Build tree: parent_pid -> [children]
        by_pid = {p['pid']: p for p in procs}
        children_map = defaultdict(list)
        roots = []
        for p in procs:
            parent = p.get('parent', '')
            parent_pid = None
            for op in procs:
                if op['name'] == parent and op['pid'] != p['pid']:
                    parent_pid = op['pid']
                    break
            if parent_pid and parent_pid in by_pid:
                children_map[parent_pid].append(p)
            else:
                roots.append(p)
        # Sort roots by risk
        roots.sort(key=lambda x: x.get('risk', 0), reverse=True)

        def _draw_tree(proc, prefix="", is_last=True):
            connector = "└── " if is_last else "├── "
            risk = proc.get('risk', 0)
            tag = 'critical' if risk > 50 else ('warning' if risk > 20 else 'default')
            star = " ★" if proc['name'].lower() in self._watchlist_procs else ""
            conns = proc.get('connections', 0)
            countries = ', '.join(proc.get('countries', [])) or '-'
            line = (f"{prefix}{connector}{proc['name']} (PID {proc['pid']}) "
                    f"risk={risk:.0f} conns={conns} geo=[{countries}]{star}\n")
            w.insert("end", line, tag)
            kids = children_map.get(proc['pid'], [])
            kids.sort(key=lambda x: x.get('risk', 0), reverse=True)
            new_prefix = prefix + ("    " if is_last else "│   ")
            for i, child in enumerate(kids):
                _draw_tree(child, new_prefix, i == len(kids) - 1)

        for i, root in enumerate(roots[:50]):
            _draw_tree(root, "  ", i == len(roots) - 1)
        w.insert("end", f"\n  Total: {len(procs)} processes tracked\n", "dim")
        w.config(state="disabled")
        self._end_refresh(w, at_bottom, frac)

    # ====================== NETWORK STATS TAB ======================
    def _refresh_netstats(self, data):
        w = self._netstats_text
        at_bottom = self._is_at_bottom(w)
        frac = w.yview()[0]
        w.config(state="normal")
        w.delete("1.0", "end")
        w.insert("end", "═" * 120 + "\n", "dim")
        w.insert("end", "  📊 NETWORK INTERFACE STATS — Real-time Bandwidth\n", "header")
        w.insert("end", "═" * 120 + "\n\n", "dim")
        iface_data = data.get('iface_stats', {})
        if not iface_data:
            w.insert("end", "  Collecting data... stats will appear after a few seconds.\n", "dim")
            w.config(state="disabled")
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
            w.insert("end", f"  │  ↑ Upload:   {self._fmt_bytes_rate(sent_rate)}  "
                            f"(Total: {self._fmt_bytes(total_sent)})\n", "info")
            w.insert("end", f"  │  ↓ Download: {self._fmt_bytes_rate(recv_rate)}  "
                            f"(Total: {self._fmt_bytes(total_recv)})\n", "cyan")
            w.insert("end", f"  │  Packets:    ↑{latest.get('packets_sent',0):,}  ↓{latest.get('packets_recv',0):,}\n")
            if errin or errout or dropin or dropout:
                w.insert("end", f"  │  Errors:     in={errin} out={errout}  "
                                f"Drops: in={dropin} out={dropout}\n", "warning")
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
                w.insert("end", f"  │  ↑ Trend:   {send_spark}\n", "info")
                w.insert("end", f"  │  ↓ Trend:   {recv_spark}\n", "cyan")
            w.insert("end", f"  └{'─' * 95}\n\n", "dim")
        # Per-IP bandwidth
        bw = data.get('conn_bandwidth', {})
        if bw:
            w.insert("end", "\n  TOP IPs BY BANDWIDTH\n", "subheader")
            w.insert("end", "  " + "─" * 95 + "\n", "dim")
            sorted_bw = sorted(bw.items(), key=lambda x: x[1].get('bytes_sent', 0) + x[1].get('bytes_recv', 0), reverse=True)
            for ip, info in sorted_bw[:20]:
                total = info.get('bytes_sent', 0) + info.get('bytes_recv', 0)
                star = " ★" if ip in self._watchlist_ips else ""
                w.insert("end", f"  {ip:>20}  ↑{self._fmt_bytes(info.get('bytes_sent',0)):>10}  "
                                f"↓{self._fmt_bytes(info.get('bytes_recv',0)):>10}  "
                                f"Total: {self._fmt_bytes(total):>10}{star}\n")
        w.config(state="disabled")
        self._end_refresh(w, at_bottom, frac)

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
        at_bottom = self._is_at_bottom(w)
        frac = w.yview()[0]
        w.config(state="normal")
        w.delete("1.0", "end")
        w.insert("end", "═" * 120 + "\n", "dim")
        w.insert("end", "  ⏱️ CONNECTION TIMELINE — All Connections (Active + Closed)\n", "header")
        w.insert("end", "═" * 120 + "\n\n", "dim")
        timeline = data.get('conn_timeline', [])
        if not timeline:
            w.insert("end", "  No connection history yet.\n", "dim")
            w.config(state="disabled")
            return
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
        w.insert("end", f"\n  Total tracked: {len(timeline)} connections\n", "dim")
        w.config(state="disabled")
        self._end_refresh(w, at_bottom, frac)

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
        w.window_create("end", window=export_btn)
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
        frac = w.yview()[0]
        w.config(state="normal")
        if self._terminal_last_count == 0:
            # First render — write header + all lines
            w.delete("1.0", "end")
            w.insert("end", "═" * 110 + "\n", "dim")
            w.insert("end", "  TERMINAL — 100% OF ALL PROCESSED OUTPUT\n", "header")
            w.insert("end", "═" * 110 + "\n\n", "dim")
        # Append only new lines since last refresh
        new_lines = lines[self._terminal_last_count:]
        for _ts, tag, text in new_lines:
            w.insert("end", text + "\n", tag)
        self._terminal_last_count = new_count
        self._highlight_search(w, self._search_terminal.get())
        w.config(state="disabled")
        # Only auto-scroll if user was at the bottom
        if at_bottom:
            w.see("end")
        else:
            w.yview_moveto(frac)

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
        self._stop.set()
        if self._update_job:
            self._root.after_cancel(self._update_job)
        if self._autosave_job:
            self._root.after_cancel(self._autosave_job)
        self._root.destroy()

    def _save_tracer_data(self):
        self._save_counter += 1
        desktop = os.path.join(os.path.expanduser("~"), "Desktop")
        filepath = os.path.join(desktop, f"GNA tracer data {self._save_counter}.txt")
        data = self._get_full_data()
        ts_now = datetime.datetime.now()
        ts = ts_now.strftime("%Y-%m-%d %H:%M:%S")
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
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines))
        _logger.info("GNA tracer data saved to %s (save #%d, runtime %s)", filepath, self._save_counter, runtime_str)


def _fmt_ts(ts):
    if not ts or ts == 0:
        return "N/A"
    try:
        return datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return str(ts)


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

        # Terminal output buffer — captures 100% of all _log output
        self.terminal_buffer: deque = deque(maxlen=10000)

        # Database
        self.db = DatabaseManager()

        # Original LAN tracking
        self.devices = {}
        self.seen_composites = set()
        self.remote_sessions = {}
        self.probe_attempts = defaultdict(int)
        self.flow_stats = defaultdict(lambda: deque(maxlen=400))
        self.mac_to_ip_history = defaultdict(set)
        self.last_alert = defaultdict(float)

        # Connection cache — populated by dedicated mapper thread
        self.conn_by_pid: dict[int, list] = defaultdict(list)
        self.conn_by_raddr: dict[str, tuple] = {}
        self.conn_cache_lock = threading.Lock()

        # Deductive Chess Engine v2
        self.dns_cache = DNSCache()
        self.beacon_detector = BeaconDetector()
        self.process_profiles: dict[int, ProcessProfile] = {}
        self.process_actions = defaultdict(list)
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

        # Watchlist / Favorites
        self._watchlist_ips: set[str] = set()
        self._watchlist_procs: set[str] = set()

        # Network interface bandwidth tracking
        self._iface_stats_prev: dict[str, tuple] = {}
        self._iface_stats_history: dict[str, deque] = defaultdict(lambda: deque(maxlen=120))

        # Admin check
        self._admin_mode = True
        try:
            psutil.net_connections(kind='inet')
        except psutil.AccessDenied:
            self._admin_mode = False

        self.stop = threading.Event()

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
        clean = self._ANSI_RE.sub('', line)
        tag = 'critical' if color == Colors.R else ('warning' if color == Colors.Y else (
            'info' if color == Colors.G else 'default'))
        with self.lock:
            self.terminal_buffer.append((ts, tag, clean))

    def _safe_alert(self, msg, color=Colors.R):
        key = msg.split('\u2192')[0].strip() if '\u2192' in msg else msg[:60]
        now = time.time()
        with self.lock:
            if now - self.last_alert.get(key, 0) > CONFIG['alert_cooldown']:
                self.last_alert[key] = now
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
        ('temp\\\\', 'TEMP_EXECUTION', 'Process running from temp directory'),
        ('appdata', 'SUSPICIOUS_PATH', 'Process running from AppData'),
        ('downloads\\\\', 'SUSPICIOUS_PATH', 'Process running from Downloads'),
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
        with self.lock:
            self.suspicious_events.append(event)

    def _auto_flag_action(self, pid, name, action, extra):
        """Check if an action matches suspicious patterns and auto-flag it."""
        combined = f"{action} {extra}".lower()
        for keyword, cat, desc in self._SUSPICIOUS_EXTRA_KW:
            if keyword in combined or keyword in name.lower():
                self._flag_suspicious(cat, "WARNING", name, pid, desc,
                    [f"Action: {action}", f"Detail: {extra}",
                     f"Process: {name} (PID {pid})",
                     f"Matched keyword: '{keyword}'"])
                return

    def _write_action(self, pid, name, action, extra=""):
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        entry = f"{ts} | {name} (PID {pid}) | {action} {extra}"
        logging.getLogger('medianbox.actions').info(entry)
        with self.lock:
            self.process_actions[pid].append((time.time(), name, action, extra))
        # Auto-detect suspicious actions
        self._auto_flag_action(pid, name, action, extra)

    def _write_deduction_log(self, d: Deduction):
        ts = datetime.datetime.fromtimestamp(d.timestamp).strftime("%Y-%m-%d %H:%M:%S")
        entry = (f"{ts} | [{d.severity}] [{d.category}] {d.process_name} (PID {d.pid}) | "
                 f"{d.message} | score={d.score:.1f} | evidence={d.evidence}")
        logging.getLogger('medianbox.deductions').info(entry)

    # ====================== SUBNET DETECTION ======================
    def _detect_subnet(self):
        for _iface, addrs in psutil.net_if_addrs().items():
            for a in addrs:
                if a.family == socket.AF_INET and not a.address.startswith('127') and a.netmask:
                    try:
                        net = ipaddress.IPv4Interface(f"{a.address}/{a.netmask}").network
                        return a.address, str(net), net
                    except Exception:
                        continue
        return "192.168.1.100", "192.168.1.0/24", ipaddress.IPv4Network("192.168.1.0/24")

    # ====================== HELPERS ======================
    def _is_public_ip(self, ip: str) -> bool:
        try:
            return ipaddress.ip_address(ip).is_global
        except Exception:
            return False

    def _composite_key(self, mac, ip):
        return hashlib.sha256(f"{mac or 'nomac'}:{ip or 'noip'}".encode()).hexdigest()[:16]

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
    def _add_deduction(self, severity, category, proc_name, pid, message, evidence, score):
        cooldown_key = f"{category}:{pid}:{hash(message[:80])}"
        now = time.time()
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
        with self.lock:
            self.deductions.append(d)
            if pid in self.process_profiles:
                self.process_profiles[pid].risk_score += escalated_score
                self.process_profiles[pid].risk_reasons.append(f"[{category}] {message}")
                self.process_profiles[pid].escalation_hits += 1

        emoji_map = {
            "MIMIC": EMOJI['mimic'], "BEACON": EMOJI['beacon'],
            "PHANTOM": EMOJI['phantom'], "IMPERSONATION": EMOJI['impersonate'],
            "FOREIGN": EMOJI['foreign'], "ANOMALY": EMOJI['anomaly'],
            "INJECTION": EMOJI['inject'], "TUNNEL": EMOJI['tunnel'],
            "EXFIL": EMOJI['exfil'], "ENTROPY": EMOJI['entropy'],
            "DLL": EMOJI['dll'], "PERSISTENCE": EMOJI['persist'],
            "IDLE_ANOMALY": EMOJI['idle'], "ML_ANOMALY": EMOJI['ml'],
        }
        icon = emoji_map.get(category, EMOJI['chess'])
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
            if profile.io_snapshot_time > 0:
                dt = now - profile.io_snapshot_time
                if dt > 0:
                    sent_rate = (io_counters.write_bytes - profile.io_baseline_sent) / dt
                    self.ml_baseline.record(profile.name.lower(), profile.connection_count,
                        len(profile.destinations), sent_rate,
                        statistics.mean(profile.cpu_samples) if profile.cpu_samples else 0)
                    if (sent_rate > CONFIG['exfil_min_bytes'] / 60 and
                            io_counters.write_bytes - profile.io_baseline_sent > CONFIG['exfil_min_bytes']):
                        evidence = [
                            f"Send rate: {sent_rate/1024:.0f} KB/s",
                            f"Total sent: {(io_counters.write_bytes - profile.io_baseline_sent)/1024/1024:.1f} MB",
                            f"Destinations: {', '.join(list(profile.destinations)[:5])}",
                        ]
                        idle_sec = self.user_idle.get_idle_seconds()
                        if idle_sec > CONFIG['user_idle_threshold']:
                            evidence.append(f"User idle for {idle_sec:.0f}s")
                        self._add_deduction("CRITICAL", "EXFIL", profile.name, profile.pid,
                            f"DATA EXFILTRATION: '{profile.name}' uploading {sent_rate/1024:.0f} KB/s",
                            evidence, 40.0)
            with self.lock:
                profile.io_baseline_sent = io_counters.write_bytes
                profile.io_baseline_recv = io_counters.read_bytes
                profile.io_snapshot_time = now
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    # ---------- DEDUCTION 10: DLL Injection ----------
    def _check_dlls(self, profile, proc):
        if profile.checked_dlls or not _IS_WINDOWS:
            return
        profile.checked_dlls = True
        suspicious = DLLInspector.inspect(proc)
        if suspicious:
            profile.loaded_dlls = suspicious
            evidence = [f"Suspicious DLL: {dll}" for dll in suspicious[:10]]
            self._add_deduction("CRITICAL", "DLL", profile.name, profile.pid,
                f"DLL INJECTION: '{profile.name}' has {len(suspicious)} suspicious modules",
                evidence, 40.0)

    # ---------- DEDUCTION 11: Persistence Changes ----------
    def _check_persistence(self):
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
    def _check_idle_anomaly(self, profile):
        idle_sec = self.user_idle.get_idle_seconds()
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
            len(profile.destinations), profile.bytes_sent, cpu_mean)
        profile.ml_anomaly_score = ml_score
        if ml_score > 30 and anomalies:
            evidence = [*anomalies, f"Overall anomaly score: {ml_score:.1f}", f"Process: {profile.name} (PID {profile.pid})"]
            sev = "CRITICAL" if ml_score > 60 else "WARNING"
            self._add_deduction(sev, "ML_ANOMALY", profile.name, profile.pid,
                f"STATISTICAL ANOMALY: '{profile.name}' deviates from baseline (score={ml_score:.0f})",
                evidence, ml_score * 0.5)

    # ---------- DEDUCTION 14: GeoIP Enrichment ----------
    def _check_geoip(self, profile, dst_ip, domains):
        try:
            ip_obj = ipaddress.ip_address(dst_ip)
            if not ip_obj.is_global:
                return
        except Exception:
            return
        geo = self.geoip.lookup(dst_ip)
        if geo:
            country = geo.get('countryCode', '??')
            org = geo.get('org', 'Unknown')
            with self.lock:
                profile.geo_countries.add(country)
            if country in CONFIG.get('high_risk_countries', set()):
                idle_sec = self.user_idle.get_idle_seconds()
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
        with self._conn_snapshot_lock:
            return list(self._conn_snapshot)

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
                        by_raddr[conn.raddr[0]] = (conn.pid, conn)
                with self.conn_cache_lock:
                    self.conn_by_pid = by_pid
                    self.conn_by_raddr = by_raddr
            except psutil.AccessDenied:
                pass
            except Exception as exc:
                _logger.debug("Connection mapper error: %s", exc)
            time.sleep(2)

    # ====================== PROCESS WATCHER ======================
    def _process_watcher(self):
        last_pids: set[int] = set()
        while not self.stop.is_set():
            current_pids: set[int] = set()
            audio_pids = set()
            camera_pids = set()
            with self.conn_cache_lock:
                conn_by_pid = dict(self.conn_by_pid)

            for proc in psutil.process_iter(['pid', 'name', 'ppid', 'exe', 'cpu_percent']):
                try:
                    pid = proc.pid
                    name = proc.name()
                    current_pids.add(pid)
                    # Hardware detection (merged — avoids double process_iter)
                    name_lower_hw = name.lower()
                    if any(kw in name_lower_hw for kw in HARDWARE_KEYWORDS['audio']):
                        if pid not in audio_pids:
                            self._flag_suspicious('HARDWARE_ACCESS', 'WARNING', name, pid,
                                f'Audio device accessed by {name}',
                                [f'Process: {name} (PID {pid})',
                                 f'Matched audio keyword in process name',
                                 f'Audio hardware is being used — potential eavesdropping if unexpected'])
                        audio_pids.add(pid)
                    if any(kw in name_lower_hw for kw in HARDWARE_KEYWORDS['camera']):
                        if pid not in camera_pids:
                            self._flag_suspicious('HARDWARE_ACCESS', 'CRITICAL', name, pid,
                                f'Camera/webcam accessed by {name}',
                                [f'Process: {name} (PID {pid})',
                                 f'Matched camera keyword in process name',
                                 f'Camera hardware is being used — potential surveillance if unexpected'])
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
                    with self.lock:
                        profile.cpu_samples.append(cpu)
                        if cpu > 5:
                            self.user_activity_ts = time.time()

                    self._check_impersonation(profile, proc)
                    for conn in conn_by_pid.get(pid, []):
                        if conn.raddr:
                            dst_ip = conn.raddr[0]
                            conn_key = (dst_ip, conn.raddr[1], conn.laddr[0] if conn.laddr else '', conn.laddr[1] if conn.laddr else 0)
                            with self.lock:
                                is_new = conn_key not in profile.seen_conn_keys
                                profile.destinations.add(dst_ip)
                                if is_new:
                                    profile.seen_conn_keys.add(conn_key)
                                    profile.connection_count += 1
                                profile.packet_timestamps.append(time.time())
                                profile.last_network_ts = time.time()
                            domains = self.dns_cache.get_domains(dst_ip)
                            with self.lock:
                                profile.dns_domains.update(domains)
                            self._write_action(pid, name, "NETWORK_FLOW",
                                f"-> {dst_ip}:{conn.raddr[1]} domains={domains or 'unresolved'}")
                            # Flag remote access ports
                            dst_port = conn.raddr[1]
                            if is_new and dst_port in CONFIG['remote_ports']:
                                port_names = {22: 'SSH', 3389: 'RDP', 5900: 'VNC', 5938: 'TeamViewer',
                                              445: 'SMB', 139: 'NetBIOS', 5985: 'WinRM', 5986: 'WinRM-S'}
                                self._flag_suspicious('REMOTE_ACCESS', 'WARNING', name, pid,
                                    f'{name} connected to remote access port {dst_port} ({port_names.get(dst_port, "Unknown")})',
                                    [f'Process: {name} (PID {pid})',
                                     f'Destination: {dst_ip}:{dst_port}',
                                     f'Protocol: {port_names.get(dst_port, "Unknown")}',
                                     f'Domain: {", ".join(domains) if domains else "unresolved"}',
                                     f'This could indicate remote control or lateral movement'])
                            # Flag connections to high-risk countries
                            if is_new and self._is_public_ip(dst_ip):
                                cc = self.geoip.get_country(dst_ip)
                                if cc in CONFIG['high_risk_countries']:
                                    self._flag_suspicious('HIGH_RISK_GEO', 'CRITICAL', name, pid,
                                        f'{name} connected to high-risk country: {cc} ({dst_ip})',
                                        [f'Process: {name} (PID {pid})',
                                         f'Destination: {dst_ip}:{dst_port}',
                                         f'Country: {cc}',
                                         f'Domain: {", ".join(domains) if domains else "unresolved"}',
                                         f'High-risk countries: {CONFIG["high_risk_countries"]}'])
                            self._check_mimic(profile, dst_ip, domains)
                            self._check_foreign(profile, dst_ip, domains)
                            self._check_behavioral_anomaly(profile, dst_ip)
                            self._check_geoip(profile, dst_ip, domains)
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
                with self.lock:
                    if pid in self.process_profiles:
                        prof = self.process_profiles[pid]
                        self._write_action(pid, prof.name, "STOPPED")
                        del self.process_profiles[pid]

            # Update hardware activity from this scan pass
            with self.lock:
                self.audio_active_pids = audio_pids
                self.camera_active_pids = camera_pids

            self._check_phantoms(current_pids)
            if _IS_WINDOWS:
                self._check_persistence()
            last_pids = current_pids
            time.sleep(CONFIG['process_scan_interval'])

    # ====================== PACKET CALLBACK (via pipeline) ======================
    def _packet_callback(self, pkt):
        """Called by pipeline workers — not directly by sniff thread."""
        if pkt.haslayer(DNS):
            self.dns_cache.process_packet(pkt)
            if pkt[DNS].qr == 0:
                try:
                    qname = pkt[DNS].qd.qname.decode(errors='ignore').rstrip('.')
                    src_q = pkt[IP].src if pkt.haslayer(IP) else '?'
                    self._check_dns_tunnel(qname, src_q)
                except Exception as exc:
                    _logger.debug("DNS tunnel check error: %s", exc)

        sni = self.sni_extractor.extract(pkt)
        if sni:
            dst_for_sni = pkt[IP].dst if pkt.haslayer(IP) else None
            if dst_for_sni:
                with self.dns_cache.lock:
                    self.dns_cache.ip_to_domains[dst_for_sni].add(sni)
                    self.dns_cache.domain_to_ips[sni].add(dst_for_sni)

        if pkt.haslayer(Raw):
            payload = bytes(pkt[Raw])
            if len(payload) >= 32:
                ent = self.entropy_analyzer.payload_entropy(payload)
                is_sus, desc = self.entropy_analyzer.is_suspicious(pkt, ent)
                if is_sus:
                    src_e = pkt[IP].src if pkt.haslayer(IP) else '?'
                    dst_e = pkt[IP].dst if pkt.haslayer(IP) else '?'
                    self._add_deduction("WARNING", "ENTROPY", "packet", 0,
                        f"HIGH ENTROPY PAYLOAD: {src_e} -> {dst_e}: {desc}",
                        [desc, f"Payload size: {len(payload)} bytes"], 15.0)

        ja4s = self.ja4plus.ja4s(pkt)
        ja4h = self.ja4plus.ja4h(pkt)

        if not (pkt.haslayer(IP) or pkt.haslayer(IPv6)):
            return

        src = pkt[IP].src if pkt.haslayer(IP) else pkt[IPv6].src
        dst = pkt[IP].dst if pkt.haslayer(IP) else pkt[IPv6].dst
        dport = pkt[TCP].dport if pkt.haslayer(TCP) else (pkt[UDP].dport if pkt.haslayer(UDP) else 0)

        mac = pkt[Ether].src.upper() if pkt.haslayer(Ether) else None
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

        proto = pkt[IP].proto if pkt.haslayer(IP) else 0
        sport = pkt[TCP].sport if pkt.haslayer(TCP) else (pkt[UDP].sport if pkt.haslayer(UDP) else 0)
        flow_key = (src, dst, proto, sport, dport)

        # Inbound SYN detection — detect port scans targeting us
        if pkt.haslayer(TCP) and pkt[TCP].flags & 0x02 and dst == self.local_ip and src != self.local_ip:
            self.inbound_scan_detector.record_inbound_syn(src, pkt[TCP].dport)

        # TLS certificate tracking (ServerHello with cert)
        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            raw_data = bytes(pkt[Raw])
            if len(raw_data) > 10 and raw_data[0] == 0x16:
                hs = raw_data[5:]
                if len(hs) > 4 and hs[0] == 0x0b:  # Certificate message
                    self.tls_cert_detector.record_cert(src, raw_data[:256])

        with self.lock:
            self.flow_stats[flow_key].append(now)
            probe_count = 0
            if pkt.haslayer(TCP) and pkt[TCP].flags & 0x02 and pkt[TCP].dport in CONFIG['probe_alert_ports']:
                self.probe_attempts[src] += 1
                probe_count = self.probe_attempts[src]

            new_remote = False
            s_port = d_port = 0
            if pkt.haslayer(TCP) and (pkt[TCP].flags & 0x10):
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
            time.sleep(random.uniform(CONFIG['scan_interval_min'], CONFIG['scan_interval_max']))

    def _sniff_thread(self):
        filt = "ip or ip6 or arp"
        while not self.stop.is_set():
            try:
                sniff(prn=self.pipeline.enqueue, filter=filt, store=False,
                      promisc=True, timeout=60,
                      stop_filter=lambda _: self.stop.is_set())
            except Exception as e:
                _logger.warning("Sniff error: %s — retrying in 5s", e)
                time.sleep(5)

    def _status_thread(self):
        while not self.stop.is_set():
            with self.lock:
                n_procs = len(self.process_profiles)
                n_deductions = len(self.deductions)
                high_risk = sum(1 for p in self.process_profiles.values() if p.risk_score > CONFIG['risk_critical'])
                n_dns = len(self.dns_cache.ip_to_domains)
                n_geo = len(self.geoip.cache)
            idle_sec = self.user_idle.get_idle_seconds()
            ml_active = sum(1 for m in self.ml_baseline.models.values()
                            if len(m['conn_rate']) >= 30)
            pipe = self.pipeline.stats()
            self._log(
                f"{EMOJI['chess']} Status: {len(self.devices)} devices | "
                f"{n_procs} processes | {n_deductions} deductions | "
                f"{high_risk} high-risk | {n_dns} DNS | {n_geo} GeoIP | "
                f"{ml_active} baselines | idle={idle_sec:.0f}s | "
                f"pipe={pipe['processed']}/{pipe['dropped']}",
                color=Colors.G)
            # Periodic cleanup of stale deduction cooldowns
            now = time.time()
            cooldown_ttl = CONFIG['deduction_cooldown'] * 2
            with self.lock:
                stale_keys = [k for k, t in self.deduction_cooldowns.items()
                              if now - t > cooldown_ttl]
                for k in stale_keys:
                    del self.deduction_cooldowns[k]
            time.sleep(15)

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
                    while ctypes.windll.kernel32.VirtualQueryEx(
                            handle, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)):
                        if mbi.State == MEM_COMMIT and mbi.Protect == PAGE_EXECUTE_READWRITE and mbi.RegionSize > 4096:
                            rwx_regions += 1
                        addr += mbi.RegionSize
                        if addr > 0x7FFFFFFFFFFF:
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
            time.sleep(30)

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
                # Connection history update
                with self._conn_snapshot_lock:
                    snapshot = list(self._conn_snapshot)
                self.conn_history.update(snapshot)
            except Exception as exc:
                _logger.debug("Extended monitor error: %s", exc)
            time.sleep(5)

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
            time.sleep(3)

    # ====================== DASHBOARD STATE ======================
    def _get_dashboard_state(self) -> dict:
        with self.lock:
            processes = []
            for _pid, p in list(self.process_profiles.items())[:200]:
                processes.append({
                    'pid': p.pid, 'name': p.name, 'exe': p.exe_path,
                    'parent': p.parent_name, 'risk': round(p.risk_score, 1),
                    'connections': p.connection_count,
                    'destinations': len(p.destinations),
                    'ml_score': round(p.ml_anomaly_score, 1),
                    'countries': sorted(p.geo_countries),
                })
            deductions_list = []
            for d in list(self.deductions)[-100:]:
                deductions_list.append({
                    'time': datetime.datetime.fromtimestamp(d.timestamp).strftime("%H:%M:%S"),
                    'severity': d.severity, 'category': d.category,
                    'process': d.process_name, 'pid': d.pid,
                    'message': d.message, 'score': round(d.score, 1),
                    'evidence': list(d.evidence),
                })
            devices_list = list(self.devices.values())
        pipe = self.pipeline.stats()
        return {
            'processes': processes, 'deductions': deductions_list,
            'devices': devices_list, 'dns_count': len(self.dns_cache.ip_to_domains),
            'geoip_count': len(self.geoip.cache),
            'idle_seconds': round(self.user_idle.get_idle_seconds(), 0),
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
        # Add raw actions log
        with self.lock:
            all_actions = []
            for pid, actions in list(self.process_actions.items()):
                for ts, name, action, extra in actions:
                    all_actions.append(
                        f"{datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')} | "
                        f"{name} (PID {pid}) | {action} {extra}"
                    )
        all_actions.sort()
        base['all_actions'] = all_actions
        # Add full deductions with evidence (all, not just last 100)
        with self.lock:
            full_deds = []
            for d in list(self.deductions):
                full_deds.append({
                    'time': datetime.datetime.fromtimestamp(d.timestamp).strftime("%H:%M:%S"),
                    'severity': d.severity, 'category': d.category,
                    'process': d.process_name, 'pid': d.pid,
                    'message': d.message, 'score': round(d.score, 1),
                    'evidence': list(d.evidence),
                })
        base['deductions'] = full_deds
        # Add 100% terminal output buffer
        with self.lock:
            base['terminal_lines'] = list(self.terminal_buffer)
        # Add suspicious activity events
        with self.lock:
            base['suspicious_events'] = list(self.suspicious_events)
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
        base['conn_timeline'] = self.conn_history.get_timeline()
        base['conn_bandwidth'] = self.conn_history.get_bandwidth()
        base['iface_stats'] = {k: list(v) for k, v in self._iface_stats_history.items()}
        base['watchlist_ips'] = list(self._watchlist_ips)
        base['watchlist_procs'] = list(self._watchlist_procs)
        base['bt_devices'] = self.bt_scanner.get_devices()
        base['bt_events'] = self.bt_scanner.get_events()
        base['serial_ports'] = self.serial_scanner.get_ports()
        base['serial_events'] = self.serial_scanner.get_events()
        base['proxy_events'] = self.proxy_detector.get_events()
        base['proxy_processes'] = self.proxy_detector.get_proxy_processes()
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
            # Save GNA tracer data on any exit
            try:
                desktop = os.path.join(os.path.expanduser('~'), 'Desktop')
                filepath = os.path.join(desktop, 'GNA tracer data.txt')
                if not os.path.exists(filepath):
                    saver = GNATracerGUI(
                        get_state_fn=self._get_dashboard_state,
                        get_full_data_fn=self._get_full_data,
                        stop_event=self.stop,
                    )
                    saver._save_tracer_data()
            except Exception:
                pass
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
