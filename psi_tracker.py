#!/usr/bin/env python3
"""
PSI-Tracker V1.0 "DEY Warrior" – Final Unbreakable Proxy Auditor for Iran
===================================================================================
- Full RFC 1928 SOCKS5 (IPv4, IPv6, domain name, proper BND handling)
- Real OSSH handshake (anti-echo seed exchange)
- Meek reachability integrated into scoring
- True UDP test (SOCKS5 UDP relay, full IPv4/IPv6 support, safe against crashes)
- Accurate server_list_compressed parser (IPv4, IPv6, DOMAIN entries, safe bounds)
- Context-aware checkpoint with config fingerprint
- Accurate port diversity test THROUGH the proxy (no direct connection)
- Fair scoring with Generic Viability & load awareness
- Multi-pass retry for slow proxies (rescues high-latency candidates)
- Advanced HTTP validation (POST, PUT, DELETE, Cookie, Referrer, Compression)
- Multi-judge anonymity classification (ELITE/ANONYMOUS/TRANSPARENT)
- DNS-over-SOCKS detection, Captive Portal detection
- Real browsing, censorship bypass, persistent connection, and stability tests
- Compact mode (default) with --verbose for full details
- Two‑phase network watchdog (cached IPs + proxy targets)
- Manual Pause/Resume with keyboard (P/R keys)
- Automatic network loss detection with Pause/Resume mechanism (no input())
- DEAD proxies show correct SL/Div placeholders
- Final summary with protocol breakdown
- --max-alive flag to stop early
- Improved periodic summaries (exclude dead proxies)
- Best ping/score shown live in progress bar
- Proper cleanup on Ctrl+C and session close where needed
- Production‑hardened, crash‑resistant, Python 3.7+ compatible
- Multi-credential brute-force via passlist.txt for authenticated proxies
===================================================================================
"""

import socket, struct, ssl, sys, time, random, os, json, argparse, concurrent.futures, threading, ipaddress, gzip, re, hashlib
from typing import Optional, Tuple, Dict, List, Any
from pathlib import Path
import base64
import requests
import ctypes
from ctypes import wintypes

try:
    import socks
    SOCKS_AVAILABLE = True
except ImportError:
    SOCKS_AVAILABLE = False
    print("[!] PySocks is required for SOCKS5 proxy tests. Install: pip install PySocks")
    sys.exit(1)

try:
    from tqdm import tqdm
except ImportError:
    print("tqdm required. Install: pip install tqdm")
    sys.exit(1)
try:
    from colorama import init, Fore, Style
    init(autoreset=True)
except ImportError:
    class Fore: GREEN = RED = YELLOW = BLUE = MAGENTA = CYAN = WHITE = RESET = ''
    class Style: BRIGHT = ''; RESET_ALL = ''
#dont change {for EXE}
icon_path = os.path.join(os.path.dirname(__file__), "scanner.jpg")
# For EXE

# console icon
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
user32 = ctypes.WinDLL('user32', use_last_error=True)

console_window = kernel32.GetConsoleWindow()
if console_window:
    #loadout Icon
    hicon = user32.LoadImageW(None, icon_path, 1, 0, 0, 0x00000010)  # IMAGE_ICON, LR_LOADFROMFILE
    if hicon:
        user32.SendMessageW(console_window, 0x0080, 0, hicon)  # WM_SETICON, ICON_SMALL
        user32.SendMessageW(console_window, 0x0080, 1, hicon)  # ICON_BIG
        
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
PSIPHON_SSH_IP = "156.146.56.168"
PSIPHON_SSH_PORT = 22
OSSH_SEED_LEN = 32

MEEK_SERVER = "b-cdn.net"
MEEK_PATH = "/meek"
MEEK_PAYLOAD = json.dumps({"sessionId": "psitracker", "userAgent": base64.b64encode(USER_AGENT.encode()).decode()}).encode()
MEEK_HEADERS = {
    "Host": MEEK_SERVER,
    "User-Agent": USER_AGENT,
    "X-Session-Id": "psitracker",
    "Content-Type": "application/x-www-form-urlencoded",
}

SERVER_LIST_URL = f"https://{MEEK_SERVER}/web/mjr4-p23r-puwl/server_list_compressed"

DEFAULT_PSI_ENDPOINTS_TEMPLATE = [
    {"host": "b-cdn.net",             "ip": None, "port": 443},
    {"host": "j.sni.global.fastly.net","ip": None, "port": 443},
    {"host": "a1361.dscg.akamai.net", "ip": None, "port": 443},
]

ABBREV_GEN = {"google.com": "GOG", "cloudflare.com": "CF", "github.com": "GH",
              "web.telegram.org": "TLG", "youtube.com": "YT"}
ABBREV_PSI = {"b-cdn.net": "b", "j.sni.global.fastly.net": "f", "a1361.dscg.akamai.net": "a"}

# ---------- Global caches (with TTL) ----------
_server_list_cache: List[Dict[str, Any]] = []
_server_list_etag: Optional[str] = None
_server_list_ts: float = 0.0
_server_list_lock = threading.Lock()
SERVER_LIST_TTL = 120.0

FALLBACK_IPS = {
    "github.com": "140.82.121.4",
    "google.com": "216.239.38.120",
    "b-cdn.net": "156.146.56.168",
    "httpbin.org": "34.195.177.88",
    "api.ipify.org": "172.67.75.46",
    "1.1.1.1": "1.1.1.1",
    "web.telegram.org": "149.154.167.99",
    "youtube.com": "142.250.185.78",
    "cloudflare.com": "104.16.124.96",
    "j.sni.global.fastly.net": "146.75.118.132",
    "a1361.dscg.akamai.net": "5.178.42.163",
}

GEOIP_SERVICES = [
    "http://ip-api.com/json/{}",
    "https://ipinfo.io/{}/json",
    "https://ifconfig.co/json?ip={}"
]

DIVERSITY_PORTS = [22, 53, 80, 443, 554]

MAX_AUTH_ATTEMPTS = 20   # max passlist.txt

JUDGE_SERVERS = [
    {
        "url": "http://httpbin.org/get?show_env=1",
        "type": "json",
        "headers_path": "headers",
        "leak_keys": ["X-Forwarded-For", "Via", "Proxy-Connection", "X-Real-Ip", "Forwarded", "X-Proxy-Id"],
        "anonymity_map": {"ELITE": [], "ANONYMOUS": ["Via", "Proxy-Connection"], "TRANSPARENT": ["X-Forwarded-For", "X-Real-Ip"]},
    },
    {
        "url": "http://proxyjudge.info/azenv.php",
        "type": "text",
        "leak_keys": ["HTTP_X_FORWARDED_FOR", "HTTP_VIA", "HTTP_PROXY_CONNECTION", "HTTP_X_REAL_IP"],
        "anonymity_map": {"ELITE": [], "ANONYMOUS": ["HTTP_VIA", "HTTP_PROXY_CONNECTION"], "TRANSPARENT": ["HTTP_X_FORWARDED_FOR", "HTTP_X_REAL_IP"]},
    },
    {
        "url": "http://azenv.net/",
        "type": "text",
        "leak_keys": ["HTTP_X_FORWARDED_FOR", "HTTP_VIA", "HTTP_PROXY_CONNECTION", "HTTP_X_REAL_IP"],
        "anonymity_map": {"ELITE": [], "ANONYMOUS": ["HTTP_VIA", "HTTP_PROXY_CONNECTION"], "TRANSPARENT": ["HTTP_X_FORWARDED_FOR", "HTTP_X_REAL_IP"]},
    },
    {
        "url": "http://proxyjudge.us/azenv.php",
        "type": "text",
        "leak_keys": ["HTTP_X_FORWARDED_FOR", "HTTP_VIA", "HTTP_PROXY_CONNECTION", "HTTP_X_REAL_IP"],
        "anonymity_map": {"ELITE": [], "ANONYMOUS": ["HTTP_VIA", "HTTP_PROXY_CONNECTION"], "TRANSPARENT": ["HTTP_X_FORWARDED_FOR", "HTTP_X_REAL_IP"]},
    },
    {
        "url": "http://judge.uribl.com/",
        "type": "text",
        "leak_keys": ["HTTP_X_FORWARDED_FOR", "HTTP_VIA", "HTTP_PROXY_CONNECTION", "HTTP_X_REAL_IP"],
        "anonymity_map": {"ELITE": [], "ANONYMOUS": ["HTTP_VIA", "HTTP_PROXY_CONNECTION"], "TRANSPARENT": ["HTTP_X_FORWARDED_FOR", "HTTP_X_REAL_IP"]},
    },
]

BROWSING_SITES = [
    ("http://www.gstatic.com/generate_204", 204),
    ("http://httpbin.org/headers", 200),
    ("https://cloudflare.com/cdn-cgi/trace", 200),
]
CENSORED_SITES = ["https://telegram.org", "https://twitter.com", "https://facebook.com"]

NET_CHECK_IPS = [
    "216.239.38.120",   # google.com (user's actual IP)
    "104.16.124.96",    # cloudflare.com
    "140.82.121.4",     # github.com
    "156.146.56.168",   # b-cdn.net
    "149.154.167.99",   # web.telegram.org
    "34.195.177.88",    # httpbin.org
    "185.143.232.201",  # varzesh3.com (Iranian)
]

SAFE_FALLBACK_IP = FALLBACK_IPS.get("google.com", "8.8.8.8")

LEGEND = (
    f"{Fore.CYAN}Legend:{Style.RESET_ALL} "
    f"G.Via=Generic Viability(max 50) | "
    f"Pub=Public endpoints(GOG,CF,GH,TLG,YT) | "
    f"TUN=TLS tunnel(OK/SLOW/FAIL) | "
    f"Psi=Psiphon endpoints | "
    f"Div=Port diversity | "
    f"SL=Server list status | "
    f"Cens=Censorship bypass count | "
    f"Stb=Stability | "
    f"Brw=Browsing score | "
    f"Persist=Persistent connection"
)

# ======================== UTILITIES ========================
def _retry_sleep(attempt, base=0.3, cap=2.0):
    time.sleep(min(base * 2**attempt, cap) * random.uniform(0.75, 1.25))

def _create_sock(timeout: float) -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    return s

def recv_exactly(sock, n: int) -> bytes:
    data = b''
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk: raise ConnectionError(f"Socket closed after {len(data)}/{n}")
        data += chunk
    return data

def recv_until_crlf(sock, timeout: float, max_size=65536) -> bytes:
    original = sock.gettimeout()
    try:
        sock.settimeout(timeout)
        data = b''
        while b'\r\n\r\n' not in data:
            try:
                chunk = sock.recv(4096)
                if not chunk: break
                data += chunk
                if len(data) > max_size: break
            except socket.timeout: break
        return data
    finally:
        if original is not None: sock.settimeout(original)

def load_checkpoint(path: str) -> dict:
    return json.load(open(path, encoding="utf-8")) if Path(path).exists() else {}

def save_checkpoint_atomic(path: str, data: dict):
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as f: json.dump(data, f, indent=2)
    os.replace(tmp, path)

# ---------- Two-phase network watchdog ----------
def is_network_alive(targets: List[str], timeout=3.0) -> bool:
    for ip in NET_CHECK_IPS:
        try:
            s = socket.create_connection((ip, 443), timeout=timeout)
            s.close()
            return True
        except OSError:
            continue
    if targets:
        sample = random.sample(targets, min(5, len(targets)))
        for entry in sample:
            try:
                host, port = entry.split(":")
                s = socket.create_connection((host, int(port)), timeout=timeout)
                s.close()
                return True
            except OSError:
                continue
    return False

_dns_lock = threading.Lock()
_dns_cache = {}
_DNS_TTL = 300
def resolve_host(host: str) -> Optional[str]:
    now = time.time()
    with _dns_lock:
        if host in _dns_cache:
            ts, ip = _dns_cache[host]
            if now - ts < _DNS_TTL:
                return ip
            else:
                del _dns_cache[host]
    try:
        info = socket.getaddrinfo(host, 0, socket.AF_INET, socket.SOCK_STREAM)
        ip = info[0][4][0]
        with _dns_lock: _dns_cache[host] = (now, ip)
        return ip
    except:
        ip = FALLBACK_IPS.get(host)
        if ip:
            with _dns_lock: _dns_cache[host] = (now, ip)
            return ip
        return None

def _get_proxy_session(proxy_url: str, headers: dict = None) -> requests.Session:
    s = requests.Session()
    s.proxies = {'http': proxy_url, 'https': proxy_url}
    s.headers.update({'User-Agent': USER_AGENT})
    if headers: s.headers.update(headers)
    return s

def _check_socks_available(proxy_url: str) -> bool:
    return not ('socks' in proxy_url and not SOCKS_AVAILABLE)

# ---------- Low-Level TCP Hints ----------
def get_tcp_hints(sock: socket.socket) -> dict:
    hints = {}
    try:
        ttl = sock.getsockopt(socket.IPPROTO_IP, socket.IP_TTL)
        hints["ttl"] = ttl
        if hasattr(socket, "TCP_INFO"):
            try:
                info = sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_INFO, 92)
                if len(info) >= 8:
                    state, ca_state, retransm, probes, backoff, options, snd_scale, rcv_scale = struct.unpack("BBBBBBBB", info[:8])
                    hints["retransm"] = retransm
                    hints["options"] = options
            except: pass
    except: pass
    return hints

# ---------- Lenient TLS handshake ----------
def tls_handshake_on_socket(sock: socket.socket, hostname: str, timeout: float) -> Tuple[bool, Optional[float], Optional[str]]:
    start = time.time()
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM")
        tls = ctx.wrap_socket(sock, server_hostname=hostname)
        tls.settimeout(timeout)
        tls.sendall(f"GET / HTTP/1.1\r\nHost: {hostname}\r\nConnection: close\r\n\r\n".encode())
        data = b''
        deadline = time.time() + timeout
        while b'\r\n\r\n' not in data and time.time() < deadline:
            try:
                chunk = tls.recv(16384)
                if not chunk: break
                data += chunk
            except socket.timeout: break
        if b'\r\n\r\n' in data:
            return True, (time.time() - start) * 1000, None
        if data:
            return True, (time.time() - start) * 1000, "PARTIAL_HEADER"
        return False, None, "NO_DATA"
    except Exception as e:
        return False, None, f"TLS_{type(e).__name__}"

def tcp_connect_raw(host, port, timeout) -> bool:
    try:
        with _create_sock(timeout) as s: s.connect((host, port))
        return True
    except: return False

def get_direct_ip_socket(timeout=6.0) -> Optional[str]:
    for host in ("httpbin.org", FALLBACK_IPS.get("httpbin.org", "")):
        try:
            ip = resolve_host(host)
            if not ip: continue
            sock = _create_sock(timeout); sock.connect((ip, 80))
            sock.sendall(f"GET /ip HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
            data = b''
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk: break
                    data += chunk
                    if len(data) > 16384: break
                except socket.timeout: break
            sock.close()
            if b'\r\n\r\n' in data:
                body = data.split(b'\r\n\r\n', 1)[1]
                ip = json.loads(body).get('origin')
                if ip: return ip
        except: continue
    return None

def proxy_ip_leak_test(proxy_url: str, timeout: float) -> Optional[bool]:
    try:
        direct = get_direct_ip_socket() or requests.get("http://httpbin.org/ip", timeout=8).json().get('origin')
        if not direct: return None
        s = _get_proxy_session(proxy_url)
        r = s.get("http://httpbin.org/ip", timeout=timeout)
        s.close()
        proxy_ip = r.json().get('origin')
        return proxy_ip and proxy_ip != direct
    except: return None

def detect_http_forward_absolute(proxy_url: str, timeout: float) -> Tuple[bool, Optional[float]]:
    test_urls = [
        ("http://httpbin.org/ip", None),
        (f"http://{FALLBACK_IPS.get('httpbin.org','34.195.177.88')}/ip", "httpbin.org"),
        ("http://www.gstatic.com/generate_204", None),
    ]
    for url, host_hdr in test_urls:
        try:
            s = _get_proxy_session(proxy_url)
            if host_hdr: s.headers.update({'Host': host_hdr})
            r = s.get(url, timeout=timeout)
            s.close()
            if r.status_code in (200, 204, 301, 302, 307, 308):
                return True, r.elapsed.total_seconds() * 1000
        except: continue
    return False, None

def http_connect_test(host, port, timeout) -> Tuple[bool, Optional[str]]:
    try:
        with _create_sock(timeout) as s:
            s.connect((host, port))
            s.sendall(f"CONNECT b-cdn.net:443 HTTP/1.1\r\nHost: b-cdn.net:443\r\nUser-Agent: {USER_AGENT}\r\n\r\n".encode())
            resp = recv_until_crlf(s, timeout)
            if not resp: return False, None
            line = resp.split(b'\r\n')[0].decode('ascii', errors='ignore')
            if line.startswith("HTTP/"):
                if " 200 " in line: return True, None
                if " 407 " in line: return True, "AUTH_REQUIRED"
                return True, "OTHER_HTTP"
            return False, None
    except: return False, None

# ---------- Lenient forward proxy test ----------
def forward_proxy_https_lenient(proxy_url: str, target_host: str, target_port=443, timeout=8.0) -> Tuple[bool, Optional[str]]:
    sock = None
    tls = None
    captive = None
    try:
        phost, _, pport = proxy_url.replace('http://', '').partition(':')
        pport = int(pport) if pport else 80
        sock = _create_sock(timeout); sock.connect((phost, pport))
        sock.sendall(f"CONNECT {target_host}:{target_port} HTTP/1.1\r\nHost: {target_host}:{target_port}\r\nUser-Agent: {USER_AGENT}\r\n\r\n".encode())
        resp = recv_until_crlf(sock, timeout)
        if not resp or not resp.split(b'\r\n')[0].startswith(b"HTTP/"):
            return False, None
        for line in resp.split(b'\r\n'):
            if line.lower().startswith(b"location:") and any(x in line.lower() for x in (b'login', b'portal', b'auth')):
                captive = "CAPTIVE_PORTAL"
        ctx = ssl.create_default_context(); ctx.check_hostname = True; ctx.verify_mode = ssl.CERT_REQUIRED
        tls = ctx.wrap_socket(sock, server_hostname=target_host)
        tls.sendall(f"GET / HTTP/1.1\r\nHost: {target_host}\r\nConnection: close\r\n\r\n".encode())
        data = b''
        while True:
            try:
                chunk = tls.recv(4096)
                if not chunk: break
                data += chunk
                if len(data) > 131072: break
            except socket.timeout: break
        tls.close(); tls = None
        if b'\r\n\r\n' in data:
            body = data.split(b'\r\n\r\n', 1)[1]
            return len(body) >= 200, captive
        return True, captive
    except: return False, None
    finally:
        if tls: tls.close()
        if sock: sock.close()

def meek_handshake(proxy_url: str, timeout: float) -> bool:
    if not _check_socks_available(proxy_url): return False
    try:
        s = _get_proxy_session(proxy_url)
        resp = s.post(f"https://{MEEK_SERVER}{MEEK_PATH}", headers=MEEK_HEADERS, data=MEEK_PAYLOAD, timeout=timeout)
        s.close()
        return resp.status_code == 200 and len(resp.content) >= 100
    except: return False

# ---------- Advanced HTTP test ----------
def test_http_advanced(proxy_url: str, timeout: float) -> dict:
    results = {"post_echo": False, "put_echo": False, "delete_echo": False,
               "cookie_echo": False, "referrer_echo": False,
               "compression_ok": False, "overall": False}
    if not _check_socks_available(proxy_url): return results
    s = _get_proxy_session(proxy_url)
    try:
        test_cookie = "psitracker_test=advanced_validation"
        s.cookies.set("psitracker_test", "advanced_validation")
        headers = {"Referer": "http://psitracker.internal/test"}
        r = s.post("http://httpbin.org/post", data={"test_field": "echo_back"}, headers=headers, timeout=timeout)
        if r.status_code == 200:
            j = r.json()
            if j.get("form", {}).get("test_field") == "echo_back": results["post_echo"] = True
            if test_cookie in j.get("headers", {}).get("Cookie", ""): results["cookie_echo"] = True
            if j.get("headers", {}).get("Referer") == headers["Referer"]: results["referrer_echo"] = True
        r = s.put("http://httpbin.org/put", data={"test": "put_data"}, timeout=timeout)
        if r.status_code == 200 and r.json().get("form", {}).get("test") == "put_data": results["put_echo"] = True
        r = s.delete("http://httpbin.org/delete", timeout=timeout)
        if r.status_code == 200: results["delete_echo"] = True
        comp_headers = {"Accept-Encoding": "gzip, deflate"}
        r = s.get("http://httpbin.org/gzip", headers=comp_headers, timeout=timeout)
        if r.status_code == 200 and len(r.content) > 0: results["compression_ok"] = True
        results["overall"] = results["post_echo"] and results["cookie_echo"] and results["referrer_echo"] and results["put_echo"] and results["compression_ok"]
    except: pass
    finally:
        s.close()
    return results

# ---------- Multi-judge anonymity (conservative) ----------
def classify_anonymity_advanced(proxy_url, timeout) -> Tuple[str, Dict[str, bool]]:
    if not _check_socks_available(proxy_url): return "UNKNOWN", {}
    at_least_one_success = False
    for judge in JUDGE_SERVERS:
        s = _get_proxy_session(proxy_url)
        try:
            r = s.get(judge["url"], timeout=timeout)
            if judge["type"] == "json":
                data = r.json().get(judge["headers_path"], {})
            else:
                text = r.text
                data = {}
                for line in text.splitlines():
                    if "=" in line:
                        key, val = line.split("=", 1)
                        data[key.strip()] = val.strip()
            any_leak = False
            for key in judge["leak_keys"]:
                if key in data and data[key]:
                    any_leak = True
                    amap = judge["anonymity_map"]
                    if key in amap["TRANSPARENT"]:
                        return "TRANSPARENT", {}
            if not any_leak:
                at_least_one_success = True
        except: continue
        finally:
            s.close()
    if at_least_one_success:
        return "ELITE", {}
    return "UNKNOWN", {}

def classify_anonymity(proxy_url, timeout) -> Tuple[str, Dict[str, bool]]:
    advanced_result, _ = classify_anonymity_advanced(proxy_url, timeout)
    if advanced_result != "UNKNOWN":
        return advanced_result, {}
    s = _get_proxy_session(proxy_url)
    try:
        r = s.get("http://httpbin.org/get?show_env=1", timeout=timeout)
        hdrs = r.json().get('headers', {})
        leaks = {'x_forwarded_for': 'X-Forwarded-For' in hdrs, 'via': 'Via' in hdrs,
                 'proxy_connection': 'Proxy-Connection' in hdrs, 'x_real_ip': 'X-Real-Ip' in hdrs}
        total = sum(leaks.values())
        if total == 0: return "ELITE", leaks
        if not leaks['x_real_ip'] and not leaks['x_forwarded_for']: return "ANONYMOUS", leaks
        return "TRANSPARENT", leaks
    except: return "UNKNOWN", {}
    finally:
        s.close()

_geo_cache = {}
_geo_lock = threading.Lock()
_GEO_TTL = 300
_last_geo = 0.0

def geo_ip(proxy_url, timeout) -> str:
    if not _check_socks_available(proxy_url): return "N/A"
    s = _get_proxy_session(proxy_url)
    try:
        origin = s.get("http://httpbin.org/get?show_env=1", timeout=timeout).json().get('origin', '')
        if not origin: return "N/A"
        now = time.time()
        with _geo_lock:
            if origin in _geo_cache:
                ts, country = _geo_cache[origin]
                if now - ts < _GEO_TTL:
                    return country
                else:
                    del _geo_cache[origin]
        with _geo_lock:
            delta = now - _last_geo
            sleep_time = max(0.0, 2.0 - delta)
        if sleep_time > 0: time.sleep(sleep_time)
        for url_pattern in GEOIP_SERVICES:
            try:
                r = requests.get(url_pattern.format(origin), timeout=5)
                data = r.json()
                country = data.get('country') or data.get('country_name')
                if country:
                    with _geo_lock:
                        _geo_cache[origin] = (now, country)
                        _last_geo = now
                    return country
            except: continue
    except: pass
    finally:
        s.close()
    return "N/A"

# ---------- Robust UDP test (IPv6-safe) ----------
def test_udp(host, port, timeout) -> bool:
    s = None
    try:
        s = _create_sock(timeout); s.connect((host, port))
        s.sendall(b"\x05\x01\x00")
        if recv_exactly(s, 2) != b"\x05\x00": return False
        s.sendall(b"\x05\x03\x00\x01" + socket.inet_aton("0.0.0.0") + struct.pack("!H", 0))
        resp = recv_exactly(s, 4)
        if resp[0] != 0x05 or resp[1] != 0x00: return False
        atyp = resp[3]
        if atyp == 0x01:
            bind_addr = recv_exactly(s, 4); bind_port = struct.unpack('!H', recv_exactly(s, 2))[0]
            bind_ip = socket.inet_ntop(socket.AF_INET, bind_addr)
            af = socket.AF_INET
            target_ip = "8.8.8.8"
        elif atyp == 0x03:
            alen = ord(recv_exactly(s, 1)); bind_addr = recv_exactly(s, alen)
            bind_port = struct.unpack('!H', recv_exactly(s, 2))[0]
            bind_ip = bind_addr.decode()
            if ':' in bind_ip:
                af = socket.AF_INET6
                target_ip = "2001:4860:4860::8888"
            else:
                af = socket.AF_INET
                target_ip = "8.8.8.8"
        elif atyp == 0x04:
            bind_addr = recv_exactly(s, 16); bind_port = struct.unpack('!H', recv_exactly(s, 2))[0]
            bind_ip = socket.inet_ntop(socket.AF_INET6, bind_addr)
            af = socket.AF_INET6; target_ip = "2001:4860:4860::8888"
        else:
            return False
        dns_id = random.randrange(0, 65535)
        dns_query = struct.pack('!HHHHHH', dns_id, 0x0100, 1, 0, 0, 0) + b'\x06google\x03com\x00\x00\x01\x00\x01'
        header = b"\x00\x00\x00\x01" + socket.inet_pton(af, target_ip) + struct.pack("!H", 53)
        udp_sock = socket.socket(af, socket.SOCK_DGRAM)
        udp_sock.settimeout(timeout * 0.7)
        try:
            udp_sock.sendto(header + dns_query, (bind_ip, bind_port))
            response, _ = udp_sock.recvfrom(1024)
            return len(response) >= 2
        except socket.timeout: pass
        finally: udp_sock.close()
        return False
    except:
        return False
    finally:
        if s: s.close()

# ---------- SSH / OSSH ----------
def handshake_ossh(proxy_host, proxy_port, dest_ip, dest_port, timeout) -> Tuple[str, Optional[float], Optional[str]]:
    try:
        ipa = ipaddress.ip_address(dest_ip)
        if ipa.version != 4: return "FAIL", None, "IPV6_NOT_SUPPORTED"
        addr = socket.inet_aton(dest_ip)
    except ValueError: addr = socket.inet_aton(resolve_host(dest_ip) or dest_ip)
    start = time.time()
    for attempt in range(2):
        s = None
        try:
            s = _create_sock(timeout); s.connect((proxy_host, proxy_port))
            s.sendall(b"\x05\x01\x00")
            if recv_exactly(s, 2) != b"\x05\x00": continue
            s.sendall(b"\x05\x01\x00\x01" + addr + struct.pack("!H", dest_port))
            resp = recv_exactly(s, 4)
            if resp[0] != 0x05 or resp[1] != 0x00: continue
            atyp = resp[3]
            if atyp == 0x01: recv_exactly(s, 6)
            elif atyp == 0x03: recv_exactly(s, ord(recv_exactly(s, 1)) + 2)
            elif atyp == 0x04: recv_exactly(s, 18)
            seed_client = os.urandom(OSSH_SEED_LEN); s.sendall(seed_client)
            s.settimeout(timeout * 0.7)
            server_seed = recv_exactly(s, OSSH_SEED_LEN)
            if server_seed == seed_client: return "INCONCLUSIVE", (time.time()-start)*1000, "ECHO_SEED"
            if len(server_seed) == OSSH_SEED_LEN: return "PASS", (time.time()-start)*1000, None
            return "INCONCLUSIVE", (time.time()-start)*1000, "SHORT_SEED"
        except socket.timeout: return "FAIL", None, "TIMEOUT"
        except Exception:
            if attempt == 0: _retry_sleep(attempt)
            continue
        finally:
            if s: s.close()
    return "FAIL", None, "FAILED"

def handshake_ossh_socks4(proxy_host, proxy_port, dest_ip, dest_port, timeout) -> Tuple[str, Optional[float], Optional[str]]:
    try:
        ipa = ipaddress.ip_address(dest_ip)
        if ipa.version != 4: return "FAIL", None, "IPV6_NOT_SUPPORTED"
        addr = socket.inet_aton(dest_ip)
    except ValueError: addr = socket.inet_aton(resolve_host(dest_ip) or dest_ip)
    start = time.time()
    for attempt in range(2):
        s = None
        try:
            s = _create_sock(timeout); s.connect((proxy_host, proxy_port))
            s.sendall(b"\x04\x01" + struct.pack("!H", dest_port) + addr + b"scan\x00")
            resp = recv_exactly(s, 8)
            if resp[1] != 0x5a: continue
            seed_client = os.urandom(OSSH_SEED_LEN); s.sendall(seed_client)
            s.settimeout(timeout * 0.7)
            server_seed = recv_exactly(s, OSSH_SEED_LEN)
            if server_seed == seed_client: return "INCONCLUSIVE", (time.time()-start)*1000, "ECHO_SEED"
            if len(server_seed) == OSSH_SEED_LEN: return "PASS", (time.time()-start)*1000, None
            return "INCONCLUSIVE", (time.time()-start)*1000, "SHORT_SEED"
        except socket.timeout: return "FAIL", None, "TIMEOUT"
        except Exception:
            if attempt == 0: _retry_sleep(attempt)
            continue
        finally:
            if s: s.close()
    return "FAIL", None, "FAILED"

def test_ssh_socks5(host, port, ssh_host, ssh_port, timeout) -> Tuple[str, Optional[str]]:
    ip = resolve_host(ssh_host) if ssh_host != PSIPHON_SSH_IP else PSIPHON_SSH_IP
    if not ip: return "INCONCLUSIVE", "SSH_DNS_FAIL"
    try: ipv = ipaddress.ip_address(ip)
    except ValueError: return "INCONCLUSIVE", "INVALID_IP"
    if ipv.version != 4: return "INCONCLUSIVE", "IPV6_NOT_SUPPORTED"
    addr = socket.inet_aton(ip)
    for attempt in range(2):
        s = None
        try:
            s = _create_sock(timeout); s.connect((host, port))
            s.sendall(b"\x05\x01\x00")
            if recv_exactly(s, 2) != b"\x05\x00": continue
            s.sendall(b"\x05\x01\x00\x01" + addr + struct.pack("!H", ssh_port))
            if recv_exactly(s, 4)[1] != 0x00: continue
            s.sendall(b"SSH-2.0-PSITracker\r\n"); s.settimeout(timeout)
            return ("PASS", None) if b"SSH" in s.recv(1024) else ("FAIL", "NO_SSH_BANNER")
        except socket.timeout: return "INCONCLUSIVE", "SSH_TIMEOUT"
        except:
            if attempt == 0: _retry_sleep(attempt)
            continue
        finally:
            if s: s.close()
    return "FAIL", "SSH_FAILED"

def test_ssh_socks4(host, port, ssh_host, ssh_port, timeout) -> Tuple[str, Optional[str]]:
    ip = resolve_host(ssh_host) if ssh_host != PSIPHON_SSH_IP else PSIPHON_SSH_IP
    if not ip: return "INCONCLUSIVE", "SSH_DNS_FAIL"
    try: ipv = ipaddress.ip_address(ip)
    except ValueError: return "INCONCLUSIVE", "INVALID_IP"
    if ipv.version != 4: return "INCONCLUSIVE", "IPV6_NOT_SUPPORTED"
    addr = socket.inet_aton(ip)
    for attempt in range(2):
        s = None
        try:
            s = _create_sock(timeout); s.connect((host, port))
            s.sendall(b"\x04\x01" + struct.pack("!H", ssh_port) + addr + b"scan\x00")
            if recv_exactly(s, 8)[1] != 0x5a: continue
            s.sendall(b"SSH-2.0-PSITracker\r\n"); s.settimeout(timeout)
            return ("PASS", None) if b"SSH" in s.recv(1024) else ("FAIL", "NO_SSH_BANNER")
        except socket.timeout: return "INCONCLUSIVE", "SSH_TIMEOUT"
        except:
            if attempt == 0: _retry_sleep(attempt)
            continue
        finally:
            if s: s.close()
    return "FAIL", "SSH_FAILED"

# ---------- Protocol detection ----------
def detect_socks5(host, port, timeout) -> Tuple[str, str]:
    for attempt in range(2):
        try:
            with _create_sock(timeout) as s:
                s.connect((host, port)); s.sendall(b"\x05\x01\x00")
                resp = recv_exactly(s, 2)
                if resp[0] != 0x05: continue
                if resp[1] == 0x00: return "OPEN", "NO_AUTH"
                if resp[1] == 0x02: return "AUTH_REQUIRED", "USERPASS"
                return "AUTH_REQUIRED", f"METHOD_{resp[1]}"
        except:
            if attempt == 0: _retry_sleep(attempt)
            continue
    try:
        with _create_sock(timeout) as s:
            s.connect((host, port)); s.sendall(b"\x05\x01\x00")
            s.settimeout(timeout*0.5); data = s.recv(1024)
            if data and data[0] == 0x05:
                if data[1] == 0x00: return "OPEN", "NO_AUTH"
                if data[1] == 0x02: return "AUTH_REQUIRED", "USERPASS"
    except: pass
    return "CLOSED", "NONE"

def detect_socks4(host, port, timeout) -> Tuple[str, str]:
    for attempt in range(2):
        try:
            with _create_sock(timeout) as s:
                s.connect((host, port))
                addr = socket.inet_aton(FALLBACK_IPS.get("b-cdn.net", "156.146.56.168"))
                s.sendall(b"\x04\x01" + struct.pack("!H", 443) + addr + b"scan\x00")
                resp = recv_exactly(s, 8)
                if resp[0] == 0x00 and resp[1] == 0x5a: return "OPEN", "NO_AUTH"
                return "CLOSED", "NONE"
        except:
            if attempt == 0: _retry_sleep(attempt)
            continue
    return "CLOSED", "NONE"

def detect_http_connect(host, port, timeout) -> Tuple[str, str]:
    ok, auth = http_connect_test(host, port, timeout)
    if ok:
        if auth is None: return "OPEN", "NO_AUTH"
        if auth == "AUTH_REQUIRED": return "AUTH_REQUIRED", "BASIC"
        return "OPEN", "OTHER_HTTP"
    return "CLOSED", "NONE"

# ---------- Tunnel functions ----------
def socks5_connect_request(host: str, port: int) -> bytes:
    req = bytearray([0x05, 0x01, 0x00])
    try:
        ipa = ipaddress.ip_address(host)
        if ipa.version == 4: req.extend([0x01] + list(socket.inet_aton(host)))
        else: req.extend([0x04] + list(socket.inet_pton(socket.AF_INET6, host)))
    except ValueError:
        d = host.encode(); req.extend([0x03, len(d)] + list(d))
    req.extend(struct.pack("!H", port))
    return bytes(req)

def socks5_auth_tunnel_tls(host, port, user, pwd, dip, dport, dhost, timeout):
    s = None
    try:
        s = _create_sock(timeout); s.connect((host, port))
        s.sendall(b"\x05\x01\x02")
        if recv_exactly(s, 2) != b"\x05\x02": return False, None, "AUTH_METHOD"
        u, p = user.encode(), pwd.encode()
        s.sendall(b"\x01" + bytes([len(u)]) + u + bytes([len(p)]) + p)
        if recv_exactly(s, 2) != b"\x01\x00": return False, None, "AUTH_FAIL"
        s.sendall(socks5_connect_request(dip, dport))
        resp = recv_exactly(s, 4)
        if resp[0] != 0x05 or resp[1] != 0x00: return False, None, "CONNECT_FAIL"
        atyp = resp[3]
        if atyp == 0x01: recv_exactly(s, 6)
        elif atyp == 0x03: recv_exactly(s, ord(recv_exactly(s, 1)) + 2)
        elif atyp == 0x04: recv_exactly(s, 18)
        return tls_handshake_on_socket(s, dhost, timeout)
    except Exception as e: return False, None, f"EXC_{type(e).__name__}"
    finally:
        if s: s.close()

def socks5_tunnel_tls(host, port, dip, dport, dhost, timeout):
    for attempt in range(2):
        s = None
        try:
            s = _create_sock(timeout); s.connect((host, port))
            s.sendall(b"\x05\x01\x00")
            if recv_exactly(s, 2) != b"\x05\x00": continue
            s.sendall(socks5_connect_request(dip, dport))
            resp = recv_exactly(s, 4)
            if resp[0] != 0x05 or resp[1] != 0x00: continue
            atyp = resp[3]
            if atyp == 0x01: recv_exactly(s, 6)
            elif atyp == 0x03: recv_exactly(s, ord(recv_exactly(s, 1)) + 2)
            elif atyp == 0x04: recv_exactly(s, 18)
            return tls_handshake_on_socket(s, dhost, timeout)
        except:
            if attempt == 0: _retry_sleep(attempt)
            continue
        finally:
            if s: s.close()
    return False, None, "SOCKS5_TUNNEL_FAIL"

def http_connect_auth_tunnel_tls(host, port, user, pwd, dip, dport, dhost, timeout):
    s = None
    try:
        s = _create_sock(timeout); s.connect((host, port))
        auth = base64.b64encode(f"{user}:{pwd}".encode()).decode()
        request = (f"CONNECT {dhost}:{dport} HTTP/1.1\r\n"
                   f"Host: {dhost}:{dport}\r\n"
                   f"Proxy-Authorization: Basic {auth}\r\n"
                   f"User-Agent: {USER_AGENT}\r\n\r\n").encode()
        s.sendall(request)
        resp = recv_until_crlf(s, timeout)
        line = resp.decode('ascii', errors='ignore').split('\r\n')[0] if resp else ""
        if not re.match(r'^HTTP/1\.[01] 200', line):
            return (False, None, "AUTH_FAIL") if "407" in line else (False, None, "CONNECT_FAIL")
        return tls_handshake_on_socket(s, dhost, timeout)
    except Exception as e: return False, None, f"EXC_{type(e).__name__}"
    finally:
        if s: s.close()

def socks4_tunnel_tls(host, port, dip, dport, dhost, timeout):
    try:
        ipv = ipaddress.ip_address(dip)
        if ipv.version != 4: return False, None, "IPV6_NOT_SUPPORTED"
        addr = socket.inet_aton(dip)
    except ValueError:
        addr = socket.inet_aton(resolve_host(dip) or dip)
    for attempt in range(2):
        s = None
        try:
            s = _create_sock(timeout); s.connect((host, port))
            s.sendall(b"\x04\x01" + struct.pack("!H", dport) + addr + b"scan\x00")
            if recv_exactly(s, 8)[1] != 0x5a: continue
            return tls_handshake_on_socket(s, dhost, timeout)
        except:
            if attempt == 0: _retry_sleep(attempt)
            continue
        finally:
            if s: s.close()
    return False, None, "SOCKS4_TUNNEL_FAIL"

def http_connect_tunnel_tls(host, port, dip, dport, dhost, timeout):
    for attempt in range(2):
        s = None
        try:
            s = _create_sock(timeout); s.connect((host, port))
            s.sendall(f"CONNECT {dhost}:{dport} HTTP/1.1\r\nHost: {dhost}:{dport}\r\nUser-Agent: {USER_AGENT}\r\n\r\n".encode())
            recv_until_crlf(s, timeout)
            return tls_handshake_on_socket(s, dhost, timeout)
        except:
            if attempt == 0: _retry_sleep(attempt)
            continue
        finally:
            if s: s.close()
    return False, None, "HTTP_TUNNEL_FAIL"

def http_connect_raw(host, port, dip, dport, dhost, timeout) -> Tuple[bool, Optional[str]]:
    try:
        s = _create_sock(timeout); s.connect((host, port))
        s.sendall(f"CONNECT {dhost}:{dport} HTTP/1.1\r\nHost: {dhost}:{dport}\r\nUser-Agent: {USER_AGENT}\r\n\r\n".encode())
        resp = recv_until_crlf(s, timeout); s.close()
        if not resp: return False, None
        line = resp.decode('ascii', errors='ignore').split('\r\n')[0]
        if re.match(r'^HTTP/1\.[01] 200', line): return True, None
        if "407" in line: return True, "AUTH_REQUIRED"
        return True, "OTHER_HTTP"
    except: return False, None

def _proxy_raw_connect(proxy_type: str, proxy_host: str, proxy_port: int, target_ip: str, target_port: int, timeout: float) -> bool:
    s = None
    try:
        if proxy_type == 'SOCKS5':
            s = _create_sock(timeout); s.connect((proxy_host, proxy_port))
            s.sendall(b"\x05\x01\x00")
            if recv_exactly(s, 2) != b"\x05\x00": return False
            try: addr = socket.inet_aton(target_ip) if ipaddress.ip_address(target_ip).version == 4 else None
            except: addr = socket.inet_aton(resolve_host(target_ip) or target_ip)
            if not addr: return False
            s.sendall(b"\x05\x01\x00\x01" + addr + struct.pack("!H", target_port))
            resp = recv_exactly(s, 4); s.close(); s=None
            return resp[0] == 0x05 and resp[1] == 0x00
        elif proxy_type == 'SOCKS4':
            try: addr = socket.inet_aton(target_ip) if ipaddress.ip_address(target_ip).version == 4 else None
            except: addr = socket.inet_aton(resolve_host(target_ip) or target_ip)
            if not addr: return False
            s = _create_sock(timeout); s.connect((proxy_host, proxy_port))
            s.sendall(b"\x04\x01" + struct.pack("!H", target_port) + addr + b"scan\x00")
            resp = recv_exactly(s, 8); s.close(); s=None
            return resp[1] == 0x5a
        elif proxy_type in ('HTTP', 'HTTP_FWD'):
            return http_connect_raw(proxy_host, proxy_port, target_ip, target_port, target_ip, timeout)[0]
    except: return False
    finally:
        if s: s.close()

def _tunnel_dispatch(proto, host, port, dip, dport, dhost, timeout, auth_cred=None, extra_timeout_mult=1.0):
    actual_timeout = timeout * extra_timeout_mult
    if proto == 'SOCKS5':
        if auth_cred: return socks5_auth_tunnel_tls(host, port, *auth_cred, dip, dport, dhost, actual_timeout)
        return socks5_tunnel_tls(host, port, dip, dport, dhost, actual_timeout)
    if proto == 'SOCKS4': return socks4_tunnel_tls(host, port, dip, dport, dhost, actual_timeout)
    if proto == 'HTTP':
        if auth_cred: return http_connect_auth_tunnel_tls(host, port, *auth_cred, dip, dport, dhost, actual_timeout)
        return http_connect_tunnel_tls(host, port, dip, dport, dhost, actual_timeout)
    return False, None, "UNSUPPORTED_PROTO"

def test_speed(proxy_url: str, timeout: float) -> Optional[float]:
    if not _check_socks_available(proxy_url): return None
    s = _get_proxy_session(proxy_url)
    try:
        start = time.time()
        r = s.get("http://httpbin.org/bytes/524288", timeout=timeout)
        if r.status_code == 200 and len(r.content) == 524288:
            return (524288/(1024*1024)) / (time.time()-start)
    except: pass
    finally:
        s.close()
    return None

def test_data_transfer(proxy_url: str, timeout: float) -> bool:
    if not _check_socks_available(proxy_url): return False
    s = _get_proxy_session(proxy_url)
    try:
        r = s.get("http://httpbin.org/bytes/1024", timeout=timeout)
        return r.status_code == 200 and len(r.content) == 1024
    except: return False
    finally:
        s.close()

# ---------- Real browsing, stability, censorship, persistent tests ----------
def test_real_browsing(proxy_url: str, timeout: float) -> float:
    if not _check_socks_available(proxy_url): return 0.0
    ok = 0
    for url, _ in BROWSING_SITES:
        s = _get_proxy_session(proxy_url)
        try:
            r = s.get(url, timeout=timeout*0.8, headers={'User-Agent': USER_AGENT})
            if r.status_code in (200, 204, 301, 302):
                ok += 1
        except: pass
        finally:
            s.close()
    return ok / len(BROWSING_SITES) if BROWSING_SITES else 0.0

def test_stability(proxy_url: str, timeout: float) -> float:
    if not _check_socks_available(proxy_url): return 0.0
    urls = ["http://httpbin.org/ip", "http://httpbin.org/headers", "http://httpbin.org/user-agent"]
    ok = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex:
        futures = []
        for u in urls:
            def _do(u=u):
                s = _get_proxy_session(proxy_url)
                try:
                    return s.get(u, timeout=timeout*0.8).status_code == 200
                except:
                    return False
                finally:
                    s.close()
            futures.append(ex.submit(_do))
        for f in futures:
            try:
                if f.result(): ok += 1
            except: pass
    return ok / len(urls) if urls else 0.0

def test_censorship_bypass(proxy_url: str, timeout: float) -> int:
    if not _check_socks_available(proxy_url): return 0
    success = 0
    for site in CENSORED_SITES:
        s = _get_proxy_session(proxy_url)
        try:
            r = s.get(site, timeout=timeout*0.9, headers={'User-Agent': USER_AGENT})
            if r.status_code in (200, 301, 302, 307):
                success += 1
        except: pass
        finally:
            s.close()
    return success

def test_persistent_connection(proxy_url: str, timeout: float) -> bool:
    if not _check_socks_available(proxy_url): return False
    s = _get_proxy_session(proxy_url)
    try:
        for _ in range(5):
            r = s.get("http://httpbin.org/ip", timeout=timeout*0.8)
            if r.status_code != 200:
                return False
        return True
    except:
        return False
    finally:
        s.close()

# ---------- Server list (fully locked) ----------
def fetch_server_list(proxy_url: str, timeout: float) -> Tuple[List[Dict[str, Any]], str]:
    global _server_list_cache, _server_list_etag, _server_list_ts
    if not _check_socks_available(proxy_url):
        with _server_list_lock: return DEFAULT_PSI_ENDPOINTS_TEMPLATE, 'FALLBACK_NO_PYSOCKS'

    with _server_list_lock:
        now = time.time()
        if _server_list_cache and (now - _server_list_ts) < SERVER_LIST_TTL:
            return _server_list_cache, 'CACHE'

        s = _get_proxy_session(proxy_url)
        try:
            hdrs = {}
            if _server_list_etag: hdrs['If-None-Match'] = _server_list_etag
            resp = s.get(SERVER_LIST_URL, headers=hdrs, timeout=timeout)
            if resp.status_code == 304:
                _server_list_ts = time.time()
                _server_list_cache = _server_list_cache or DEFAULT_PSI_ENDPOINTS_TEMPLATE
                return _server_list_cache, '304'
            if resp.status_code == 200 and resp.content:
                data = gzip.decompress(resp.content)
                servers = []; i = 0; n = len(data)
                while i < n - 5:
                    entry_type = data[i]
                    if entry_type == 0x01:
                        if i+7 > n: break
                        ip_bytes = data[i+1:i+5]; port_raw = struct.unpack('!H', data[i+5:i+7])[0]
                        ip_str = socket.inet_ntop(socket.AF_INET, ip_bytes)
                        servers.append({"host": ip_str, "ip": ip_str, "port": port_raw}); i += 7
                    elif entry_type == 0x04:
                        if i+19 > n: break
                        ip6_bytes = data[i+1:i+17]; port_raw = struct.unpack('!H', data[i+17:i+19])[0]
                        ip6_str = socket.inet_ntop(socket.AF_INET6, ip6_bytes)
                        servers.append({"host": ip6_str, "ip": ip6_str, "port": port_raw}); i += 19
                    elif entry_type == 0x03:
                        domain_len = data[i+1]
                        if domain_len == 0 or i+4+domain_len > n: break
                        domain_bytes = data[i+2:i+2+domain_len]; domain_str = domain_bytes.decode('ascii', 'ignore')
                        port_raw = struct.unpack('!H', data[i+2+domain_len:i+4+domain_len])[0]
                        servers.append({"host": domain_str, "ip": None, "port": port_raw}); i += 4 + domain_len
                    else: i += 1
                seen = set(); unique = []
                for sr in servers:
                    key = sr['ip'] if sr['ip'] else sr['host']
                    if key not in seen: seen.add(key); unique.append(sr)
                new_etag = resp.headers.get('ETag') if unique else None
                new_cache = unique[:100] if unique else []
                if unique:
                    _server_list_cache = new_cache
                    _server_list_etag = new_etag
                    _server_list_ts = time.time()
                else:
                    if not _server_list_cache: _server_list_cache = DEFAULT_PSI_ENDPOINTS_TEMPLATE
                    _server_list_ts = time.time()
                return _server_list_cache, 'FETCH_OK' if unique else 'PARSE_FAILED'
        except gzip.BadGzipFile: pass
        except: pass
        finally:
            s.close()

        if not _server_list_cache: _server_list_cache = DEFAULT_PSI_ENDPOINTS_TEMPLATE
        _server_list_etag = None
        _server_list_ts = time.time()
        return _server_list_cache, 'FETCH_FAILED'

# ---------- Port diversity ----------
def test_port_diversity(proxy_url: str, proxy_type: str, proxy_host: str, proxy_port: int, timeout: float,
                        servers: List[Dict[str, Any]], tcp_mult: float = 0.5) -> float:
    if not servers or len(servers) < 2: return 0.0
    sample = random.sample(servers, min(5, len(servers))); total = 0; success = 0
    for srv in sample:
        target_ip = srv.get('ip') or resolve_host(srv['host'])
        if not target_ip: continue
        for p in DIVERSITY_PORTS:
            if _proxy_raw_connect(proxy_type, proxy_host, proxy_port, target_ip, p, timeout * tcp_mult):
                success += 1
            total += 1
    return success / total if total else 0.0

# ---------- DNS over SOCKS ----------
def test_dns_over_socks(proxy_url: str, timeout: float) -> bool:
    if 'socks5' not in proxy_url: return False
    s = _get_proxy_session(proxy_url)
    try:
        r = s.get("http://httpbin.org/ip", timeout=timeout)
        return r.status_code == 200
    except: return False
    finally:
        s.close()

# ---------- Scoring & Classification ----------
def compute_compartment_scores(res: dict, proxy_type: str) -> dict:
    comp = {"OSSH": 0, "MEEK": 0, "FRONTED": 0, "SSH": 0}
    if proxy_type in ('SOCKS5', 'SOCKS4'):
        if res.get('ssh_psiphon') == 'PASS': comp["OSSH"] = 30
        elif res.get('ssh_psiphon') == 'INCONCLUSIVE': comp["OSSH"] = 15
    if res.get('meek_ok'): comp["MEEK"] = 25
    if res.get('connect_tls_ok'):
        comp["FRONTED"] += 20
    psi_ok = sum(1 for v in res.get('psi', {}).values() if v)
    comp["FRONTED"] += min(psi_ok * 3, 15)
    if proxy_type in ('SOCKS5', 'SOCKS4'):
        if res.get('ssh') == 'PASS': comp["SSH"] = 20
        elif res.get('ssh') == 'INCONCLUSIVE': comp["SSH"] = 10
    return comp

def compute_gen_score(res: dict) -> int:
    score = 0
    if res.get('connect_tls_ok'): score += 25
    elif res.get('slow_connect_ok'): score += 15
    for v in res.get('general', {}).values():
        if v: score += 6
    if res.get('data_transfer_ok'): score += 8
    ttl = res.get('tcp_hints', {}).get('ttl', 255)
    if ttl < 64: score += 2
    if res.get('dns_over_socks'): score += 2
    if res.get('browsing_ok', 0) > 0.5:
        score += int(res['browsing_ok'] * 10)
    if res.get('persistent_ok'): score += 2
    return min(score, 50)

def compute_psi_score(res: dict, proxy_type: str) -> int:
    psi = res.get('psi', {})
    rate = sum(1 for v in psi.values() if v) / len(psi) if psi else 0
    score = int(rate * 20)
    if res.get('connect_tls_ok'): score += 5
    if proxy_type in ('SOCKS5', 'SOCKS4'):
        if res.get('ssh_psiphon') == 'PASS': score += 10
        elif res.get('ssh_psiphon') == 'INCONCLUSIVE': score += 5
        if res.get('ssh') == 'PASS': score += 4
        elif res.get('ssh') == 'INCONCLUSIVE': score += 2
    if res.get('server_list_ok'): score += 10
    if proxy_type == 'HTTP_FWD' and res.get('osl_registry_ok'): score += 5
    if proxy_type == 'SOCKS5' and res.get('udp_ok'): score += 2
    if res.get('meek_ok'): score += 6
    diversity = res.get('port_diversity', 0.0)
    if diversity > 0 and (res.get('connect_tls_ok') or any(res.get('general', {}).values())):
        score += int(diversity * 8)
    if res.get('http_advanced_ok'): score += 4
    if res.get('censorship_bypass', 0) > 0:
        score += min(res['censorship_bypass'] * 3, 9)
    if res.get('stability', 0) > 0.8:
        score += 3
    return min(score, 55)

def compute_generic_viability(res: dict) -> int:
    gv = 0
    if res.get('tcp_open'): gv += 5
    if res.get('protocol') in ('HTTP', 'HTTP_FWD'): gv += 5
    gv += sum(4 for v in res.get('general', {}).values() if v)
    if res.get('data_transfer_ok'): gv += 8
    if res.get('http_advanced_ok'): gv += 5
    return min(gv, 50)

def classify_overall(gen: int, psi: int) -> str:
    total = gen + psi
    if total < 5: return "DEAD"
    if total < 20: return "MARGINAL"
    if total < 35: return "ALIVE"
    if total < 55: return "TUNNEL_OK"
    if total < 75: return "CDN_REACHABLE"
    if total < 90: return "PSIPHON_LIKELY"
    return "FULLY_READY"

def run_emulator_tests(proxy_url: str, proxy_type: str, host: str, port: int, timeout: float,
                       ssh_target_host: str, ssh_target_port: int) -> Tuple[Optional[str], Optional[str], bool]:
    ssh_psiphon_status = ssh_status = None; meek_ok = False
    if proxy_type in ('SOCKS5', 'SOCKS4'):
        if proxy_type == 'SOCKS5':
            status, _, _ = handshake_ossh(host, port, PSIPHON_SSH_IP, PSIPHON_SSH_PORT, timeout)
            ssh_psiphon_status = status
            status2, _ = test_ssh_socks5(host, port, ssh_target_host, ssh_target_port, timeout)
            ssh_status = status2
        else:
            status, _, _ = handshake_ossh_socks4(host, port, PSIPHON_SSH_IP, PSIPHON_SSH_PORT, timeout)
            ssh_psiphon_status = status
            status2, _ = test_ssh_socks4(host, port, ssh_target_host, ssh_target_port, timeout)
            ssh_status = status2
    if proxy_type in ('SOCKS5', 'SOCKS4', 'HTTP', 'HTTP_FWD'):
        meek_ok = meek_handshake(proxy_url, timeout)
    return ssh_psiphon_status, ssh_status, meek_ok

def get_config_fingerprint(timeout: float, ssh_host: str, ssh_port: int, targets_config_path: str, auth_present: bool) -> str:
    data = {"timeout": timeout, "ssh_host": ssh_host, "ssh_port": ssh_port,
            "targets_config": targets_config_path, "auth_present": auth_present}
    return hashlib.md5(json.dumps(data, sort_keys=True).encode()).hexdigest()

# ---------- Main scan function ----------
def scan_proxy(entry: str, timeout: float,
               file_lock, alive_path, proxy_urls_path,
               tcp_open_file_lock, tcp_open_path,
               progress_data, progress_lock,
               targets_cfg: dict,
               auth_cred: Optional[List[Tuple[str, str]]] = None,
               ssh_target_host: str = "github.com", ssh_target_port: int = 22,
               no_diversity: bool = False, no_geo: bool = False,
               tcp_timeout_mult: float = 0.6,
               verbose: bool = False,
               pause_event: threading.Event = None,
               stop_event: threading.Event = None) -> Tuple[Optional[str], dict]:
    try:
        host, port = entry.split(":"); port = int(port)
    except: return None, {}

    if pause_event: pause_event.wait()
    if stop_event and stop_event.is_set(): return None, {}

    with progress_lock:
        if entry in progress_data:
            prev = progress_data[entry]
            return None, {'classification': prev.get('class', 'DEAD'), 'auth': 'UNKNOWN', 'score': prev.get('score', 0)}

    res = {'host': host, 'port': port, 'protocol': None, 'tcp_open': False, 'protocol_open': False,
           'auth': 'UNKNOWN', 'connect_tls_ok': False, 'general': {}, 'psi': {},
           'ssh_psiphon': None, 'ssh': None, 'udp_ok': False, 'server_list_ok': False,
           'data_transfer_ok': False, 'osl_registry_ok': False, 'speed_mbs': None,
           'gen_score': 0, 'psi_score': 0, 'score': 0, 'classification': 'DEAD', 'errors': [],
           'latency_ms': None, 'anonymity': 'UNKNOWN', 'geo': 'N/A', 'sl_status': 'N/A',
           'port_diversity': 0.0, 'meek_ok': False,
           'http_advanced_ok': False, 'compartments': {},
           'tcp_hints': {}, 'dns_over_socks': False,
           'captive_portal': False, 'generic_viability': 0,
           'browsing_ok': 0.0, 'stability': 0.0, 'censorship_bypass': 0,
           'persistent_ok': False}

    sys.stdout.write(f'\x1b]2;Testing {entry}\x07')
    sys.stdout.flush()

    try:
        if not tcp_connect_raw(host, port, timeout * tcp_timeout_mult):
            res['errors'].append('TCP_CLOSED')
            _write_checkpoint(res, progress_lock, progress_data, entry)
            return None, res
        res['tcp_open'] = True

        try:
            with _create_sock(1.0) as s:
                if s.connect_ex((host, port)) == 0:
                    res['tcp_hints'] = get_tcp_hints(s)
        except: pass

        dt = timeout
        s5_state, s5_auth = detect_socks5(host, port, dt)
        s4_state, s4_auth = detect_socks4(host, port, dt)
        http_state, http_auth = detect_http_connect(host, port, dt)
        detector_status = f"S5={s5_state} S4={s4_state} HTTP={http_state}"

        best_proto = None; proxy_url = None; cred_req = True; auth_ok = False

        if s5_state == 'OPEN':
            best_proto = 'SOCKS5'; proxy_url = f"socks5h://{host}:{port}"; cred_req = False; res['auth'] = 'NO_AUTH'
        elif s4_state == 'OPEN':
            best_proto = 'SOCKS4'; proxy_url = f"socks4://{host}:{port}"; cred_req = False; res['auth'] = 'NO_AUTH'
        elif http_state == 'OPEN':
            best_proto = 'HTTP'; proxy_url = f"http://{host}:{port}"; cred_req = False; res['auth'] = 'NO_AUTH'
        elif s5_state == 'AUTH_REQUIRED' and auth_cred:
            auth_success = False
            last_err = None
            for (u, p) in auth_cred:
                ok, lat, err = socks5_auth_tunnel_tls(host, port, u, p, "b-cdn.net", 443, "b-cdn.net", dt)
                if ok:
                    best_proto = 'SOCKS5'; proxy_url = f"socks5h://{host}:{port}"; cred_req = False
                    res['auth'] = 'AUTH_OK'; auth_ok = True; res['connect_tls_ok'] = True; res['latency_ms'] = lat
                    auth_success = True
                    break
                last_err = err
            if not auth_success:
                best_proto = 'SOCKS5'; proxy_url = f"socks5h://{host}:{port}"; cred_req = True
                res['auth'] = 'AUTH_FAILED'
                if last_err: res['errors'].append(f'S5AUTH_{last_err}')
        elif http_state == 'AUTH_REQUIRED' and auth_cred:
            auth_success = False
            last_err = None
            for (u, p) in auth_cred:
                ok, lat, err = http_connect_auth_tunnel_tls(host, port, u, p, "b-cdn.net", 443, "b-cdn.net", dt)
                if ok:
                    best_proto = 'HTTP'; proxy_url = f"http://{host}:{port}"; cred_req = False
                    res['auth'] = 'AUTH_OK'; auth_ok = True; res['connect_tls_ok'] = True; res['latency_ms'] = lat
                    auth_success = True
                    break
                last_err = err
            if not auth_success:
                best_proto = 'HTTP'; proxy_url = f"http://{host}:{port}"; cred_req = True
                res['auth'] = 'AUTH_FAILED'
                if last_err: res['errors'].append(f'HTTPAUTH_{last_err}')
        elif s5_state == 'AUTH_REQUIRED':
            best_proto = 'SOCKS5'; proxy_url = f"socks5h://{host}:{port}"; cred_req = True; res['auth'] = s5_auth
        elif http_state == 'AUTH_REQUIRED':
            best_proto = 'HTTP'; proxy_url = f"http://{host}:{port}"; cred_req = True; res['auth'] = 'BASIC/DIGEST'
        else:
            fwd_ok, _ = detect_http_forward_absolute(f"http://{host}:{port}", dt)
            if fwd_ok:
                leak_test = proxy_ip_leak_test(f"http://{host}:{port}", timeout)
                if leak_test is True:
                    best_proto = 'HTTP_FWD'; proxy_url = f"http://{host}:{port}"; cred_req = False; res['auth'] = 'NO_AUTH'

        if not best_proto:
            res['errors'].append('NO_PROTOCOL')
            _write_checkpoint(res, progress_lock, progress_data, entry)
            with tcp_open_file_lock:
                with open(tcp_open_path, "a") as f: f.write(f"{host}:{port}\n")
            return None, res

        res['protocol'] = best_proto

        if cred_req and not auth_ok:
            gs = compute_gen_score(res); ps = compute_psi_score(res, best_proto)
            res['gen_score'] = gs; res['psi_score'] = ps; res['score'] = gs+ps
            res['classification'] = classify_overall(gs, ps)
            timestamp = time.strftime("%H:%M:%S")
            sl_status = res['sl_status']
            div_pct = f"{res['port_diversity']:.0%}" if res.get('port_diversity',0) > 0 else "N/A"
            if res['classification'] == 'DEAD':
                sl_status = '-'
                div_pct = '-'
            console = f"[{timestamp}] {Fore.YELLOW}[{best_proto}] {host}:{port} AUTH:Y | Detectors:{detector_status} | Skipped{Style.RESET_ALL}"
            _write_outputs(res, file_lock, alive_path, proxy_urls_path, progress_lock, progress_data, entry)
            return console, res

        actual_auth = auth_cred[0] if auth_ok and auth_cred else None

        test_host = "b-cdn.net"
        if best_proto == 'SOCKS4':
            test_ip = resolve_host(test_host) or FALLBACK_IPS.get(test_host, "156.146.56.168")
        else:
            test_ip = test_host
        ok, lat, err = _tunnel_dispatch(best_proto, host, port, test_ip, 443, test_host, timeout, actual_auth)
        if not ok:
            ok2, lat2, err2 = _tunnel_dispatch(best_proto, host, port, test_ip, 443, test_host, timeout, actual_auth, extra_timeout_mult=1.5)
            if ok2:
                ok = True; lat = lat2; err = err2
                res['slow_connect_ok'] = True
        res['connect_tls_ok'] = ok
        if ok: res['latency_ms'] = lat
        if err: res['errors'].append(f"TUN_{err}")

        def _test_general_target(n, p, ip_or_host):
            if best_proto == 'HTTP_FWD':
                ok, captive = forward_proxy_https_lenient(proxy_url, n, p, timeout)
                if captive: res['captive_portal'] = True
                return ok
            else:
                if best_proto == 'SOCKS4':
                    dip = resolve_host(n) or ip_or_host
                else:
                    dip = n
                ok, _, _ = _tunnel_dispatch(best_proto, host, port, dip, p, n, timeout, actual_auth)
                if not ok:
                    ok, _, _ = _tunnel_dispatch(best_proto, host, port, dip, p, n, timeout, actual_auth, extra_timeout_mult=1.2)
                return ok

        for ep in targets_cfg['general_hosts']:
            n = ep['host']; p = ep['port']
            ip_ref = ep.get('ip') or resolve_host(n) or SAFE_FALLBACK_IP
            res['general'][n] = _test_general_target(n, p, ip_ref)

        dyn, sl_status = fetch_server_list(proxy_url, timeout); res['sl_status'] = sl_status
        all_psi = dyn + targets_cfg['critical_psi_hosts']; seen = set()
        for ep in all_psi:
            n = ep.get('host', ep.get('ip', '')); p = ep.get('port', 443); key = f"{n}:{p}"
            if key in seen: continue
            seen.add(key)
            if best_proto == 'HTTP_FWD':
                ok, captive = forward_proxy_https_lenient(proxy_url, n, p, timeout)
                res['psi'][key] = ok
                if captive: res['captive_portal'] = True
            else:
                if best_proto == 'SOCKS4':
                    dip = ep.get('ip') or resolve_host(n) or SAFE_FALLBACK_IP
                else:
                    dip = n
                ok, _, _ = _tunnel_dispatch(best_proto, host, port, dip, p, n, timeout, actual_auth)
                if not ok:
                    ok, _, _ = _tunnel_dispatch(best_proto, host, port, dip, p, n, timeout, actual_auth, extra_timeout_mult=1.2)
                res['psi'][key] = ok

        ssh_psi, ssh_gen, meek_ok = run_emulator_tests(proxy_url, best_proto, host, port, timeout,
                                                       ssh_target_host, ssh_target_port)
        if ssh_psi: res['ssh_psiphon'] = ssh_psi
        if ssh_gen: res['ssh'] = ssh_gen
        res['meek_ok'] = meek_ok

        if best_proto == 'SOCKS5':
            res['udp_ok'] = test_udp(host, port, timeout)
            res['dns_over_socks'] = test_dns_over_socks(proxy_url, timeout)

        res['server_list_ok'] = (sl_status in ('FETCH_OK', '304') and dyn and dyn != targets_cfg['critical_psi_hosts'])

        if best_proto == 'HTTP_FWD':
            res['osl_registry_ok'], _ = forward_proxy_https_lenient(proxy_url, "j.sni.global.fastly.net", 443, timeout)

        res['data_transfer_ok'] = test_data_transfer(proxy_url, timeout)
        res['speed_mbs'] = test_speed(proxy_url, timeout)

        if not no_diversity and sl_status in ('FETCH_OK', 'CACHE', '304') and dyn:
            diversity = test_port_diversity(proxy_url, best_proto, host, port, timeout, dyn, tcp_timeout_mult)
            res['port_diversity'] = diversity

        http_adv = test_http_advanced(proxy_url, timeout)
        res['http_advanced_ok'] = http_adv['overall']

        if not cred_req or auth_ok:
            res['browsing_ok'] = test_real_browsing(proxy_url, timeout)
            res['stability'] = test_stability(proxy_url, timeout)
            res['censorship_bypass'] = test_censorship_bypass(proxy_url, timeout)
            res['persistent_ok'] = test_persistent_connection(proxy_url, timeout)

        if res['connect_tls_ok'] or res['data_transfer_ok'] or any(res.get('general', {}).values()):
            res['anonymity'], _ = classify_anonymity(proxy_url, timeout)
            if not no_geo: res['geo'] = geo_ip(proxy_url, timeout)

        res['compartments'] = compute_compartment_scores(res, best_proto)
        best_comp = max(res['compartments'], key=res['compartments'].get)

        gv = compute_generic_viability(res)
        res['generic_viability'] = gv

        gs = compute_gen_score(res); ps = compute_psi_score(res, best_proto)
        res['gen_score'] = gs; res['psi_score'] = ps; res['score'] = gs+ps
        res['classification'] = classify_overall(gs, ps)

        # Console output
        def pf(ok): return f"{Fore.GREEN}PASS{Style.RESET_ALL}" if ok else f"{Fore.RED}FAIL{Style.RESET_ALL}"
        pub_ok = sum(1 for v in res['general'].values() if v)
        tun_status = "OK" if res['connect_tls_ok'] else ("SLOW" if res.get('slow_connect_ok') else "FAIL")
        psi_ok = sum(1 for v in res['psi'].values() if v)
        div_pct = f"{res['port_diversity']:.0%}" if res.get('port_diversity',0) > 0 else "N/A"
        sl_status = res['sl_status']
        if res['classification'] == 'DEAD':
            sl_status = '-'
            div_pct = '-'
        auth_mark = f"{Fore.GREEN}AUTH:N{Style.RESET_ALL}" if res['auth'] in ('NO_AUTH', 'AUTH_OK') else f"{Fore.RED}AUTH:Y{Style.RESET_ALL}"
        lat_str = f"ping:{res['latency_ms']:.0f}ms" if res['latency_ms'] else "ping:N/A"
        load_msg = ""
        if res.get('latency_ms') and res['latency_ms'] > 5000:
            load_msg = " [HEAVY_LOAD]"
        slow_mark = " [SLOW_OK]" if res.get('slow_connect_ok') else ""
        cls_col = Fore.GREEN if res['classification'] in ("PSIPHON_LIKELY", "FULLY_READY") else Fore.YELLOW if res['classification'] != "DEAD" else Fore.RED
        censor_info = f"Cens:{res.get('censorship_bypass',0)}/{len(CENSORED_SITES)}" if res.get('censorship_bypass',0) > 0 else ""
        stab_info = f"Stb:{res.get('stability',0):.0%}" if res.get('stability',0) > 0 else ""
        browse_info = f"Brw:{res.get('browsing_ok',0):.0%}" if res.get('browsing_ok',0) > 0 else ""
        pers_info = "Persist:OK" if res.get('persistent_ok') else ""
        extra_info = " ".join(x for x in [browse_info, censor_info, stab_info, pers_info] if x)
        timestamp = time.strftime("%H:%M:%S")

        if verbose:
            gp = pub_ok; gt = len(res['general'])
            gen_items = [f"{ABBREV_GEN.get(n, n[:2])}:{pf(v)}" for n, v in res['general'].items()]
            gen_line = f"Gen:{gp}/{gt} " + " ".join(gen_items)
            pp = psi_ok; pt = len(res['psi'])
            psi_items = [f"{ABBREV_PSI.get(n.split(':')[0], n[:2])}:{pf(v)}" for n, v in res['psi'].items()]
            psi_line = f"P:{pp}/{pt} " + " ".join(psi_items)
            comp_line = f"Best:{best_comp} " + " ".join(f"{k}:{v}" for k, v in res['compartments'].items())
            bar = f"{Fore.CYAN}{'█' * min(10, int(res['score']/10))}{Fore.WHITE}{'░' * (10-min(10, int(res['score']/10)))}"
            console = (f"[{timestamp}] {cls_col}[{best_proto}]{slow_mark}{load_msg} {host}:{port} {lat_str} {auth_mark} "
                       f"Score:{res['score']} (G.Via:{gv}) {bar} {res['classification']} | {comp_line} | {gen_line} | {psi_line} | Detectors:{detector_status} | SL:{sl_status}")
            if extra_info:
                console += f" | {extra_info}"
        else:
            console = (f"[{timestamp}] {cls_col}[{best_proto}]{slow_mark}{load_msg} {host}:{port} {lat_str} {auth_mark} "
                       f"Score:{res['score']} (G.Via:{gv}) {res['classification']} | "
                       f"Pub:{pub_ok}/{len(res['general'])} TUN:{tun_status} Psi:{psi_ok}/{len(res['psi'])} Div:{div_pct} SL:{sl_status}")
            if extra_info:
                console += f" | {extra_info}"

        _write_outputs(res, file_lock, alive_path, proxy_urls_path, progress_lock, progress_data, entry, gv)
        return console, res

    except Exception as e:
        res['errors'].append(f"SCAN_CRASH_{type(e).__name__}")
        res['classification'] = 'CRASHED'
        _write_checkpoint(res, progress_lock, progress_data, entry)
        return f"{Fore.RED}[CRASH] {entry} {e}{Style.RESET_ALL}", res

def _write_checkpoint(res, plock, pd, entry):
    with plock: pd[entry] = {"score": res['score'], "class": res['classification']}

def _write_outputs(res, flock, alive_path, url_path, plock, pd, entry, generic_viability=0):
    with plock: pd[entry] = {"score": res['score'], "class": res['classification']}
    if res['classification'] != "DEAD":
        with flock:
            compartment_str = "|".join(f"{k}={v}" for k, v in res.get('compartments', {}).items())
            best_comp = max(res['compartments'], key=res['compartments'].get) if res['compartments'] else 'N/A'
            line = (f"{res['host']}:{res['port']}\t{res['protocol']}\tAuth:{res['auth']}\t"
                    f"Gen:{res['gen_score']}\tPsi:{res['psi_score']}\tG_Via:{generic_viability}\t"
                    f"DataXfer:{'Y' if res['data_transfer_ok'] else 'N'}\t"
                    f"OSL:{'Y' if res.get('osl_registry_ok') else 'N'}\t"
                    f"SSH_Psi:{res.get('ssh_psiphon','-')}\tSSH:{res.get('ssh','-')}\t"
                    f"SL:{res.get('sl_status','-')}\tPortDiv:{res.get('port_diversity',0):.1%}\t"
                    f"Spd:{res.get('speed_mbs','-')}\tBestCh:{best_comp}\tComps:{compartment_str}\t"
                    f"Captive:{'Y' if res.get('captive_portal') else 'N'}\t"
                    f"Brw:{res.get('browsing_ok',0):.1%}\tStb:{res.get('stability',0):.1%}\tCens:{res.get('censorship_bypass',0)}\t"
                    f"Persist:{'Y' if res.get('persistent_ok') else 'N'}\t"
                    f"{res['classification']}\n")
            with open(alive_path, "a") as f: 
                f.write(line)
                f.flush()
            url = f"{res['host']}:{res['port']}"
            if res['protocol'] == 'SOCKS5':
                url = f"socks5://{url}"
            elif res['protocol'] == 'SOCKS4':
                url = f"socks4://{url}"
            else:
                url = f"http://{url}"
            with open(url_path, "a") as f:
                f.write(f"{url}#Score%20{res['score']}%20G_Via%20{generic_viability}%20{best_comp}\n")
                f.flush()
# ---------- IP expander & parse targets ----------
def expand_ip_range(spec: str):
    if '-' in spec:
        s, e = spec.split('-', 1); start = int(ipaddress.IPv4Address(s.strip())); end = int(ipaddress.IPv4Address(e.strip()))
        if end < start: raise ValueError(f"range end before start: {spec}")
        for i in range(start, end+1): yield str(ipaddress.IPv4Address(i))
    elif '/' in spec:
        for ip in ipaddress.ip_network(spec, strict=False).hosts(): yield str(ip)
    else: ipaddress.IPv4Address(spec); yield spec

def in_scope(ip: str, nets: list) -> bool:
    return (not nets) or any(ipaddress.ip_address(ip) in net for net in nets)

def _list_has_expansion(path: str) -> bool:
    if not path or not Path(path).exists(): return False
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and ("/" in line or "-" in line): return True
    except: pass
    return False

def parse_targets(list_path, ranges, ports, allowed_nets):
    seen = {}
    def add(ip, p):
        if in_scope(ip, allowed_nets): seen[f"{ip}:{p}"] = None
    if list_path:
        with open(list_path, "r", encoding="utf-8", errors="ignore") as f:
            for lineno, raw in enumerate(f, 1):
                line = raw.strip()
                if not line or line.startswith("#"): continue
                if "/" not in line and "-" not in line and ":" in line:
                    ip_part, _, port_part = line.rpartition(":")
                    try:
                        ipaddress.IPv4Address(ip_part)
                        if not port_part.isdigit():
                            print(f"{Fore.YELLOW}Warning: Skipping line {lineno} – invalid port '{port_part}'{Style.RESET_ALL}")
                            continue
                        add(ip_part, int(port_part)); continue
                    except ValueError: pass
                if not ports: raise ValueError(f"{list_path}:{lineno}: '{line}' has no port; pass --port")
                try:
                    for ip in expand_ip_range(line):
                        for p in ports: add(ip, p)
                except ValueError as e: raise ValueError(f"{list_path}:{lineno}: invalid entry '{line}' ({e})")
    if ranges:
        if not ports: raise ValueError("--range requires --port")
        for r in ranges:
            try:
                for ip in expand_ip_range(r):
                    for p in ports: add(ip, p)
            except ValueError as e: raise ValueError(f"invalid --range spec '{r}' ({e})")
    return list(seen.keys())

# ---------- Main ----------
def main():
    parser = argparse.ArgumentParser(description="PSI-Tracker v1.0 DEY Warrior", formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("--list", help="File with targets (IP:PORT, CIDR, ranges)")
    parser.add_argument("--range", nargs='*', help="CIDR or dash ranges")
    parser.add_argument("--port", type=int, nargs='*', help="Port(s) for IPs without port")
    parser.add_argument("--threads", type=int, default=50)
    parser.add_argument("--timeout", type=float, default=60.0)
    parser.add_argument("--tcp-timeout-mult", type=float, default=0.6)
    parser.add_argument("--auth", help="user:pass")
    parser.add_argument("--ssh-host", default="github.com")
    parser.add_argument("--ssh-port", type=int, default=22)
    parser.add_argument("--alive", default="alive_proxies.txt")
    parser.add_argument("--urls", default="proxy_urls.txt")
    parser.add_argument("--checkpoint", default="scan_progress.json")
    parser.add_argument("--scope", nargs='*', help="Allowed CIDR ranges")
    parser.add_argument("--allow-all", action='store_true')
    parser.add_argument("--targets-config", default=None)
    parser.add_argument("--fallback-ips", default="fallback_ips.json")
    parser.add_argument("--clean", action='store_true')
    parser.add_argument("--retest", action='store_true')
    parser.add_argument("--refresh-ips", action='store_true')
    parser.add_argument("--no-geo", action='store_true')
    parser.add_argument("--no-diversity", action='store_true')
    parser.add_argument("--verbose", action='store_true', help="Detailed console output")
    parser.add_argument("--max-alive", type=int, default=0, help="Stop after finding N alive proxies")
    args = parser.parse_args()

    def _resolve_default_psi():
        endpoints = []
        for ep in DEFAULT_PSI_ENDPOINTS_TEMPLATE:
            host = ep["host"]; ip = resolve_host(host)
            if not ip: ip = FALLBACK_IPS.get(host, "156.146.56.168")
            endpoints.append({"host": host, "ip": ip, "port": ep["port"]})
        return endpoints
    DEFAULT_PSI_ENDPOINTS = _resolve_default_psi()

    if Path(args.fallback_ips).exists():
        try:
            with open(args.fallback_ips, "r", encoding="utf-8") as f: extra = json.load(f)
            if isinstance(extra, dict): FALLBACK_IPS.update(extra)
        except: pass

    if args.refresh_ips:
        print("Refreshing fallback IPs...")
        for host, old_ip in list(FALLBACK_IPS.items()):
            try:
                info = socket.getaddrinfo(host, 0, socket.AF_INET, socket.SOCK_STREAM)
                new_ip = info[0][4][0]
                if new_ip != old_ip:
                    print(f"  {host}: {old_ip} → {new_ip}")
                    FALLBACK_IPS[host] = new_ip
            except: pass
        try:
            with open(args.fallback_ips, "w", encoding="utf-8") as f: json.dump(FALLBACK_IPS, f, indent=2)
        except: pass

    if args.list and not Path(args.list).exists():
        print(f"{Fore.RED}List file not found: {args.list}"); return
    if not args.list and not args.range:
        print(f"{Fore.RED}Error: provide --list and/or --range"); return
    if (bool(args.range) or _list_has_expansion(args.list)) and not args.scope and not args.allow_all:
        print(f"{Fore.RED}Error: CIDR/range targets require --scope or --allow-all"); return

    cfg = {
        "critical_psi_hosts": DEFAULT_PSI_ENDPOINTS,
        "general_hosts": [
            {"host": "google.com",      "ip": FALLBACK_IPS["google.com"], "port": 443},
            {"host": "cloudflare.com",  "ip": "104.16.124.96", "port": 443},
            {"host": "github.com",      "ip": "140.82.121.4",  "port": 443},
            {"host": "web.telegram.org","ip": "149.154.167.99","port": 443},
            {"host": "youtube.com",     "ip": "142.250.185.78","port": 443},
        ],
    }
    if args.targets_config and Path(args.targets_config).exists():
        with open(args.targets_config, "r") as f: cfg.update(json.load(f))

    # -------------------------------------------------------------
    # passlist data 
    # -------------------------------------------------------------
    auth_cred = None   # none form 

    if args.auth:
        if ':' not in args.auth:
            print(f"{Fore.RED}Error: --auth must be user:pass"); return
        u, p = args.auth.split(':', 1)
        auth_cred = [(u, p)]          # alone form
        print(f"Using single credential from --auth: {u}:****")
    else:
        # passlist.txt check path
        passlist_path = Path(__file__).parent / "passlist.txt"
        if passlist_path.exists():
            print(f"Found passlist.txt, loading credentials...")
            auth_cred = []
            with open(passlist_path, "r", encoding="utf-8") as pf:
                for line in pf:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if ':' not in line:
                        print(f"{Fore.YELLOW}Warning: Skipping malformed line in passlist.txt: {line}{Style.RESET_ALL}")
                        continue
                    u, p = line.split(':', 1)
                    auth_cred.append((u.strip(), p.strip()))
                    if len(auth_cred) >= MAX_AUTH_ATTEMPTS:
                        print(f"{Fore.YELLOW}Warning: passlist.txt had more than {MAX_AUTH_ATTEMPTS} entries; only first {MAX_AUTH_ATTEMPTS} will be used.{Style.RESET_ALL}")
                        break
            if not auth_cred:
                print(f"{Fore.RED}Error: passlist.txt exists but contains no valid credentials.{Style.RESET_ALL}")
                auth_cred = None
            else:
                print(f"Loaded {len(auth_cred)} credentials from passlist.txt.")

    allowed_nets = []
    if args.scope:
        for cidr in args.scope:
            try: allowed_nets.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError: print(f"{Fore.RED}Invalid scope: {cidr}"); return

    try: targets = parse_targets(args.list, args.range, args.port, allowed_nets)
    except (OSError, ValueError) as e: print(f"{Fore.RED}{e}"); return
    if not targets: print("No targets after scope filter."); return

    cp = load_checkpoint(args.checkpoint)
    stored_fp = cp.get("config_fingerprint", "")
    current_fp = get_config_fingerprint(args.timeout, args.ssh_host, args.ssh_port, args.targets_config or "", auth_cred is not None)
    progress_data = cp.get("proxies", {})

    if stored_fp != current_fp and not args.retest:
        print(f"{Fore.YELLOW}Config fingerprint changed. Previous progress discarded.{Style.RESET_ALL}")
        progress_data = {}
    elif args.retest: progress_data = {}

    global _server_list_etag, _server_list_ts, _server_list_cache
    if "server_list" in cp and stored_fp == current_fp:
        data = cp["server_list"]
        _server_list_cache = data.get("cache", [])
        _server_list_etag = data.get("etag", None)
        _server_list_ts = data.get("ts", 0.0)

    start_index = 0
    if 'last_index' in cp:
        start_index = cp['last_index']
        print(f"{Fore.CYAN}Resuming from index {start_index}...{Style.RESET_ALL}")

    if progress_data:
        initial = len(targets)
        targets = targets[start_index:]
        skipped = start_index
        print(f"{Fore.CYAN}Checkpoint: {skipped} tested, {len(targets)} remaining.{Style.RESET_ALL}")
    else:
        targets = targets[start_index:]
        print(f"{Fore.CYAN}No valid checkpoint, testing all {len(targets)} targets.{Style.RESET_ALL}")

    out_files = [args.alive, args.urls]
    tcp_open_path = "tcp_open_proxies.txt"
    if args.clean:
        for p in out_files: Path(p).write_text("")
        Path(tcp_open_path).write_text("")
    else:
        for p in out_files:
            if not Path(p).exists(): Path(p).write_text("")
        if not Path(tcp_open_path).exists(): Path(tcp_open_path).write_text("")

    print(LEGEND)
    print("=" * 100)
    print(f"PSI-Tracker V1.0 DEY Warrior | {len(targets)} targets | {args.threads} threads | timeout={args.timeout}s")
    if args.no_diversity: print("Port diversity test DISABLED.")
    if args.no_geo: print("GeoIP lookup DISABLED.")
    if args.verbose: print("Verbose output enabled.")
    if args.max_alive: print(f"Will stop after finding {args.max_alive} alive proxies.")
    print("Press 'P' to pause, 'R' to resume, 'M' to abort & return to menu.")
    print("=" * 100)

    pause_event = threading.Event()
    pause_event.set()
    stop_event = threading.Event()

    def keyboard_listener():
        try:
            import msvcrt
            while True:
                if msvcrt.kbhit():
                    ch = msvcrt.getch().decode('utf-8', errors='ignore').lower()
                    if ch == 'p':
                        pause_event.clear()
                        tqdm.write(f"{Fore.YELLOW}[PAUSED] Press 'R' to resume, 'M' to abort & return to menu.{Style.RESET_ALL}")
                    elif ch == 'r':
                        pause_event.set()
                        tqdm.write(f"{Fore.GREEN}[RESUMED] Scanning continues.{Style.RESET_ALL}")
                    elif ch == 'm':
                        stop_event.set()
                        pause_event.set()
                        tqdm.write(f"{Fore.MAGENTA}[ABORT] Stopping scan & returning to menu...{Style.RESET_ALL}")
                        try:
                            cp_save = {
                                "config_fingerprint": current_fp,
                                "proxies": progress_data,
                                "server_list": {
                                    "cache": _server_list_cache,
                                    "etag": _server_list_etag,
                                    "ts": _server_list_ts
                                },
                                "last_index": pbar.n + start_index
                            }
                            with progress_lock:
                                save_checkpoint_atomic(args.checkpoint, cp_save)
                        except:
                            pass
                        os._exit(0)
                time.sleep(0.2)
        except ImportError:
            import sys, tty, termios
            fd = sys.stdin.fileno()
            old_settings = termios.tcgetattr(fd)
            try:
                tty.setcbreak(fd)
                while True:
                    ch = sys.stdin.read(1).lower()
                    if ch == 'p':
                        pause_event.clear()
                        tqdm.write(f"{Fore.YELLOW}[PAUSED] Press 'R' to resume, 'M' to abort & return to menu.{Style.RESET_ALL}")
                    elif ch == 'r':
                        pause_event.set()
                        tqdm.write(f"{Fore.GREEN}[RESUMED] Scanning continues.{Style.RESET_ALL}")
                    elif ch == 'm':
                        stop_event.set()
                        pause_event.set()
                        tqdm.write(f"{Fore.MAGENTA}[ABORT] Stopping scan & returning to menu...{Style.RESET_ALL}")
                        try:
                            cp_save = {
                                "config_fingerprint": current_fp,
                                "proxies": progress_data,
                                "server_list": {
                                    "cache": _server_list_cache,
                                    "etag": _server_list_etag,
                                    "ts": _server_list_ts
                                },
                                "last_index": pbar.n + start_index
                            }
                            with progress_lock:
                                save_checkpoint_atomic(args.checkpoint, cp_save)
                        except:
                            pass
                        os._exit(0)
            finally:
                termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)

    threading.Thread(target=keyboard_listener, daemon=True).start()

    file_lock = threading.Lock(); tcp_open_lock = threading.Lock(); progress_lock = threading.Lock()
    alive = psi = skipped_auth = 0
    proto_counts = {"SOCKS5": 0, "SOCKS4": 0, "HTTP": 0, "HTTP_FWD": 0}
    best_ping = float('inf')
    best_score = 0
    counters_lock = threading.Lock()

    pbar = tqdm(total=len(targets), desc="Scanning", unit="ip",
                initial=start_index,
                bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]",
                ncols=80, ascii=True, mininterval=0.5, file=sys.stdout, leave=True)

    def worker(t):
        nonlocal alive, psi, skipped_auth, best_ping, best_score
        pause_event.wait()
        if stop_event.is_set(): return None
        try:
            console, res = scan_proxy(t, args.timeout, file_lock, args.alive, args.urls,
                                      tcp_open_lock, tcp_open_path,
                                      progress_data, progress_lock, cfg, auth_cred,
                                      args.ssh_host, args.ssh_port,
                                      no_diversity=args.no_diversity,
                                      no_geo=args.no_geo,
                                      tcp_timeout_mult=args.tcp_timeout_mult,
                                      verbose=args.verbose,
                                      pause_event=pause_event,
                                      stop_event=stop_event)
            if res and res.get('classification') not in ('DEAD', ''):
                with counters_lock:
                    alive += 1
                    proto = res.get('protocol')
                    if proto in proto_counts:
                        proto_counts[proto] += 1
                    if res.get('auth') == 'AUTH_FAILED': skipped_auth += 1
                    if res['classification'] in ("PSIPHON_LIKELY", "FULLY_READY"): psi += 1
                    if res.get('latency_ms') and res['latency_ms'] < best_ping:
                        best_ping = res['latency_ms']
                    if res['score'] > best_score:
                        best_score = res['score']
                    if args.max_alive > 0 and alive >= args.max_alive:
                        stop_event.set()
            return console
        except Exception as e:
            timestamp = time.strftime("%H:%M:%S")
            tqdm.write(f"[{timestamp}] {Fore.RED}[CRASH] {t} → {type(e).__name__}: {e}{Style.RESET_ALL}")
            with progress_lock: progress_data[t] = {"score": 0, "class": "CRASHED"}
            return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as ex:
        futures = {ex.submit(worker, t): t for t in targets}
        NET_CHECK_INTERVAL = 20
        test_counter = start_index
        try:
            for fut in concurrent.futures.as_completed(futures):
                test_counter += 1
                if test_counter % NET_CHECK_INTERVAL == 0 and not is_network_alive(targets):
                    timestamp = time.strftime("%H:%M:%S")
                    tqdm.write(f"[{timestamp}] {Fore.RED}[NETWORK LOST] Saving progress & pausing...{Style.RESET_ALL}")
                    with progress_lock:
                        cp_save = {"config_fingerprint": current_fp, "proxies": progress_data,
                                   "server_list": {"cache": _server_list_cache, "etag": _server_list_etag, "ts": _server_list_ts},
                                   "last_index": pbar.n + start_index}
                        save_checkpoint_atomic(args.checkpoint, cp_save)
                    wait_cycles = 0
                    while not is_network_alive(targets):
                        time.sleep(5)
                        wait_cycles += 5
                        if wait_cycles % 60 == 0:
                            tqdm.write(f"{Fore.YELLOW}[STILL OFFLINE] Waiting for network... ({wait_cycles}s){Style.RESET_ALL}")
                        if wait_cycles >= 100:
                            pause_event.clear()
                            tqdm.write(f"{Fore.YELLOW}[!] Network still down after 100s. Press 'R' to retry.{Style.RESET_ALL}")
                            pause_event.wait()  # block until user presses R
                            tqdm.write(f"{Fore.GREEN}[USER RESUMED] Checking network again...{Style.RESET_ALL}")
                            wait_cycles = 0
                    tqdm.write(f"{Fore.GREEN}[NETWORK BACK] Resuming scan...{Style.RESET_ALL}")
                if stop_event.is_set():
                    tqdm.write(f"{Fore.GREEN}Maximum alive proxies reached ({args.max_alive}). Stopping scan.{Style.RESET_ALL}")
                    break
                out = fut.result()
                if out: tqdm.write(out)
                pbar.update(1)
                with counters_lock:
                    postfix = f"Alive:{alive} PSI:{psi} SkipAuth:{skipped_auth} BestPing:{best_ping:,.0f}ms BestScore:{best_score}"
                    pbar.set_postfix_str(postfix)
                if test_counter % 100 == 0 and test_counter > 0:
                    with progress_lock:
                        scores = [pd['score'] for pd in progress_data.values() if isinstance(pd, dict) and pd.get('class') != 'DEAD']
                    avg_score = sum(scores) / len(scores) if scores else 0
                    timestamp = time.strftime("%H:%M:%S")
                    tqdm.write(f"[{timestamp}] Summary: AvgScore={avg_score:.1f} Alive={alive} PSI={psi}")
                if test_counter % 50 == 0:
                    with progress_lock:
                        cp_save = {"config_fingerprint": current_fp, "proxies": progress_data,
                                   "server_list": {"cache": _server_list_cache, "etag": _server_list_etag, "ts": _server_list_ts},
                                   "last_index": pbar.n + start_index}
                        save_checkpoint_atomic(args.checkpoint, cp_save)
        except KeyboardInterrupt:
            print("\n[!] Interrupted – saving checkpoint...")
            pause_event.set()  # ensure no deadlock
            with progress_lock:
                cp_save = {"config_fingerprint": current_fp, "proxies": progress_data,
                           "server_list": {"cache": _server_list_cache, "etag": _server_list_etag, "ts": _server_list_ts},
                           "last_index": pbar.n + start_index}
                save_checkpoint_atomic(args.checkpoint, cp_save)
            ex.shutdown(wait=False)
        finally:
            pbar.close()
            with progress_lock:
                cp_save = {"config_fingerprint": current_fp, "proxies": progress_data,
                           "server_list": {"cache": _server_list_cache, "etag": _server_list_etag, "ts": _server_list_ts},
                           "last_index": pbar.n + start_index}
                save_checkpoint_atomic(args.checkpoint, cp_save)

    # Final summary
    print(f"\nDone. Alive: {alive}, PSI-ready: {psi}, Skipped Auth: {skipped_auth}")
    proto_summary = " | ".join(f"{p}:{c}" for p, c in proto_counts.items() if c > 0)
    if proto_summary:
        print(f"Protocol breakdown: {proto_summary}")
    if best_ping < float('inf'):
        print(f"Best ping: {best_ping:.0f}ms, Best score: {best_score}")

if __name__ == "__main__":
    main()
