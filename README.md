# Psiphon Tracker V 1.0 “DEY Warrior”  
**Unbreakable Proxy Scanner for Censored Networks**  
*Built to win the war against censorship – dedicated to the immortal names of Iran Land, Dey 1404.*

[![Python 3.7+](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

---

## 🔬 What is PSI‑Tracker “DEY Warrior”?

PSI‑Tracker is a **multi‑stage, thread‑parallel proxy scanner** designed for **high‑latency, heavily censored environments** (like Iran).  
Every single test is performed **through the proxy itself** – the scanner **never** uses its own internet connection to judge a proxy’s health.  
This means it works perfectly even when DNS, ICMP, and all foreign websites are blocked.

The scanner accurately **emulates Psiphon’s real connection protocols** (OSSH seed exchange, Meek, Fronted TLS) based on reverse engineering.  
Each proxy receives a **fair, multi‑axis score** (Gen, PSI, Generic Viability) and is classified from **DEAD** to **FULLY_READY**.

> **Dedication**: This tool is proudly dedicated to the immortal names of Iran Land – Dey 1404.

---

## ✨ Key Features

- **Full RFC 1928 SOCKS5** – IPv4, IPv6, domain name support, proper BND.ADDR handling
- **Psiphon Emulation** – Real OSSH seed exchange (anti‑echo), Meek POST with obfuscated headers, Fronted TLS to real CDNs
- **True UDP Test** – SOCKS5 UDP relay, full IPv4/IPv6 support, crash‑safe
- **Accurate Server List Parser** – Binary compressed list parser (IPv4, IPv6, DOMAIN entries) with safe bounds
- **Context‑Aware Checkpoint** – Resume scans exactly from the last tested proxy; config fingerprint prevents stale data
- **Port Diversity Test** – Tests multiple ports **through the proxy**, never directly
- **Two‑Phase Network Watchdog** – Hardcoded IPs first, then samples your own proxies; auto‑pause only when both phases fail
- **Manual Pause/Resume** – Press `P` to pause, `R` to resume anytime (no input blocking)
- **`--max-alive`** – Auto‑stop after finding a set number of alive proxies
- **Fair Multi‑Axis Scoring** – General Score (everyday use), PSI Score (Psiphon compatibility), Generic Viability (non‑Psiphon tools)
- **Real‑World Tests** – Real browsing, censorship bypass (Telegram, Twitter, Facebook), stability, persistent connection
- **Advanced HTTP Validation** – POST/PUT/DELETE echo, Cookie & Referrer transport, Gzip compression
- **Multi‑Judge Anonymity** – 5 judges classify proxies as ELITE / ANONYMOUS / TRANSPARENT (conservative)
- **DNS‑over‑SOCKS Detection** – Confirms the proxy handles DNS internally
- **Captive Portal Detection** – Identifies login walls
- **Multi‑pass Retry** – Slow proxies get an automatic second chance and are labelled `SLOW_OK`
- **Compact & Verbose Modes** – Default compact; `--verbose` shows every endpoint test result
- **Production‑Hardened** – All sockets & sessions properly closed, caches expire after 5 min, atomic file writes, thread‑safe

---

## 📦 Installation

### Requirements
- **Python 3.7** or newer
- `tqdm`, `colorama`, `requests`, `PySocks`

```bash
git clone https://github.com/SulgX/PSI_Tracker.git
cd PSI_Tracker
pip install -r requirements.txt
```

`requirements.txt` content:

```
tqdm>=4.64.0
colorama>=0.4.6
requests>=2.28.0
PySocks>=1.7.1
```

Note: Without PySocks, raw‑socket SOCKS tests still work, but some high‑level features (Meek over SOCKS) are limited.

---

## 🚀 Quick Start with the Launcher (Windows)

A professional Windows batch launcher (`launcher.bat`) is included to manage all settings and run scans in the same window (so P/R keys work).

How to use:

1. Double‑click `launcher.bat`.
2. Press `[1]` to set your proxy list file (e.g., `my_ips.txt`).
3. Choose a scan mode:
   - **Q** – Quick Scan (20 threads, 30s timeout, `--no-geo --no-diversity`)
   - **D** – Deep Scan (50 threads, 90s timeout, `--verbose`)
   - **F** – Full Scan (50 threads, 120s timeout, `--verbose`)
   - **C** – Custom Scan (uses manually configured settings)
4. Press `Y` to start.
5. During scan: press `P` to pause, `R` to resume.

The launcher saves your settings in `launcher_settings.ini` for next time.

---

## ⚙️ Manual Command Line Usage

All arguments can be used directly with `python psi_tracker.py` (the script is the same file provided).

### Basic scan
```bash
python psi_tracker.py --list proxies.txt --alive alive.txt --urls urls.txt
```

### CIDR range with multiple ports
```bash
python psi_tracker.py --range 192.168.1.0/24 --port 1080 8080 --scope 192.168.0.0/16
```

### Authentication
```bash
python psi_tracker.py --list auth_proxies.txt --auth admin:123456 --timeout 45
```

### Resume previous scan
Progress is saved in `scan_progress.json`. Just run again with the same `--list` or `--range` – it will automatically resume.

```bash
python psi_tracker.py --list proxies.txt
```

### Fast scan (no GeoIP, no diversity)
```bash
python psi_tracker.py --list proxies.txt --no-diversity --no-geo
```

### Stop after finding 20 alive proxies
```bash
python psi_tracker.py --list proxies.txt --max-alive 20
```

### Refresh fallback IPs only (no scan)
```bash
python psi_tracker.py --refresh-ips
```

---

## 📋 Full Command‑Line Arguments

| Argument | Description |
|----------|-------------|
| `--list FILE` | Target file (IP:PORT, CIDR, dash ranges) |
| `--range RANGE [RANGE ...]` | CIDR or dash ranges (requires `--port`) |
| `--port PORT [PORT ...]` | Port(s) for IPs without port |
| `--threads N` | Number of threads (default: 50) |
| `--timeout SECONDS` | Per‑proxy timeout (default: 60) |
| `--tcp-timeout-mult X` | TCP connect multiplier (default: 0.6) |
| `--auth USER:PASS` | Credentials for proxies that require authentication |
| `--ssh-host HOST` | SSH target host (default: github.com) |
| `--ssh-port PORT` | SSH target port (default: 22) |
| `--alive FILE` | Output file for alive proxies with full details |
| `--urls FILE` | Output file for proxy URLs |
| `--checkpoint FILE` | Progress checkpoint file (default: scan_progress.json) |
| `--scope CIDR [CIDR ...]` | Restrict range expansion to these CIDRs |
| `--allow-all` | Bypass the `--scope` requirement |
| `--targets-config JSON` | Custom test targets JSON config |
| `--fallback-ips JSON` | Additional fallback IPs JSON file |
| `--clean` | Clear output files before starting |
| `--retest` | Ignore existing checkpoint and re‑test all |
| `--refresh-ips` | Re‑resolve known hosts and update the fallback IPs file |
| `--no-geo` | Disable GeoIP lookup |
| `--no-diversity` | Skip port diversity test |
| `--verbose` | Detailed console output (shows every endpoint test) |
| `--max-alive N` | Stop scanning after finding N alive proxies |

---

## 📈 Scoring System

Every proxy receives three scores that reflect its real‑world usability.

### 1. General Score (Gen, max 50)
Measures everyday proxy performance:

- TLS tunnel success to b-cdn.net: **+25**
- Slow TLS success (after retry): **+15**
- Each reachable public endpoint (Google, Cloudflare, GitHub, Telegram Web, YouTube): **+6**
- Successful 1 KB data transfer: **+8**
- TCP hints (TTL < 64): **+2**
- DNS over SOCKS: **+2**
- Real browsing success (>50%): up to **+10**
- Persistent connection (5 sequential requests): **+2**

### 2. PSI Score (Psiphon compatibility, max 55)
Measures Psiphon‑specific compatibility:

- Psiphon server list reachability: up to **30**
- TLS tunnel success: **+5**
- OSSH seed exchange: **+10** (PASS) / **+5** (INCONCLUSIVE)
- SSH banner detection: **+4** (PASS) / **+2** (INCONCLUSIVE)
- Server list fetch: **+10**
- Meek handshake: **+6**
- UDP relay: **+2**
- Port diversity (through proxy): up to **+8**
- Advanced HTTP (POST/PUT/DELETE, Cookie, Referrer, Compression): **+4**
- Censorship bypass success: up to **+9** (3 sites)
- Stability ≥ 80%: **+3**

### 3. Generic Viability (G_Via, max 50)
Usefulness for non‑Psiphon tools like V2Ray / VPNs:

- TCP open: **+5**
- Forward proxy detected (HTTP_FWD): **+5**
- Each reachable general endpoint: **+4**
- Data transfer: **+8**
- Advanced HTTP: **+5**
(and other minor contributions)

**Total Score = Gen + PSI (max 105)**

---

## 🏷️ Classification

| Class | Total Score |
|------|-----------|
| DEAD | < 5 |
| MARGINAL | 5 – 19 |
| ALIVE | 20 – 34 |
| TUNNEL_OK | 35 – 54 |
| CDN_REACHABLE | 55 – 74 |
| PSIPHON_LIKELY | 75 – 89 |
| FULLY_READY | ≥ 90 |

---

## 📺 Console Legend

On startup the scanner prints a legend that explains every field:

```
G.Via = Generic Viability (max 50)
Pub   = Public endpoints (GOG=google, CF=cloudflare, GH=github, TLG=telegram web, YT=youtube)
TUN   = TLS tunnel (OK / SLOW / FAIL)
Psi   = Psiphon endpoints
Div   = Port diversity
SL    = Server list status
Cens  = Censorship bypass count
Stb   = Stability
Brw   = Browsing score
Persist = Persistent connection
```

---

## 📄 Output Files

- **alive_proxies.txt** – Tab‑separated detailed results (20+ columns) including protocol, auth status, compartment scores, anonymity, captcha detection, etc.
- **proxy_urls.txt** – Ready‑to‑use proxy URLs with scores. Format:

```
socks5://10.20.30.40:1080 #Score 82 #G_Via 45 #FRONTED
http://172.16.0.1:8080    #Score 67 #G_Via 38 #MEEK
```

- **scan_progress.json** – Checkpoint file that stores progress, server list cache, and config fingerprint.
- **tcp_open_proxies.txt** – Proxies where TCP port is open but no known protocol was detected.

---

## 🛡️ Two‑Phase Network Watchdog

A unique mechanism that never blocks the scan unnecessarily:

**Phase 1 – Hardcoded IPs:** Checks TCP port 443 on well‑known IPs (Google, Cloudflare, GitHub, …). No DNS needed.

**Phase 2 – Proxy targets:** If Phase 1 fails, it randomly samples proxies from your own list. If even one proxy responds, the network is considered alive.

Only when **both phases** fail will the scanner pause and wait for the network to return. It automatically resumes when connectivity is restored, or you can press `R` to force a retry.

---

## ⚡ Advanced Internals

- **Socket tuning:** TCP_NODELAY on every socket.
- **TLS enforcement:** Only TLS 1.2+ with AEAD ciphers, mandatory certificate verification.
- **Retry logic:** Exponential backoff + jitter, plus per‑test timeout multipliers (1.2×, 1.5×).
- **Atomic checkpoint:** Write‑temp‑then‑rename – never corrupts progress.
- **Thread safety:** Locks protect all shared caches and file writes.
- **Memory control:** DNS & GeoIP caches expire after 300 s; server list limited to 100 entries.
- **Zero DNS dependency:** All tests use hostnames through the proxy. Only SOCKS4 requires a pre‑resolved IP (from cache or fallback).
- **Manual Pause/Resume:** Cross‑platform keyboard listener with threading.Event.

---

## 🧩 Final Notes

- Proxies that require authentication but none is provided are marked `AUTH:Y` and skipped (score 0).
- Slow proxies get an automatic second chance and are labelled `SLOW_OK`.
- Ping > 5000 ms triggers a `HEAVY_LOAD` warning but does not discard the proxy.
- Every single test is performed through the proxy. No direct connections are used for scoring.
- Press `P` to pause, `R` to resume during scan.
- Python 3.7+ compatible. Tested on Linux, Windows, macOS.

---

❤️ **Dedicated to the immortal names of Iran Land – Dey 1404.**  
Their memory lives on in every line of code that defends free access to information.
```
