# PSI-Tracker V1.0 "DEY_Immortal" – Unbreakable Proxy Auditor for Iran
** In memory of the immortal Iranians **

**Find working SOCKS/HTTP proxies when DNS, ICMP, and all foreign websites are blocked.**

[![Python 3.7+](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

---

## 🔬 What is PSI-Tracker?

PSI-Tracker is a multi‑stage, thread‑parallel proxy auditor built for **high‑latency, heavily censored environments** (like Iran).  
It performs deep inspection of **SOCKS4/5, HTTP CONNECT, and HTTP Forward** proxies **through the proxy itself** – the scanner never uses its own internet connection to judge a proxy’s health.

The scanner accurately **emulates Psiphon’s real connection protocols** (OSSH, Meek, Fronted) based on reverse engineering of Psiphon and the ShiroKhorshid Android project.  
Every proxy receives a **fair, multi‑axis score** (General, Psiphon, Generic Viability) and is classified from **DEAD** to **FULLY_READY**.

---

## ✨ Key Features

- **Full RFC 1928 SOCKS5** – IPv4, IPv6, domain name support (proper BND.ADDR handling)
- **Psiphon Emulation** – OSSH seed exchange, Meek POST with obfuscated headers, Fronted TLS to CDNs
- **Two‑Phase Network Watchdog** – Checks hardcoded IPs first, then falls back to sampling your own proxy list
- **Manual Pause/Resume** – Press `P` to pause, `R` to resume anytime
- **`--max-alive`** – Auto‑stop after finding a set number of alive proxies
- **Fair Scoring** – Gen Score (general use), PSI Score (Psiphon compatibility), Generic Viability (non‑Psiphon tools like V2Ray)
- **Real‑World Tests** – Browsing, Censorship Bypass (Telegram, Twitter, Facebook), Stability, Persistent Connection
- **Advanced HTTP Validation** – POST/PUT/DELETE echo, Cookie & Referrer transport, Gzip compression
- **Multi‑Judge Anonymity Classification** – ELITE / ANONYMOUS / TRANSPARENT (5 judges)
- **Atomic Checkpoint** – Resume interrupted scans exactly from the last tested proxy
- **Compact & Verbose Modes** – Default shows only essential stats; `--verbose` for full details
- **Zero Hardcoded IPs for Connectivity** – Tests use hostnames (domain fronting); only SOCKS4 resolves in advance
- **Production‑Hardened** – All sockets and HTTP sessions are properly closed; memory caches expire after 5 minutes

---

## 📦 Installation

### Requirements
- Python 3.7 or newer
- `tqdm`, `colorama`, `requests`, `PySocks`

### Setup
```bash
git clone https://github.com/SulgX/PSI_Tracker.git
cd PSI_Tracker
pip install -r requirements.txt
