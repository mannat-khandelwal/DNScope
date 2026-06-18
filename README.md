# DNScope — DNS Intelligence & Enumeration Tool

```
 ██████╗ ███╗   ██╗███████╗ ██████╗ ██████╗ ██████╗ ███████╗
 ██╔══██╗████╗  ██║██╔════╝██╔════╝██╔═══██╗██╔══██╗██╔════╝
 ██║  ██║██╔██╗ ██║███████╗██║     ██║   ██║██████╔╝█████╗  
 ██║  ██║██║╚██╗██║╚════██║██║     ██║   ██║██╔═══╝ ██╔══╝  
 ██████╔╝██║ ╚████║███████║╚██████╗╚██████╔╝██║     ███████╗
 ╚═════╝ ╚═╝  ╚═══╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝     ╚══════╝
```

**Author:** Mannat Khandelwal  
**Language:** Python 3  
**Purpose:** Educational DNS Intelligence & Enumeration  

> ⚠️ **For authorized and educational use only.** Always obtain permission before scanning any domain you do not own.

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Flags Reference](#flags-reference)
- [Examples](#examples)
- [Output Formats](#output-formats)
- [Modules Explained](#modules-explained)
- [Project Structure](#project-structure)
- [Disclaimer](#disclaimer)

---

## Overview

DNScope is a comprehensive, command-line DNS recon tool written in Python. It is ideal for learning DNS enumeration, network reconnaissance, and web fingerprinting in a controlled, educational environmens.

---

## Features

| Module | Description |
|---|---|
| **DNS Records** | Query 17 record types: A, AAAA, MX, TXT, NS, SOA, CNAME, SRV, CAA, PTR, HINFO, NAPTR, DS, DNSKEY, TLSA, SPF, DMARC |
| **Reverse DNS** | Resolve PTR records from domain or IP |
| **GeoIP & WHOIS** | Get country, city, ISP, ASN, and org info for the resolved IP |
| **SSL/TLS** | Retrieve certificate details: issuer, SANs, validity dates, serial |
| **HTTP/HTTPS Probe** | Deep web fingerprinting — tech stack, server headers, redirects, cookies |
| **Tech Detection** | Identify 20+ technologies: WordPress, Laravel, React, Nginx, Cloudflare, AWS, and more |
| **Security Headers** | Audit for HSTS, CSP, X-Frame-Options, Referrer-Policy, etc. |
| **Cookie Audit** | Flag cookies missing Secure or HttpOnly attributes |
| **Email Security** | Check SPF, DMARC, and DKIM records across common selectors |
| **Zone Transfer** | Attempt AXFR against all NS servers to detect misconfiguration |
| **DNSSEC** | Check for DS and DNSKEY records |
| **Port Scanner** | Threaded TCP scan of 18 common ports with service name labels |
| **Passive Subdomains** | Enumerate subdomains via crt.sh certificate transparency logs |
| **Subdomain Brute-Force** | Multi-threaded wordlist-based subdomain discovery |
| **Custom Nameserver** | Route all DNS queries through a specified nameserver |
| **JSON / CSV Export** | Save full reports in structured formats |

---

## Installation

### 1. Clone or download the script

```bash
git clone https://github.com/mannat-khandelwal/dnscope.git
cd dnscope
```

### 2. Install dependencies

```bash
pip install dnspython requests beautifulsoup4
```

Or use a requirements file:

```bash
pip install -r requirements.txt
```

**requirements.txt**
```
dnspython
requests
beautifulsoup4
```

### 3. (Optional) Make executable on Linux/macOS

```bash
chmod +x dnscope.py
```

---

## Usage

```
python dnscope.py -d <domain> [options]
```

---

## Flags Reference

### Target

| Flag | Description |
|---|---|
| `-d`, `--domain` | **(Required)** Target domain, e.g. `example.com` |
| `-n`, `--nameserver` | Use a custom DNS nameserver, e.g. `8.8.8.8` |

### DNS Modules

| Flag | Description |
|---|---|
| `-r`, `--records` | Comma-separated record types to query (default: all 17 types) |
| `--axfr` | Attempt DNS zone transfer against all NS servers |
| `--dnssec` | Check if DNSSEC (DS / DNSKEY) is configured |

### Recon Modules

| Flag | Description |
|---|---|
| `--http` | WhatWeb-style HTTP + HTTPS deep probe |
| `--ssl` | Retrieve and display SSL/TLS certificate info |
| `--reverse` | Perform reverse DNS lookup + GeoIP + WHOIS |
| `--email` | Audit SPF, DMARC, and DKIM email security records |
| `--ports` | TCP scan of 18 common ports |
| `--port-list` | Custom port list, e.g. `22,80,443,3306` |

### Subdomain Enumeration

| Flag | Description |
|---|---|
| `--crt` | Passive subdomain discovery via crt.sh (no wordlist needed) |
| `-w`, `--wordlist` | Path to wordlist for brute-force subdomain enumeration |
| `--threads` | Number of threads for brute-force (default: `100`) |

### Convenience

| Flag | Description |
|---|---|
| `--all` | Run all modules (except subdomain brute-force) |
| `-q`, `--quiet` | Suppress the banner |

### Output

| Flag | Description |
|---|---|
| `-oj`, `--json-output` | Save full report to a JSON file |
| `-oc`, `--csv-output` | Save full report to a CSV file |

---

## Examples

**1. Basic DNS record enumeration**
```bash
python dnscope.py -d example.com
```

**2. Run every module at once**
```bash
python dnscope.py -d example.com --all
```

**3. HTTP/HTTPS probe + SSL + email audit**
```bash
python dnscope.py -d example.com --http --ssl --email
```

**4. Query specific record types only**
```bash
python dnscope.py -d example.com -r A,MX,TXT,NS,CAA
```

**5. Use a custom nameserver (e.g. Google)**
```bash
python dnscope.py -d example.com -n 8.8.8.8
```

**6. Port scan with custom ports**
```bash
python dnscope.py -d example.com --ports --port-list 22,80,443,8080,3306
```

**7. Passive subdomain discovery (no wordlist)**
```bash
python dnscope.py -d example.com --crt
```

**8. Subdomain brute-force with wordlist**
```bash
python dnscope.py -d example.com -w wordlist.txt --threads 150
```

**9. Check for zone transfer vulnerability**
```bash
python dnscope.py -d example.com --axfr
```

**10. Full recon + save JSON and CSV reports**
```bash
python dnscope.py -d example.com --all -oj report.json -oc report.csv
```

---

## Output Formats

### JSON (`-oj report.json`)
A structured nested report covering every module that was run:
```json
{
    "target": "example.com",
    "timestamp": "2025-01-01T12:00:00",
    "dns": {
        "A": ["93.184.216.34"],
        "MX": ["10 mail.example.com."]
    },
    "ssl": {
        "subject": { "commonName": "example.com" },
        "not_after": "Mar 15 00:00:00 2026 GMT"
    },
    "web": [ { "status": 200, "technologies": ["Nginx"] } ],
    ...
}
```

### CSV (`-oc report.csv`)
A flat key-value export of all findings — useful for spreadsheets:
```
Key,Value
dns.A.0,93.184.216.34
ssl.issuer.organizationName,DigiCert Inc
web.0.status,200
...
```

---

## Modules Explained

### DNS Records
Queries all standard record types using `dnspython`. Supports routing through a custom nameserver with `-n`.

### Reverse DNS + GeoIP + WHOIS
Resolves the domain to an IP, performs a PTR lookup, then enriches with geolocation (country, city, ISP) via `ip-api.com` and org info via `ipinfo.io`. No API keys required.

### SSL/TLS Certificate
Opens a raw TLS socket and pulls the server certificate — issuer, subject, SANs (Subject Alternative Names), validity window, and serial number.

### HTTP/HTTPS Probe
Sends a GET request to both `http://` and `https://` endpoints and extracts:
- Page title, status code, content length
- Server and X-Powered-By headers
- Technology stack (20+ signature patterns)
- Security header audit (HSTS, CSP, X-Frame-Options, etc.)
- Cookie flag audit (Secure, HttpOnly)
- Redirect chain

### Email Security Audit
- **SPF** — checks the TXT record for `v=spf1`
- **DMARC** — queries `_dmarc.<domain>` for the policy
- **DKIM** — tries 10 common selectors (`default`, `google`, `mail`, `s1`, `selector1`, etc.)

### Zone Transfer (AXFR)
Attempts a full zone transfer against every NS server. A successful transfer indicates a **critical misconfiguration** that leaks all DNS records.

### DNSSEC
Checks for `DS` and `DNSKEY` records to determine if the domain has DNSSEC enabled.

### Port Scanner
Threaded TCP connect scan using Python sockets. Default ports:
`21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443, 8888, 27017`

### Passive Subdomains (crt.sh)
Queries the Certificate Transparency log aggregator at `crt.sh` for all certificates ever issued to subdomains of the target — no brute-force required.

### Subdomain Brute-Force
Multi-threaded DNS resolution of `<word>.<domain>` for every entry in a wordlist. A popular wordlist source is [SecLists](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS).

---

## Project Structure

```
dnscope/
├── dnscope.py       # Main tool
├── README.md        # This file
└── requirements.txt # Python dependencies
```

---

## Disclaimer

DNScope is developed strictly for **educational purposes** and authorized security research. Running this tool against domains or systems **without explicit written permission** from the owner may be **illegal** under laws such as the Computer Fraud and Abuse Act (CFAA), the IT Act, and similar legislation in other jurisdictions.

The author, **Mannat Khandelwal**, takes no responsibility for any misuse of this tool. Use responsibly and ethically.

---

*DNScope — DNS Intelligence & Enumeration Tool | Author: Mannat Khandelwal*
