#!/usr/bin/env python3

"""
DNScope - DNS Intelligence & Enumeration Tool
Author: Mannat Khandelwal

A comprehensive DNS recon tool combining features of dig, dnsrecon, and whatweb.
For educational and authorized use only.
"""

import argparse
import csv
import json
import socket
import sys
import os
import ipaddress
import time
import re
import ssl
import hashlib
from datetime import datetime
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
    import dns.resolver
    import dns.reversename
    import dns.zone
    import dns.query
    import dns.exception
    from bs4 import BeautifulSoup
    requests.packages.urllib3.disable_warnings()
except ImportError as e:
    print(f"[!] Missing dependency: {e}")
    print("[!] Run: pip install dnspython requests beautifulsoup4")
    sys.exit(1)

# ─────────────────────────────────────────────
#  COLORS
# ─────────────────────────────────────────────

class C:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    BLUE   = "\033[94m"
    MAGENTA= "\033[95m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RESET  = "\033[0m"

def c(color, text):
    return f"{color}{text}{C.RESET}"

# ─────────────────────────────────────────────
#  BANNER
# ─────────────────────────────────────────────

BANNER = f"""
{C.CYAN}{C.BOLD}
 ██████╗ ███╗   ██╗███████╗ ██████╗ ██████╗ ██████╗ ███████╗
 ██╔══██╗████╗  ██║██╔════╝██╔════╝██╔═══██╗██╔══██╗██╔════╝
 ██║  ██║██╔██╗ ██║███████╗██║     ██║   ██║██████╔╝█████╗  
 ██║  ██║██║╚██╗██║╚════██║██║     ██║   ██║██╔═══╝ ██╔══╝  
 ██████╔╝██║ ╚████║███████║╚██████╗╚██████╔╝██║     ███████╗
 ╚═════╝ ╚═╝  ╚═══╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝     ╚══════╝
{C.RESET}
{C.YELLOW}  DNS Intelligence & Enumeration Tool{C.RESET}
{C.DIM}  Author  : Mannat Khandelwal{C.RESET}
{C.DIM}  For authorized / educational use only{C.RESET}
"""

# ─────────────────────────────────────────────
#  CONSTANTS
# ─────────────────────────────────────────────

ALL_RECORD_TYPES = [
    "A", "AAAA", "MX", "TXT", "NS",
    "SOA", "CNAME", "SRV", "CAA",
    "PTR", "HINFO", "NAPTR", "DS",
    "DNSKEY", "TLSA", "SPF", "DMARC"
]

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
                3306, 3389, 5432, 6379, 8080, 8443, 8888, 27017]

TECH_SIGNATURES = {
    "WordPress"     : [r"wp-content", r"wp-includes", r"WordPress"],
    "Joomla"        : [r"Joomla!", r"/components/com_"],
    "Drupal"        : [r"Drupal", r"/sites/default/files/"],
    "Laravel"       : [r"laravel_session", r"Laravel"],
    "Django"        : [r"csrfmiddlewaretoken", r"django"],
    "Ruby on Rails" : [r"_rails-", r"X-Powered-By: Phusion Passenger"],
    "React"         : [r"react\.min\.js", r"__REACT_DEVTOOLS"],
    "Angular"       : [r"ng-version", r"angular\.min\.js"],
    "Vue.js"        : [r"vue\.min\.js", r"__vue__"],
    "jQuery"        : [r"jquery", r"jQuery"],
    "Bootstrap"     : [r"bootstrap\.min\.css", r"bootstrap\.min\.js"],
    "Nginx"         : [r"nginx"],
    "Apache"        : [r"Apache"],
    "IIS"           : [r"Microsoft-IIS"],
    "Cloudflare"    : [r"cloudflare", r"cf-ray"],
    "AWS"           : [r"amazonaws", r"x-amz-"],
    "Google Cloud"  : [r"x-goog-", r"storage\.googleapis"],
    "PHP"           : [r"\.php", r"X-Powered-By: PHP"],
    "ASP.NET"       : [r"ASP\.NET", r"__VIEWSTATE"],
    "Node.js"       : [r"X-Powered-By: Express"],
}

# ─────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────

def print_section(title):
    width = 60
    print(f"\n{C.CYAN}{C.BOLD}{'─' * width}{C.RESET}")
    print(f"{C.CYAN}{C.BOLD}  {title}{C.RESET}")
    print(f"{C.CYAN}{C.BOLD}{'─' * width}{C.RESET}\n")

def print_ok(msg):
    print(f"  {C.GREEN}[+]{C.RESET} {msg}")

def print_info(msg):
    print(f"  {C.BLUE}[*]{C.RESET} {msg}")

def print_warn(msg):
    print(f"  {C.YELLOW}[!]{C.RESET} {msg}")

def print_err(msg):
    print(f"  {C.RED}[-]{C.RESET} {msg}")


# ─────────────────────────────────────────────
#  DNS FUNCTIONS
# ─────────────────────────────────────────────

def lookup_record(domain, record_type, nameserver=None):
    """Query a DNS record; optionally against a custom nameserver."""
    try:
        resolver = dns.resolver.Resolver()
        if nameserver:
            resolver.nameservers = [socket.gethostbyname(nameserver)]
        answers = resolver.resolve(domain, record_type, lifetime=5)
        return [str(r) for r in answers]
    except dns.resolver.NXDOMAIN:
        return []
    except dns.resolver.NoAnswer:
        return []
    except Exception:
        return []


def reverse_dns(ip_or_domain):
    """Resolve PTR record for a domain or IP."""
    try:
        ip = socket.gethostbyname(ip_or_domain)
        rev_name = dns.reversename.from_address(ip)
        answers = dns.resolver.resolve(rev_name, "PTR", lifetime=5)
        return ip, [str(x) for x in answers]
    except Exception:
        return None, []


def get_spf_policy(domain):
    """Extract and parse SPF record."""
    txts = lookup_record(domain, "TXT")
    for txt in txts:
        if "v=spf1" in txt.lower():
            return txt
    return None


def get_dmarc(domain):
    """Fetch DMARC policy."""
    return lookup_record(f"_dmarc.{domain}", "TXT")


def get_dkim(domain, selectors=None):
    """Try common DKIM selectors."""
    if selectors is None:
        selectors = [
            "default", "google", "mail", "k1", "s1", "s2",
            "selector1", "selector2", "dkim", "email"
        ]
    results = {}
    for sel in selectors:
        rec = lookup_record(f"{sel}._domainkey.{domain}", "TXT")
        if rec:
            results[sel] = rec
    return results


def zone_transfer(domain):
    """Attempt AXFR zone transfer against all NS servers."""
    results = {}
    ns_records = lookup_record(domain, "NS")
    for ns in ns_records:
        ns = ns.rstrip(".")
        try:
            z = dns.zone.from_xfr(dns.query.xfr(ns, domain, timeout=5))
            records = []
            for name, node in z.nodes.items():
                records.append(str(name))
            results[ns] = records
        except Exception as e:
            results[ns] = f"FAILED: {e}"
    return results


def dnssec_check(domain):
    """Check if DNSSEC is enabled."""
    ds   = lookup_record(domain, "DS")
    dkey = lookup_record(domain, "DNSKEY")
    return {"DS": ds, "DNSKEY": dkey, "enabled": bool(ds or dkey)}


def whois_ip(ip):
    """Lightweight WHOIS via ipinfo.io."""
    try:
        r = requests.get(
            f"https://ipinfo.io/{ip}/json",
            timeout=5,
            headers={"User-Agent": "DNScope/2.0"}
        )
        return r.json()
    except Exception:
        return {}


def geo_ip(ip):
    """GeoIP lookup via ip-api.com (free, no key)."""
    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,org,isp,as",
            timeout=5
        )
        return r.json()
    except Exception:
        return {}


# ─────────────────────────────────────────────
#  PORT SCANNER
# ─────────────────────────────────────────────

def scan_port(ip, port, timeout=1.0):
    """Single TCP port check."""
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except Exception:
        return False


def port_scan(ip, ports=None, threads=50):
    """Threaded TCP port scanner."""
    if ports is None:
        ports = COMMON_PORTS
    open_ports = []
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(scan_port, ip, p): p for p in ports}
        for f in as_completed(futures):
            if f.result():
                open_ports.append(futures[f])
    return sorted(open_ports)


SERVICE_NAMES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 8888: "HTTP-Alt", 27017: "MongoDB"
}


# ─────────────────────────────────────────────
#  SSL / TLS
# ─────────────────────────────────────────────

def get_ssl_info(domain, port=443):
    """Retrieve SSL certificate details."""
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(
            socket.create_connection((domain, port), timeout=5),
            server_hostname=domain
        ) as s:
            cert = s.getpeercert()
            return {
                "subject"   : dict(x[0] for x in cert.get("subject", [])),
                "issuer"    : dict(x[0] for x in cert.get("issuer", [])),
                "not_before": cert.get("notBefore"),
                "not_after" : cert.get("notAfter"),
                "san"       : [v for _, v in cert.get("subjectAltName", [])],
                "version"   : cert.get("version"),
                "serial"    : cert.get("serialNumber"),
            }
    except Exception as e:
        return {"error": str(e)}


# ─────────────────────────────────────────────
#  HTTP / HTTPS PROBING  (WhatWeb-style)
# ─────────────────────────────────────────────

def detect_technologies(headers, body):
    """Signature-based tech detection."""
    combined = " ".join(headers.values()) + " " + body
    detected = []
    for tech, patterns in TECH_SIGNATURES.items():
        for pat in patterns:
            if re.search(pat, combined, re.IGNORECASE):
                detected.append(tech)
                break
    return detected


def extract_meta(soup):
    """Pull useful <meta> tags."""
    meta = {}
    for tag in soup.find_all("meta"):
        name = tag.get("name") or tag.get("property") or ""
        content = tag.get("content", "")
        if name and content:
            meta[name.lower()] = content
    return meta


def extract_links(soup, base_domain):
    """Collect internal vs external links."""
    internal, external = [], []
    for a in soup.find_all("a", href=True):
        href = a["href"]
        try:
            parsed = urlparse(href)
            if parsed.netloc and base_domain not in parsed.netloc:
                external.append(href)
            elif href.startswith("/") or base_domain in href:
                internal.append(href)
        except Exception:
            pass
    return list(set(internal))[:20], list(set(external))[:20]


def probe_url(url, domain):
    """Deep probe a URL — headers, body, tech stack, cookies."""
    try:
        r = requests.get(
            url, timeout=8, verify=False,
            allow_redirects=True,
            headers={"User-Agent": "DNScope/2.0 (Educational)"}
        )
        soup = BeautifulSoup(r.text, "html.parser")
        title = soup.title.text.strip() if soup.title else ""
        headers_dict = dict(r.headers)
        techs = detect_technologies(headers_dict, r.text)
        meta  = extract_meta(soup)
        int_links, ext_links = extract_links(soup, domain)

        security_headers = {
            "Strict-Transport-Security" : r.headers.get("Strict-Transport-Security"),
            "Content-Security-Policy"   : r.headers.get("Content-Security-Policy"),
            "X-Frame-Options"           : r.headers.get("X-Frame-Options"),
            "X-Content-Type-Options"    : r.headers.get("X-Content-Type-Options"),
            "Referrer-Policy"           : r.headers.get("Referrer-Policy"),
            "Permissions-Policy"        : r.headers.get("Permissions-Policy"),
        }

        cookies = []
        for ck in r.cookies:
            cookies.append({
                "name"    : ck.name,
                "secure"  : ck.secure,
                "httponly": ck.has_nonstandard_attr("HttpOnly"),
            })

        return {
            "url"              : r.url,
            "original_url"     : url,
            "status"           : r.status_code,
            "length"           : len(r.text),
            "server"           : r.headers.get("Server", ""),
            "powered_by"       : r.headers.get("X-Powered-By", ""),
            "content_type"     : r.headers.get("Content-Type", ""),
            "title"            : title,
            "technologies"     : techs,
            "security_headers" : security_headers,
            "cookies"          : cookies,
            "meta"             : meta,
            "internal_links"   : int_links,
            "external_links"   : ext_links,
            "redirects"        : [h.url for h in r.history],
            "live"             : True,
        }
    except Exception as e:
        return {"url": url, "live": False, "error": str(e)}


def check_web(domain):
    """Probe HTTP and HTTPS concurrently."""
    urls = [f"http://{domain}", f"https://{domain}"]
    results = []
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(probe_url, u, domain) for u in urls]
        for f in as_completed(futures):
            results.append(f.result())
    return results


# ─────────────────────────────────────────────
#  SUBDOMAIN ENUMERATION
# ─────────────────────────────────────────────

def resolve_host(host):
    try:
        ip = socket.gethostbyname(host)
        return host, ip
    except Exception:
        return host, None


def enumerate_subdomains(domain, wordlist, threads=100):
    """Brute-force subdomain discovery via wordlist."""
    found = []
    try:
        with open(wordlist) as f:
            words = [l.strip() for l in f if l.strip()]
    except FileNotFoundError:
        print_err(f"Wordlist not found: {wordlist}")
        return []

    total  = len(words)
    done   = 0
    subs   = [f"{w}.{domain}" for w in words]

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(resolve_host, s): s for s in subs}
        for f in as_completed(futures):
            done += 1
            host, ip = f.result()
            if ip:
                found.append({"subdomain": host, "ip": ip})
                print_ok(f"{c(C.GREEN, host):50s}  {c(C.DIM, ip)}")
            if done % 500 == 0:
                print_info(f"Progress: {done}/{total} ({done*100//total}%)")

    return found


def crt_sh_subdomains(domain):
    """Passive subdomain discovery via crt.sh (certificate transparency)."""
    try:
        r = requests.get(
            f"https://crt.sh/?q=%.{domain}&output=json",
            timeout=10,
            headers={"User-Agent": "DNScope/2.0"}
        )
        data = r.json()
        subs = set()
        for entry in data:
            name = entry.get("name_value", "")
            for sub in name.split("\n"):
                sub = sub.strip().lstrip("*.")
                if domain in sub:
                    subs.add(sub)
        return sorted(subs)
    except Exception:
        return []


# ─────────────────────────────────────────────
#  EMAIL SECURITY AUDIT
# ─────────────────────────────────────────────

def audit_email_security(domain):
    """Check SPF, DMARC, DKIM."""
    result = {}

    spf = get_spf_policy(domain)
    result["spf"] = spf if spf else "NOT FOUND"

    dmarc = get_dmarc(domain)
    result["dmarc"] = dmarc[0] if dmarc else "NOT FOUND"

    dkim = get_dkim(domain)
    result["dkim"] = dkim if dkim else {}

    mx = lookup_record(domain, "MX")
    result["mx"] = mx

    return result


# ─────────────────────────────────────────────
#  OUTPUT
# ─────────────────────────────────────────────

def export_json(filename, data):
    with open(filename, "w") as f:
        json.dump(data, f, indent=4, default=str)
    print_ok(f"JSON saved → {filename}")


def export_csv(filename, data):
    rows = []
    def flatten(obj, prefix=""):
        if isinstance(obj, dict):
            for k, v in obj.items():
                flatten(v, f"{prefix}{k}.")
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                flatten(v, f"{prefix}{i}.")
        else:
            rows.append([prefix.rstrip("."), str(obj)])
    flatten(data)
    with open(filename, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["Key", "Value"])
        w.writerows(rows)
    print_ok(f"CSV saved → {filename}")


# ─────────────────────────────────────────────
#  MAIN REPORT PRINTER
# ─────────────────────────────────────────────

def run_dns_records(domain, records, nameserver, report):
    print_section("DNS RECORD ENUMERATION")
    report["dns"] = {}
    for rtype in records:
        res = lookup_record(domain, rtype, nameserver)
        report["dns"][rtype] = res
        if res:
            print(f"  {c(C.BOLD, rtype)}")
            for item in res:
                print(f"      {c(C.GREEN, item)}")
            print()
        else:
            print(f"  {c(C.DIM, rtype + ':  (no record)')}")


def run_whois_geo(domain, report):
    print_section("IP / WHOIS / GEO")
    ip, ptrs = reverse_dns(domain)
    report["reverse"] = {"ip": ip, "ptr": ptrs}
    if ip:
        print_info(f"Resolved IP : {c(C.YELLOW, ip)}")
        for ptr in ptrs:
            print_info(f"PTR         : {ptr}")
        geo = geo_ip(ip)
        report["geo"] = geo
        if geo.get("status") == "success":
            print_ok(f"Location    : {geo.get('city')}, {geo.get('regionName')}, {geo.get('country')}")
            print_ok(f"ISP / ASN   : {geo.get('isp')} / {geo.get('as')}")
        wi = whois_ip(ip)
        report["whois"] = wi
        if wi.get("org"):
            print_ok(f"Org         : {wi.get('org')}")
    else:
        print_warn("Could not resolve IP.")


def run_ssl(domain, report):
    print_section("SSL / TLS CERTIFICATE")
    ssl_info = get_ssl_info(domain)
    report["ssl"] = ssl_info
    if "error" in ssl_info:
        print_warn(f"SSL Error: {ssl_info['error']}")
    else:
        subj = ssl_info.get("subject", {})
        print_ok(f"Common Name : {subj.get('commonName', 'N/A')}")
        issuer = ssl_info.get("issuer", {})
        print_ok(f"Issuer      : {issuer.get('organizationName', 'N/A')}")
        print_ok(f"Valid From  : {ssl_info.get('not_before')}")
        print_ok(f"Valid To    : {ssl_info.get('not_after')}")
        san = ssl_info.get("san", [])
        if san:
            print_ok(f"SANs ({len(san)})  : {', '.join(san[:8])}{'...' if len(san) > 8 else ''}")


def run_web_probe(domain, report):
    print_section("WEB PROBE  (HTTP + HTTPS)")
    report["web"] = []
    for res in check_web(domain):
        report["web"].append(res)
        if not res.get("live"):
            print_warn(f"Not reachable: {res['url']}")
            continue
        status_color = C.GREEN if res["status"] < 400 else C.RED
        print_ok(
            f"[{c(status_color, str(res['status']))}] "
            f"{c(C.BOLD, res['url'][:60])}"
        )
        if res.get("title"):
            print_info(f"  Title       : {res['title']}")
        if res.get("server"):
            print_info(f"  Server      : {res['server']}")
        if res.get("powered_by"):
            print_info(f"  Powered-By  : {res['powered_by']}")
        if res.get("technologies"):
            techs = ", ".join(res["technologies"])
            print_info(f"  Tech Stack  : {c(C.MAGENTA, techs)}")
        if res.get("redirects"):
            print_info(f"  Redirects   : {' → '.join(res['redirects'])}")
        sec = res.get("security_headers", {})
        missing = [k for k, v in sec.items() if not v]
        if missing:
            print_warn(f"  Missing Sec : {', '.join(missing)}")
        if res.get("cookies"):
            for ck in res["cookies"]:
                flags = []
                if not ck.get("secure"):    flags.append("no-Secure")
                if not ck.get("httponly"):  flags.append("no-HttpOnly")
                if flags:
                    print_warn(f"  Cookie [{ck['name']}]: {', '.join(flags)}")
        print()


def run_email_audit(domain, report):
    print_section("EMAIL SECURITY AUDIT")
    audit = audit_email_security(domain)
    report["email_security"] = audit

    spf = audit.get("spf")
    if "v=spf1" in str(spf):
        print_ok(f"SPF   : {c(C.GREEN, 'Found')}  → {spf}")
    else:
        print_warn(f"SPF   : {c(C.RED, 'Not Found')}")

    dmarc = audit.get("dmarc")
    if "v=DMARC1" in str(dmarc):
        print_ok(f"DMARC : {c(C.GREEN, 'Found')}  → {dmarc[:80]}")
    else:
        print_warn(f"DMARC : {c(C.RED, 'Not Found')}")

    dkim = audit.get("dkim", {})
    if dkim:
        for sel, rec in dkim.items():
            print_ok(f"DKIM  : selector={sel}  {rec[0][:60]}")
    else:
        print_warn(f"DKIM  : {c(C.RED, 'No common selectors found')}")

    mx = audit.get("mx", [])
    if mx:
        print_ok(f"MX    : {', '.join(mx)}")


def run_zone_transfer(domain, report):
    print_section("ZONE TRANSFER ATTEMPT (AXFR)")
    results = zone_transfer(domain)
    report["zone_transfer"] = results
    for ns, data in results.items():
        if isinstance(data, list):
            print_ok(f"VULNERABLE: {ns} — {len(data)} records leaked!")
            for r in data[:10]:
                print(f"      {r}")
        else:
            print_info(f"{ns}: {data}")


def run_dnssec(domain, report):
    print_section("DNSSEC")
    info = dnssec_check(domain)
    report["dnssec"] = info
    if info["enabled"]:
        print_ok(f"DNSSEC is {c(C.GREEN, 'ENABLED')}")
        if info["DS"]:
            for ds in info["DS"]:
                print_info(f"DS     : {ds}")
        if info["DNSKEY"]:
            for dk in info["DNSKEY"][:2]:
                print_info(f"DNSKEY : {dk[:80]}...")
    else:
        print_warn(f"DNSSEC is {c(C.RED, 'NOT enabled')}")


def run_ports(domain, ports, report):
    print_section("PORT SCAN")
    ip = None
    try:
        ip = socket.gethostbyname(domain)
    except Exception:
        print_err("Could not resolve domain for port scan.")
        return
    print_info(f"Scanning {ip} ...")
    open_ports = port_scan(ip, ports)
    report["ports"] = open_ports
    if open_ports:
        for p in open_ports:
            svc = SERVICE_NAMES.get(p, "Unknown")
            print_ok(f"{str(p):6s}  {c(C.CYAN, svc)}")
    else:
        print_warn("No common ports open.")


def run_crtsh(domain, report):
    print_section("PASSIVE SUBDOMAIN DISCOVERY (crt.sh)")
    subs = crt_sh_subdomains(domain)
    report["crt_subdomains"] = subs
    if subs:
        for s in subs:
            print_ok(s)
        print_info(f"Total: {len(subs)}")
    else:
        print_warn("No results from crt.sh")


def run_subdomain_brute(domain, wordlist, threads, report):
    print_section("SUBDOMAIN BRUTE-FORCE")
    found = enumerate_subdomains(domain, wordlist, threads)
    report["subdomains"] = found
    print_info(f"Found: {len(found)}")


# ─────────────────────────────────────────────
#  CLI
# ─────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="dnscope",
        description="DNScope — DNS Intelligence & Enumeration Tool by Mannat Khandelwal",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  dnscope -d example.com
  dnscope -d example.com --all
  dnscope -d example.com --http --ssl --email --ports
  dnscope -d example.com -r A,MX,TXT,NS
  dnscope -d example.com --crt --wordlist subs.txt
  dnscope -d example.com --all -oj report.json -oc report.csv
        """
    )

    # Target
    parser.add_argument("-d", "--domain",   required=True,      help="Target domain (e.g. example.com)")
    parser.add_argument("-n", "--nameserver",                    help="Custom nameserver (e.g. 8.8.8.8)")

    # DNS
    parser.add_argument("-r", "--records",  default=None,        help="Comma-separated record types (e.g. A,MX,TXT). Default: all common types")
    parser.add_argument("--axfr",           action="store_true", help="Attempt DNS zone transfer (AXFR)")
    parser.add_argument("--dnssec",         action="store_true", help="Check DNSSEC status")

    # Recon
    parser.add_argument("--http",           action="store_true", help="WhatWeb-style HTTP/HTTPS probe")
    parser.add_argument("--ssl",            action="store_true", help="Retrieve SSL/TLS certificate details")
    parser.add_argument("--reverse",        action="store_true", help="Reverse DNS + GeoIP + WHOIS")
    parser.add_argument("--email",          action="store_true", help="Email security audit (SPF / DMARC / DKIM)")
    parser.add_argument("--ports",          action="store_true", help="TCP port scan (common ports)")
    parser.add_argument("--port-list",      default=None,        help="Custom ports: 22,80,443,8080")

    # Subdomains
    parser.add_argument("--crt",            action="store_true", help="Passive subdomain discovery via crt.sh")
    parser.add_argument("-w", "--wordlist",                      help="Wordlist for subdomain brute-force")
    parser.add_argument("--threads",        type=int, default=100, help="Threads for subdomain brute-force (default 100)")

    # Convenience
    parser.add_argument("--all",            action="store_true", help="Run ALL modules (except subdomain brute-force)")

    # Output
    parser.add_argument("-oj", "--json-output",                  help="Save report as JSON")
    parser.add_argument("-oc", "--csv-output",                   help="Save report as CSV")
    parser.add_argument("-q",  "--quiet",   action="store_true", help="Suppress banner")

    args = parser.parse_args()

    if not args.quiet:
        print(BANNER)

    domain = args.domain.strip().lower()
    if domain.startswith("http://") or domain.startswith("https://"):
        domain = urlparse(domain).netloc

    print(f"\n  {c(C.BOLD, 'Target')} : {c(C.YELLOW, domain)}")
    print(f"  {c(C.BOLD, 'Date')}   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    report = {
        "target"    : domain,
        "timestamp" : datetime.now().isoformat(),
    }

    # ── DNS Records ──────────────────────────────────────
    records = [
        x.strip().upper()
        for x in args.records.split(",")
    ] if args.records else ALL_RECORD_TYPES
    run_dns_records(domain, records, args.nameserver, report)

    # ── Reverse / GeoIP / WHOIS ─────────────────────────
    if args.reverse or args.all:
        run_whois_geo(domain, report)

    # ── SSL ─────────────────────────────────────────────
    if args.ssl or args.all:
        run_ssl(domain, report)

    # ── HTTP Probe ───────────────────────────────────────
    if args.http or args.all:
        run_web_probe(domain, report)

    # ── Email Security ───────────────────────────────────
    if args.email or args.all:
        run_email_audit(domain, report)

    # ── Zone Transfer ────────────────────────────────────
    if args.axfr or args.all:
        run_zone_transfer(domain, report)

    # ── DNSSEC ───────────────────────────────────────────
    if args.dnssec or args.all:
        run_dnssec(domain, report)

    # ── Port Scan ────────────────────────────────────────
    if args.ports or args.all:
        custom_ports = None
        if args.port_list:
            try:
                custom_ports = [int(x) for x in args.port_list.split(",")]
            except ValueError:
                print_warn("Invalid --port-list; using default common ports.")
        run_ports(domain, custom_ports, report)

    # ── Passive Subdomain (crt.sh) ───────────────────────
    if args.crt or args.all:
        run_crtsh(domain, report)

    # ── Subdomain Brute-Force ────────────────────────────
    if args.wordlist:
        run_subdomain_brute(domain, args.wordlist, args.threads, report)

    # ── Output ───────────────────────────────────────────
    if args.json_output:
        export_json(args.json_output, report)
    if args.csv_output:
        export_csv(args.csv_output, report)

    print(f"\n{c(C.CYAN, '─' * 60)}")
    print(f"{c(C.GREEN, C.BOLD + '  DNScope completed.'+ C.RESET)}")
    print(f"{c(C.CYAN, '─' * 60)}\n")


if __name__ == "__main__":
    main()
