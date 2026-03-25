#!/usr/bin/env python3
"""
zeek_triage.py — Automated Zeek Log Threat Analysis + Unicode & Crypto Detection
Author: Yana Ivanov
Usage:
  Network triage:  python3 zeek_triage.py /path/to/zeek/logs
  Unicode scan:    python3 zeek_triage.py --scan-code /path/to/source/code
  Both:            python3 zeek_triage.py /path/to/zeek/logs --scan-code /path/to/source/code
"""

import os
import sys
from collections import defaultdict

# ─────────────────────────────────────────────
# TERMINAL COLORS
# ─────────────────────────────────────────────

class C:
    RED    = "\033[91m"
    ORANGE = "\033[38;5;208m"
    BLUE   = "\033[94m"
    GREEN  = "\033[92m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RESET  = "\033[0m"

def red(t):    return f"{C.BOLD}{C.RED}{t}{C.RESET}"
def orange(t): return f"{C.BOLD}{C.ORANGE}{t}{C.RESET}"
def blue(t):   return f"{C.BOLD}{C.BLUE}{t}{C.RESET}"
def green(t):  return f"{C.BOLD}{C.GREEN}{t}{C.RESET}"
def bold(t):   return f"{C.BOLD}{t}{C.RESET}"
def dim(t):    return f"{C.DIM}{t}{C.RESET}"

# ─────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────

SUSPICIOUS_TLDS = [".su", ".ru", ".cc", ".xyz", ".top", ".pw", ".cyou", ".lat"]

SAFE_HOSTS = [
    "adobe", "digicert", "ocsp", "microsoft", "windowsupdate", "msocsp", "google",
    "akamai", "cloudflare", "office", "bing", "gstatic", "msftconnect", "msn",
    "live", "skype", "azure", "lencr.org", "pki.goog"
]

KNOWN_BAD_DOMAINS = [
    # IOCs from lab analysis
    "fakeurl.htm", "set_agent", "whitepepper.su",
    "communicationfirewall-security.cc", "holiday-forever.cc",
    "whooptm.cyou", "megafilehub",
    # Dynamic DNS providers — almost exclusively used by C2 infrastructure
    "tempuri.org", "duckdns.org", "no-ip.com", "ddns.net", "hopto.org",
    "servebeer.com", "serveftp.com", "myftp.biz", "redirectme.net",
    "zapto.org", "sytes.net", "ignorelist.com", "dynamic-dns.net",
    "chickenkiller.com", "strangled.net", "otzo.com", "zzux.com",
]

# ── Blockchain / Cryptocurrency C2 Infrastructure ──────────────────────────
# These domains/endpoints have no legitimate use in defense contractor environments.
# Glassworm and other malware families use blockchain nodes as C2 channels
# because there is no IP to block and transactions cannot be deleted.
CRYPTO_BLOCKCHAIN_DOMAINS = [
    # Solana — Glassworm primary C2 channel
    "solana.com", "mainnet.helius-rpc.com", "api.mainnet-beta.solana.com",
    "solana-api.projectserum.com", "rpc.ankr.com",
    # Ethereum
    "infura.io", "alchemyapi.io", "etherscan.io", "alchemy.com",
    "rpc.flashbots.net", "cloudflare-eth.com",
    # General crypto infrastructure
    "blockchain.info", "blockchain.com", "blockchair.com",
    "btc.com", "ethplorer.io", "web3.storage",
    "ipfs.io", "gateway.ipfs.io", "dweb.link",
    # Crypto wallets / exchanges that malware contacts for staging
    "binance.com", "coinbase.com", "kraken.com",
    # NFT / Web3 infrastructure used for payload hosting
    "opensea.io", "nftport.xyz", "pinata.cloud",
]

# ── Invisible Unicode — Glassworm PUA codepoint ranges ─────────────────────
# These ranges have ZERO legitimate use in production source code.
# Any occurrence is an unambiguous indicator of malicious payload injection.
UNICODE_PUA_RANGES = [
    (0xFE00, 0xFE0F, "Variation Selectors (VS1-VS16) — primary Glassworm range"),
    (0xE0100, 0xE01EF, "Variation Selectors Supplement — secondary Glassworm range"),
    (0x200B, 0x200F, "Zero-Width Characters — used for text-based steganography"),
    (0xFEFF, 0xFEFF, "Zero-Width No-Break Space (BOM outside file start)"),
    (0x00AD, 0x00AD, "Soft Hyphen — invisible in most renderers"),
]

# Source code file extensions to scan
CODE_EXTENSIONS = {
    ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs",
    ".py", ".rb", ".php", ".java", ".cs", ".go",
    ".rs", ".cpp", ".c", ".h", ".swift", ".kt",
    ".sh", ".bash", ".zsh", ".ps1", ".psm1",
    ".json", ".yaml", ".yml", ".toml", ".env",
    ".html", ".htm", ".vue", ".svelte",
}

# ─────────────────────────────────────────────
# CORE PARSER
# ─────────────────────────────────────────────

def parse_zeek_log(filepath):
    fields = []
    rows = []
    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            if line.startswith("#fields"):
                fields = line.split("\t")[1:]
            elif line.startswith("#"):
                continue
            else:
                values = line.split("\t")
                rows.append(dict(zip(fields, values)))
    return rows

# ─────────────────────────────────────────────
# NETWORK ANALYSIS — Zeek log steps
# ─────────────────────────────────────────────

def get_host_identity(log_dir):
    filepath = os.path.join(log_dir, "dhcp.log")
    if not os.path.exists(filepath):
        return None
    rows = parse_zeek_log(filepath)
    if rows:
        row = rows[0]
        return {
            "ip":       row.get("assigned_addr", "unknown"),
            "mac":      row.get("mac", "unknown"),
            "hostname": row.get("host_name", "unknown")
        }
    return None

def get_username(log_dir):
    filepath = os.path.join(log_dir, "kerberos.log")
    if not os.path.exists(filepath):
        return None
    for row in parse_zeek_log(filepath):
        if row.get("request_type") == "AS" and row.get("success") == "T":
            client = row.get("client", "")
            if client:
                return client.split("/")[0]
    return None

def get_known_bad_hits(log_dir):
    hits = []
    seen = set()
    for filename, field_host, field_uri, field_ip in [
        ("http.log", "host", "uri", "id.resp_h"),
        ("ssl.log",  "server_name", None, "id.resp_h"),
    ]:
        path = os.path.join(log_dir, filename)
        if not os.path.exists(path):
            continue
        for row in parse_zeek_log(path):
            host = row.get(field_host, "")
            uri  = row.get(field_uri, "") if field_uri else ""
            ip   = row.get(field_ip, "")
            combined = host + uri
            for ioc in KNOWN_BAD_DOMAINS:
                if ioc in combined and host not in seen:
                    seen.add(host)
                    hits.append({"indicator": ioc, "host": host, "ip": ip, "source": filename})
    return hits

def get_crypto_blockchain_hits(log_dir):
    """
    Scan http.log, ssl.log, and dns.log for connections to blockchain
    and cryptocurrency infrastructure. These connections have no legitimate
    use in a defense contractor environment and indicate potential Glassworm
    or similar blockchain-C2 malware activity.
    """
    hits = []
    seen = set()

    checks = [
        ("http.log",  "host",        "id.resp_h", "id.orig_h"),
        ("ssl.log",   "server_name", "id.resp_h", "id.orig_h"),
        ("dns.log",   "query",       "id.resp_h", "id.orig_h"),
    ]

    for filename, host_field, dst_field, src_field in checks:
        path = os.path.join(log_dir, filename)
        if not os.path.exists(path):
            continue
        for row in parse_zeek_log(path):
            host    = row.get(host_field, "").lower()
            dst_ip  = row.get(dst_field, "")
            src_ip  = row.get(src_field, "")
            if not host:
                continue
            for crypto_domain in CRYPTO_BLOCKCHAIN_DOMAINS:
                if crypto_domain in host and host not in seen:
                    seen.add(host)
                    # Classify the category
                    if any(x in host for x in ["solana", "serum", "helius"]):
                        category = "Solana Blockchain — Glassworm primary C2 channel"
                        attack   = "Glassworm / Blockchain C2"
                    elif any(x in host for x in ["infura", "alchemy", "ethereum", "etherscan", "flashbots", "cloudflare-eth"]):
                        category = "Ethereum Blockchain — Blockchain C2 infrastructure"
                        attack   = "Blockchain C2"
                    elif any(x in host for x in ["ipfs", "dweb", "web3.storage", "pinata"]):
                        category = "IPFS / Decentralized Storage — used for payload hosting"
                        attack   = "Decentralized Payload Hosting"
                    elif any(x in host for x in ["binance", "coinbase", "kraken"]):
                        category = "Cryptocurrency Exchange — staging or exfiltration endpoint"
                        attack   = "Crypto Exchange Contact"
                    else:
                        category = "Cryptocurrency / Blockchain Infrastructure"
                        attack   = "Blockchain C2 / Crypto Contact"
                    hits.append({
                        "host":     host,
                        "src_ip":   src_ip,
                        "dst_ip":   dst_ip,
                        "category": category,
                        "attack":   attack,
                        "source":   filename,
                    })
    return hits

def get_suspicious_http(log_dir):
    filepath = os.path.join(log_dir, "http.log")
    if not os.path.exists(filepath):
        return []
    seen = {}
    for row in parse_zeek_log(filepath):
        host   = row.get("host", "")
        method = row.get("method", "")
        uri    = row.get("uri", "")
        dst_ip = row.get("id.resp_h", "")
        if host and not any(safe in host for safe in SAFE_HOSTS):
            if host not in seen:
                seen[host] = {"host": host, "ip": dst_ip, "methods": set(), "uris": set(), "count": 0}
            seen[host]["methods"].add(method)
            seen[host]["uris"].add(uri)
            seen[host]["count"] += 1
    return list(seen.values())

def get_suspicious_tls(log_dir):
    filepath = os.path.join(log_dir, "ssl.log")
    if not os.path.exists(filepath):
        return []
    suspicious = []
    seen = set()
    for row in parse_zeek_log(filepath):
        server_name = row.get("server_name", "")
        dst_ip      = row.get("id.resp_h", "")
        for tld in SUSPICIOUS_TLDS:
            if server_name.endswith(tld) and server_name not in seen:
                seen.add(server_name)
                suspicious.append({"domain": server_name, "ip": dst_ip, "tld": tld})
    return suspicious

def get_data_volumes(log_dir, suspicious_ips):
    filepath = os.path.join(log_dir, "conn.log")
    if not os.path.exists(filepath):
        return {}
    totals = defaultdict(lambda: {"sent": 0, "received": 0, "connections": 0})
    for row in parse_zeek_log(filepath):
        dst_ip = row.get("id.resp_h", "")
        if dst_ip in suspicious_ips:
            try:
                totals[dst_ip]["sent"]        += int(row.get("orig_bytes", 0) or 0)
                totals[dst_ip]["received"]    += int(row.get("resp_bytes", 0) or 0)
                totals[dst_ip]["connections"] += 1
            except ValueError:
                pass
    return totals

# ─────────────────────────────────────────────
# UNICODE SCANNER
# ─────────────────────────────────────────────

def scan_unicode(path, findings):
    """
    Scan a single file for invisible Unicode characters used by Glassworm
    and similar supply chain attack tools. Checks all PUA ranges defined
    in UNICODE_PUA_RANGES. Returns list of finding dicts.
    """
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line_num, line in enumerate(f, 1):
                for char_pos, char in enumerate(line):
                    cp = ord(char)
                    for (range_start, range_end, range_desc) in UNICODE_PUA_RANGES:
                        if range_start <= cp <= range_end:
                            # Collect surrounding context — strip the invisible char for display
                            context = line.strip().replace(char, "·")[:120]
                            findings.append({
                                "file":      path,
                                "line":      line_num,
                                "position":  char_pos,
                                "codepoint": f"U+{cp:04X}",
                                "range":     range_desc,
                                "context":   context,
                                "attack":    "Glassworm / Invisible Unicode Payload Injection",
                                "signature": f"PUA codepoint U+{cp:04X} in range U+{range_start:04X}–U+{range_end:04X}",
                            })
    except (IOError, PermissionError):
        pass
    return findings

def run_unicode_scan(scan_path):
    """
    Walk scan_path recursively and scan all source code files.
    Returns aggregated list of findings.
    """
    findings = []
    scanned  = 0
    skipped  = 0

    if os.path.isfile(scan_path):
        scan_unicode(scan_path, findings)
        scanned = 1
    else:
        for root, dirs, files in os.walk(scan_path):
            # Skip common non-code directories
            dirs[:] = [d for d in dirs if d not in {
                ".git", "node_modules", "__pycache__", ".venv",
                "venv", "dist", "build", ".next", ".nuxt"
            }]
            for fname in files:
                ext = os.path.splitext(fname)[1].lower()
                if ext in CODE_EXTENSIONS:
                    full = os.path.join(root, fname)
                    before = len(findings)
                    scan_unicode(full, findings)
                    scanned += 1
                else:
                    skipped += 1

    return findings, scanned, skipped

# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────

def format_bytes(num):
    if num >= 1_000_000: return f"{num / 1_000_000:.2f} MB"
    if num >= 1_000:     return f"{num / 1_000:.1f} KB"
    return f"{num} bytes"

def divider():    return "=" * 64
def subdiv():     return dim("-" * 64)

# ─────────────────────────────────────────────
# REPORT
# ─────────────────────────────────────────────

def print_network_report(log_dir, host, username, known_bad, crypto_hits, http_hits, tls_hits, volumes):
    print(f"\n{bold(divider())}")
    print(f"  {bold('ZEEK TRIAGE REPORT — NETWORK ANALYSIS')}")
    print(f"  {dim('Log directory: ' + log_dir)}")
    print(f"{bold(divider())}")

    # Host identity
    print(f"\n{blue('[ INFECTED HOST IDENTITY ]')}")
    print(subdiv())
    if host:
        print(f"  IP Address   : {host['ip']}")
        print(f"  MAC Address  : {host['mac']}")
        print(f"  Hostname     : {host['hostname']}")
    else:
        print(f"  {orange('dhcp.log not found — host identity unavailable')}")
    if username:
        print(f"  Username     : {red(username)}")
    else:
        print(f"  {dim('kerberos.log not found — username unavailable')}")

    # Known bad IOCs
    print(f"\n{red('[ CONFIRMED MALICIOUS IOCs ]')} — {red(str(len(known_bad))) if known_bad else '0'} matches")
    print(subdiv())
    if known_bad:
        for hit in known_bad:
            print(f"  {red('!! MATCH')}  {red(hit['host'])}  {dim(hit['ip'])}")
            print(f"               IOC       : {bold(hit['indicator'])}")
            print(f"               Source    : {dim(hit['source'])}")
    else:
        print(f"  {dim('None found')}")

    # Crypto / blockchain hits
    label = red('[ CRYPTO / BLOCKCHAIN C2 CONNECTIONS ]') if crypto_hits else blue('[ CRYPTO / BLOCKCHAIN C2 CONNECTIONS ]')
    print(f"\n{label} — {red(str(len(crypto_hits))) if crypto_hits else '0'} found")
    print(subdiv())
    if crypto_hits:
        for hit in crypto_hits:
            print(f"  {red('!! CRYPTO')} {red(hit['host'])}")
            print(f"               Source IP : {bold(hit['src_ip'])}")
            print(f"               Dest IP   : {dim(hit['dst_ip'])}")
            print(f"               Category  : {orange(hit['category'])}")
            print(f"               Attack    : {red(hit['attack'])}")
            print(f"               Seen in   : {dim(hit['source'])}")
    else:
        print(f"  {dim('None found')}")
        print(f"  {dim('Tip: If crypto domains are blocked at your firewall, traffic will not appear here.')}")

    # Suspicious HTTP
    print(f"\n{blue('[ SUSPICIOUS HTTP REQUESTS ]')} — {red(str(len(http_hits))) if http_hits else '0'} unique hosts")
    print(subdiv())
    if http_hits:
        for hit in http_hits:
            methods = ", ".join(sorted(hit['methods']))
            print(f"  {red(methods) if 'POST' in methods else methods:<12} {red(hit['host'])}  {dim('(' + str(hit['count']) + ' requests)')}")
            for uri in list(hit['uris'])[:2]:
                print(f"               {dim((uri[:80] + '...') if len(uri) > 80 else uri)}")
    else:
        print(f"  {dim('None found')}")

    # Suspicious TLS
    print(f"\n{blue('[ SUSPICIOUS TLS DOMAINS ]')} — {red(str(len(tls_hits))) if tls_hits else '0'} found")
    print(subdiv())
    if tls_hits:
        for hit in tls_hits:
            print(f"  {red(hit['domain'].ljust(42))} {dim(hit['ip'])}  [{hit['tld']}]")
    else:
        print(f"  {dim('None found')}")

    # Data volumes
    print(f"\n{blue('[ DATA VOLUMES TO SUSPICIOUS IPs ]')}")
    print(subdiv())
    if volumes:
        for ip, data in sorted(volumes.items(), key=lambda x: x[1]["sent"], reverse=True):
            sent_fmt = format_bytes(data['sent'])
            sent_disp = red(sent_fmt) if data['sent'] >= 1_000_000 else orange(sent_fmt)
            print(f"  {bold(ip)}")
            print(f"    Sent        : {sent_disp}")
            print(f"    Received    : {format_bytes(data['received'])}")
            print(f"    Connections : {data['connections']}")
    else:
        print(f"  {dim('No data volume information available')}")

    # Severity
    total_sent = sum(v["sent"] for v in volumes.values())
    findings   = len(http_hits) + len(tls_hits)
    print(f"\n{blue('[ SEVERITY SUMMARY ]')}")
    print(subdiv())

    if known_bad or crypto_hits or total_sent > 1_000_000:
        severity = red(bold("CRITICAL"))
    elif total_sent > 100_000 or findings > 3:
        severity = orange(bold("HIGH"))
    elif findings > 0:
        severity = orange("MEDIUM")
    else:
        severity = "LOW"

    print(f"  Confirmed malicious IOCs       : {red(str(len(known_bad))) if known_bad else str(len(known_bad))}")
    print(f"  Blockchain / crypto C2 hits    : {red(str(len(crypto_hits))) if crypto_hits else str(len(crypto_hits))}")
    print(f"  Suspicious HTTP hosts          : {red(str(len(http_hits))) if http_hits else str(len(http_hits))}")
    print(f"  Suspicious TLS domains         : {red(str(len(tls_hits))) if tls_hits else str(len(tls_hits))}")
    print(f"  Total data to suspicious IPs   : {red(format_bytes(total_sent)) if total_sent > 1_000_000 else orange(format_bytes(total_sent))}")
    print(f"  Overall severity               : {severity}")
    print(f"\n{bold(divider())}\n")


def print_unicode_report(findings, scanned, skipped, scan_path):
    print(f"\n{bold(divider())}")
    print(f"  {bold('INVISIBLE UNICODE SCAN REPORT')}")
    print(f"  {dim('Scan path : ' + scan_path)}")
    print(f"  {dim(f'Files scanned : {scanned}  |  Files skipped (non-code) : {skipped}')}")
    print(f"{bold(divider())}")

    if not findings:
        print(f"\n  {green('[ CLEAN ]')} No invisible Unicode characters detected.")
        print(f"  {dim('No PUA codepoints found in any scanned file.')}")
        print(f"\n{bold(divider())}\n")
        return

    # Group findings by file
    by_file = defaultdict(list)
    for f in findings:
        by_file[f["file"]].append(f)

    print(f"\n{red('[ INVISIBLE UNICODE DETECTED ]')} — {red(str(len(findings)))} instance(s) in {red(str(len(by_file)))} file(s)")
    print(subdiv())

    for filepath, file_findings in sorted(by_file.items()):
        print(f"\n  {red('!! FILE')} {bold(filepath)}")
        print(f"  {dim(f'{len(file_findings)} suspicious codepoint(s) found')}")
        for hit in file_findings:
            print(f"\n    Line     : {bold(str(hit['line']))}  Position: {hit['position']}")
            print(f"    Codepoint: {red(hit['codepoint'])}")
            print(f"    Range    : {orange(hit['range'])}")
            print(f"    Attack   : {red(hit['attack'])}")
            print(f"    Signature: {dim(hit['signature'])}")
            if hit['context']:
                print(f"    Context  : {dim(hit['context'])}")

    # Summary
    print(f"\n{blue('[ SCAN SUMMARY ]')}")
    print(subdiv())
    print(f"  Files scanned             : {scanned}")
    print(f"  Files with findings       : {red(str(len(by_file)))}")
    print(f"  Total codepoints flagged  : {red(str(len(findings)))}")

    ranges_found = {}
    for f in findings:
        ranges_found[f['range']] = ranges_found.get(f['range'], 0) + 1
    for range_desc, count in sorted(ranges_found.items(), key=lambda x: x[1], reverse=True):
        print(f"  {dim(range_desc + ':')} {red(str(count))}")

    print(f"\n  Severity  : {red(bold('CRITICAL'))} — Invisible Unicode in source code is an unambiguous")
    print(f"              indicator of Glassworm or similar supply chain payload injection.")
    print(f"              Quarantine affected files immediately. Do not execute or deploy.")
    print(f"\n{bold(divider())}\n")

# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

def main():
    args = sys.argv[1:]

    if not args:
        print("Usage:")
        print("  Network triage:  python3 zeek_triage.py /path/to/zeek/logs")
        print("  Unicode scan:    python3 zeek_triage.py --scan-code /path/to/source")
        print("  Both:            python3 zeek_triage.py /path/to/zeek/logs --scan-code /path/to/source")
        sys.exit(1)

    # Parse arguments
    log_dir   = None
    scan_path = None

    i = 0
    while i < len(args):
        if args[i] == "--scan-code":
            i += 1
            if i < len(args):
                scan_path = args[i]
            else:
                print("Error: --scan-code requires a path argument")
                sys.exit(1)
        else:
            log_dir = args[i]
        i += 1

    # ── Network analysis ──────────────────────────────────────
    if log_dir:
        if not os.path.isdir(log_dir):
            print(f"Error: '{log_dir}' is not a valid directory")
            sys.exit(1)

        print(f"\nAnalyzing Zeek logs in: {log_dir}")

        host        = get_host_identity(log_dir);  print(f"  [+] Host identity: done")
        username    = get_username(log_dir);        print(f"  [+] Username: done")
        known_bad   = get_known_bad_hits(log_dir);  print(f"  [+] Known bad IOCs: {len(known_bad)} matches")
        crypto_hits = get_crypto_blockchain_hits(log_dir); print(f"  [+] Blockchain/crypto: {len(crypto_hits)} hits")
        http_hits   = get_suspicious_http(log_dir); print(f"  [+] HTTP analysis: {len(http_hits)} hits")
        tls_hits    = get_suspicious_tls(log_dir);  print(f"  [+] TLS analysis: {len(tls_hits)} hits")

        suspicious_ips = set()
        for src in [known_bad, crypto_hits, http_hits, tls_hits]:
            for hit in src:
                ip = hit.get("ip") or hit.get("dst_ip") or ""
                if ip:
                    suspicious_ips.add(ip)

        volumes = get_data_volumes(log_dir, suspicious_ips)
        print_network_report(log_dir, host, username, known_bad, crypto_hits, http_hits, tls_hits, volumes)

    # ── Unicode scan ──────────────────────────────────────────
    if scan_path:
        if not os.path.exists(scan_path):
            print(f"Error: '{scan_path}' does not exist")
            sys.exit(1)

        print(f"\nScanning for invisible Unicode in: {scan_path}")
        findings, scanned, skipped = run_unicode_scan(scan_path)
        print(f"  [+] Scan complete: {scanned} files scanned, {len(findings)} findings")
        print_unicode_report(findings, scanned, skipped, scan_path)

    if not log_dir and not scan_path:
        print("Nothing to analyze. Provide a Zeek log directory and/or --scan-code path.")
        sys.exit(1)


if __name__ == "__main__":
    main()
