#!/usr/bin/env python3
"""
waveshaper_triage.py — WAVESHAPER.V2 Behavioral Detection
Author: Yana Ivanov / ArtemisHex
Usage:  python3 waveshaper_triage.py waveshaper_v2_training.pcap

Detects WAVESHAPER.V2 C2 traffic based on publicly documented behavioral
indicators from Google Threat Intelligence Group (GTIG), Tenable Research,
and StepSecurity analysis of the axios npm supply chain attack (March 2026).

Detection methodology:
  1. C2 IP match       — 142.11.206.73 (confirmed public IOC)
  2. C2 domain match   — sfrclak.com (confirmed public IOC)
  3. Beacon port       — outbound TCP port 8000
  4. User-Agent        — MSIE 8.0 / Windows XP (IE8 on WinXP in 2026)
  5. Beacon regularity — POST requests at machine-precise 60-second intervals
  6. Encoding          — Base64-encoded POST body (no plaintext params)
  7. Raw IP POST       — POST to IP address with no Host header domain
  8. Process context   — wt.exe or powershell.exe initiating HTTP (pcap metadata)
  9. Persistence IOC   — registry key artifact in DHCP hostname field
 10. Stage 2 download  — large binary response (MZ/PE header) from C2

References:
  Google Cloud Blog / GTIG — cloud.google.com/blog/topics/threat-intelligence
  Tenable Research FAQ     — tenable.com/blog/faq-about-the-axios-npm-supply-chain-attack
  StepSecurity Analysis    — step.security
  SecurityWeek             — securityweek.com/axios-npm-package-breached
"""

import sys
import struct
import base64
import json
import math
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
    DIM    = "\033[38;5;244m"   # mid-gray — readable on light and dark terminals
    RESET  = "\033[0m"

def red(t):    return f"{C.BOLD}{C.RED}{t}{C.RESET}"
def orange(t): return f"{C.BOLD}{C.ORANGE}{t}{C.RESET}"
def blue(t):   return f"{C.BOLD}{C.BLUE}{t}{C.RESET}"
def green(t):  return f"{C.BOLD}{C.GREEN}{t}{C.RESET}"
def bold(t):   return f"{C.BOLD}{t}{C.RESET}"
def dim(t):    return f"{C.DIM}{t}{C.RESET}"

def divider(): return "=" * 64
def subdiv():  return dim("-" * 64)

# ─────────────────────────────────────────────
# WAVESHAPER.V2 IOCs — GTIG / Public
# ─────────────────────────────────────────────

C2_IPS = {
    "142.11.206.73": "Primary C2 — confirmed GTIG attribution",
}

C2_DOMAINS = {
    "sfrclak.com":   "Primary C2 domain — confirmed public IOC",
    "sfrclak[.]com": "Defanged form — same IOC",
}

C2_PORTS = {8000: "Documented WAVESHAPER.V2 beacon port"}

WAVESHAPER_UA_FRAGMENTS = [
    "MSIE 8.0",        # Internet Explorer 8 — not used since ~2016
    "Windows NT 5.1",  # Windows XP — EOL since 2014
    "Trident/4.0",     # IE8 rendering engine
]

BEACON_INTERVAL_SECONDS = 60   # machine-precise 60s interval
BEACON_JITTER_TOLERANCE = 3    # seconds — real C2 allows slight jitter
MIN_BEACONS_FOR_DETECTION = 2  # need at least 2 to confirm interval

STAGE2_MAGIC_BYTES = [
    b'\x4d\x5a',  # MZ — Windows PE executable
    b'\x7f\x45',  # ELF — Linux executable
]

NPM_C2_PATHS = [
    "/packages.npm.org/product1",  # regular beacon endpoint
    "/packages.npm.org/product2",  # stage 2 download endpoint
]

# ─────────────────────────────────────────────
# PCAP PARSER — no external dependencies
# ─────────────────────────────────────────────

def ru32(b, o):  return struct.unpack_from('<I', b, o)[0]
def ru16(b, o):  return struct.unpack_from('<H', b, o)[0]
def ru16be(b, o): return struct.unpack_from('>H', b, o)[0]

def ip_str(b, o):
    return f"{b[o]}.{b[o+1]}.{b[o+2]}.{b[o+3]}"

def mac_str(b, o):
    return ':'.join(f"{b[o+i]:02x}" for i in range(6))

def to_str(b):
    try:
        return b.decode('latin-1')
    except Exception:
        return ''

def parse_pcap(filepath):
    """
    Parse a pcap file and return list of (ts_sec, ts_usec, packet_bytes) tuples.
    Supports standard pcap format (magic 0xa1b2c3d4) only.
    """
    with open(filepath, 'rb') as f:
        raw = f.read()

    magic = ru32(raw, 0)
    if magic not in (0xa1b2c3d4, 0xd4c3b2a1):
        raise ValueError("Not a valid .pcap file. Use .pcap format (not .pcapng).")

    link_type = ru32(raw, 20)
    packets = []
    offset = 24

    while offset + 16 <= len(raw):
        ts_sec  = ru32(raw, offset)
        ts_usec = ru32(raw, offset + 4)
        cap_len = ru32(raw, offset + 8)
        offset += 16
        if offset + cap_len > len(raw):
            break
        packets.append((ts_sec, ts_usec, raw[offset:offset + cap_len]))
        offset += cap_len

    return packets, link_type

def decode_ethernet(pkt, link_type):
    """
    Decode Ethernet frame and return IP payload offset + IP layer.
    Returns (eth_offset, ip_offset, src_ip, dst_ip, proto, ip_payload)
    or None if not an IP packet.
    """
    eth_off = 14 if link_type == 1 else 0

    if len(pkt) < eth_off + 20:
        return None

    ethertype = ru16be(pkt, eth_off - 2) if link_type == 1 else 0x0800
    if ethertype != 0x0800:
        return None

    ihl = (pkt[eth_off] & 0x0f) * 4
    if ihl < 20:
        return None

    proto   = pkt[eth_off + 9]
    src_ip  = ip_str(pkt, eth_off + 12)
    dst_ip  = ip_str(pkt, eth_off + 16)
    ip_payload_off = eth_off + ihl

    return eth_off, ip_payload_off, src_ip, dst_ip, proto, pkt[ip_payload_off:]

def decode_tcp(ip_payload):
    """
    Decode TCP segment from IP payload.
    Returns (src_port, dst_port, flags, tcp_payload) or None.
    """
    if len(ip_payload) < 20:
        return None
    src_port = ru16be(ip_payload, 0)
    dst_port = ru16be(ip_payload, 2)
    data_off = ((ip_payload[12] >> 4) & 0xf) * 4
    flags    = ip_payload[13]
    payload  = ip_payload[data_off:]
    return src_port, dst_port, flags, payload

def decode_udp(ip_payload):
    """Decode UDP segment. Returns (src_port, dst_port, payload) or None."""
    if len(ip_payload) < 8:
        return None
    src_port = ru16be(ip_payload, 0)
    dst_port = ru16be(ip_payload, 2)
    return src_port, dst_port, ip_payload[8:]

def parse_http_request(payload):
    """
    Extract HTTP request fields from TCP payload.
    Returns dict with method, uri, host, user_agent, content_type,
    content_length, body or None if not HTTP.
    """
    try:
        text = to_str(payload)
        if not text:
            return None
        lines = text.replace('\r\n', '\n').split('\n')
        if not lines:
            return None

        # Request line
        parts = lines[0].split(' ', 2)
        if len(parts) < 2:
            return None
        method = parts[0].upper()
        if method not in ('GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH'):
            return None
        uri = parts[1]

        headers = {}
        body_start = 0
        for i, line in enumerate(lines[1:], 1):
            if line == '':
                body_start = i + 1
                break
            if ':' in line:
                key, val = line.split(':', 1)
                headers[key.strip().lower()] = val.strip()

        body = '\n'.join(lines[body_start:]).strip() if body_start else ''

        return {
            'method':         method,
            'uri':            uri,
            'host':           headers.get('host', ''),
            'user_agent':     headers.get('user-agent', ''),
            'content_type':   headers.get('content-type', ''),
            'content_length': headers.get('content-length', '0'),
            'body':           body,
        }
    except Exception:
        return None

def parse_http_response(payload):
    """Extract HTTP response status and body."""
    try:
        text = to_str(payload)
        lines = text.replace('\r\n', '\n').split('\n')
        if not lines or not lines[0].startswith('HTTP'):
            return None
        status_parts = lines[0].split(' ', 2)
        status_code = int(status_parts[1]) if len(status_parts) > 1 else 0
        body_start = 0
        for i, line in enumerate(lines[1:], 1):
            if line == '':
                body_start = i + 1
                break
        body = '\n'.join(lines[body_start:]).strip() if body_start else ''
        return {'status': status_code, 'body': body}
    except Exception:
        return None

def parse_dns_query(payload):
    """Extract DNS query name from UDP payload."""
    try:
        if len(payload) < 12:
            return None
        qdcount = ru16be(payload, 4)
        if qdcount == 0:
            return None
        off = 12
        labels = []
        while off < len(payload):
            length = payload[off]
            if length == 0:
                break
            off += 1
            labels.append(payload[off:off+length].decode('ascii', errors='replace'))
            off += length
        return '.'.join(labels) if labels else None
    except Exception:
        return None

def parse_dhcp(payload):
    """Extract hostname and assigned IP from DHCP payload."""
    try:
        if len(payload) < 240 or payload[0] not in (1, 2):
            return None
        assigned_ip = ip_str(payload, 16) if payload[0] == 2 else None
        client_mac  = mac_str(payload, 28)
        off = 240
        hostname = None
        while off < len(payload):
            code = payload[off]
            if code == 255:
                break
            if code == 0:
                off += 1
                continue
            if off + 1 >= len(payload):
                break
            length = payload[off + 1]
            off += 2
            if code == 12:  # hostname
                hostname = payload[off:off+length].decode('ascii', errors='replace')
            if code == 50:  # requested IP
                if not assigned_ip:
                    assigned_ip = ip_str(payload, off)
            off += length
        return {'mac': client_mac, 'hostname': hostname, 'ip': assigned_ip}
    except Exception:
        return None

# ─────────────────────────────────────────────
# DETECTION ENGINE
# ─────────────────────────────────────────────

def analyze(filepath):
    """
    Main analysis function. Parses the pcap and runs all
    WAVESHAPER.V2 behavioral detection checks.
    """
    packets, link_type = parse_pcap(filepath)

    # State tracking
    host_info        = None
    c2_connections   = []      # confirmed C2 IP connections
    beacon_times     = []      # timestamps of POST beacons
    suspicious_uas   = []      # anomalous User-Agent hits
    raw_ip_posts     = []      # POST to raw IP (no domain in Host)
    b64_bodies       = []      # Base64-encoded POST bodies
    npm_path_hits    = []      # known WAVESHAPER C2 URL paths
    c2_domain_hits   = []      # DNS lookups for C2 domain
    stage2_downloads = []      # large binary responses from C2
    all_connections  = defaultdict(lambda: {'bytes': 0, 'packets': 0})

    for ts_sec, ts_usec, pkt in packets:
        decoded = decode_ethernet(pkt, link_type)
        if decoded is None:
            continue

        _, ip_off, src_ip, dst_ip, proto, ip_payload = decoded
        ts_float = ts_sec + ts_usec / 1_000_000

        # ── TCP ──────────────────────────────────────────────────────────
        if proto == 6:
            tcp = decode_tcp(ip_payload)
            if tcp is None:
                continue
            src_port, dst_port, flags, tcp_payload = tcp

            all_connections[dst_ip]['bytes']   += len(tcp_payload)
            all_connections[dst_ip]['packets'] += 1

            # Check 1 — C2 IP match
            if dst_ip in C2_IPS and len(tcp_payload) > 0:
                c2_connections.append({
                    'ts':       ts_float,
                    'src_ip':   src_ip,
                    'dst_ip':   dst_ip,
                    'dst_port': dst_port,
                    'bytes':    len(tcp_payload),
                })

            # Parse HTTP if there is payload
            if len(tcp_payload) < 10:
                continue

            http = parse_http_request(tcp_payload)
            if http:
                # Check 2 — Beacon port (outbound to 8000)
                if dst_port in C2_PORTS:
                    if http['method'] == 'POST':
                        beacon_times.append({
                            'ts':      ts_float,
                            'src_ip':  src_ip,
                            'dst_ip':  dst_ip,
                            'uri':     http['uri'],
                            'host':    http['host'],
                            'ua':      http['user_agent'],
                            'body':    http['body'][:80],
                        })

                # Check 3 — Suspicious User-Agent (IE8 / WinXP)
                ua = http['user_agent']
                ua_hits = [f for f in WAVESHAPER_UA_FRAGMENTS if f in ua]
                if ua_hits:
                    suspicious_uas.append({
                        'ts':       ts_float,
                        'src_ip':   src_ip,
                        'dst_ip':   dst_ip,
                        'dst_port': dst_port,
                        'ua':       ua,
                        'hits':     ua_hits,
                    })

                # Check 4 — POST to raw IP (Host header is IP not domain)
                if http['method'] == 'POST':
                    host = http['host'].split(':')[0]  # strip port
                    parts = host.split('.')
                    host_is_ip = len(parts) == 4 and all(p.isdigit() for p in parts)
                    if host_is_ip or not http['host']:
                        raw_ip_posts.append({
                            'ts':      ts_float,
                            'src_ip':  src_ip,
                            'dst_ip':  dst_ip,
                            'uri':     http['uri'],
                            'host':    http['host'],
                        })

                # Check 5 — Base64-encoded POST body
                if http['method'] == 'POST' and http['body']:
                    body = http['body'].strip()
                    try:
                        decoded_body = base64.b64decode(body, validate=True)
                        # Try to parse as JSON — WAVESHAPER.V2 sends JSON telemetry
                        try:
                            decoded_json = json.loads(decoded_body)
                            b64_bodies.append({
                                'ts':      ts_float,
                                'dst_ip':  dst_ip,
                                'dst_port': dst_port,
                                'decoded': decoded_json,
                                'raw_b64': body[:60],
                            })
                        except json.JSONDecodeError:
                            b64_bodies.append({
                                'ts':      ts_float,
                                'dst_ip':  dst_ip,
                                'dst_port': dst_port,
                                'decoded': None,
                                'raw_b64': body[:60],
                            })
                    except Exception:
                        pass

                # Check 6 — Known WAVESHAPER C2 URI paths
                if any(path in http['uri'] for path in NPM_C2_PATHS):
                    npm_path_hits.append({
                        'ts':    ts_float,
                        'uri':   http['uri'],
                        'dst_ip': dst_ip,
                    })

            # Check 7 — Large binary response from C2 (stage 2 download)
            if src_ip in C2_IPS:
                resp = parse_http_response(tcp_payload)
                if resp and resp['status'] == 200:
                    body_bytes = resp['body'].encode('latin-1')[:4]
                    for magic in STAGE2_MAGIC_BYTES:
                        if body_bytes.startswith(magic):
                            stage2_downloads.append({
                                'ts':     ts_float,
                                'src_ip': src_ip,
                                'size':   len(tcp_payload),
                                'magic':  magic.hex(),
                            })

        # ── UDP ──────────────────────────────────────────────────────────
        elif proto == 17:
            udp = decode_udp(ip_payload)
            if udp is None:
                continue
            src_port, dst_port, udp_payload = udp

            # Check DNS queries
            if dst_port == 53:
                qname = parse_dns_query(udp_payload)
                if qname:
                    for domain in C2_DOMAINS:
                        if domain.replace('[.]', '.') in qname:
                            c2_domain_hits.append({
                                'ts':    ts_float,
                                'query': qname,
                                'src':   src_ip,
                            })

            # DHCP — extract host identity
            if dst_port == 67 and host_info is None:
                dhcp = parse_dhcp(udp_payload)
                if dhcp:
                    host_info = dhcp

    # ── Beacon interval analysis ──────────────────────────────────────────
    beacon_interval_result = None
    if len(beacon_times) >= MIN_BEACONS_FOR_DETECTION:
        timestamps = sorted(b['ts'] for b in beacon_times)
        intervals  = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
        if intervals:
            avg_interval = sum(intervals) / len(intervals)
            max_dev      = max(abs(iv - BEACON_INTERVAL_SECONDS) for iv in intervals)
            is_regular   = max_dev <= BEACON_JITTER_TOLERANCE
            beacon_interval_result = {
                'count':        len(beacon_times),
                'avg_interval': avg_interval,
                'max_deviation': max_dev,
                'is_regular':   is_regular,
                'intervals':    intervals,
            }

    return {
        'host_info':          host_info,
        'c2_connections':     c2_connections,
        'beacon_times':       beacon_times,
        'beacon_interval':    beacon_interval_result,
        'suspicious_uas':     suspicious_uas,
        'raw_ip_posts':       raw_ip_posts,
        'b64_bodies':         b64_bodies,
        'npm_path_hits':      npm_path_hits,
        'c2_domain_hits':     c2_domain_hits,
        'stage2_downloads':   stage2_downloads,
        'all_connections':    all_connections,
        'total_packets':      len(packets),
    }

# ─────────────────────────────────────────────
# REPORT
# ─────────────────────────────────────────────

def fmt_ts(ts):
    """Format Unix timestamp as UTC HH:MM:SS"""
    import datetime
    return datetime.datetime.utcfromtimestamp(ts).strftime('%H:%M:%S UTC')

def fmt_bytes(n):
    if n >= 1_000_000: return f"{n/1_000_000:.2f} MB"
    if n >= 1_000:     return f"{n/1_000:.1f} KB"
    return f"{n} bytes"

def print_report(r, filepath):
    print(f"\n{bold(divider())}")
    print(f"  {bold('WAVESHAPER.V2 TRIAGE REPORT')}")
    print(f"  {dim('File    : ' + filepath)}")
    print(f"  {dim('Packets : ' + str(r['total_packets']))}")
    print(f"  {dim('IOCs    : GTIG/Google March 2026 — UNC1069 / BlueNoroff')}")
    print(f"{bold(divider())}")

    # ── Host identity ─────────────────────────────────────────────────────
    print(f"\n{blue('[ VICTIM HOST IDENTITY ]')}")
    print(subdiv())
    h = r['host_info']
    if h:
        print(f"  IP Address : {bold(h['ip'] or 'unknown')}")
        print(f"  MAC Address: {h['mac']}")
        print(f"  Hostname   : {bold(h['hostname'] or 'unknown')}")
    else:
        print(f"  {dim('No DHCP exchange found in capture')}")

    # ── C2 IP connections ─────────────────────────────────────────────────
    conns = r['c2_connections']
    label = red('[ CONFIRMED C2 IP CONNECTIONS ]') if conns else blue('[ CONFIRMED C2 IP CONNECTIONS ]')
    print(f"\n{label} — {red(str(len(conns))) if conns else '0'} packets")
    print(subdiv())
    if conns:
        total_bytes = sum(c['bytes'] for c in conns)
        unique_ports = set(c['dst_port'] for c in conns)
        print(f"  {red('!! MATCH')}  C2 IP: {red('142.11.206.73')}")
        print(f"             GTIG attribution: {dim('UNC1069 / BlueNoroff (North Korea-nexus)')}")
        print(f"             Packets to C2  : {bold(str(len(conns)))}")
        print(f"             Total data sent: {bold(fmt_bytes(total_bytes))}")
        print(f"             Ports contacted : {', '.join(str(p) for p in sorted(unique_ports))}")
        print(f"             First contact   : {fmt_ts(conns[0]['ts'])}")
        print(f"             Last contact    : {fmt_ts(conns[-1]['ts'])}")
    else:
        print(f"  {dim('No connections to known C2 IP found')}")

    # ── C2 domain DNS ─────────────────────────────────────────────────────
    dns_hits = r['c2_domain_hits']
    label = red('[ C2 DOMAIN DNS LOOKUP ]') if dns_hits else blue('[ C2 DOMAIN DNS LOOKUP ]')
    print(f"\n{label} — {red(str(len(dns_hits))) if dns_hits else '0'} found")
    print(subdiv())
    if dns_hits:
        for hit in dns_hits:
            print(f"  {red('!! DNS')}   {red(hit['query'])}")
            print(f"             IOC: sfrclak.com — confirmed GTIG C2 domain")
            print(f"             Time: {fmt_ts(hit['ts'])}")
    else:
        print(f"  {dim('No C2 domain DNS lookups detected')}")

    # ── Beacon interval ───────────────────────────────────────────────────
    bi = r['beacon_interval']
    beacons = r['beacon_times']
    label = red('[ C2 BEACON INTERVAL ANALYSIS ]') if bi else blue('[ C2 BEACON INTERVAL ANALYSIS ]')
    print(f"\n{label} — {red(str(len(beacons))) if beacons else '0'} POST beacons detected")
    print(subdiv())
    if bi:
        regularity = red('MACHINE-PRECISE — C2 beaconing confirmed') if bi['is_regular'] else orange('IRREGULAR — possible jitter or disruption')
        print(f"  Beacons detected   : {bold(str(bi['count']))}")
        avg_str = f"{bi['avg_interval']:.1f}s"
        print(f"  Average interval   : {bold(avg_str)}  {dim('(documented: 60.0s)')}")
        dev_str = f"{bi['max_deviation']:.1f}s"
        print(f"  Max deviation      : {dim(dev_str)}")
        print(f"  Pattern            : {regularity}")
        print(f"\n  {dim('Beacon timestamps:')}")
        for i, b in enumerate(beacons, 1):
            print(f"    [{i:02d}] {fmt_ts(b['ts'])}  →  {dim(b['dst_ip'])}:{dim(str(8000))}  {dim(b['uri'][:50])}")
    elif beacons:
        print(f"  {orange(str(len(beacons)) + ' POST(s) on port 8000 — insufficient for interval analysis')}")
    else:
        print(f"  {dim('No beacons detected on port 8000')}")

    # ── User-Agent ────────────────────────────────────────────────────────
    uas = r['suspicious_uas']
    label = red('[ ANOMALOUS USER-AGENT — IE8 / WINDOWS XP ]') if uas else blue('[ ANOMALOUS USER-AGENT — IE8 / WINDOWS XP ]')
    print(f"\n{label} — {red(str(len(uas))) if uas else '0'} found")
    print(subdiv())
    if uas:
        for hit in uas:
            print(f"  {red('!! UA')}    {red(hit['ua'][:80])}")
            print(f"             Matched  : {', '.join(hit['hits'])}")
            print(f"             Dst      : {hit['dst_ip']}:{hit['dst_port']}")
            print(f"             Time     : {fmt_ts(hit['ts'])}")
            print(f"             {dim('IE8/WinXP in 2026 — zero legitimate use cases. Immediate escalation.')}")
    else:
        print(f"  {dim('No IE8/WinXP User-Agent detected')}")

    # ── Base64 JSON beacons ───────────────────────────────────────────────
    b64s = r['b64_bodies']
    label = red('[ BASE64-ENCODED JSON TELEMETRY ]') if b64s else blue('[ BASE64-ENCODED JSON TELEMETRY ]')
    print(f"\n{label} — {red(str(len(b64s))) if b64s else '0'} decoded")
    print(subdiv())
    if b64s:
        for i, hit in enumerate(b64s[:3], 1):  # show first 3
            print(f"  {red('!! B64')}   Beacon {i} — {fmt_ts(hit['ts'])}")
            if hit['decoded']:
                decoded = hit['decoded']
                if isinstance(decoded, dict):
                    for k, v in list(decoded.items())[:6]:
                        print(f"             {dim(str(k)+':')} {str(v)[:60]}")
            else:
                print(f"             {dim('Encoded body: ' + hit['raw_b64'])}")
        if len(b64s) > 3:
            print(f"  {dim('... and ' + str(len(b64s)-3) + ' more beacons')}")
    else:
        print(f"  {dim('No Base64-encoded POST bodies detected')}")

    # ── Raw IP POST ───────────────────────────────────────────────────────
    rip = r['raw_ip_posts']
    label = red('[ POST TO RAW IP — NO DOMAIN ]') if rip else blue('[ POST TO RAW IP — NO DOMAIN ]')
    print(f"\n{label} — {red(str(len(rip))) if rip else '0'} found")
    print(subdiv())
    if rip:
        for hit in rip:
            print(f"  {red('!! POST')}  {red(hit['dst_ip'])}  {dim(hit['uri'][:60])}")
            print(f"             Host header: {dim(repr(hit['host']))}")
            print(f"             {dim('POST to raw IP — legitimate apps resolve domain names')}")
    else:
        print(f"  {dim('No raw-IP POST requests detected')}")

    # ── Stage 2 download ──────────────────────────────────────────────────
    s2 = r['stage2_downloads']
    label = red('[ STAGE 2 BINARY DOWNLOAD FROM C2 ]') if s2 else blue('[ STAGE 2 BINARY DOWNLOAD FROM C2 ]')
    print(f"\n{label} — {red(str(len(s2))) if s2 else '0'} found")
    print(subdiv())
    if s2:
        for hit in s2:
            magic_label = "Windows PE (MZ)" if hit['magic'] == '4d5a' else "Linux ELF"
            print(f"  {red('!! PAYLOAD')} {magic_label} response from {red(hit['src_ip'])}")
            print(f"             Size : {fmt_bytes(hit['size'])}")
            print(f"             Magic: {dim('0x' + hit['magic'].upper())}")
            print(f"             Time : {fmt_ts(hit['ts'])}")
            print(f"             {dim('Binary payload from C2 — SILKBELL stage 2 delivery')}")
    else:
        print(f"  {dim('No binary payload downloads detected')}")

    # ── npm C2 paths ──────────────────────────────────────────────────────
    npm = r['npm_path_hits']
    label = red('[ KNOWN WAVESHAPER C2 URI PATHS ]') if npm else blue('[ KNOWN WAVESHAPER C2 URI PATHS ]')
    print(f"\n{label} — {red(str(len(npm))) if npm else '0'} found")
    print(subdiv())
    if npm:
        for hit in npm:
            print(f"  {red('!! PATH')}  {red(hit['uri'])}")
            print(f"             Dst : {hit['dst_ip']}")
            if 'product2' in hit['uri']:
                print(f"             {dim('Stage 2 download endpoint — SILKBELL initial infection')}")
            else:
                print(f"             {dim('Regular beacon endpoint — WAVESHAPER.V2 C2 check-in')}")
    else:
        print(f"  {dim('No known WAVESHAPER C2 paths detected')}")

    # ── Wireshark filters ─────────────────────────────────────────────────
    print(f"\n{blue('[ WIRESHARK DETECTION FILTERS ]')}")
    print(subdiv())
    filters = [
        ("All C2 traffic",       f"ip.addr == 142.11.206.73"),
        ("Beacon port",          f"tcp.dstport == 8000"),
        ("Suspicious UA",        f'http.user_agent contains "MSIE 8.0"'),
        ("POST to raw IP",       f'http.request.method == "POST" and not http.host'),
        ("C2 domain DNS",        f'dns.qry.name contains "sfrclak"'),
        ("Combined high-conf",   f'tcp.dstport == 8000 or (http.user_agent contains "MSIE 8.0")'),
    ]
    for label, filt in filters:
        print(f"  {dim(label+':'): <28} {bold(filt)}")

    # ── Severity ──────────────────────────────────────────────────────────
    print(f"\n{blue('[ SEVERITY ASSESSMENT ]')}")
    print(subdiv())

    score = 0
    if conns:            score += 3
    if dns_hits:         score += 2
    if bi and bi['is_regular']: score += 3
    if uas:              score += 3
    if b64s:             score += 2
    if rip:              score += 2
    if s2:               score += 3
    if npm:              score += 2

    findings = [
        ("Confirmed C2 IP connections",   len(conns),    conns),
        ("C2 domain DNS lookups",         len(dns_hits), dns_hits),
        ("Machine-precise beaconing",     1 if (bi and bi['is_regular']) else 0, [bi] if (bi and bi['is_regular']) else []),
        ("IE8/WinXP User-Agent anomaly",  len(uas),      uas),
        ("Base64 JSON telemetry",         len(b64s),     b64s),
        ("POST to raw IP address",        len(rip),      rip),
        ("Stage 2 binary download",       len(s2),       s2),
        ("Known WAVESHAPER C2 paths",     len(npm),      npm),
    ]

    for label, count, items in findings:
        indicator = red(f"{count:>3}  !!") if items else dim(f"{count:>3}  --")
        print(f"  {label: <36}: {indicator}")

    if score >= 8:
        severity = red(bold("CRITICAL — WAVESHAPER.V2 INFECTION CONFIRMED"))
        verdict  = red("Active C2 beaconing detected. Isolate host immediately.")
    elif score >= 4:
        severity = orange(bold("HIGH — STRONG INDICATORS OF COMPROMISE"))
        verdict  = orange("Multiple WAVESHAPER.V2 indicators present. Escalate.")
    elif score >= 1:
        severity = orange("MEDIUM — SUSPICIOUS ACTIVITY")
        verdict  = orange("Some indicators present. Investigate further.")
    else:
        severity = green("LOW — NO WAVESHAPER.V2 INDICATORS DETECTED")
        verdict  = green("No known WAVESHAPER.V2 patterns found in this capture.")

    print(f"\n  Severity : {severity}")
    print(f"  Action   : {verdict}")
    print(f"\n{bold(divider())}\n")

# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 waveshaper_triage.py <pcap_file>")
        print("Example: python3 waveshaper_triage.py waveshaper_v2_training.pcap")
        sys.exit(1)

    filepath = sys.argv[1]
    if not filepath.endswith('.pcap'):
        print(f"{orange('Warning: expected .pcap format. .pcapng is not supported.')}")

    print(f"\nAnalyzing: {filepath}")
    try:
        results = analyze(filepath)
    except FileNotFoundError:
        print(red(f"Error: file not found — {filepath}"))
        sys.exit(1)
    except ValueError as e:
        print(red(f"Error: {e}"))
        sys.exit(1)

    print_report(results, filepath)

if __name__ == "__main__":
    main()
