#!/usr/bin/env python3
# make_full_pcap_b64.py
# Full PCAP generator (base64-encoded chunks in DNS qnames, TCP noise + initial handshake)
#
# Requirements: scapy
#   pip install scapy

import time
import random
import base64
from scapy.all import (
    Ether, IP, UDP, TCP, ARP, DNS, DNSQR, DNSRR, Raw, wrpcap
)

# ---------------- CONFIG ----------------
FLAG = "securinets{th3se_4re_n0t_h0t_m1lfs}"   # <-- set your flag
CHUNK_B64_LEN = 4    # number of base64 chars per chunk (must keep <= 63 for a single DNS label)
NUM_REPEATS = 1       # repeats per chunk (1 = no redundancy)
OUTFILE = "full_challenge_b64.pcap"
BASE_DOMAIN = "evil_hot_milfs.com"                # qnames will be <base64chunk>.evil.com
SRC_IP_POOL = ["10.0.0.{}".format(i) for i in range(2, 20)]
ROUTER_IP = "10.0.0.1"
ROUTER_MAC = "52:54:00:12:34:56"
DST_IP_RESOLVER = "8.8.8.8"          # what queries have as IP.dst
BASE_SRC_MAC = "02:00:00:00:00:"     # base for src MAC (last octet randomized)
DELAY_BETWEEN_PACKETS = 0.5          # seconds between consecutive queries (must be > RESPONSE_DELAY)
RESPONSE_DELAY = 0.25                # seconds after query when DNS response arrives
START_TIME = time.time()
RANDOM_SEED = None                   # set int for deterministic results
ANSWER_IP = "93.184.216.34"          # A record returned in fake responses

# TCP flow defaults
HTTP_DST_IP = "93.184.216.34"  # server to talk to (example.com)
HTTP_DST_PORT = 80

# Noise & handshake
NOISE_TCP_FLOWS = 4   # number of random TCP noise handshakes per chunk (no payload)
INITIAL_HANDSHAKE = True  # add a TCP handshake at the very start

# ----------------------------------------

if CHUNK_B64_LEN <= 0 or CHUNK_B64_LEN > 63:
    raise ValueError("CHUNK_B64_LEN must be between 1 and 63 (DNS label length limit).")

if RANDOM_SEED is not None:
    random.seed(RANDOM_SEED)

# safety: ensure DELAY_BETWEEN_PACKETS > RESPONSE_DELAY
if RESPONSE_DELAY >= DELAY_BETWEEN_PACKETS:
    DELAY_BETWEEN_PACKETS = RESPONSE_DELAY + 0.001

# ---------------- helpers ----------------
def make_chunks_base64(flag_str, chunk_b64_len):
    """Return list of base64 string chunks (no numbering)."""
    b64 = base64.b64encode(flag_str.encode("utf-8")).decode("ascii")
    chunks = [b64[i:i+chunk_b64_len] for i in range(0, len(b64), chunk_b64_len)]
    chunks = [c for c in chunks if c]
    print(f"[+] base64 full: {b64}")
    print(f"[+] chunks (count={len(chunks)}): {chunks}")
    return chunks

def make_qname_b64(b64chunk):
    # qname: <base64chunk>.evil.com
    return f"{b64chunk}.{BASE_DOMAIN}"

def gen_mac_for_ip(src_ip, mac_map):
    """Return consistent src_mac for a given src_ip (generate once)."""
    if src_ip in mac_map:
        return mac_map[src_ip]
    last_octet = random.randint(0, 255)
    mac = BASE_SRC_MAC + ("%02x" % last_octet)
    mac_map[src_ip] = mac
    return mac

# ARP
def make_arp_request(src_ip, src_mac, target_ip, ts=None):
    eth = Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff")
    arp = ARP(op=1, hwsrc=src_mac, psrc=src_ip, hwdst="00:00:00:00:00:00", pdst=target_ip)
    pkt = eth / arp
    pkt.time = ts if ts is not None else time.time()
    return pkt

def make_arp_reply(src_ip, src_mac, target_ip, target_mac, ts=None):
    eth = Ether(src=target_mac, dst=src_mac)
    arp = ARP(op=2, hwsrc=target_mac, psrc=target_ip, hwdst=src_mac, pdst=src_ip)
    pkt = eth / arp
    pkt.time = ts if ts is not None else time.time()
    return pkt

# DNS query + response
def make_query_packet(src_ip, src_mac, dst_ip, qname, ts=None):
    src_port = random.randint(1024, 65535)
    eth = Ether(src=src_mac, dst=ROUTER_MAC)
    ip = IP(src=src_ip, dst=dst_ip, ttl=64, id=random.randint(0, 65535))
    udp = UDP(sport=src_port, dport=53)
    dns_id = random.randint(0, 0xFFFF)
    dns = DNS(id=dns_id, rd=1, qd=DNSQR(qname=qname))
    pkt = eth / ip / udp / dns
    pkt.time = ts if ts is not None else time.time()
    return pkt

def make_response_for_query(query_pkt, ip_answer=ANSWER_IP, resp_delay=RESPONSE_DELAY):
    eth = query_pkt[Ether].copy()
    eth.src, eth.dst = query_pkt[Ether].dst, query_pkt[Ether].src
    ip = IP(src=query_pkt[IP].dst, dst=query_pkt[IP].src, ttl=53, id=random.randint(0,65535))
    udp = UDP(sport=query_pkt[UDP].dport, dport=query_pkt[UDP].sport)
    qd = query_pkt[DNS].qd
    dns = DNS(
        id=query_pkt[DNS].id,
        qr=1, aa=0, ra=1,
        qd=DNSQR(qname=qd.qname),
        an=DNSRR(rrname=qd.qname, type="A", rdata=ip_answer, ttl=300)
    )
    resp = eth / ip / udp / dns
    resp.time = query_pkt.time + resp_delay
    return resp

# TCP helpers for handshake/noise/HTTP flow
def make_tcp_syn(src_ip, src_mac, dst_ip, dst_mac, src_port, dst_port, seq=None, ts=None):
    seq = seq if seq is not None else random.randint(0, 0xFFFFFFFF)
    eth = Ether(src=src_mac, dst=dst_mac)
    ip = IP(src=src_ip, dst=dst_ip, ttl=64, id=random.randint(0,65535))
    tcp = TCP(sport=src_port, dport=dst_port, flags="S", seq=seq, window=64240,
              options=[('MSS',1460), ('NOP',None), ('WScale',8), ('SAckOK','')])
    pkt = eth / ip / tcp
    pkt.time = ts if ts is not None else time.time()
    return pkt

def make_tcp_synack(src_ip, src_mac, dst_ip, dst_mac, src_port, dst_port, seq=None, ack=None, ts=None):
    seq = seq if seq is not None else random.randint(0, 0xFFFFFFFF)
    ack = 0 if ack is None else ack
    eth = Ether(src=src_mac, dst=dst_mac)
    ip = IP(src=src_ip, dst=dst_ip, ttl=64, id=random.randint(0,65535))
    tcp = TCP(sport=src_port, dport=dst_port, flags="SA", seq=seq, ack=ack, window=64240)
    pkt = eth / ip / tcp
    pkt.time = ts if ts is not None else time.time()
    return pkt

def make_tcp_ack(src_ip, src_mac, dst_ip, dst_mac, src_port, dst_port, seq, ack, ts=None):
    eth = Ether(src=src_mac, dst=dst_mac)
    ip = IP(src=src_ip, dst=dst_ip, ttl=64, id=random.randint(0,65535))
    tcp = TCP(sport=src_port, dport=dst_port, flags="A", seq=seq, ack=ack, window=64240)
    pkt = eth / ip / tcp
    pkt.time = ts if ts is not None else time.time()
    return pkt

def make_tcp_fin(src_ip, src_mac, dst_ip, dst_mac, src_port, dst_port, seq, ack, ts=None):
    eth = Ether(src=src_mac, dst=dst_mac)
    ip = IP(src=src_ip, dst=dst_ip, ttl=64, id=random.randint(0,65535))
    tcp = TCP(sport=src_port, dport=dst_port, flags="FA", seq=seq, ack=ack, window=64240)
    pkt = eth / ip / tcp
    pkt.time = ts if ts is not None else time.time()
    return pkt

def make_http_flow(src_ip, src_mac, dst_ip, dst_mac, ts,
                   src_port=None, dst_port=HTTP_DST_PORT,
                   http_path="/", host_header="example.com",
                   response_body=b"Hello world"):
    """
    Build a TCP handshake + HTTP GET + HTTP response + FIN sequence.
    ts is the starting timestamp (monotonic).
    Returns (list_of_packets, new_ts)
    """
    pkts = []
    src_port = src_port or random.randint(32768, 60999)

    cli_isn = random.randint(0, 0xFFFFFFFF)
    srv_isn = random.randint(0, 0xFFFFFFFF)

    # SYN
    syn = make_tcp_syn(src_ip, src_mac, dst_ip, dst_mac, src_port, dst_port, seq=cli_isn, ts=ts)
    pkts.append(syn)
    ts += 0.001

    # SYN-ACK
    synack = make_tcp_synack(src_ip=dst_ip, src_mac=dst_mac, dst_ip=src_ip, dst_mac=src_mac,
                             src_port=dst_port, dst_port=src_port, seq=srv_isn, ack=cli_isn + 1, ts=ts)
    pkts.append(synack)
    ts += 0.001

    # ACK (client)
    ack1 = make_tcp_ack(src_ip, src_mac, dst_ip, dst_mac, src_port, dst_port,
                        seq=cli_isn + 1, ack=srv_isn + 1, ts=ts)
    pkts.append(ack1)
    ts += 0.001

    # HTTP request (client -> server)
    http_req = (f"GET {http_path} HTTP/1.1\r\nHost: {host_header}\r\nUser-Agent: curl/7.XX\r\nAccept: */*\r\n\r\n").encode()
    req_pkt = None
    if http_req:
        req_pkt = (Ether(src=src_mac, dst=dst_mac) /
                   IP(src=src_ip, dst=dst_ip) /
                   TCP(sport=src_port, dport=dst_port, flags="PA", seq=cli_isn + 1, ack=srv_isn + 1) /
                   Raw(load=http_req))
        req_pkt.time = ts
        pkts.append(req_pkt)
    ts += 0.005

    # Server ACK
    srv_ack = make_tcp_ack(src_ip=dst_ip, src_mac=dst_mac, dst_ip=src_ip, dst_mac=src_mac,
                           src_port=dst_port, dst_port=src_port,
                           seq=srv_isn + 1, ack=cli_isn + 1 + (len(http_req) if http_req else 0), ts=ts)
    pkts.append(srv_ack)
    ts += 0.001

    # Server response
    http_resp_payload = (b"HTTP/1.1 200 OK\r\n"
                         b"Content-Length: " + str(len(response_body)).encode() + b"\r\n"
                         b"Content-Type: text/plain\r\n\r\n") + response_body
    srv_resp = (Ether(src=dst_mac, dst=src_mac) /
                IP(src=dst_ip, dst=src_ip) /
                TCP(sport=dst_port, dport=src_port, flags="PA", seq=srv_isn + 1, ack=cli_isn + 1) /
                Raw(load=http_resp_payload))
    srv_resp.time = ts
    pkts.append(srv_resp)
    ts += 0.005

    # Client ACK of response
    cli_ack2 = make_tcp_ack(src_ip, src_mac, dst_ip, dst_mac, src_port, dst_port,
                            seq=cli_isn + 1 + (len(http_req) if http_req else 0),
                            ack=srv_isn + 1 + len(http_resp_payload), ts=ts)
    pkts.append(cli_ack2)
    ts += 0.001

    # FIN from client
    fin = make_tcp_fin(src_ip, src_mac, dst_ip, dst_mac, src_port, dst_port,
                       seq=cli_isn + 1 + (len(http_req) if http_req else 0),
                       ack=srv_isn + 1 + len(http_resp_payload), ts=ts)
    pkts.append(fin)
    ts += 0.001

    # FIN-ACK server -> ack & FIN
    finack = make_tcp_ack(src_ip=dst_ip, src_mac=dst_mac, dst_ip=src_ip, dst_mac=src_mac,
                         src_port=dst_port, dst_port=src_port,
                         seq=srv_isn + 1 + len(http_resp_payload),
                         ack=cli_isn + 2 + (len(http_req) if http_req else 0), ts=ts)
    pkts.append(finack)
    ts += 0.001

    fin_from_srv = make_tcp_fin(src_ip=dst_ip, src_mac=dst_mac, dst_ip=src_ip, dst_mac=src_mac,
                                src_port=dst_port, dst_port=src_port,
                                seq=srv_isn + 1 + len(http_resp_payload),
                                ack=cli_isn + 2 + (len(http_req) if http_req else 0), ts=ts)
    pkts.append(fin_from_srv)
    ts += 0.001

    # final ACK from client
    final_ack = make_tcp_ack(src_ip, src_mac, dst_ip, dst_mac, src_port, dst_port,
                             seq=cli_isn + 2 + (len(http_req) if http_req else 0),
                             ack=srv_isn + 2 + len(http_resp_payload), ts=ts)
    pkts.append(final_ack)
    ts += 0.001

    return pkts, ts

def make_tcp_handshake_only(src_ip, src_mac, dst_ip, dst_mac, ts, src_port=None, dst_port=HTTP_DST_PORT):
    """Create SYN, SYN-ACK, ACK (no data). Returns pkts, new_ts."""
    pkts = []
    src_port = src_port or random.randint(32768, 60999)
    cli_isn = random.randint(0, 0xFFFFFFFF)
    srv_isn = random.randint(0, 0xFFFFFFFF)

    syn = make_tcp_syn(src_ip, src_mac, dst_ip, dst_mac, src_port, dst_port, seq=cli_isn, ts=ts)
    pkts.append(syn)
    ts += 0.001

    synack = make_tcp_synack(src_ip=dst_ip, src_mac=dst_mac, dst_ip=src_ip, dst_mac=src_mac,
                             src_port=dst_port, dst_port=src_port, seq=srv_isn, ack=cli_isn + 1, ts=ts)
    pkts.append(synack)
    ts += 0.001

    ack = make_tcp_ack(src_ip, src_mac, dst_ip, dst_mac, src_port, dst_port, seq=cli_isn + 1, ack=srv_isn + 1, ts=ts)
    pkts.append(ack)
    ts += 0.001

    return pkts, ts

def make_tcp_noise_flows(src_ip, src_mac, dst_ip, dst_mac, ts, count=1):
    """Create 'count' small TCP noise flows (handshake + immediate FIN from client). No payload."""
    pkts = []
    for _ in range(count):
        src_port = random.randint(32768, 60999)
        cli_isn = random.randint(0, 0xFFFFFFFF)
        srv_isn = random.randint(0, 0xFFFFFFFF)

        # SYN
        syn = make_tcp_syn(src_ip, src_mac, dst_ip, dst_mac, src_port, HTTP_DST_PORT, seq=cli_isn, ts=ts)
        pkts.append(syn)
        ts += 0.0008

        # SYN-ACK
        synack = make_tcp_synack(src_ip=dst_ip, src_mac=dst_mac, dst_ip=src_ip, dst_mac=src_mac,
                                 src_port=HTTP_DST_PORT, dst_port=src_port, seq=srv_isn, ack=cli_isn + 1, ts=ts)
        pkts.append(synack)
        ts += 0.0008

        # ACK
        ack = make_tcp_ack(src_ip, src_mac, dst_ip, dst_mac, src_port, HTTP_DST_PORT, seq=cli_isn + 1, ack=srv_isn + 1, ts=ts)
        pkts.append(ack)
        ts += 0.0008

        # immediate FIN from client
        fin = make_tcp_fin(src_ip, src_mac, dst_ip, dst_mac, src_port, HTTP_DST_PORT, seq=cli_isn + 1, ack=srv_isn + 1, ts=ts)
        pkts.append(fin)
        ts += 0.0008

        # ACK from server (finalize)
        ack_srv = make_tcp_ack(src_ip=dst_ip, src_mac=dst_mac, dst_ip=src_ip, dst_mac=src_mac,
                               src_port=HTTP_DST_PORT, dst_port=src_port, seq=srv_isn + 1, ack=cli_isn + 2, ts=ts)
        pkts.append(ack_srv)
        ts += 0.001
    return pkts, ts

# --------------- main ---------------
def main():
    chunks = make_chunks_base64(FLAG, CHUNK_B64_LEN)
    print(f"[+] FLAG encoded and split into {len(chunks)} base64 chunk(s).")
    for idx, c in enumerate(chunks):
        print(f"    chunk {idx} -> {c}")

    packets = []
    ts = START_TIME

    mac_map = {}       # src_ip -> src_mac (consistent per source IP)
    used_src_ips = set()

    # simple round-robin over source IPs
    src_ips = list(SRC_IP_POOL)
    ip_index = 0
    total_src = len(src_ips)

    # prepare MAC for first src ip
    if total_src == 0:
        raise RuntimeError("No source IPs configured in SRC_IP_POOL.")
    first_src = src_ips[0]
    first_mac = gen_mac_for_ip(first_src, mac_map)

    # ARP for first_src so initial handshake can look legit
    if INITIAL_HANDSHAKE:
        # initial ARP request/reply to make first_src "on the wire"
        arp_req = make_arp_request(src_ip=first_src, src_mac=first_mac, target_ip=ROUTER_IP, ts=ts)
        packets.append(arp_req)
        ts += 0.001
        arp_reply = make_arp_reply(src_ip=first_src, src_mac=first_mac, target_ip=ROUTER_IP, target_mac=ROUTER_MAC, ts=ts)
        packets.append(arp_reply)
        ts += 0.001
        used_src_ips.add(first_src)

        # initial TCP handshake at start
        handshake_pkts, ts = make_tcp_handshake_only(
            src_ip=first_src, src_mac=first_mac,
            dst_ip=HTTP_DST_IP, dst_mac=ROUTER_MAC,
            ts=ts
        )
        packets.extend(handshake_pkts)
        # small gap after initial handshake
        ts += 0.005

    for (idx, hexchunk) in enumerate(chunks):
        qname = make_qname_b64(hexchunk)

        for _ in range(NUM_REPEATS):
            src_ip = src_ips[ip_index % total_src]
            ip_index += 1

            # get consistent mac for this src_ip
            src_mac = gen_mac_for_ip(src_ip, mac_map)

            # emit ARP req+reply once for this src_ip (if not seen)
            if src_ip not in used_src_ips:
                used_src_ips.add(src_ip)
                arp_req = make_arp_request(src_ip=src_ip, src_mac=src_mac, target_ip=ROUTER_IP, ts=ts)
                packets.append(arp_req)
                ts += 0.001

                arp_reply = make_arp_reply(src_ip=src_ip, src_mac=src_mac, target_ip=ROUTER_IP, target_mac=ROUTER_MAC, ts=ts)
                packets.append(arp_reply)
                ts += 0.001

            # create DNS query and response
            query_pkt = make_query_packet(src_ip, src_mac, DST_IP_RESOLVER, qname, ts=ts)
            packets.append(query_pkt)

            resp_pkt = make_response_for_query(query_pkt, ip_answer=ANSWER_IP, resp_delay=RESPONSE_DELAY)
            packets.append(resp_pkt)

            # advance ts so next query is after response and respects DELAY_BETWEEN_PACKETS
            ts = max(ts + DELAY_BETWEEN_PACKETS, resp_pkt.time + 0.000001)

            # add some TCP noise flows (no payload)
            if NOISE_TCP_FLOWS > 0:
                noise_pkts, ts = make_tcp_noise_flows(
                    src_ip=src_ip, src_mac=src_mac,
                    dst_ip=HTTP_DST_IP, dst_mac=ROUTER_MAC,
                    ts=ts, count=NOISE_TCP_FLOWS
                )
                packets.extend(noise_pkts)

            # Interleave a short HTTP flow (optional) after the DNS response to simulate "normal traffic"
            # You can comment this block out if you don't want HTTP flows for every chunk.
            http_pkts, ts = make_http_flow(
                src_ip=src_ip, src_mac=src_mac,
                dst_ip=HTTP_DST_IP, dst_mac=ROUTER_MAC,
                ts=ts,
                http_path=f"/resource/{idx}",
                host_header="example.com",
                response_body=(f"Hello from server chunk {idx}").encode()
            )
            packets.extend(http_pkts)
            # ts is updated by make_http_flow

    # write pcap
    wrpcap(OUTFILE, packets)
    print(f"[+] Wrote {len(packets)} packets to {OUTFILE}")
    print("[+] Packets (qnames):")
    for i, c in enumerate(chunks):
        print("   ", make_qname_b64(c))

if __name__ == "__main__":
    main()
