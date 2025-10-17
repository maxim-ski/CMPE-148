import os
import socket
import struct
import time
import select
import statistics
import argparse
import sys

ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REPLY   = 0
ICMP_CODE         = 0

def checksum(data: bytes) -> int:

    if len(data) % 2:
        data += b'\x00'
    s = 0
    for i in range(0, len(data), 2):
        word = data[i] << 8 | data[i+1]
        s = (s + word) & 0xffffffff

    while (s >> 16):
        s = (s & 0xffff) + (s >> 16)
    s = ~s & 0xffff
    return s

def build_packet(ident: int, seq: int, payload_size: int = 32) -> bytes:

    header = struct.pack('!BBHHH', ICMP_ECHO_REQUEST, ICMP_CODE, 0, ident, seq)
    send_time = struct.pack('!d', time.time())
    pad = bytes(max(0, payload_size - len(send_time)))
    data = send_time + pad
    csum = checksum(header + data)
    header = struct.pack('!BBHHH', ICMP_ECHO_REQUEST, ICMP_CODE, csum, ident, seq)
    return header + data

def parse_reply(packet: bytes, ident: int, seq: int):

    if len(packet) < 20:
        return None
    ip_header_len = (packet[0] & 0x0F) * 4
    icmp = packet[ip_header_len:]
    if len(icmp) < 8:
        return None

    icmp_type, icmp_code, recv_checksum, recv_id, recv_seq = struct.unpack('!BBHHH', icmp[:8])
    if icmp_type != ICMP_ECHO_REPLY or icmp_code != ICMP_CODE:
        return None
    if recv_id != ident or recv_seq != seq:
        return None


    if len(icmp) < 8 + 8:
        return None
    send_time = struct.unpack('!d', icmp[8:16])[0]
    rtt = time.time() - send_time
    return rtt

def do_ping(dest_host: str, count: int, timeout: float, interval: float, ttl: int, payload_size: int):

    try:
        dest_addr = socket.gethostbyname(dest_host)
    except socket.gaierror as e:
        print(f"Cannot resolve {dest_host}: {e}")
        return 1

    print(f"PING {dest_host} ({dest_addr}): {payload_size} data bytes")


    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except PermissionError:
        print("Error: raw sockets require administrator/root privileges.", file=sys.stderr)
        return 1


    sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
    sock.settimeout(timeout)

    ident = os.getpid() & 0xFFFF
    rtts = []
    sent = 0
    received = 0

    for seq in range(1, count + 1):
        packet = build_packet(ident, seq, payload_size)
        sent += 1
        try:
            sock.sendto(packet, (dest_addr, 0))
            start = time.time()


            timeout_left = timeout
            rtt = None
            while timeout_left > 0:
                ready, _, _ = select.select([sock], [], [], timeout_left)
                if not ready:
                    break  # timeout
                recv_packet, addr = sock.recvfrom(65535)
                rtt = parse_reply(recv_packet, ident, seq)
                if rtt is not None:
                    break

                timeout_left = timeout - (time.time() - start)

            if rtt is not None:
                received += 1
                rtts.append(rtt * 1000.0)
                print(f"{len(packet)} bytes from {dest_addr}: icmp_seq={seq} ttl={ttl} time={rtt*1000:.3f} ms")
            else:
                print(f"Request timeout for icmp_seq {seq}")
        except socket.timeout:
            print(f"Request timeout for icmp_seq {seq}")
        except OSError as e:
            print(f"Send/recv error: {e}")
            break

        if seq != count:
            sleep_left = interval - (time.time() - start)
            if sleep_left > 0:
                time.sleep(sleep_left)

    sock.close()

    loss = 100.0 * (sent - received) / max(1, sent)
    print(f"\n--- {dest_host} ping statistics ---")
    print(f"{sent} packets transmitted, {received} packets received, {loss:.1f}% packet loss")
    if rtts:
        mn = min(rtts)
        mx = max(rtts)
        avg = statistics.mean(rtts)
        sd = statistics.pstdev(rtts)
        print(f"round-trip min/avg/max/stddev = {mn:.3f}/{avg:.3f}/{mx:.3f}/{sd:.3f} ms")

    return 0

def main():
    parser = argparse.ArgumentParser(description="ICMP Ping (educational)")
    parser.add_argument("host", help="destination hostname or IPv4 address")
    parser.add_argument("-c", "--count", type=int, default=4, help="number of echo requests (default 4)")
    parser.add_argument("-W", "--timeout", type=float, default=1.0, help="per-packet timeout seconds (default 1.0)")
    parser.add_argument("-i", "--interval", type=float, default=1.0, help="interval between pings seconds (default 1.0)")
    parser.add_argument("-t", "--ttl", type=int, default=64, help="IP time-to-live (default 64)")
    parser.add_argument("-s", "--size", type=int, default=32, help="payload size in bytes (default 32)")
    args = parser.parse_args()

    sys.exit(do_ping(args.host, args.count, args.timeout, args.interval, args.ttl, args.size))

if __name__ == "__main__":

    main()
