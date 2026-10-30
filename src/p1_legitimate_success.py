import argparse
import select
import socket
import struct
import threading
import time

SERVER = "10.10.1.2"
LEGIT_SOURCE = "10.10.1.1"
QUERY_NAME = "test.lab.test"
LEGIT_QPS = 50
DURATION = 40
FLOOD_PORT = 53
LEGIT_PORT = 53

def make_query(txid):
    labels = QUERY_NAME.split(".")
    qname = b"".join(bytes([len(label)]) + label.encode() for label in labels) + b"\x00"
    return struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0) + qname + struct.pack("!HH", 1, 1)

def flood_worker(source_ip, rate, start_event, stop_event, stats, mode):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind((source_ip, 0))
    except OSError as exc:
        print(f"Cannot bind flood source {source_ip}: {exc}", flush=True)
        stop_event.set()
        return
    interval = 1.0 / rate
    start_event.wait()
    next_send = time.monotonic()
    while not stop_event.is_set():
        now = time.monotonic()
        elapsed = now - stats["start"]
        if elapsed >= DURATION:
            break
        active = mode == "continuous" or (10 <= elapsed < 20) or (30 <= elapsed < 40)
        if active:
            packet = make_query(stats["flood_id"] & 0xffff)
            stats["flood_id"] += 1
            try:
                sock.sendto(packet, (SERVER, FLOOD_PORT))
                with stats["lock"]:
                    stats["flood_sent"] += 1
            except OSError:
                pass
            next_send += interval
            delay = next_send - time.monotonic()
            if delay > 0:
                time.sleep(delay)
            else:
                next_send = time.monotonic()
        else:
            time.sleep(0.005)
            next_send = time.monotonic()
    sock.close()

def run(pattern, flood_sources, rate_per_source, mode):
    global SERVER, QUERY_NAME, DURATION, LEGIT_QPS
    parser = argparse.ArgumentParser(description="Measure legitimate DNS success during a controlled lab flood.")
    parser.add_argument("--server", default=SERVER)
    parser.add_argument("--duration", type=int, default=DURATION)
    parser.add_argument("--legit-qps", type=int, default=LEGIT_QPS)
    parser.add_argument("--query", default=QUERY_NAME)
    args = parser.parse_args()

    SERVER = args.server
    QUERY_NAME = args.query
    DURATION = args.duration
    LEGIT_QPS = args.legit_qps

    stats = {"start": 0.0, "flood_sent": 0, "flood_id": 1000, "lock": threading.Lock()}
    start_event = threading.Event()
    stop_event = threading.Event()
    threads = []
    for source in flood_sources:
        thread = threading.Thread(
            target=flood_worker,
            args=(source, rate_per_source, start_event, stop_event, stats, mode),
            daemon=True
        )
        thread.start()
        threads.append(thread)

    legit = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    legit.bind((LEGIT_SOURCE, 0))
    legit.setblocking(False)

    sent = 0
    noerror = 0
    other_rcode = 0
    pending = set()
    next_txid = 1
    start = time.monotonic()
    stats["start"] = start
    start_event.set()
    interval = 1.0 / LEGIT_QPS
    next_query = start
    finish = start + DURATION
    drain_until = finish + 2.0

    while time.monotonic() < drain_until:
        now = time.monotonic()
        if now < finish and now >= next_query:
            txid = next_txid & 0xffff
            next_txid += 1
            packet = make_query(txid)
            try:
                legit.sendto(packet, (SERVER, 53))
                pending.add(txid)
                sent += 1
            except OSError:
                pass
            next_query += interval
            if next_query < now - interval:
                next_query = now + interval

        timeout = 0.01
        if now < finish:
            timeout = min(timeout, max(0.0, next_query - now))
        readable, _, _ = select.select([legit], [], [], timeout)
        if readable:
            try:
                data, addr = legit.recvfrom(4096)
            except BlockingIOError:
                continue
            if addr[0] != SERVER or len(data) < 12:
                continue
            txid, flags = struct.unpack("!HH", data[:4])
            if txid not in pending or not (flags & 0x8000):
                continue
            pending.remove(txid)
            rcode = flags & 0x000f
            if rcode == 0:
                noerror += 1
            else:
                other_rcode += 1

    stop_event.set()
    for thread in threads:
        thread.join(timeout=1)
    legit.close()

    lost = sent - noerror - other_rcode
    success_rate = (noerror / sent * 100.0) if sent else 0.0
    with stats["lock"]:
        flood_sent = stats["flood_sent"]

    print("\n===== LEGITIMATE DNS RESULT =====")
    print(f"Pattern: {pattern}")
    print(f"DNS server: {SERVER}")
    print(f"Legitimate source: {LEGIT_SOURCE}")
    print(f"Legitimate query: {QUERY_NAME} A")
    print(f"Legitimate query rate: {LEGIT_QPS} QPS")
    print(f"Test duration: {DURATION} seconds")
    print(f"Legitimate queries sent: {sent}")
    print(f"NOERROR responses received: {noerror}")
    print(f"Other DNS response codes: {other_rcode}")
    print(f"No response / timed out: {lost}")
    print(f"Legitimate DNS success rate: {success_rate:.2f}%")
    print(f"Flood packets sent by generator: {flood_sent}")
    print("=================================")
    print("Success rate is NOERROR responses divided by legitimate queries sent.")
    print("Check that the flood and legitimate source IPs are configured on node0.")


if __name__ == "__main__":
    run("P1 single-source continuous flood", ["10.10.1.101"], 3000, "continuous")
