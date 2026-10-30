# PS-022: eBPF/XDP Rate Limiting for DNS Query Floods

## 1. Project Overview

This project implements an eBPF-based XDP rate limiter to protect a Linux DNS server against high-volume UDP DNS query floods.

XDP processes packets at the network interface level, allowing unwanted traffic to be dropped before it reaches the normal Linux networking stack.

The system implements:
- Per-source IP rate limiting.
- Global DNS query rate limiting.
- Adaptive source throttling and blocking.
- DNS packet validation.
- Packet statistics and performance monitoring.

The implementation is evaluated against two baselines:
1. No filtering.
2. Linux nftables rate limiting.

All experiments are conducted in a controlled CloudLab environment using synthetic DNS traffic.

## 2. Project Architecture

The project uses two Linux hosts:

| Host | Role | Experiment IP |
|---|---|---|
| Node 0 | DNS traffic generator | 10.10.1.1 |
| Node 1 | DNS server and XDP filter | 10.10.1.2 |

Node 0 generates synthetic DNS traffic, while Node 1 receives the packets, applies filtering, and serves legitimate DNS queries.

The experiment uses the `eno1d1` network interface.

## 3. Repository Structure

```text
src/
├── common.h
├── dns_tracer.bpf.c
├── dns_tracer.c
├── flood_p1.py
├── flood_p2.py
├── run_p3.sh
├── query_file.txt
├── nftables.text
├── Makefile
├── commands.txt
└── README.md
```

### File Descriptions

| File | Description |
|---|---|
| `common.h` | Shared configuration, data structures, and packet statistics |
| `dns_tracer.bpf.c` | XDP/eBPF packet parsing and rate-limiting logic |
| `dns_tracer.c` | Userspace controller that loads and attaches the XDP program |
| `flood_p1.py` | Single-source DNS flood generator |
| `flood_p2.py` | Multi-source DNS flood generator |
| `run_p3.sh` | Runs legitimate DNS queries alongside bursty flood traffic |
| `query_file.txt` | DNS queries used by dnsperf |
| `nftables.text` | nftables filtering configuration |
| `Makefile` | Builds the XDP project |
| `commands.txt` | Useful experiment and setup commands |

## 4. Requirements

- Ubuntu Linux 22.04
- Linux kernel with eBPF and XDP support
- Clang and LLVM
- Linux kernel headers
- libbpf development libraries
- bpftool (if required by the build process)
- Python 3
- dnsperf
- dnsmasq
- nftables
- sysstat

The experiments use XDP generic/SKB mode on the CloudLab interface.

## 5. DNS Server Setup

Node 1 runs dnsmasq and serves DNS queries for the laboratory domain.

Example configuration:

```ini
port=53
interface=eno1d1
listen-address=10.10.1.2
bind-interfaces
no-resolv
no-hosts
address=/lab.test/192.0.2.10
```

Restart dnsmasq:

```bash
sudo systemctl restart dnsmasq
```

Test DNS resolution:

```bash
dig @10.10.1.2 test.lab.test A
```

Expected answer:

```text
192.0.2.10
```

## 6. Building the Project

Navigate to the source directory:

```bash
cd src
```

Build the project:

```bash
make setup
make clean
make
```

The build should generate the `dns_tracer` executable.

## 7. Running the XDP Filter

On Node 1:

```bash
sudo ./dns_tracer <INTERFACE>
```

To enable adaptive rate limiting:

```bash
sudo ./dns_tracer --adaptive <INTERFACE>
```

The default static rate limits are:

| Parameter | Default |
|---|---:|
| Per-source rate | 1000 packets/sec |
| Per-source burst | 100 packets |
| Global rate | 20000 packets/sec |
| Global burst | 1000 packets |

The controller displays packet statistics when stopped using `Ctrl+C`.

## 8. Synthetic Traffic Experiments

Three synthetic traffic patterns are evaluated.

### P1: Single-Source DNS Flood

Tests per-source rate limiting and adaptive source blocking.

On Node 0:

```bash
sudo python3 flood_p1.py 10.10.1.2 3000
```

The generator sends DNS queries from a single source at the specified rate.

### P2: Multi-Source DNS Flood

Tests global rate limiting using multiple source IP addresses.

Node 0 uses 25 source addresses from `10.10.1.101` to `10.10.1.125`.

Example:

```bash
sudo python3 flood_p2.py 10.10.1.2 700
```

To test a higher aggregate traffic rate:

```bash
sudo python3 flood_p2.py 10.10.1.2 900
```

Each rate value represents the approximate packet rate per source.

### P3: Legitimate DNS Traffic During Bursty Floods

Tests whether legitimate DNS requests continue to succeed during intermittent DNS floods.

The experiment uses:
- Legitimate DNS queries at 50 queries/sec.
- Total experiment duration of 40 seconds.
- Two quiet periods.
- Two flood periods.
- Flood traffic at approximately 3000 packets/sec.

The legitimate query file contains:

```text
test.lab.test A
```

Run the experiment on Node 0:

```bash
sudo bash run_p3.sh
```

The experiment uses dnsperf to measure legitimate DNS query success and response latency.

## 9. Performance Evaluation

The project compares four configurations:

1. No filtering.
2. nftables.
3. Static XDP rate limiting.
4. Adaptive XDP rate limiting.

The following metrics are recorded:

| Metric | Description |
|---|---|
| Legitimate DNS success rate | Percentage of legitimate queries successfully answered |
| CPU utilization | Average CPU usage during the experiment |
| Incoming packet rate | Number of packets received per second |
| Passed packet rate | Number of packets allowed through the filter per second |
| Dropped packets | Number of packets dropped by the filtering mechanism |
| Average DNS latency | Average response time for legitimate DNS queries |
| P95 DNS latency | 95th percentile response time, if available |

### Legitimate DNS Success Rate

The most important metric for evaluating the impact on legitimate users is:

```text
Success Rate (%) =
(Successful Legitimate Queries / Total Legitimate Queries Sent) * 100
```

### CPU Monitoring

Use the following commands on Node 1:

```bash
sar -u 1 45
sar -r 1 45
sar -n DEV 1 45
```

These collect CPU, memory, and network statistics.

## 10. nftables Baseline

The nftables configuration provides a traditional Linux firewall comparison.

Apply the nftables rules on Node 1 using the configuration in `nftables.text`.

Validate the rules before applying them:

```bash
sudo nft -c -f nftables.text
```

Apply the configuration:

```bash
sudo nft -f nftables.text
```

Inspect the active rules and counters:

```bash
sudo nft list table inet dnsfilter
```

Remove the experimental table after testing:

```bash
sudo nft delete table inet dnsfilter
```

Run the same traffic experiments under nftables, no-filter, and XDP configurations to ensure a fair comparison.

## 11. Results

Record the results of each experiment in a comparison table.

| Metric | No Filter | nftables | Static XDP | Adaptive XDP |
|---|---|---|---|---|
| Legitimate DNS success (%) | | | | |
| Average CPU utilization (%) | | | | |
| Incoming packets/sec | | | | |
| Passed packets/sec | | | | |
| Dropped packets | | | | |
| Average DNS latency (ms) | | | | |
| P95 DNS latency (ms) | | | | |

## 12. Expected Outcome

The project aims to demonstrate that:

- XDP can filter unwanted DNS traffic before it reaches the normal networking stack.
- Per-source rate limiting can control excessive traffic from individual sources.
- Global rate limiting can control aggregate DNS traffic from multiple sources.
- Adaptive rate limiting can throttle and temporarily block abusive sources.
- Legitimate DNS requests can continue to succeed during controlled flood experiments.
- XDP performance can be compared with nftables and no-filter baselines.

## 13. Safety and Experiment Scope

All traffic generation is restricted to the controlled CloudLab environment.

The traffic generators are intended for synthetic laboratory experiments only. Do not run flood tests against public DNS servers or networks without explicit authorization.

The project focuses on DNS query rate limiting and does not claim to eliminate DNS reflection or amplification attacks.