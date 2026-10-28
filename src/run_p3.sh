#!/bin/bash
# Pattern P3: Bursty flood + legitimate load test harness[cite: 9]
TARGET_IP=$1

if [ -z "$TARGET_IP" ]; then
    echo "Usage: ./run_p3.sh <TARGET_IP>"
    exit 1
fi

echo "=== Starting Pattern P3 Evaluation ==="
echo "1. Launching continuous low-rate legitimate client (dnsperf at 50 qps)..."
dnsperf -s "$TARGET_IP" -d query_file.txt -Q 50 -c 1 -l 40 > legit_results.log 2>&1 &
DNSCONF_PID=$!

echo "2. Executing bursty flood cycles (10s normal, 10s heavy flood burst)..."
for i in {1..2}; do
    echo "--- Cycle $i: Quiet period (legit traffic only) ---"
    sleep 10

    echo "--- Cycle $i: BURST FLOOD ACTIVE (Injecting 3000 pps flood) ---"
    python3 flood_p1.py "$TARGET_IP" 3000 &
    FLOOD_PID=$!
    
    sleep 10
    echo "--- Cycle $i: Stopping flood burst (Observing recovery) ---"
    kill "$FLOOD_PID" 2>/dev/null
    wait "$FLOOD_PID" 2>/dev/null
done

echo "Waiting for legitimate client session to finalize..."
wait "$DNSCONF_PID"
echo "=== P3 Evaluation Completed. Check 'legit_results.log' for final success percentages. ==="