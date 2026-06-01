#!/bin/bash
MODE=${1:-normal}
echo "--- Starting Data Collection Loop (Label: $MODE) ---"
echo "Press Ctrl+C to stop."

while true; do
    echo "[*] Capturing 10 seconds of traffic..."
    rm -f /app/captures/iot_traffic.pcap
    
    netsniff-ng --in eth0 --out /app/captures/iot_traffic.pcap --silent &
    PID=$!
    
    sleep 10
    kill -SIGINT $PID
    sleep 2 # Wait for disk write
    
    python3 /app/batch_extractor.py $MODE
    echo "---------------------------------------------------"
done