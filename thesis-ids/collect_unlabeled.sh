#!/bin/bash
echo "--- Starting UNLABELED Data Collection Loop ---"
echo "Press Ctrl+C to stop."

while true; do
    echo "[*] Capturing 10 seconds of raw, unlabeled traffic..."
    rm -f /app/captures/iot_traffic.pcap
    
    # Start Capture
    netsniff-ng --in eth0 --out /app/captures/iot_traffic.pcap --silent &
    PID=$!
    
    sleep 10
    kill -SIGINT $PID
    sleep 2 # Wait for disk write
    
    # Run the extractor in unlabeled mode
    python3 /app/extractor_unlabeled.py
    echo "---------------------------------------------------"
done