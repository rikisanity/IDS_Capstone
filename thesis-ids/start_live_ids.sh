#!/bin/bash
echo "--- Starting Phase 2: LIVE Real-Time IDS ---"

# 1. Clean old logs
rm -f /app/captures/*.log

# 2. Start Zeek listening on eth0 in the background
# -i eth0 tells Zeek to listen live instead of reading a file
echo "[*] Initializing Zeek on interface eth0..."
cd /app/captures
zeek -C -i eth0 &
ZEEK_PID=$!

sleep 3 # Give Zeek time to create the log files

# 3. Start Python monitoring script
echo "[*] Zeek is running. Starting Python live monitor..."
python3 /app/live_detector.py

# Cleanup if Python exits
kill -SIGINT $ZEEK_PID