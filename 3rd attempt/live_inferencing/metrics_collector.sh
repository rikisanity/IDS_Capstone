#!/bin/bash
# metrics_collector.sh — IoT IDS Thesis Performance Metrics Collector
# EEE 196 / EEE 199 — Group Zero, UP Diliman
#
# Collects CPU, memory, network, and file descriptor metrics from the
# mosquitto_broker container during each attack for Section 4.4.
#
# USAGE:
#   ./metrics_collector.sh <attack_label> [duration_seconds]
#
#   attack_label   — one of: normal, ddos, dos, password, injection, mitm, scanning
#   duration       — how long to collect in seconds (default: 60)
#
# EXAMPLES:
#   # Collect 60s of normal traffic baseline
#   ./metrics_collector.sh normal 60
#
#   # Collect during DDoS attack
#   ./metrics_collector.sh ddos 60
#
# OUTPUT:
#   metrics_<label>_<timestamp>.csv  — raw per-second samples
#   metrics_<label>_<timestamp>_summary.txt — min/max/avg for thesis table
#
# RUN ON: the Ubuntu host machine (NOT inside any container)
# The script talks to Docker directly via docker stats and docker exec.
#
# HOW TO USE WITH ATTACK MENU:
#   Terminal 1:  ./metrics_collector.sh ddos 60
#   Terminal 2:  docker exec -it thesis_attacker bash
#                ./attack_menu.sh   (select option 2)
#   After 60s:   Ctrl+C the attacker, check the output CSV.
# ─────────────────────────────────────────────────────────────────────────────

# ── Force output to the reports directory ────────────────────────────
OUT_DIR="/home/five-tau/Ondrej/user/thesis-ids/reports"
mkdir -p "$OUT_DIR"
cd "$OUT_DIR" || { echo "Failed to navigate to $OUT_DIR"; exit 1; }
# ─────────────────────────────────────────────────────────────────────

ATTACK_LABEL="${1:-unknown}"
DURATION="${2:-60}"
INTERVAL=1   # sample every 1 second

TIMESTAMP=$(date +%s)
OUT_CSV="metrics_${ATTACK_LABEL}_${TIMESTAMP}.csv"
OUT_SUMMARY="metrics_${ATTACK_LABEL}_${TIMESTAMP}_summary.txt"

CONTAINER="mosquitto_broker"

# ── Validate container is running ─────────────────────────────────────────────
if ! docker inspect "$CONTAINER" > /dev/null 2>&1; then
    echo "[ERROR] Container '$CONTAINER' not found. Is the IDS stack running?"
    echo "        cd ~/thesis/Auth && docker compose up -d"
    exit 1
fi

echo "=============================================="
echo "  IoT IDS — Performance Metrics Collector"
echo "=============================================="
echo "  Attack label : $ATTACK_LABEL"
echo "  Duration     : ${DURATION}s"
echo "  Sample rate  : ${INTERVAL}s"
echo "  Output       : $OUT_CSV"
echo "  Container    : $CONTAINER"
echo "=============================================="
echo ""
echo "[*] Starting collection. Run the attack now in another terminal."
echo "[*] Press Ctrl+C to stop early."
echo ""

# ── CSV header ────────────────────────────────────────────────────────────────
echo "timestamp_unix,elapsed_s,attack,cpu_pct,mem_usage_mb,mem_limit_mb,mem_pct,net_rx_mb,net_tx_mb,broker_fd_count,broker_conn_count,esp32_auth_fails" \
    > "$OUT_CSV"

# ── Trap for clean exit ───────────────────────────────────────────────────────
RUNNING=true
trap 'RUNNING=false' INT TERM

# ── Auth fail counter baseline (from zkp_server logs) ─────────────────────────
# We count new REJECT lines since collection started.
get_auth_fails() {
    docker logs zkp_server --since "${DURATION}s" 2>/dev/null \
        | grep -c "REJECT\|auth.*fail\|invalid.*proof" 2>/dev/null \
        || echo 0
}

# ── Broker fd count ───────────────────────────────────────────────────────────
get_fd_count() {
    MPID=$(docker exec "$CONTAINER" sh -c 'pgrep mosquitto 2>/dev/null | head -1')
    if [ -n "$MPID" ]; then
        docker exec "$CONTAINER" sh -c "ls /proc/${MPID}/fd 2>/dev/null | wc -l" 2>/dev/null || echo 0
    else
        echo 0
    fi
}

# ── Active MQTT connection count from mosquitto log ───────────────────────────
get_conn_count() {
    # Count lines containing "Client connected" minus "disconnected" since start
    # As a simpler proxy: count current "New connection" entries in last interval
    docker exec "$CONTAINER" sh -c \
        "tail -50 /mosquitto/log/mosquitto.log 2>/dev/null | grep -c 'connected'" \
        2>/dev/null || echo 0
}

# ── Main collection loop ──────────────────────────────────────────────────────
START_TIME=$(date +%s)
ELAPSED=0

while $RUNNING && [ "$ELAPSED" -lt "$DURATION" ]; do
    NOW=$(date +%s)
    ELAPSED=$((NOW - START_TIME))

    # ── docker stats (single snapshot) ──────────────────────────────────────
    RAW=$(docker stats "$CONTAINER" --no-stream --format \
        "{{.CPUPerc}}|{{.MemUsage}}|{{.MemPerc}}|{{.NetIO}}" 2>/dev/null)

    if [ -z "$RAW" ]; then
        echo "[WARN] docker stats returned empty at elapsed=${ELAPSED}s — container may be restarting"
        sleep "$INTERVAL"
        continue
    fi

    # Parse CPU %
    CPU=$(echo "$RAW" | cut -d'|' -f1 | tr -d '%' | tr -d ' ')

    # Parse memory — "123.4MiB / 7.8GiB" or "123.4MB / 7.8GB"
    MEM_RAW=$(echo "$RAW" | cut -d'|' -f2)
    MEM_USAGE=$(echo "$MEM_RAW" | awk '{print $1}' | sed 's/MiB//;s/MB//;s/GiB/*1024/;s/GB/*1024/' | bc 2>/dev/null || echo 0)
    MEM_LIMIT=$(echo "$MEM_RAW" | awk '{print $3}' | sed 's/MiB//;s/MB//;s/GiB/*1024/;s/GB/*1024/' | bc 2>/dev/null || echo 0)

    # Parse memory %
    MEM_PCT=$(echo "$RAW" | cut -d'|' -f3 | tr -d '%' | tr -d ' ')

    # Parse network IO — "1.23MB / 4.56MB"
    NET_RAW=$(echo "$RAW" | cut -d'|' -f4)
    NET_RX=$(echo "$NET_RAW" | awk '{print $1}' | sed 's/MB//;s/MiB//;s/kB/\/1024/;s/GB/*1024/' | bc 2>/dev/null || echo 0)
    NET_TX=$(echo "$NET_RAW" | awk '{print $3}' | sed 's/MB//;s/MiB//;s/kB/\/1024/;s/GB/*1024/' | bc 2>/dev/null || echo 0)

    # ── Additional broker metrics ────────────────────────────────────────────
    FD_COUNT=$(get_fd_count)
    CONN_COUNT=$(get_conn_count)
    AUTH_FAILS=$(get_auth_fails)

    # ── Write row ────────────────────────────────────────────────────────────
    echo "$NOW,$ELAPSED,$ATTACK_LABEL,$CPU,$MEM_USAGE,$MEM_LIMIT,$MEM_PCT,$NET_RX,$NET_TX,$FD_COUNT,$CONN_COUNT,$AUTH_FAILS" \
        >> "$OUT_CSV"

    # ── Live display ─────────────────────────────────────────────────────────
    printf "\r[%3ds/%3ds] CPU: %5s%%  MEM: %6sMB (%s%%)  FDs: %4s  NET_RX: %sMB" \
        "$ELAPSED" "$DURATION" "$CPU" "$MEM_USAGE" "$MEM_PCT" "$FD_COUNT" "$NET_RX"

    sleep "$INTERVAL"
done

echo ""
echo ""
echo "[*] Collection complete. Rows: $(wc -l < "$OUT_CSV")"

# ── Generate summary ──────────────────────────────────────────────────────────
python3 - "$OUT_CSV" "$OUT_SUMMARY" "$ATTACK_LABEL" <<'PYEOF'
import sys, csv, statistics

csv_path     = sys.argv[1]
out_path     = sys.argv[2]
attack_label = sys.argv[3]

rows = []
with open(csv_path) as f:
    reader = csv.DictReader(f)
    for row in reader:
        rows.append(row)

if not rows:
    print("[ERROR] No data rows in CSV.")
    sys.exit(1)

def stats(col):
    vals = []
    for r in rows:
        try:
            v = float(r[col])
            vals.append(v)
        except (ValueError, KeyError):
            pass
    if not vals:
        return {"min": 0, "max": 0, "avg": 0, "p95": 0}
    vals.sort()
    p95_idx = int(len(vals) * 0.95)
    return {
        "min": min(vals),
        "max": max(vals),
        "avg": statistics.mean(vals),
        "p95": vals[p95_idx],
    }

metrics = {
    "CPU %":          stats("cpu_pct"),
    "Memory (MB)":    stats("mem_usage_mb"),
    "Memory %":       stats("mem_pct"),
    "Net RX (MB)":    stats("net_rx_mb"),
    "Net TX (MB)":    stats("net_tx_mb"),
    "FD Count":       stats("broker_fd_count"),
    "MQTT Conns":     stats("broker_conn_count"),
    "Auth Fails":     stats("esp32_auth_fails"),
}

lines = []
lines.append(f"=== PERFORMANCE SUMMARY: {attack_label.upper()} ===")
lines.append(f"Samples: {len(rows)}")
lines.append("")
lines.append(f"{'Metric':<20} {'Min':>8} {'Avg':>8} {'P95':>8} {'Max':>8}")
lines.append("-" * 56)
for name, s in metrics.items():
    lines.append(f"{name:<20} {s['min']:>8.2f} {s['avg']:>8.2f} {s['p95']:>8.2f} {s['max']:>8.2f}")

lines.append("")
lines.append("=== THESIS TABLE VALUES (copy into Section 4.4) ===")
lines.append(f"Attack Type   : {attack_label}")
lines.append(f"Avg CPU %     : {metrics['CPU %']['avg']:.2f}%")
lines.append(f"Peak CPU %    : {metrics['CPU %']['max']:.2f}%")
lines.append(f"Avg Memory MB : {metrics['Memory (MB)']['avg']:.1f} MB")
lines.append(f"Peak Memory MB: {metrics['Memory (MB)']['max']:.1f} MB")
lines.append(f"Peak FD Count : {metrics['FD Count']['max']:.0f}")
lines.append(f"Total Net RX  : {metrics['Net RX (MB)']['max']:.2f} MB")
lines.append(f"Auth Failures : {metrics['Auth Fails']['max']:.0f}")

output = "\n".join(lines)
print(output)
with open(out_path, "w") as f:
    f.write(output + "\n")
PYEOF

echo ""
echo "[*] Summary saved to: $OUT_SUMMARY"
echo "[*] Raw CSV saved to: $OUT_CSV"
echo ""
echo "Files ready for Section 4.4."
