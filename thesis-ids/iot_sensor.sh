#!/bin/bash
TARGET="test.mosquitto.org"
TOPIC="thesis/sensor1/temp"

echo "--- Starting Smart IoT Traffic Generator ---"
echo "Target Broker: $TARGET | Topic: $TOPIC"
echo "Press Ctrl+C to stop."

while true; do
    TEMP=$(awk -v min=20 -v max=25 'BEGIN{srand(); print min+rand()*(max-min)}')
    echo "Sending Data: $TEMP°C"
    mosquitto_pub -h $TARGET -t "$TOPIC" -m "$TEMP"
    sleep 1
done