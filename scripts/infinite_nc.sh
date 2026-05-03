#!/bin/bash

# Script to keep netcat running on port 4444
# It will automatically restart nc if it dies

PORT=4444

echo "Starting netcat auto-restart script on port $PORT"
echo "Press Ctrl+C to stop the script"

while true; do
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] Starting nc on port $PORT..."

  killall nc
  echo "exit" | nc -l -p $PORT

  echo "[$(date '+%Y-%m-%d %H:%M:%S')] nc died, restarting in 2 seconds..."
  sleep 2
done
