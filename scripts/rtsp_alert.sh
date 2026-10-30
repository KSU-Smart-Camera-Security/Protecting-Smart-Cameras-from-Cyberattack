#!/bin/bash
# Watches the kernel log for iptables "RTSP_ATTACK" entries and sends an email alert.
# Requires: sqlite3, mailutils (the `mail` command), journalctl.
#
# Configure with environment variables (e.g. in the systemd unit):
#   ALERT_EMAIL  - where alerts are sent
#   DB_PATH      - path to the SQLite database
#   COOLDOWN     - minimum seconds between two emails (default 60)

EMAIL="${ALERT_EMAIL:-your-email@example.com}"
DB_PATH="${DB_PATH:-/var/www/database/system_users.db}"
LOG_FILE="/var/log/camera_security_events.log"
COOLDOWN="${COOLDOWN:-60}"
LAST_SENT=0

journalctl -f | while read -r line; do

    echo "$line" | grep -q "RTSP_ATTACK" || continue

    RTSP_STATUS=$(sqlite3 "$DB_PATH" "SELECT rtsp_protected FROM users WHERE username='admin' LIMIT 1;")
    [ "$RTSP_STATUS" = "1" ] || continue

    IP=$(echo "$line" | grep -oP 'SRC=\K[0-9.]+')
    NOW=$(date +%s)

    echo "$(date '+%Y-%m-%d %H:%M:%S') | RTSP Attack Detected | IP: $IP" >> "$LOG_FILE"

    # Avoid flooding the mailbox during a scan
    if [ $((NOW - LAST_SENT)) -lt "$COOLDOWN" ]; then
        continue
    fi
    LAST_SENT=$NOW

    MESSAGE="
Warning!

Unauthorized RTSP access attempt detected.

IP Address: $IP

Time: $(date '+%Y-%m-%d %H:%M:%S')

The system detected suspicious activity targeting RTSP port 554.
"
    echo "$MESSAGE" | mail -s "RTSP Attack Detected" "$EMAIL"

done
