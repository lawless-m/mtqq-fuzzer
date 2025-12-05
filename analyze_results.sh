#!/bin/bash
# Analyze fuzzing results without requiring active session

FUZZER_DIR="/home/matt/Git/mtqq-fuzzer"
RESULTS_DIR="${FUZZER_DIR}/boofuzz-results"
LOG_DIR="${FUZZER_DIR}/logs"

echo "MQTT Fuzzing Results Analysis"
echo "=============================="
echo ""

# Find latest database
LATEST_DB=$(ls -t "${RESULTS_DIR}"/*.db 2>/dev/null | head -1)

if [ -z "${LATEST_DB}" ]; then
    echo "No results database found in ${RESULTS_DIR}"
    exit 1
fi

echo "Analyzing: $(basename ${LATEST_DB})"
echo "Size: $(du -h ${LATEST_DB} | cut -f1)"
echo ""

# Run Python analysis
export DB_PATH="${LATEST_DB}"
python3 << PYEOF
import sqlite3
import sys
from datetime import datetime
import os

db_path = os.environ.get('DB_PATH')
if not db_path:
    print("ERROR: DB_PATH not set")
    sys.exit(1)

conn = sqlite3.connect(db_path)
c = conn.cursor()

# Overall statistics
c.execute("SELECT COUNT(*) FROM cases")
total_cases = c.fetchone()[0]

c.execute("SELECT COUNT(*) FROM steps")
total_steps = c.fetchone()[0]

# Time range
c.execute("SELECT MIN(timestamp), MAX(timestamp) FROM cases")
start_time, end_time = c.fetchone()

print(f"Total Test Cases: {total_cases:,}")
print(f"Total Test Steps: {total_steps:,}")
print(f"Campaign Start: {start_time}")
print(f"Campaign End: {end_time}")

if start_time and end_time:
    start = datetime.fromisoformat(start_time.replace('[', '').replace(']', '').split(',')[0])
    end = datetime.fromisoformat(end_time.replace('[', '').replace(']', '').split(',')[0])
    duration = end - start
    print(f"Duration: {duration}")

    if duration.total_seconds() > 0:
        rate = total_cases / duration.total_seconds()
        print(f"Test Rate: {rate:.2f} tests/second")

print("\n" + "="*50)
print("Mutation Coverage by Packet Type")
print("="*50)

# Packet type breakdown
c.execute("""
    SELECT
        CASE
            WHEN name LIKE 'MQTT-CONNECT%' THEN 'CONNECT'
            WHEN name LIKE 'MQTT-PUBLISH%' THEN 'PUBLISH'
            WHEN name LIKE 'MQTT-SUBSCRIBE%' THEN 'SUBSCRIBE'
            WHEN name LIKE 'MQTT-UNSUBSCRIBE%' THEN 'UNSUBSCRIBE'
            WHEN name LIKE 'MQTT-PUBACK%' THEN 'PUBACK'
            WHEN name LIKE 'MQTT-PUBREC%' THEN 'PUBREC'
            WHEN name LIKE 'MQTT-PUBREL%' THEN 'PUBREL'
            WHEN name LIKE 'MQTT-PUBCOMP%' THEN 'PUBCOMP'
            WHEN name LIKE 'MQTT-PINGREQ%' THEN 'PINGREQ'
            WHEN name LIKE 'MQTT-DISCONNECT%' THEN 'DISCONNECT'
            ELSE 'OTHER'
        END as packet_type,
        COUNT(*) as count
    FROM cases
    GROUP BY packet_type
    ORDER BY count DESC
""")

for packet_type, count in c.fetchall():
    pct = (count / total_cases) * 100
    print(f"{packet_type:15s}: {count:8,} ({pct:5.1f}%)")

print("\n" + "="*50)
print("Checking for Crashes or Anomalies")
print("="*50)

# Look for crash indicators in step descriptions
c.execute("""
    SELECT DISTINCT description
    FROM steps
    WHERE description LIKE '%crash%'
       OR description LIKE '%error%'
       OR description LIKE '%fail%'
       OR description LIKE '%exception%'
    LIMIT 20
""")

anomalies = c.fetchall()
if anomalies:
    print("\nFound potential issues:")
    for desc, in anomalies:
        if 'No crash detected' not in desc:
            print(f"  - {desc}")
else:
    print("\nNo crashes or errors detected in test results")

# Check for repeated failures on specific mutations
c.execute("""
    SELECT name, COUNT(*) as failures
    FROM cases c
    WHERE EXISTS (
        SELECT 1 FROM steps s
        WHERE s.test_case_index = c.number
        AND s.description NOT LIKE '%No crash%'
        AND s.type = 'check'
    )
    GROUP BY name
    ORDER BY failures DESC
    LIMIT 10
""")

failures = c.fetchall()
if failures:
    print("\n" + "="*50)
    print("Test Cases with Non-Standard Results")
    print("="*50)
    for name, count in failures:
        print(f"{name}: {count} instances")

conn.close()

print("\n" + "="*50)
print("ASAN Error Log Check")
print("="*50)

import glob
import os

log_dir = os.path.dirname(db_path.replace('/boofuzz-results/', '/logs/'))
asan_logs = glob.glob(f"{log_dir}/asan-*.log")

if asan_logs:
    latest_asan = max(asan_logs, key=os.path.getmtime)
    print(f"\nLatest ASAN log: {os.path.basename(latest_asan)}")

    with open(latest_asan, 'r') as f:
        content = f.read()
        if 'ERROR' in content or 'ASAN' in content or 'heap' in content:
            print("\n!!! ASAN ERRORS DETECTED !!!")
            print("\nRelevant excerpts:")
            for line in content.split('\n'):
                if any(kw in line for kw in ['ERROR', 'SUMMARY', 'heap-', 'stack-', 'ASAN']):
                    print(f"  {line}")
        elif 'No ASAN error logs found' in content:
            print("No ASAN errors detected")
        else:
            print(f"ASAN log size: {len(content)} bytes")
else:
    print("No ASAN logs found")

print("\n" + "="*50)
PYEOF

echo ""
echo "Analysis complete"
echo ""
echo "For detailed investigation:"
echo "  sqlite3 ${LATEST_DB}"
echo "  .schema"
echo "  SELECT * FROM cases LIMIT 10;"
