#!/bin/bash
# Monitor ongoing fuzzing campaign without interfering

FUZZER_DIR="/home/matt/Git/mtqq-fuzzer"
RESULTS_DIR="${FUZZER_DIR}/boofuzz-results"
LOG_DIR="${FUZZER_DIR}/logs"

echo "MQTT Fuzzing Campaign Monitor"
echo "==============================="
echo ""

# Check if fuzzer is running
if pgrep -f "mqtt_fuzzer.py" >/dev/null; then
    echo "Status: FUZZER IS RUNNING"
    FUZZER_PID=$(pgrep -f "mqtt_fuzzer.py")
    echo "PID: ${FUZZER_PID}"
    echo "Runtime: $(ps -p ${FUZZER_PID} -o etime= | tr -d ' ')"
else
    echo "Status: Fuzzer is not running"
fi

echo ""

# Check NanoMQ in VM
echo "NanoMQ Status in VM:"
if ssh -p 2227 debian@localhost 'pgrep -f nanomq' >/dev/null 2>&1; then
    NANOMQ_PID=$(ssh -p 2227 debian@localhost 'pgrep -f nanomq')
    echo "  Running (PID: ${NANOMQ_PID})"
    ssh -p 2227 debian@localhost "ps -p ${NANOMQ_PID} -o rss=,vsz=,etime=" 2>/dev/null | \
        awk '{printf "  Memory: RSS=%s KB, VSZ=%s KB, Runtime=%s\n", $1, $2, $3}'
else
    echo "  Not running"
fi

echo ""

# Check latest database
if [ -d "${RESULTS_DIR}" ]; then
    LATEST_DB=$(ls -t "${RESULTS_DIR}"/*.db 2>/dev/null | head -1)
    if [ -n "${LATEST_DB}" ]; then
        echo "Latest Results Database:"
        echo "  File: $(basename ${LATEST_DB})"
        echo "  Size: $(du -h ${LATEST_DB} | cut -f1)"
        echo "  Modified: $(stat -c '%y' ${LATEST_DB} | cut -d. -f1)"

        # Query test case count
        TEST_COUNT=$(sqlite3 "${LATEST_DB}" "SELECT COUNT(*) FROM cases;" 2>/dev/null || echo "N/A")
        echo "  Test cases: ${TEST_COUNT}"

        # Get timestamp of last test
        LAST_TEST=$(sqlite3 "${LATEST_DB}" "SELECT timestamp FROM cases ORDER BY number DESC LIMIT 1;" 2>/dev/null || echo "N/A")
        echo "  Last test: ${LAST_TEST}"
    else
        echo "No results databases found"
    fi
fi

echo ""

# Show latest log entries
if [ -d "${LOG_DIR}" ]; then
    LATEST_LOG=$(ls -t "${LOG_DIR}"/campaign-*.log 2>/dev/null | head -1)
    if [ -n "${LATEST_LOG}" ]; then
        echo "Latest Campaign Log (last 10 lines):"
        echo "  $(basename ${LATEST_LOG})"
        echo ""
        tail -10 "${LATEST_LOG}" | sed 's/^/  /'
    fi
fi

echo ""
echo "==============================="
echo ""
echo "Commands:"
echo "  Watch logs:     tail -f ${LOG_DIR}/campaign-*.log"
echo "  Analyze results: ./analyze_results.sh"
echo "  Stop fuzzing:    pkill -f mqtt_fuzzer.py"
