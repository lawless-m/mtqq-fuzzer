#!/bin/bash
# Complete standalone MQTT fuzzing script for NanoMQ
# Run this from YOUR terminal (not through Claude Code)

set -euo pipefail

TIMESTAMP=$(date +%Y%m%d-%H%M%S)
LOG_DIR="./logs"
CAMPAIGN_LOG="${LOG_DIR}/nanomq-campaign-${TIMESTAMP}.log"
VM_SSH_PORT=2227
VM_USER=debian
VM_HOST=localhost
MQTT_PORT=1883

mkdir -p "${LOG_DIR}" "boofuzz-results"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "${CAMPAIGN_LOG}"
}

cleanup() {
    log "Cleaning up..."
    ssh -p "${VM_SSH_PORT}" "${VM_USER}@${VM_HOST}" 'pkill -9 nanomq' 2>/dev/null || true
    log "Cleanup complete"
}

trap cleanup EXIT INT TERM

log "========================================="
log "NanoMQ v0.23.0 Fuzzing Campaign with ASAN"
log "========================================="
log "Target: ${VM_HOST}:${MQTT_PORT}"
log "Log: ${CAMPAIGN_LOG}"
log ""

# Check VM connectivity
log "Checking VM connectivity..."
if ! ssh -p "${VM_SSH_PORT}" -o ConnectTimeout=5 "${VM_USER}@${VM_HOST}" 'echo OK' >/dev/null 2>&1; then
    log "ERROR: Cannot connect to VM at ${VM_HOST}:${VM_SSH_PORT}"
    exit 1
fi
log "✓ VM is accessible"

# Create NanoMQ config
log "Creating NanoMQ config..."
ssh -p "${VM_SSH_PORT}" "${VM_USER}@${VM_HOST}" 'cat > /tmp/nanomq-fuzz.conf << "EOFCONF"
listeners.tcp {
    bind = "0.0.0.0:1883"
}
mqtt {
    max_packet_size = 1MB
    max_mqueue_len = 2048
    retry_interval = 10s
    keepalive_multiplier = 1.25
}
log {
    to = [console]
    level = error
}
EOFCONF' >/dev/null 2>&1

# Start NanoMQ with ASAN
log "Starting NanoMQ v0.23.0 with AddressSanitizer..."
ssh -p "${VM_SSH_PORT}" "${VM_USER}@${VM_HOST}" 'pkill -9 nanomq' 2>/dev/null || true
sleep 2

ssh -p "${VM_SSH_PORT}" "${VM_USER}@${VM_HOST}" \
    "cd ~/nanomq/build && setsid bash -c 'ASAN_OPTIONS=\"detect_leaks=1:abort_on_error=0:halt_on_error=0:print_stats=1:log_path=/tmp/asan-nanomq\" ./nanomq/nanomq start --conf /tmp/nanomq-fuzz.conf > /tmp/nanomq.log 2>&1 </dev/null &' &" \
    >/dev/null 2>&1

sleep 3

# Verify NanoMQ is running
if ! ssh -p "${VM_SSH_PORT}" "${VM_USER}@${VM_HOST}" 'pgrep -f nanomq/nanomq' >/dev/null 2>&1; then
    log "ERROR: NanoMQ failed to start"
    ssh -p "${VM_SSH_PORT}" "${VM_USER}@${VM_HOST}" 'cat /tmp/nanomq.log'
    exit 1
fi
log "✓ NanoMQ started successfully"

# Wait for MQTT port
log "Waiting for MQTT port ${MQTT_PORT}..."
for i in {1..30}; do
    if nc -z "${VM_HOST}" "${MQTT_PORT}" 2>/dev/null; then
        log "✓ MQTT port is ready"
        break
    fi
    sleep 1
    if [ $i -eq 30 ]; then
        log "ERROR: MQTT port ${MQTT_PORT} not available"
        exit 1
    fi
done

# Start fuzzer
log ""
log "========================================="
log "Starting Fuzzer (171,554+ test cases)"
log "========================================="
log "This will take several hours..."
log "Monitor progress: ./monitor_fuzzing.sh"
log ""

cd "$(dirname "$0")"

if [ -d "venv" ]; then
    source venv/bin/activate
fi

python3 mqtt_fuzzer.py -t "${VM_HOST}" -p "${MQTT_PORT}" 2>&1 | tee -a "${CAMPAIGN_LOG}"

FUZZER_EXIT=$?

# Collect ASAN logs
log ""
log "========================================="
log "Collecting Results"
log "========================================="

ssh -p "${VM_SSH_PORT}" "${VM_USER}@${VM_HOST}" \
    'cat /tmp/asan-nanomq.* 2>/dev/null || echo "No ASAN errors detected"' \
    > "${LOG_DIR}/asan-nanomq-${TIMESTAMP}.log"

ssh -p "${VM_SSH_PORT}" "${VM_USER}@${VM_HOST}" \
    'cat /tmp/nanomq.log 2>/dev/null' \
    >> "${CAMPAIGN_LOG}" 2>&1 || true

log ""
log "Campaign complete!"
log "Exit code: ${FUZZER_EXIT}"
log ""
log "Results:"
log "  Campaign log: ${CAMPAIGN_LOG}"
log "  ASAN log: ${LOG_DIR}/asan-nanomq-${TIMESTAMP}.log"
log "  Database: boofuzz-results/run-*.db"
log ""
log "Analyze: ./analyze_results.sh"

exit ${FUZZER_EXIT}
