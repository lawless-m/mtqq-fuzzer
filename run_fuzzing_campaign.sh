#!/bin/bash
# Standalone MQTT Fuzzing Campaign Runner
# Runs independently without requiring an active Claude Code session

set -euo pipefail

# Configuration
VM_SSH_PORT="${VM_SSH_PORT:-2227}"
VM_USER="${VM_USER:-debian}"
VM_HOST="${VM_HOST:-localhost}"
MQTT_PORT="${MQTT_PORT:-1883}"
FUZZER_DIR="/home/matt/Git/mtqq-fuzzer"
LOG_DIR="${FUZZER_DIR}/logs"
RESULTS_DIR="${FUZZER_DIR}/boofuzz-results"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
CAMPAIGN_LOG="${LOG_DIR}/campaign-${TIMESTAMP}.log"
NANOMQ_LOG="${LOG_DIR}/nanomq-${TIMESTAMP}.log"

# Ensure directories exist
mkdir -p "${LOG_DIR}" "${RESULTS_DIR}"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "${CAMPAIGN_LOG}"
}

cleanup() {
    log "Cleaning up fuzzing campaign..."

    # Stop NanoMQ in VM
    ssh -p "${VM_SSH_PORT}" "${VM_USER}@${VM_HOST}" \
        'pkill -9 nanomq || true' 2>/dev/null || true

    log "Cleanup complete"
}

trap cleanup EXIT INT TERM

# Main execution
log "========================================="
log "Starting MQTT Fuzzing Campaign"
log "========================================="
log "Target: ${VM_HOST}:${MQTT_PORT}"
log "Campaign log: ${CAMPAIGN_LOG}"
log "NanoMQ log: ${NANOMQ_LOG}"
log ""

# Check VM is accessible
log "Checking VM connectivity..."
if ! ssh -p "${VM_SSH_PORT}" -o ConnectTimeout=5 "${VM_USER}@${VM_HOST}" 'echo VM is alive' 2>/dev/null; then
    log "ERROR: Cannot connect to VM at ${VM_HOST}:${VM_SSH_PORT}"
    exit 1
fi
log "VM is accessible"

# Start NanoMQ with ASAN in VM
log "Starting NanoMQ with AddressSanitizer in VM..."
ssh -p "${VM_SSH_PORT}" "${VM_USER}@${VM_HOST}" 'pkill -9 nanomq || true' 2>/dev/null || true
sleep 2

ssh -p "${VM_SSH_PORT}" "${VM_USER}@${VM_HOST}" \
    "cd ~/nanomq/build && nohup bash -c 'ASAN_OPTIONS=\"detect_leaks=1:abort_on_error=0:halt_on_error=0:print_stats=1:log_path=/tmp/asan\" ./nanomq/nanomq start 2>&1' > /tmp/nanomq.log 2>&1 &" \
    2>&1 | tee -a "${NANOMQ_LOG}"

sleep 3

# Verify NanoMQ is running
if ssh -p "${VM_SSH_PORT}" "${VM_USER}@${VM_HOST}" 'pgrep -f nanomq' >/dev/null 2>&1; then
    log "NanoMQ started successfully"
else
    log "ERROR: NanoMQ failed to start"
    exit 1
fi

# Wait for MQTT port to be available
log "Waiting for MQTT port ${MQTT_PORT} to be ready..."
for i in {1..30}; do
    if nc -z "${VM_HOST}" "${MQTT_PORT}" 2>/dev/null; then
        log "MQTT port is ready"
        break
    fi
    sleep 1
    if [ $i -eq 30 ]; then
        log "ERROR: MQTT port ${MQTT_PORT} did not become available"
        exit 1
    fi
done

# Start fuzzer
log "Starting fuzzer..."
log "Results will be saved to: ${RESULTS_DIR}/"
log ""

cd "${FUZZER_DIR}"

# Activate venv and run fuzzer
if [ -d "venv" ]; then
    source venv/bin/activate
fi

python3 mqtt_fuzzer.py \
    -t "${VM_HOST}" \
    -p "${MQTT_PORT}" \
    2>&1 | tee -a "${CAMPAIGN_LOG}"

FUZZER_EXIT=$?

# Collect ASAN logs from VM
log ""
log "Collecting ASAN logs from VM..."
ssh -p "${VM_SSH_PORT}" "${VM_USER}@${VM_HOST}" \
    'cat /tmp/asan.* 2>/dev/null || echo "No ASAN error logs found"' \
    > "${LOG_DIR}/asan-${TIMESTAMP}.log" 2>&1

# Collect NanoMQ logs
ssh -p "${VM_SSH_PORT}" "${VM_USER}@${VM_HOST}" \
    'cat /tmp/nanomq.log 2>/dev/null' \
    >> "${NANOMQ_LOG}" 2>&1 || true

log ""
log "========================================="
log "Fuzzing Campaign Complete"
log "========================================="
log "Exit code: ${FUZZER_EXIT}"
log "Campaign log: ${CAMPAIGN_LOG}"
log "NanoMQ log: ${NANOMQ_LOG}"
log "ASAN log: ${LOG_DIR}/asan-${TIMESTAMP}.log"
log "Results: ${RESULTS_DIR}/"
log ""

exit ${FUZZER_EXIT}
