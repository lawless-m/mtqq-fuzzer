#!/bin/bash
# Quick fuzzing script for Mosquitto (already running in VM)
set -euo pipefail

TIMESTAMP=$(date +%Y%m%d-%H%M%S)
LOG_DIR="./logs"
CAMPAIGN_LOG="${LOG_DIR}/mosquitto-campaign-${TIMESTAMP}.log"

mkdir -p "${LOG_DIR}"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "${CAMPAIGN_LOG}"
}

log "========================================="
log "Starting Mosquitto Fuzzing Campaign"
log "========================================="
log "Target: localhost:1883 (Mosquitto with ASAN)"
log "Campaign log: ${CAMPAIGN_LOG}"
log ""

# Verify target is up
if ! nc -z localhost 1883 2>/dev/null; then
    log "ERROR: Cannot reach localhost:1883"
    exit 1
fi

log "Target is reachable, starting fuzzer..."
log ""

# Activate venv and run
if [ -d "venv" ]; then
    source venv/bin/activate
fi

python3 mqtt_fuzzer.py -t localhost -p 1883 2>&1 | tee -a "${CAMPAIGN_LOG}"

log ""
log "Campaign complete. Collecting ASAN logs..."
ssh -p 2227 debian@localhost 'cat /tmp/asan.* 2>/dev/null || echo "No ASAN errors"' \
    > "${LOG_DIR}/mosquitto-asan-${TIMESTAMP}.log"

log "ASAN log: ${LOG_DIR}/mosquitto-asan-${TIMESTAMP}.log"
log "Results: boofuzz-results/"
