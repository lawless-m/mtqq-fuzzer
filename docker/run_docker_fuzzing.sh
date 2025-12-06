#!/bin/bash
# Standalone Docker-based MQTT fuzzing campaign
# Can be copied to any server with Docker installed

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "${SCRIPT_DIR}")"

cd "${SCRIPT_DIR}"

TIMESTAMP=$(date +%Y%m%d-%H%M%S)
LOG_FILE="./logs/campaign-${TIMESTAMP}.log"

mkdir -p logs results

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "${LOG_FILE}"
}

cleanup() {
    log "Stopping containers..."
    docker compose down
    log "Cleanup complete"
}

trap cleanup EXIT INT TERM

log "========================================="
log "Docker-based MQTT Fuzzing Campaign (EMQX)"
log "========================================="
log "Campaign log: ${LOG_FILE}"
log ""

# Build images
log "Building Docker images (this may take 10-15 minutes)..."
docker compose build

# Start EMQX
log "Starting EMQX with ASAN..."
docker compose up -d emqx

# Wait for EMQX to be ready
log "Waiting for EMQX to start..."
sleep 15

if ! docker compose exec -T emqx pgrep beam.smp >/dev/null 2>&1; then
    log "ERROR: EMQX failed to start"
    docker compose logs emqx
    exit 1
fi
log "✓ EMQX started successfully"

# Start fuzzer
log ""
log "========================================="
log "Starting Fuzzer (171,554+ test cases)"
log "========================================="
log "This will take several hours..."
log ""
log "Monitor progress:"
log "  docker compose logs -f fuzzer"
log ""

# Run fuzzer (blocking)
docker compose up fuzzer

FUZZER_EXIT=$?

log ""
log "========================================="
log "Campaign Complete"
log "========================================="
log "Exit code: ${FUZZER_EXIT}"
log ""
log "Results:"
log "  Campaign log: ${LOG_FILE}"
log "  ASAN logs: ./logs/asan.*"
log "  Fuzzing database: ./results/*.db"
log ""
log "Check for crashes:"
log "  grep -i 'error\\|asan\\|heap' ./logs/asan.*"

exit ${FUZZER_EXIT}
