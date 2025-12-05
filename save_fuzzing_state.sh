#!/bin/bash
# Save fuzzing state and ASAN logs from VM
# Run this manually when you want to save fuzzing data

set -euo pipefail

VM_SSH_PORT=2227
VM_USER=debian
VM_HOST=localhost
SAVE_DIR="./logs/saved-$(date +%Y%m%d-%H%M%S)"

echo "Saving fuzzing state from VM..."

mkdir -p "${SAVE_DIR}"

# Collect ASAN logs
echo "Collecting ASAN logs..."
ssh -p "${VM_SSH_PORT}" "${VM_USER}@${VM_HOST}" \
    'cat /tmp/asan-*.* 2>/dev/null' > "${SAVE_DIR}/asan-logs.txt" 2>&1 || echo "No ASAN logs found"

# Collect NanoMQ logs
echo "Collecting NanoMQ logs..."
ssh -p "${VM_SSH_PORT}" "${VM_USER}@${VM_HOST}" \
    'cat /tmp/nanomq.log 2>/dev/null' > "${SAVE_DIR}/nanomq.log" 2>&1 || true

echo ""
echo "Fuzzing state saved to: ${SAVE_DIR}"
echo ""
echo "Files:"
ls -lh "${SAVE_DIR}"
