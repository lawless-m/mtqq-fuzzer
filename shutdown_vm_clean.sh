#!/bin/bash
# Graceful VM shutdown via ACPI
# Called by systemd when stopping qemu-fuzzing-vm.service

set -euo pipefail

VM_SSH_PORT=2227
VM_USER=debian
VM_HOST=localhost

echo "[$(date)] VM shutdown initiated by systemd"

# Check if VM is accessible
if ssh -p "${VM_SSH_PORT}" -o ConnectTimeout=2 "${VM_USER}@${VM_HOST}" 'echo OK' >/dev/null 2>&1; then
    echo "[$(date)] Sending ACPI poweroff to VM..."
    ssh -p "${VM_SSH_PORT}" "${VM_USER}@${VM_HOST}" 'sudo poweroff' 2>/dev/null || true

    # Give VM time to shutdown gracefully
    echo "[$(date)] Waiting for guest OS to shutdown..."
    sleep 5
else
    echo "[$(date)] VM not accessible, will let QEMU terminate naturally"
fi

echo "[$(date)] VM shutdown script complete"
