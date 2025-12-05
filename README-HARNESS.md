# Standalone MQTT Fuzzing Harness

This harness runs independently without requiring an active Claude Code session.

## Components

### 1. Main Campaign Runner
**File**: `run_fuzzing_campaign.sh`

Orchestrates the complete fuzzing campaign:
- Starts NanoMQ with ASAN in the VM
- Launches the fuzzer
- Collects logs and results
- Handles cleanup on exit

**Usage**:
```bash
./run_fuzzing_campaign.sh
```

**Environment variables**:
- `VM_SSH_PORT` (default: 2227)
- `VM_USER` (default: debian)
- `VM_HOST` (default: localhost)
- `MQTT_PORT` (default: 1883)

### 2. Monitor Script
**File**: `monitor_fuzzing.sh`

Check fuzzing progress without interfering:
```bash
./monitor_fuzzing.sh
```

Shows:
- Fuzzer process status and runtime
- NanoMQ status and memory usage
- Test case count and progress
- Recent log entries

### 3. Results Analyzer
**File**: `analyze_results.sh`

Comprehensive analysis of fuzzing results:
```bash
./analyze_results.sh
```

Generates:
- Overall statistics (test count, duration, rate)
- Coverage breakdown by packet type
- Crash and anomaly detection
- ASAN error log analysis

### 4. Systemd Service (Optional)
**File**: `mqtt-fuzzer.service`

For automated/scheduled fuzzing campaigns:

```bash
# Install (one time)
sudo cp mqtt-fuzzer.service /etc/systemd/system/
sudo systemctl daemon-reload

# Run campaign
sudo systemctl start mqtt-fuzzer

# Check status
sudo systemctl status mqtt-fuzzer

# View logs
sudo journalctl -u mqtt-fuzzer -f
```

## Directory Structure

```
mtqq-fuzzer/
├── mqtt_fuzzer.py              # The boofuzz-based fuzzer
├── run_fuzzing_campaign.sh     # Main harness script
├── monitor_fuzzing.sh          # Progress monitoring
├── analyze_results.sh          # Results analysis
├── mqtt-fuzzer.service         # Systemd service
├── logs/                       # Campaign logs
│   ├── campaign-TIMESTAMP.log  # Main campaign log
│   ├── nanomq-TIMESTAMP.log    # NanoMQ output
│   └── asan-TIMESTAMP.log      # ASAN error logs
└── boofuzz-results/            # Fuzzing databases
    └── run-TIMESTAMP.db        # SQLite results

```

## Logs

All logs are timestamped and saved to `logs/`:

- **Campaign log**: Complete execution trace
- **NanoMQ log**: Broker stdout/stderr
- **ASAN log**: Memory error reports from AddressSanitizer

## Running in Background

### Using nohup
```bash
nohup ./run_fuzzing_campaign.sh > campaign.out 2>&1 &
```

### Using tmux/screen
```bash
tmux new -s fuzzing
./run_fuzzing_campaign.sh
# Detach: Ctrl+B, D
# Reattach: tmux attach -t fuzzing
```

### Using systemd (recommended for long campaigns)
```bash
sudo systemctl start mqtt-fuzzer
```

## Monitoring Long-Running Campaigns

Check progress without interrupting:
```bash
./monitor_fuzzing.sh
```

Watch live logs:
```bash
tail -f logs/campaign-*.log
```

Check for crashes in real-time:
```bash
watch -n 60 './analyze_results.sh | grep -A10 "ASAN ERRORS"'
```

## Stopping a Campaign

```bash
# If running in foreground: Ctrl+C

# If running via systemd:
sudo systemctl stop mqtt-fuzzer

# If running in background:
pkill -f mqtt_fuzzer.py

# Force kill everything:
pkill -9 -f mqtt_fuzzer.py
ssh -p 2227 debian@localhost 'pkill -9 nanomq'
```

## Post-Campaign Analysis

After completion (or anytime):
```bash
./analyze_results.sh
```

Direct database queries:
```bash
sqlite3 boofuzz-results/run-*.db

# Example queries:
SELECT COUNT(*) FROM cases;
SELECT name, COUNT(*) FROM cases GROUP BY name LIMIT 10;
SELECT * FROM steps WHERE description LIKE '%crash%';
```

## Example Workflow

```bash
# 1. Start a fuzzing campaign in background
tmux new -s mqtt-fuzzing
./run_fuzzing_campaign.sh

# 2. Detach and let it run (Ctrl+B, D)

# 3. Check progress later
./monitor_fuzzing.sh

# 4. When complete, analyze results
./analyze_results.sh

# 5. Deep dive if needed
sqlite3 boofuzz-results/run-*.db
grep -r "ERROR" logs/asan-*.log
```

## Notes

- The harness handles all cleanup automatically
- Safe to Ctrl+C - cleanup trap will stop NanoMQ in VM
- Can run multiple campaigns - results are timestamped
- Old results are preserved for comparison
- No dependency on Claude Code session being active
