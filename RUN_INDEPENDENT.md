# Running Independent Fuzzing Campaigns

This guide shows how to run fuzzing campaigns **independently** (outside Claude Code sessions).

## Quick Start

In **YOUR terminal** (not through Claude Code):

```bash
cd /home/matt/Git/mtqq-fuzzer

# Option 1: tmux (RECOMMENDED - you can detach/reattach)
tmux new -s nanomq-fuzzing
./fuzz_nanomq.sh
# Press Ctrl+B, then D to detach
# Reattach later: tmux attach -t nanomq-fuzzing

# Option 2: nohup (fire and forget)
nohup ./fuzz_nanomq.sh > fuzzing.out 2>&1 &

# Option 3: screen
screen -S nanomq-fuzzing
./fuzz_nanomq.sh
# Press Ctrl+A, then D to detach
```

## What It Tests

**Target**: NanoMQ v0.23.0 with AddressSanitizer (ASAN)
**Test Cases**: 171,554+ malformed MQTT packets
**Duration**: ~5-6 hours
**Goal**: Find memory errors, crashes, vulnerabilities

## Monitoring Progress

While it runs, check progress without interfering:

```bash
# Quick status
./monitor_fuzzing.sh

# Watch live logs
tail -f logs/nanomq-campaign-*.log

# Count test cases completed
ls -lh boofuzz-results/*.db
```

## After Completion

Analyze results:

```bash
./analyze_results.sh
```

Check for ASAN errors:

```bash
cat logs/asan-nanomq-*.log
grep -i "error\|heap\|buffer" logs/asan-nanomq-*.log
```

Query database directly:

```bash
sqlite3 boofuzz-results/run-*.db

# Example queries:
SELECT COUNT(*) FROM cases;
SELECT * FROM cases LIMIT 10;
```

## Stopping Early

```bash
# If running in foreground: Ctrl+C

# If in background:
pkill -f mqtt_fuzzer.py

# Or kill specific tmux session:
tmux kill-session -t nanomq-fuzzing
```

## Files Created

```
mtqq-fuzzer/
├── logs/
│   ├── nanomq-campaign-TIMESTAMP.log  # Full campaign log
│   └── asan-nanomq-TIMESTAMP.log      # ASAN error log
├── boofuzz-results/
│   └── run-TIMESTAMP.db               # Test results database
└── fuzz_nanomq.sh                     # The fuzzing script
```

## Troubleshooting

**VM not accessible:**
```bash
ssh -p 2227 debian@localhost
# If fails, start VM:
sudo systemctl start qemu-fuzzing-vm
```

**MQTT port not ready:**
```bash
# Check if nanomq is running in VM:
ssh -p 2227 debian@localhost 'ps aux | grep nanomq'

# Check port forwarding:
nc -zv localhost 1883
```

**Fuzzer exits immediately:**
- Make sure venv is activated: `source venv/bin/activate`
- Check dependencies: `pip3 list | grep boofuzz`

## Notes

- The script **auto-cleans** on exit (kills NanoMQ in VM)
- Safe to Ctrl+C - cleanup trap handles it
- Results are timestamped and never overwrite
- ASAN slows down the broker ~2-5x but catches memory errors
- No need to keep Claude Code running - this runs independently!

## Expected Output

**If no bugs found:**
```
Total test cases: 171,554
No ASAN errors detected
All tests: "No crash detected"
```

**If bugs found:**
```
ASAN ERRORS DETECTED!
ERROR: AddressSanitizer: heap-buffer-overflow
[Stack trace showing where the bug occurred]
```

Finding a crash = SUCCESS! That's what fuzzing is for.
