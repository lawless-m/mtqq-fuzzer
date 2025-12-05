# MQTT Fuzzer Testing Guide

Instructions for executing MQTT broker fuzzing tests. This document is designed
to be read on the target machine.

---

## Quick Start

```bash
# Install boofuzz
pip3 install boofuzz

# Basic fuzzing against localhost
python3 mqtt_fuzzer.py -t localhost -p 1883

# Stateful fuzzing (establishes connection first)
python3 mqtt_fuzzer_stateful.py -t localhost -p 1883

# List available request types
python3 mqtt_fuzzer.py -l
```

---

## Test Environment Setup

### Option A: Docker (Recommended)

#### 1. Basic Mosquitto

```bash
# Start Mosquitto with verbose logging
docker run -it --rm -p 1883:1883 eclipse-mosquitto:latest mosquitto -v
```

#### 2. Mosquitto with AddressSanitizer

```bash
# Build ASAN image
docker build -f Dockerfile.mosquitto-asan -t mosquitto-asan .

# Run with ASAN enabled
docker run -it --rm -p 1883:1883 mosquitto-asan

# Monitor output for ASAN errors
docker logs -f <container_id> 2>&1 | grep -E "ERROR|SUMMARY|AddressSanitizer"
```

#### 3. NanoMQ with AddressSanitizer (Primary Target)

```bash
# Build ASAN image
docker build -f Dockerfile.nanomq-asan -t nanomq-asan .

# Run with ASAN enabled
docker run -it --rm -p 1883:1883 nanomq-asan
```

### Option B: QEMU VM (Maximum Isolation)

For testing with full VM isolation per the Roo-VMS skill.

#### 1. Start Debian VM

```bash
cd /home/matt/Git/VoE/qemu-vms
qemu-system-x86_64 -name mqtt-target -m 1024 \
  -hda debian-12-generic-amd64.qcow2 \
  -netdev user,id=net0,hostfwd=tcp::2224-:22,hostfwd=tcp::1883-:1883 \
  -device e1000,netdev=net0 \
  -nographic
```

#### 2. SSH to VM and Start Broker

```bash
ssh -p 2224 debian@localhost

# Inside VM: Install and run Mosquitto
sudo apt update && sudo apt install -y mosquitto
sudo mosquitto -v -p 1883
```

#### 3. Run Fuzzer from Host

```bash
# Target the VM's forwarded port
python3 mqtt_fuzzer.py -t localhost -p 1883
```

#### 4. Or Run Fuzzer Inside VM

```bash
# Copy fuzzer to VM
scp -P 2224 mqtt_fuzzer.py mqtt_fuzzer_stateful.py debian@localhost:~/

# SSH and run
ssh -p 2224 debian@localhost
pip3 install boofuzz
python3 mqtt_fuzzer.py -t localhost -p 1883
```

---

## Testing Phases

### Phase 1: Smoke Test

Quick validation that fuzzer works:

```bash
# Terminal 1: Start broker
docker run -it --rm -p 1883:1883 eclipse-mosquitto:latest mosquitto -v

# Terminal 2: Run basic fuzzer
python3 mqtt_fuzzer.py -t localhost -p 1883 -r MQTT-CONNECT
```

Expected: Fuzzer connects, sends packets, broker logs show incoming connections.

### Phase 2: Full Protocol Coverage

```bash
# Basic fuzzer - all standard packets
python3 mqtt_fuzzer.py -t localhost -p 1883

# With edge cases and malformed packets
python3 mqtt_fuzzer.py -t localhost -p 1883 --all
```

### Phase 3: Stateful Fuzzing

Tests bugs that only appear in connected state:

```bash
python3 mqtt_fuzzer_stateful.py -t localhost -p 1883
```

### Phase 4: NanoMQ Deep Dive (High-Value Target)

NanoMQ has many recent CVEs. Focus here for new findings.

```bash
# Terminal 1: Start NanoMQ with ASAN
docker run -it --rm -p 1883:1883 nanomq-asan 2>&1 | tee nanomq.log

# Terminal 2: Run stateful fuzzer
python3 mqtt_fuzzer_stateful.py -t localhost -p 1883

# Terminal 3: Monitor for crashes
tail -f nanomq.log | grep -E "(ERROR|SUMMARY|AddressSanitizer|SEGV|heap)"
```

---

## Request Types Reference

### Basic Fuzzer (mqtt_fuzzer.py)

| Request Name | Description |
|--------------|-------------|
| `MQTT-CONNECT` | Basic connection request |
| `MQTT-CONNECT-Full` | Connection with username/password/will |
| `MQTT-PUBLISH-QoS0` | Fire-and-forget publish |
| `MQTT-PUBLISH-QoS1` | At-least-once publish |
| `MQTT-PUBLISH-QoS2` | Exactly-once publish |
| `MQTT-SUBSCRIBE` | Single topic subscription |
| `MQTT-SUBSCRIBE-Multi` | Multiple topics |
| `MQTT-UNSUBSCRIBE` | Unsubscribe from topic |
| `MQTT-PINGREQ` | Keep-alive ping |
| `MQTT-DISCONNECT` | Graceful disconnect |
| `MQTT-PUBACK` | QoS 1 acknowledgment |
| `MQTT-PUBREC` | QoS 2 step 2 |
| `MQTT-PUBREL` | QoS 2 step 3 |
| `MQTT-PUBCOMP` | QoS 2 step 4 |

**Edge cases (with `--all`):**

| Request Name | Description |
|--------------|-------------|
| `MQTT-Malformed-RemainingLength` | Invalid length encoding |
| `MQTT-Malformed-UTF8` | Invalid UTF-8 strings |
| `MQTT-Topic-Wildcards` | Invalid wildcard patterns |
| `MQTT-Zero-Length` | Zero-length fields |
| `MQTT-Oversized` | Maximum size packets |
| `MQTT-Invalid-Type` | Reserved packet types |
| `MQTT-Duplicate-CONNECT` | Protocol violation |

### Stateful Fuzzer (mqtt_fuzzer_stateful.py)

| Request Name | Description |
|--------------|-------------|
| `MQTT-PUBLISH-Connected` | Publish in session |
| `MQTT-SUBSCRIBE-Connected` | Subscribe in session |
| `MQTT-UNSUBSCRIBE-Connected` | Unsubscribe in session |
| `MQTT-PUBLISH-QoS1-Connected` | QoS 1 in session |
| `MQTT-PUBLISH-QoS2-Connected` | QoS 2 in session |
| `MQTT-PUBREL-Connected` | Orphan PUBREL |
| `MQTT-PINGREQ-Connected` | Ping with extra bytes |
| `MQTT-Second-CONNECT` | Duplicate CONNECT |
| `MQTT-Massive-Topic` | Very long topic name |
| `MQTT-SUBSCRIBE-Wildcards` | Invalid wildcards |

---

## Monitoring and Results

### Web UI

Both fuzzers expose a web interface:

- Basic fuzzer: http://localhost:26000
- Stateful fuzzer: http://localhost:26001

### Results Database

Results are stored in SQLite:

```bash
# List results
ls boofuzz-results/

# Open in web UI
boo open boofuzz-results/run-YYYY-MM-DD_HH-MM-SS.db
```

### Query Crashes

```python
import sqlite3
conn = sqlite3.connect('boofuzz-results/run-YYYY-MM-DD.db')
cursor = conn.cursor()

# Find failures
cursor.execute("""
    SELECT id, name, type, timestamp
    FROM cases
    WHERE type LIKE '%fail%' OR type LIKE '%crash%'
""")
for row in cursor.fetchall():
    print(row)
```

### ASAN Output

When running ASAN-enabled brokers, watch for:

```
=================================================================
==12345==ERROR: AddressSanitizer: heap-buffer-overflow
    #0 0x... in vulnerable_function
    #1 0x... in handle_packet
```

---

## Network Configuration

### From Host to Docker

```
Host (fuzzer) --> localhost:1883 --> Docker container
```

### From Host to QEMU VM

```
Host (fuzzer) --> localhost:1883 --> QEMU port forward --> VM:1883
```

### From VM to Host

If running fuzzer inside VM targeting host:

```bash
# Host is 10.0.2.2 from inside QEMU user-mode networking
python3 mqtt_fuzzer.py -t 10.0.2.2 -p 1883
```

---

## Troubleshooting

### Connection Refused

```bash
# Check broker is running
ss -tlnp | grep 1883

# Check Docker/VM is exposing port
docker ps
```

### Fuzzer Hangs

```bash
# Reduce sleep time
# Edit mqtt_fuzzer.py: sleep_time=0.01
```

### No ASAN Output

Ensure ASAN environment is set:

```bash
export ASAN_OPTIONS="detect_leaks=1:abort_on_error=0:halt_on_error=0"
```

### VM Network Issues

```bash
# Inside VM, check interface
ip addr show
ping 10.0.2.2  # Should reach host
```

---

## Safety Notes

- Run brokers in containers or VMs for isolation
- ASAN builds may be slower but catch memory bugs
- Monitor system resources during extended fuzzing
- Results are stored locally - back up interesting findings

---

## CVE Research Focus

Based on NanoMQ's CVE history, prioritize:

1. **CONNECT parsing** - CVE-2024-42648 (heap overflow)
2. **PUBLISH handler** - CVE-2024-42650 (segfault)
3. **SUBSCRIBE handler** - CVE-2024-42651 (use-after-free)
4. **Wildcard processing** - CVE-2024-42655 (access control bypass)
5. **Variable length decoding** - CVE-2024-31036 (heap overflow)

Use `--all` flag and stateful fuzzer to hit these code paths.

---

## Responsible Disclosure

If you find a vulnerability:

1. Do NOT open a public issue
2. Contact vendor security team:
   - NanoMQ/EMQX: security@emqx.io
   - Mosquitto: security@eclipse.org
3. Allow 90 days for fix before disclosure
4. See `references/disclosure.md` for templates
