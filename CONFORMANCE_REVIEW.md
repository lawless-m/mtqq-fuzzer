# MQTT Fuzzer Skills Conformance Review

**Date:** 2025-12-05
**Reviewed:** mqtt-fuzzer project files
**Skills:** Boofuzz-Fuzzer, Roo-VMS
**Status:** CONFORMANT

---

## Summary

| File | Conformance | Notes |
|------|-------------|-------|
| `mqtt_fuzzer.py` | Excellent | OO style, Protocol-Action naming |
| `mqtt_fuzzer_stateful.py` | Excellent | OO style, proper callbacks |
| `Dockerfile.mosquitto-asan` | Excellent | ASAN configuration |
| `Dockerfile.nanomq-asan` | Excellent | ASAN configuration |
| `TESTING.md` | New | Execution guide for target machine |

---

## Boofuzz-Fuzzer Skill Conformance

### 1. Naming Conventions

**Skill Requirement:**
| Element | Convention | Example |
|---------|-----------|---------|
| Request | Protocol-Action format | `"MQTT-CONNECT"` |
| Block | Protocol terminology | `"Fixed-Header"` |
| Primitive | Spec field names | `"packet_type"` |

**Implementation:**
- Requests: `"MQTT-CONNECT"`, `"MQTT-PUBLISH-QoS0"`, `"MQTT-SUBSCRIBE"` ✓
- Blocks: `"Fixed-Header"`, `"Variable-Header"`, `"Payload"` ✓
- Primitives: `"packet_type"`, `"remaining_length"`, `"protocol_level"` ✓

### 2. Code Style (Object-Oriented)

**Skill Preference:**
```python
req = Request("Protocol-Message", children=(
    Block("Header", children=(
        Byte("opcode", default_value=0x01),
    )),
))
```

**Implementation:**
```python
def define_mqtt_connect():
    return Request("MQTT-CONNECT", children=(
        Block("Fixed-Header", children=(
            Byte(name="packet_type", default_value=MQTT_CONNECT, fuzzable=True),
            Byte(name="remaining_length", default_value=0x00, fuzzable=True),
        )),
        Block("Variable-Header", children=(...)),
        Block("Payload", children=(...)),
    ))
```

**Status:** Fully conformant with OO style ✓

### 3. Session Configuration

**Skill Requirement:**
```python
session = Session(
    target=Target(...),
    web_port=26000,
    keep_web_open=True,
    crash_threshold_element=3,
)
```

**Implementation:**
```python
session = Session(
    target=Target(connection=TCPSocketConnection(host, port)),
    sleep_time=0.1,
    restart_sleep_time=0.5,
    web_port=26000,
    keep_web_open=True,
    crash_threshold_element=3,
    crash_threshold_request=10,
)
```

**Status:** Fully conformant ✓

### 4. Script Structure

| Element | Status |
|---------|--------|
| Shebang | ✓ `#!/usr/bin/env python3` |
| Docstring | ✓ Includes protocol reference |
| Constants | ✓ All MQTT packet types defined |
| argparse CLI | ✓ `-t`, `-p`, `--all`, `-r`, `-l` |
| `main()` entry | ✓ Proper structure |

### 5. Stateful Protocol Handling

**Skill Guidance:**
```python
def pre_send_callback(target, fuzz_data_logger, session, sock):
    """Execute before each test case - establish session state."""
    pass

session = Session(
    pre_send_callbacks=[pre_send_callback],
    post_test_case_callbacks=[post_test_case_callback],
)
```

**Implementation (mqtt_fuzzer_stateful.py):**
- `MQTTConnection` class manages CONNECT/CONNACK handshake
- `pre_send_connect` callback ensures connection before each test
- `post_test_case_callback` checks connection health with PINGREQ
- Automatic reconnection on failure

**Status:** Fully conformant ✓

### 6. Disclosure Guidelines

- README.md includes vendor contacts
- Responsible disclosure guidance present
- References `references/disclosure.md` template

**Status:** Conformant ✓

---

## Roo-VMS Skill Conformance

### 1. ASAN Build Pattern

**Skill Example:**
```bash
export CFLAGS="-fsanitize=address -g"
export LDFLAGS="-fsanitize=address"
```

**Dockerfiles:**
```dockerfile
-DCMAKE_C_FLAGS="-fsanitize=address -fno-omit-frame-pointer -g -O1"
-DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address"
```

**Status:** Conformant with enhanced options ✓

### 2. ASAN Runtime Options

```dockerfile
ENV ASAN_OPTIONS="detect_leaks=1:abort_on_error=0:print_stats=1:halt_on_error=0"
```

**Status:** Optimal for continuous fuzzing ✓

### 3. Testing Environment Integration

**TESTING.md covers both:**
- Docker container pattern (primary)
- QEMU VM pattern (per Roo-VMS skill)

Including:
- VM startup commands
- SSH access instructions
- Network configuration (host=10.0.2.2 from VM)
- Port forwarding patterns

**Status:** Fully documented ✓

### 4. Monitoring Patterns

```bash
tail -f nanomq.log | grep -E "(ERROR|SUMMARY|AddressSanitizer|SEGV|heap)"
```

**Status:** Conformant ✓

---

## Detailed Checklist

### mqtt_fuzzer.py

| Check | Status |
|-------|--------|
| Shebang | ✓ |
| Docstring with protocol reference | ✓ |
| Constants section | ✓ |
| OO-style Request definitions | ✓ |
| Protocol-Action naming | ✓ |
| Block naming (Fixed-Header, etc.) | ✓ |
| Primitive naming (spec fields) | ✓ |
| Session with web_port | ✓ |
| Session with crash_threshold | ✓ |
| argparse CLI | ✓ |
| Error handling | ✓ |

### mqtt_fuzzer_stateful.py

| Check | Status |
|-------|--------|
| OO-style Request definitions | ✓ |
| Protocol-Action naming | ✓ |
| pre_send_callbacks | ✓ |
| post_test_case_callbacks | ✓ |
| Session state management | ✓ |
| Reconnection handling | ✓ |
| Different web_port (26001) | ✓ |

### Dockerfiles

| Check | Status |
|-------|--------|
| Multi-stage build | ✓ |
| ASAN compiler flags | ✓ |
| Debug symbols (-g) | ✓ |
| Frame pointers preserved | ✓ |
| libasan runtime | ✓ |
| ASAN_OPTIONS env | ✓ |
| Usage documentation | ✓ |
| Port 1883 exposed | ✓ |

### TESTING.md

| Check | Status |
|-------|--------|
| Quick start instructions | ✓ |
| Docker setup | ✓ |
| QEMU VM setup (Roo-VMS) | ✓ |
| Network configuration | ✓ |
| Request type reference | ✓ |
| Monitoring guidance | ✓ |
| Troubleshooting | ✓ |
| CVE research focus | ✓ |
| Disclosure guidance | ✓ |

---

## Conclusion

The mqtt-fuzzer project is **fully conformant** with both skills:

- **Boofuzz-Fuzzer skill:** 100% conformant
  - OO-style definitions
  - Protocol-Action naming convention
  - Proper session configuration
  - Stateful protocol callbacks

- **Roo-VMS skill:** 100% conformant
  - ASAN build patterns
  - Docker and QEMU options documented
  - Network configuration guidance
  - Monitoring patterns

The code follows security research best practices and is ready for MQTT broker vulnerability testing.
