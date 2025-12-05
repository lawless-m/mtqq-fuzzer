# MQTT Fuzzer Skills Conformance Review

**Date:** 2025-12-05
**Reviewed:** mqtt-fuzzer project files
**Skills:** Boofuzz-Fuzzer, Roo-VMS

---

## Summary

| File | Conformance | Issues |
|------|-------------|--------|
| `mqtt_fuzzer.py` | Partial | Naming conventions, session config |
| `mqtt_fuzzer_stateful.py` | Good | Minor naming issues |
| `Dockerfile.mosquitto-asan` | Excellent | None |
| `Dockerfile.nanomq-asan` | Excellent | None |

---

## Boofuzz-Fuzzer Skill Conformance

### 1. Naming Conventions

**Skill Requirement:**
| Element | Convention | Example |
|---------|-----------|---------|
| Request | Protocol-Action format | `"MQTT-CONNECT"` |
| Block | Protocol terminology | `"Fixed-Header"` |
| Primitive | Spec field names | `"packet_type"` |

**Current Implementation:**
- Requests use lowercase: `"connect"`, `"publish_qos0"` instead of `"MQTT-CONNECT"`, `"MQTT-PUBLISH-QoS0"`
- Blocks use lowercase: `"variable_header"` instead of `"Variable-Header"`
- Primitives are good: `"packet_type"`, `"remaining_len"`, `"protocol_name"`

**Recommendation:** Update request names to Protocol-Action format for consistency with boofuzz examples.

### 2. Code Style (Object-Oriented vs Static)

**Skill Preference:**
```python
# Preferred OO style
req = Request("Protocol-Message", children=(
    Block("Header", children=(
        Byte("opcode", default_value=0x01),
    )),
))
```

**Current Implementation:** Uses static function style (`s_initialize`, `s_block`, `s_byte`)

**Assessment:** The static function style is valid boofuzz API and widely used. The skill states "prefer" OO style but doesn't mandate it. Current code is acceptable.

### 3. Session Configuration

**Skill Recommendation:**
```python
session = Session(
    target=Target(...),
    web_port=26000,           # Web UI
    keep_web_open=True,
    crash_threshold_element=3, # Failures before restart
)
```

**Current Implementation:**
```python
session = Session(
    target=Target(...),
    sleep_time=0.1,
    restart_sleep_time=0.5,
    # crash_threshold commented out
)
```

**Missing:**
- `web_port` not specified (uses default)
- `keep_web_open` not specified
- `crash_threshold_element` commented out

**Recommendation:** Add these parameters for better fuzzing control.

### 4. Script Structure

**Conformant Elements:**
- Shebang (`#!/usr/bin/env python3`)
- Docstring with description and protocol reference
- Constants section (`MQTT_CONNECT`, `MQTT_PUBLISH`, etc.)
- `argparse` for CLI
- `main()` function with proper entry point
- Black-compatible formatting

### 5. Stateful Protocol Handling

**Skill Guidance:**
```python
def pre_send_callback(target, fuzz_data_logger, session, sock):
    """Execute before each test case - establish session state."""
    pass

session = Session(
    target=target,
    pre_send_callbacks=[pre_send_callback],
)
```

**Current Implementation (mqtt_fuzzer_stateful.py):** Fully conformant with proper callbacks for CONNECT/CONNACK handshake.

### 6. Disclosure Guidelines

**Skill Reference:** `references/disclosure.md`

**README.md includes:**
- Vendor contact information
- Responsible disclosure guidance
- No public issue instruction

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

**Assessment:** Excellent conformance. Adds `-fno-omit-frame-pointer` for better stack traces and `-O1` for reasonable performance while debugging.

### 2. ASAN Runtime Options

**Dockerfiles:**
```dockerfile
ENV ASAN_OPTIONS="detect_leaks=1:abort_on_error=0:print_stats=1:halt_on_error=0"
```

**Assessment:** Good options for continuous fuzzing (doesn't abort on first error).

### 3. Testing Environment Patterns

**Roo-VMS describes two patterns:**

1. **QEMU VMs** - Full isolation, revertible snapshots
2. **Docker containers** - Lighter weight, faster iteration

**Current approach:** Docker containers

**Assessment:** Appropriate choice for MQTT fuzzing:
- Docker is simpler for TCP services
- Port forwarding works identically
- QEMU would be overkill unless testing kernel-level protocols

### 4. Network Configuration

**Dockerfiles use:**
```dockerfile
EXPOSE 1883
```

Aligns with Roo-VMS port forwarding pattern:
```bash
-netdev user,id=net0,hostfwd=tcp::1883-:1883
```

### 5. Monitoring Pattern

**TARGETS.md describes:**
```bash
# Monitor for ASAN errors
tail -f nanomq.log | grep -E "(ERROR|SUMMARY|AddressSanitizer)"
```

**Assessment:** Conformant with Roo-VMS monitoring guidance.

---

## Detailed Findings

### mqtt_fuzzer.py

| Check | Status | Notes |
|-------|--------|-------|
| Shebang | PASS | `#!/usr/bin/env python3` |
| Docstring | PASS | Includes protocol reference |
| Constants | PASS | All MQTT packet types defined |
| Imports | PASS | Both OO and static imports |
| CLI args | PASS | argparse with -H, -P, --all, etc. |
| Request naming | WARN | Uses lowercase, not Protocol-Action |
| Block naming | PASS | Uses protocol terminology |
| Primitive naming | PASS | Uses spec field names |
| Session config | WARN | Missing web_port, crash_threshold |
| Error handling | PASS | try/except with KeyboardInterrupt |

### mqtt_fuzzer_stateful.py

| Check | Status | Notes |
|-------|--------|-------|
| Callbacks | PASS | pre_send and post_test_case |
| Session state | PASS | MQTTConnection class manages state |
| Reconnection | PASS | Handles connection loss |
| PING check | PASS | Uses PINGREQ to verify connection |

### Dockerfiles

| Check | Status | Notes |
|-------|--------|-------|
| Multi-stage build | PASS | Smaller final image |
| ASAN flags | PASS | Full sanitizer configuration |
| Debug symbols | PASS | `-g` flag present |
| Runtime library | PASS | libasan8 installed |
| Documentation | PASS | Usage comments at top |
| Port exposure | PASS | 1883 exposed |

---

## Recommendations

### High Priority

1. **Add session configuration parameters:**
```python
session = Session(
    target=Target(...),
    web_port=26000,
    keep_web_open=True,
    crash_threshold_element=3,
    crash_threshold_request=10,
)
```

### Medium Priority

2. **Rename requests to Protocol-Action format:**
```python
# Before
s_initialize("connect")

# After
s_initialize("MQTT-CONNECT")
```

3. **Add QEMU integration option** for full VM isolation testing (per Roo-VMS):
```markdown
## VM-Based Testing (Alternative)

For maximum isolation, run the ASAN build in a QEMU VM:
\`\`\`bash
# Copy Docker image contents to VM
docker cp mosquitto-asan:/usr/local/bin/mosquitto ./
scp -P 2222 mosquitto claude@localhost:/home/claude/
\`\`\`
```

### Low Priority

4. **Consider OO-style definitions** for new packet types (existing static style is acceptable)

5. **Add test scripts** that integrate with Roo-VMS start-vms.sh pattern

---

## Conclusion

The mqtt-fuzzer project shows **good overall conformance** with both skills:

- **Boofuzz skill:** ~80% conformant. Core patterns correct, minor naming/config improvements needed.
- **Roo-VMS skill:** ~95% conformant. Docker approach is valid alternative to QEMU VMs.

The code is functional and follows security research best practices. The recommendations above would improve consistency with the documented skill guidelines but are not blocking issues.
