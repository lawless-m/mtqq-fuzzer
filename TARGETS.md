# MQTT Broker Fuzzing Targets

A guide to setting up various MQTT brokers for security testing with our boofuzz fuzzer.

## Target Overview

| Broker | Language | CVE History | Docker Available | ASAN Support | Priority |
|--------|----------|-------------|------------------|--------------|----------|
| **NanoMQ** | C | High (many recent CVEs) | Yes | Yes | 🔴 HIGH |
| **Mosquitto** | C | Medium | Yes | Yes | 🟡 MEDIUM |
| **EMQX** | Erlang | Low (mostly logic bugs) | Yes | N/A | 🟢 LOW |
| **VerneMQ** | Erlang | Very Low | Yes | N/A | 🟢 LOW |

**Why NanoMQ is the top target:**
- Written in C (memory safety issues likely)
- Many recent CVEs: heap overflows, use-after-free, segfaults
- CVE-2024-42648: heap overflow via crafted CONNECT
- CVE-2024-42650: segfault via crafted PUBLISH
- CVE-2024-42651: use-after-free via crafted SUBSCRIBE
- Actively developed, maintainers responsive to reports
- Edge computing focus means resource constraints = corner cutting

---

## NanoMQ Setup

### Basic Docker

```bash
# Latest release
docker run -d --name nanomq -p 1883:1883 emqx/nanomq:latest

# With verbose logging
docker run -it --rm -p 1883:1883 emqx/nanomq:latest \
    nanomq start --log_level=debug
```

### Build with AddressSanitizer

```dockerfile
# Dockerfile.nanomq-asan
FROM debian:bookworm-slim AS builder

RUN apt-get update && apt-get install -y \
    git cmake build-essential ninja-build \
    && rm -rf /var/lib/apt/lists/*

# Clone NanoMQ and submodules
RUN git clone --recursive https://github.com/nanomq/nanomq.git /nanomq

WORKDIR /nanomq/build

# Build with ASAN
RUN cmake .. -G Ninja \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_C_FLAGS="-fsanitize=address -fno-omit-frame-pointer -g -O1" \
    -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address" \
    -DNNG_ENABLE_TLS=OFF \
    -DENABLE_JWT=OFF \
    && ninja

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y libasan8 && rm -rf /var/lib/apt/lists/*

COPY --from=builder /nanomq/build/nanomq/nanomq /usr/local/bin/

ENV ASAN_OPTIONS="detect_leaks=1:abort_on_error=0:print_stats=1:halt_on_error=0"

EXPOSE 1883

CMD ["nanomq", "start", "--log_level", "debug"]
```

Build and run:
```bash
docker build -f Dockerfile.nanomq-asan -t nanomq-asan .
docker run -it --rm -p 1883:1883 nanomq-asan
```

### Interesting NanoMQ Attack Surface

Based on CVE history, focus fuzzing on:
1. **CONNECT message parsing** (CVE-2024-42648 - heap overflow)
2. **PUBLISH handler** (CVE-2024-42650 - segfault in pub_handler.c)
3. **SUBSCRIBE handler** (CVE-2024-42651 - use-after-free in sub_Ctx_handle)
4. **Topic wildcard processing** (CVE-2024-42655 - access control bypass)
5. **Variable length encoding** (CVE-2024-31036 - heap-buffer-overflow in read_byte)

---

## Mosquitto Setup

### Basic Docker

```bash
# Official image with verbose logging
docker run -it --rm -p 1883:1883 eclipse-mosquitto:latest mosquitto -v

# Or with config file for anonymous access
echo -e "listener 1883 0.0.0.0\nallow_anonymous true\nlog_type all" > mosquitto.conf
docker run -it --rm -p 1883:1883 -v $(pwd)/mosquitto.conf:/mosquitto/config/mosquitto.conf eclipse-mosquitto:latest
```

### Build with AddressSanitizer

See `Dockerfile.mosquitto-asan` in this repository.

### Interesting Mosquitto Attack Surface

Based on CVE history:
1. **Initial packet handling** (CVE-2023-0809 - memory allocation on non-CONNECT)
2. **Will message properties** (CVE-2023-3592 - memory leak on invalid properties)
3. **QoS 2 message handling** (CVE-2023-28366 - memory leak on duplicate IDs)
4. **UTF-8 string validation**

---

## EMQX Setup

EMQX is Erlang-based, so memory corruption unlikely. Focus on logic bugs.

```bash
docker run -d --name emqx -p 1883:1883 -p 18083:18083 emqx/emqx:latest
# Dashboard: http://localhost:18083 (admin/public)
```

---

## VerneMQ Setup

Also Erlang-based, less actively maintained.

```bash
docker run -d --name vernemq -p 1883:1883 vernemq/vernemq:latest
```

---

## Testing Strategy

### Phase 1: Quick Smoke Test
```bash
python mqtt_fuzzer.py -H localhost -P 1883
```

### Phase 2: NanoMQ Deep Dive (Primary Target)
```bash
# Terminal 1: Start with ASAN
docker run -it --rm -p 1883:1883 nanomq-asan 2>&1 | tee nanomq.log

# Terminal 2: Stateful fuzzing
python mqtt_fuzzer_stateful.py -H localhost -P 1883

# Terminal 3: Monitor for ASAN errors
tail -f nanomq.log | grep -E "(ERROR|SUMMARY|AddressSanitizer)"
```

### Phase 3: Edge Cases
```bash
python mqtt_fuzzer.py -H localhost -P 1883 --all
```

---

## Responsible Disclosure

| Vendor | Contact |
|--------|---------|
| NanoMQ/EMQX | security@emqx.io |
| Mosquitto | security@eclipse.org |
| VerneMQ | GitHub Issues |

---

## NanoMQ CVE History (2023-2024)

| CVE | Type | Component |
|-----|------|-----------|
| CVE-2024-42655 | Access Control Bypass | Wildcard handling |
| CVE-2024-42651 | Use-After-Free | sub_Ctx_handle |
| CVE-2024-42650 | Segfault | pub_handler.c |
| CVE-2024-42648 | Heap Overflow | CONNECT handler |
| CVE-2024-42646 | Segfault | Crafted messages |
| CVE-2024-44460 | Invalid Read | - |
| CVE-2024-31036 | Heap Buffer Overflow | read_byte() |
| CVE-2023-33656 | DoS | message.c |

This pattern shows NanoMQ's MQTT parsing is a rich target for fuzzing.
