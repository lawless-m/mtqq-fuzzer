# MQTT 3.1.1 Protocol Fuzzer for boofuzz

A comprehensive fuzzer for testing MQTT broker implementations against the OASIS MQTT 3.1.1 specification.

> "The S in IoT stands for Security"

## Features

- **Full MQTT 3.1.1 coverage**: CONNECT, PUBLISH (QoS 0/1/2), SUBSCRIBE, UNSUBSCRIBE, PING, DISCONNECT
- **QoS handshake packets**: PUBACK, PUBREC, PUBREL, PUBCOMP
- **Edge case testing**: Malformed UTF-8, invalid remaining length encoding, oversized packets
- **Wildcard fuzzing**: Tests topic filter wildcards (+, #) in invalid positions
- **Protocol violation testing**: Duplicate CONNECT, invalid packet types, reserved bits

## Requirements

```bash
pip install boofuzz
```

## Quick Start

### 1. Start a test broker

Using Docker (recommended for isolation):

```bash
# Basic Mosquitto
docker run -it --rm -p 1883:1883 eclipse-mosquitto:latest

# Or with verbose logging
docker run -it --rm -p 1883:1883 eclipse-mosquitto:latest mosquitto -v
```

### 2. Run the fuzzer

```bash
# Basic fuzzing
python mqtt_fuzzer.py -H localhost -P 1883

# Include malformed/edge case packets
python mqtt_fuzzer.py -H localhost -P 1883 --all

# Fuzz only CONNECT packets
python mqtt_fuzzer.py -H localhost -P 1883 -r connect

# List available request types
python mqtt_fuzzer.py --list
```

## Testing with AddressSanitizer (ASAN)

For serious vulnerability hunting, build Mosquitto with ASAN:

```dockerfile
# Dockerfile.mosquitto-asan
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    git build-essential cmake libssl-dev libcjson-dev \
    && rm -rf /var/lib/apt/lists/*

RUN git clone https://github.com/eclipse/mosquitto.git /mosquitto \
    && cd /mosquitto \
    && mkdir build && cd build \
    && cmake .. \
        -DCMAKE_C_FLAGS="-fsanitize=address -fno-omit-frame-pointer -g" \
        -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address" \
        -DWITH_TLS=OFF \
        -DWITH_CJSON=OFF \
        -DDOCUMENTATION=OFF \
    && make -j$(nproc)

EXPOSE 1883
CMD ["/mosquitto/build/src/mosquitto", "-v"]
```

Build and run:

```bash
docker build -f Dockerfile.mosquitto-asan -t mosquitto-asan .
docker run -it --rm -p 1883:1883 mosquitto-asan
```

Any memory errors will be reported by ASAN with full stack traces.

## Packet Types Covered

| Packet | Type Code | Fuzzer Request Name |
|--------|-----------|---------------------|
| CONNECT | 0x10 | `connect`, `connect_full` |
| PUBLISH QoS 0 | 0x30 | `publish_qos0` |
| PUBLISH QoS 1 | 0x32 | `publish_qos1` |
| PUBLISH QoS 2 | 0x34 | `publish_qos2` |
| SUBSCRIBE | 0x82 | `subscribe`, `subscribe_multi` |
| UNSUBSCRIBE | 0xA2 | `unsubscribe` |
| PINGREQ | 0xC0 | `pingreq` |
| DISCONNECT | 0xE0 | `disconnect` |
| PUBACK | 0x40 | `puback` |
| PUBREC | 0x50 | `pubrec` |
| PUBREL | 0x62 | `pubrel` |
| PUBCOMP | 0x70 | `pubcomp` |

### Edge Cases (with `--all` flag)

| Test | Request Name |
|------|--------------|
| Invalid remaining length | `malformed_remaining_length` |
| Invalid UTF-8 strings | `malformed_utf8` |
| Wildcard edge cases | `topic_wildcards` |
| Zero-length fields | `zero_length` |
| Oversized packets | `oversized` |
| Invalid packet type | `invalid_type` |
| Duplicate CONNECT | `duplicate_connect` |

## Interpreting Results

boofuzz creates a SQLite database in `./boofuzz-results/` with all test case data.

To view results:

```bash
# Open the web UI (runs on port 26000 by default)
boo open boofuzz-results/run-YYYY-MM-DD_HH-MM-SS.db
```

Or query directly:

```python
import sqlite3

conn = sqlite3.connect('boofuzz-results/run-YYYY-MM-DD_HH-MM-SS.db')
cursor = conn.cursor()

# Find crashes
cursor.execute("""
    SELECT name, type, timestamp 
    FROM cases 
    WHERE type LIKE '%fail%' OR type LIKE '%crash%'
""")
for row in cursor.fetchall():
    print(row)
```

## Responsible Disclosure

If you find a vulnerability:

1. **Do not** open a public issue
2. Contact the vendor's security team:
   - Mosquitto: security@eclipse.org
   - EMQX: security@emqx.io
   - NanoMQ: See GitHub security policy
3. Allow reasonable time for a fix before public disclosure
4. Consider requesting a CVE if appropriate

## Tested Brokers

This fuzzer is designed to test any MQTT 3.1.1 compliant broker:

- [Eclipse Mosquitto](https://mosquitto.org/)
- [EMQX](https://www.emqx.io/)
- [NanoMQ](https://nanomq.io/)
- [VerneMQ](https://vernemq.com/)
- [HiveMQ](https://www.hivemq.com/)

## Protocol Reference

- [MQTT 3.1.1 OASIS Standard](https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html)
- [MQTT 5.0 OASIS Standard](https://docs.oasis-open.org/mqtt/mqtt/v5.0/mqtt-v5.0.html)

## License

MIT

## Contributing

Contributions welcome! Areas that could use work:

- MQTT 5.0 support (new packet types, properties)
- TLS/SSL connection support
- Authentication testing (username/password, client certificates)
- Stateful fuzzing (proper session management)
- Response validation callbacks
