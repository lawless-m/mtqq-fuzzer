#!/usr/bin/env python3
"""
MQTT 3.1.1 Protocol Fuzzer

A comprehensive fuzzer for MQTT brokers implementing the OASIS MQTT 3.1.1 specification.
Designed for security testing of brokers like Mosquitto, NanoMQ, EMQX, etc.

Protocol reference: https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html
"""

from boofuzz import (
    Session,
    Target,
    TCPSocketConnection,
    Request,
    Block,
    Byte,
    Bytes,
    Word,
    String,
    Static,
    s_get,
    BIG_ENDIAN,
)
import argparse
import sys


# =============================================================================
# MQTT 3.1.1 Constants (per OASIS specification)
# =============================================================================

MQTT_PORT = 1883

# Control Packet Types (upper 4 bits of first byte)
MQTT_CONNECT     = 0x10  # 1 << 4
MQTT_CONNACK     = 0x20  # 2 << 4
MQTT_PUBLISH     = 0x30  # 3 << 4
MQTT_PUBACK      = 0x40  # 4 << 4
MQTT_PUBREC      = 0x50  # 5 << 4
MQTT_PUBREL      = 0x62  # 6 << 4 | 0x02 (fixed flags)
MQTT_PUBCOMP     = 0x70  # 7 << 4
MQTT_SUBSCRIBE   = 0x82  # 8 << 4 | 0x02 (fixed flags)
MQTT_SUBACK      = 0x90  # 9 << 4
MQTT_UNSUBSCRIBE = 0xA2  # 10 << 4 | 0x02 (fixed flags)
MQTT_UNSUBACK    = 0xB0  # 11 << 4
MQTT_PINGREQ     = 0xC0  # 12 << 4
MQTT_PINGRESP    = 0xD0  # 13 << 4
MQTT_DISCONNECT  = 0xE0  # 14 << 4

# Protocol constants
MQTT_PROTOCOL_NAME = b"MQTT"
MQTT_PROTOCOL_LEVEL = 0x04  # Version 3.1.1


# =============================================================================
# MQTT Protocol Definitions (Object-Oriented Style)
# =============================================================================

def define_mqtt_connect():
    """
    MQTT-CONNECT: Client requests connection to Server.
    Per MQTT 3.1.1 Section 3.1.
    """
    return Request("MQTT-CONNECT", children=(
        # Fixed Header
        Block("Fixed-Header", children=(
            Byte(name="packet_type", default_value=MQTT_CONNECT, fuzzable=True),
            Byte(name="remaining_length", default_value=0x00, fuzzable=True),
        )),
        # Variable Header
        Block("Variable-Header", children=(
            Word(name="protocol_name_length", default_value=0x0004, endian=BIG_ENDIAN, fuzzable=True),
            Static(name="protocol_name", default_value=MQTT_PROTOCOL_NAME),
            Byte(name="protocol_level", default_value=MQTT_PROTOCOL_LEVEL, fuzzable=True),
            Byte(name="connect_flags", default_value=0x02, fuzzable=True),  # Clean Session
            Word(name="keep_alive", default_value=60, endian=BIG_ENDIAN, fuzzable=True),
        )),
        # Payload
        Block("Payload", children=(
            Word(name="client_id_length", default_value=0x0007, endian=BIG_ENDIAN, fuzzable=True),
            String(name="client_id", default_value="fuzzer1", fuzzable=True, max_len=65535),
        )),
    ))


def define_mqtt_connect_full():
    """
    MQTT-CONNECT-Full: Connection with all optional fields.
    Tests Username, Password, and Will message parsing.
    """
    return Request("MQTT-CONNECT-Full", children=(
        Block("Fixed-Header", children=(
            Byte(name="packet_type", default_value=MQTT_CONNECT, fuzzable=True),
            Byte(name="remaining_length", default_value=0x00, fuzzable=True),
        )),
        Block("Variable-Header", children=(
            Word(name="protocol_name_length", default_value=0x0004, endian=BIG_ENDIAN, fuzzable=True),
            Static(name="protocol_name", default_value=MQTT_PROTOCOL_NAME),
            Byte(name="protocol_level", default_value=MQTT_PROTOCOL_LEVEL, fuzzable=True),
            # Flags: Username(1) + Password(1) + Will Retain(1) + Will QoS 2(10) + Will(1) + Clean(1)
            Byte(name="connect_flags", default_value=0xF6, fuzzable=True),
            Word(name="keep_alive", default_value=60, endian=BIG_ENDIAN, fuzzable=True),
        )),
        Block("Payload", children=(
            # Client ID
            Word(name="client_id_length", default_value=0x0008, endian=BIG_ENDIAN, fuzzable=True),
            String(name="client_id", default_value="fuzzfull", fuzzable=True, max_len=65535),
            # Will Topic
            Word(name="will_topic_length", default_value=0x000A, endian=BIG_ENDIAN, fuzzable=True),
            String(name="will_topic", default_value="will/topic", fuzzable=True, max_len=65535),
            # Will Message
            Word(name="will_message_length", default_value=0x000C, endian=BIG_ENDIAN, fuzzable=True),
            String(name="will_message", default_value="will message", fuzzable=True, max_len=65535),
            # Username
            Word(name="username_length", default_value=0x0008, endian=BIG_ENDIAN, fuzzable=True),
            String(name="username", default_value="testuser", fuzzable=True, max_len=65535),
            # Password
            Word(name="password_length", default_value=0x0008, endian=BIG_ENDIAN, fuzzable=True),
            String(name="password", default_value="testpass", fuzzable=True, max_len=65535),
        )),
    ))


def define_mqtt_publish_qos0():
    """
    MQTT-PUBLISH-QoS0: Publish with at-most-once delivery.
    Per MQTT 3.1.1 Section 3.3.
    """
    return Request("MQTT-PUBLISH-QoS0", children=(
        Block("Fixed-Header", children=(
            Byte(name="packet_type", default_value=MQTT_PUBLISH, fuzzable=True),
            Byte(name="remaining_length", default_value=0x00, fuzzable=True),
        )),
        Block("Variable-Header", children=(
            Word(name="topic_length", default_value=0x000A, endian=BIG_ENDIAN, fuzzable=True),
            String(name="topic_name", default_value="test/topic", fuzzable=True, max_len=65535),
            # No Packet Identifier for QoS 0
        )),
        Block("Payload", children=(
            String(name="application_message", default_value="Hello MQTT", fuzzable=True, max_len=65535),
        )),
    ))


def define_mqtt_publish_qos1():
    """
    MQTT-PUBLISH-QoS1: Publish with at-least-once delivery.
    Includes Packet Identifier, expects PUBACK.
    """
    return Request("MQTT-PUBLISH-QoS1", children=(
        Block("Fixed-Header", children=(
            # PUBLISH + QoS 1 (0x32 = 0x30 | 0x02)
            Byte(name="packet_type", default_value=0x32, fuzzable=True),
            Byte(name="remaining_length", default_value=0x00, fuzzable=True),
        )),
        Block("Variable-Header", children=(
            Word(name="topic_length", default_value=0x000B, endian=BIG_ENDIAN, fuzzable=True),
            String(name="topic_name", default_value="test/topic1", fuzzable=True, max_len=65535),
            Word(name="packet_identifier", default_value=0x0001, endian=BIG_ENDIAN, fuzzable=True),
        )),
        Block("Payload", children=(
            String(name="application_message", default_value="QoS 1 Message", fuzzable=True, max_len=65535),
        )),
    ))


def define_mqtt_publish_qos2():
    """
    MQTT-PUBLISH-QoS2: Publish with exactly-once delivery.
    Initiates 4-way handshake (PUBLISH -> PUBREC -> PUBREL -> PUBCOMP).
    """
    return Request("MQTT-PUBLISH-QoS2", children=(
        Block("Fixed-Header", children=(
            # PUBLISH + QoS 2 (0x34 = 0x30 | 0x04)
            Byte(name="packet_type", default_value=0x34, fuzzable=True),
            Byte(name="remaining_length", default_value=0x00, fuzzable=True),
        )),
        Block("Variable-Header", children=(
            Word(name="topic_length", default_value=0x000B, endian=BIG_ENDIAN, fuzzable=True),
            String(name="topic_name", default_value="test/topic2", fuzzable=True, max_len=65535),
            Word(name="packet_identifier", default_value=0x0002, endian=BIG_ENDIAN, fuzzable=True),
        )),
        Block("Payload", children=(
            String(name="application_message", default_value="QoS 2 Message", fuzzable=True, max_len=65535),
        )),
    ))


def define_mqtt_subscribe():
    """
    MQTT-SUBSCRIBE: Client subscribes to topic filters.
    Per MQTT 3.1.1 Section 3.8.
    """
    return Request("MQTT-SUBSCRIBE", children=(
        Block("Fixed-Header", children=(
            Byte(name="packet_type", default_value=MQTT_SUBSCRIBE, fuzzable=True),
            Byte(name="remaining_length", default_value=0x00, fuzzable=True),
        )),
        Block("Variable-Header", children=(
            Word(name="packet_identifier", default_value=0x0001, endian=BIG_ENDIAN, fuzzable=True),
        )),
        Block("Payload", children=(
            Word(name="topic_filter_length", default_value=0x000A, endian=BIG_ENDIAN, fuzzable=True),
            String(name="topic_filter", default_value="test/topic", fuzzable=True, max_len=65535),
            Byte(name="requested_qos", default_value=0x00, fuzzable=True),
        )),
    ))


def define_mqtt_subscribe_multi():
    """
    MQTT-SUBSCRIBE-Multi: Subscribe to multiple topic filters.
    Tests list parsing in subscription handler.
    """
    return Request("MQTT-SUBSCRIBE-Multi", children=(
        Block("Fixed-Header", children=(
            Byte(name="packet_type", default_value=MQTT_SUBSCRIBE, fuzzable=True),
            Byte(name="remaining_length", default_value=0x00, fuzzable=True),
        )),
        Block("Variable-Header", children=(
            Word(name="packet_identifier", default_value=0x0002, endian=BIG_ENDIAN, fuzzable=True),
        )),
        Block("Payload", children=(
            # Topic Filter 1
            Word(name="topic1_length", default_value=0x0007, endian=BIG_ENDIAN, fuzzable=True),
            String(name="topic1", default_value="topic/1", fuzzable=True, max_len=65535),
            Byte(name="qos1", default_value=0x00, fuzzable=True),
            # Topic Filter 2
            Word(name="topic2_length", default_value=0x0007, endian=BIG_ENDIAN, fuzzable=True),
            String(name="topic2", default_value="topic/2", fuzzable=True, max_len=65535),
            Byte(name="qos2", default_value=0x01, fuzzable=True),
            # Topic Filter 3 (with wildcard)
            Word(name="topic3_length", default_value=0x0008, endian=BIG_ENDIAN, fuzzable=True),
            String(name="topic3", default_value="topic/#", fuzzable=True, max_len=65535),
            Byte(name="qos3", default_value=0x02, fuzzable=True),
        )),
    ))


def define_mqtt_unsubscribe():
    """
    MQTT-UNSUBSCRIBE: Client unsubscribes from topic filters.
    Per MQTT 3.1.1 Section 3.10.
    """
    return Request("MQTT-UNSUBSCRIBE", children=(
        Block("Fixed-Header", children=(
            Byte(name="packet_type", default_value=MQTT_UNSUBSCRIBE, fuzzable=True),
            Byte(name="remaining_length", default_value=0x00, fuzzable=True),
        )),
        Block("Variable-Header", children=(
            Word(name="packet_identifier", default_value=0x0001, endian=BIG_ENDIAN, fuzzable=True),
        )),
        Block("Payload", children=(
            Word(name="topic_filter_length", default_value=0x000A, endian=BIG_ENDIAN, fuzzable=True),
            String(name="topic_filter", default_value="test/topic", fuzzable=True, max_len=65535),
        )),
    ))


def define_mqtt_pingreq():
    """
    MQTT-PINGREQ: Client ping to keep connection alive.
    Per MQTT 3.1.1 Section 3.12.
    """
    return Request("MQTT-PINGREQ", children=(
        Block("Fixed-Header", children=(
            Byte(name="packet_type", default_value=MQTT_PINGREQ, fuzzable=True),
            Byte(name="remaining_length", default_value=0x00, fuzzable=True),
        )),
    ))


def define_mqtt_disconnect():
    """
    MQTT-DISCONNECT: Client graceful disconnect.
    Per MQTT 3.1.1 Section 3.14.
    """
    return Request("MQTT-DISCONNECT", children=(
        Block("Fixed-Header", children=(
            Byte(name="packet_type", default_value=MQTT_DISCONNECT, fuzzable=True),
            Byte(name="remaining_length", default_value=0x00, fuzzable=True),
        )),
    ))


def define_mqtt_puback():
    """
    MQTT-PUBACK: Acknowledgment for QoS 1 PUBLISH.
    Per MQTT 3.1.1 Section 3.4.
    """
    return Request("MQTT-PUBACK", children=(
        Block("Fixed-Header", children=(
            Byte(name="packet_type", default_value=MQTT_PUBACK, fuzzable=True),
            Byte(name="remaining_length", default_value=0x02, fuzzable=True),
        )),
        Block("Variable-Header", children=(
            Word(name="packet_identifier", default_value=0x0001, endian=BIG_ENDIAN, fuzzable=True),
        )),
    ))


def define_mqtt_pubrec():
    """
    MQTT-PUBREC: Part of QoS 2 handshake.
    Per MQTT 3.1.1 Section 3.5.
    """
    return Request("MQTT-PUBREC", children=(
        Block("Fixed-Header", children=(
            Byte(name="packet_type", default_value=MQTT_PUBREC, fuzzable=True),
            Byte(name="remaining_length", default_value=0x02, fuzzable=True),
        )),
        Block("Variable-Header", children=(
            Word(name="packet_identifier", default_value=0x0001, endian=BIG_ENDIAN, fuzzable=True),
        )),
    ))


def define_mqtt_pubrel():
    """
    MQTT-PUBREL: Part of QoS 2 handshake.
    Per MQTT 3.1.1 Section 3.6. Fixed flags MUST be 0010.
    """
    return Request("MQTT-PUBREL", children=(
        Block("Fixed-Header", children=(
            Byte(name="packet_type", default_value=MQTT_PUBREL, fuzzable=True),
            Byte(name="remaining_length", default_value=0x02, fuzzable=True),
        )),
        Block("Variable-Header", children=(
            Word(name="packet_identifier", default_value=0x0001, endian=BIG_ENDIAN, fuzzable=True),
        )),
    ))


def define_mqtt_pubcomp():
    """
    MQTT-PUBCOMP: Final part of QoS 2 handshake.
    Per MQTT 3.1.1 Section 3.7.
    """
    return Request("MQTT-PUBCOMP", children=(
        Block("Fixed-Header", children=(
            Byte(name="packet_type", default_value=MQTT_PUBCOMP, fuzzable=True),
            Byte(name="remaining_length", default_value=0x02, fuzzable=True),
        )),
        Block("Variable-Header", children=(
            Word(name="packet_identifier", default_value=0x0001, endian=BIG_ENDIAN, fuzzable=True),
        )),
    ))


# =============================================================================
# Edge Case / Malformed Packet Definitions
# =============================================================================

def define_mqtt_malformed_remaining_length():
    """
    MQTT-Malformed-RemainingLength: Test remaining length edge cases.
    Invalid continuation bytes, maximum values, truncated encoding.
    """
    return Request("MQTT-Malformed-RemainingLength", children=(
        Block("Fixed-Header", children=(
            Byte(name="packet_type", default_value=MQTT_CONNECT, fuzzable=True),
            # Maximum/invalid remaining length encoding
            Bytes(name="remaining_length", default_value=b"\xFF\xFF\xFF\x7F", fuzzable=True, max_len=8),
        )),
    ))


def define_mqtt_malformed_utf8():
    """
    MQTT-Malformed-UTF8: Test UTF-8 string handling edge cases.
    Invalid sequences, overlong encodings, null characters.
    """
    return Request("MQTT-Malformed-UTF8", children=(
        Block("Fixed-Header", children=(
            Byte(name="packet_type", default_value=MQTT_CONNECT, fuzzable=True),
            Byte(name="remaining_length", default_value=0x20, fuzzable=True),
        )),
        Block("Variable-Header", children=(
            Word(name="protocol_name_length", default_value=0x0004, endian=BIG_ENDIAN, fuzzable=True),
            # Invalid UTF-8 bytes
            Bytes(name="protocol_name", default_value=b"\xFF\xFE\x00\x00", fuzzable=True, max_len=256),
            Byte(name="protocol_level", default_value=MQTT_PROTOCOL_LEVEL, fuzzable=True),
            Byte(name="connect_flags", default_value=0x02, fuzzable=True),
            Word(name="keep_alive", default_value=60, endian=BIG_ENDIAN, fuzzable=True),
        )),
        Block("Payload", children=(
            Word(name="client_id_length", default_value=0x0010, endian=BIG_ENDIAN, fuzzable=True),
            # Invalid UTF-8 continuation bytes
            Bytes(name="client_id",
                  default_value=b"\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8A\x8B\x8C\x8D\x8E\x8F",
                  fuzzable=True, max_len=65535),
        )),
    ))


def define_mqtt_topic_wildcards():
    """
    MQTT-Topic-Wildcards: Test wildcard handling edge cases.
    Invalid wildcard positions, mixed wildcards.
    """
    return Request("MQTT-Topic-Wildcards", children=(
        Block("Fixed-Header", children=(
            Byte(name="packet_type", default_value=MQTT_SUBSCRIBE, fuzzable=True),
            Byte(name="remaining_length", default_value=0x00, fuzzable=True),
        )),
        Block("Variable-Header", children=(
            Word(name="packet_identifier", default_value=0x0003, endian=BIG_ENDIAN, fuzzable=True),
        )),
        Block("Payload", children=(
            Word(name="topic_filter_length", default_value=0x0011, endian=BIG_ENDIAN, fuzzable=True),
            # Invalid: # must be last, + cannot be adjacent to non-separator
            String(name="topic_filter", default_value="test/+/data/#/bad", fuzzable=True, max_len=65535),
            Byte(name="requested_qos", default_value=0x00, fuzzable=True),
        )),
    ))


def define_mqtt_zero_length():
    """
    MQTT-Zero-Length: Test zero-length strings and fields.
    """
    return Request("MQTT-Zero-Length", children=(
        Block("Fixed-Header", children=(
            Byte(name="packet_type", default_value=MQTT_CONNECT, fuzzable=True),
            Byte(name="remaining_length", default_value=0x0C, fuzzable=True),
        )),
        Block("Variable-Header", children=(
            Word(name="protocol_name_length", default_value=0x0004, endian=BIG_ENDIAN, fuzzable=True),
            Static(name="protocol_name", default_value=MQTT_PROTOCOL_NAME),
            Byte(name="protocol_level", default_value=MQTT_PROTOCOL_LEVEL, fuzzable=True),
            Byte(name="connect_flags", default_value=0x02, fuzzable=True),
            Word(name="keep_alive", default_value=60, endian=BIG_ENDIAN, fuzzable=True),
        )),
        Block("Payload", children=(
            # Zero-length client ID (allowed with Clean Session)
            Word(name="client_id_length", default_value=0x0000, endian=BIG_ENDIAN, fuzzable=True),
        )),
    ))


def define_mqtt_oversized():
    """
    MQTT-Oversized: Test maximum packet size handling.
    """
    return Request("MQTT-Oversized", children=(
        Block("Fixed-Header", children=(
            Byte(name="packet_type", default_value=MQTT_PUBLISH, fuzzable=True),
            # Maximum remaining length encoding
            Bytes(name="remaining_length", default_value=b"\xFF\xFF\xFF\x7F", fuzzable=True, max_len=4),
        )),
        Block("Variable-Header", children=(
            Word(name="topic_length", default_value=0xFFFF, endian=BIG_ENDIAN, fuzzable=True),
            Bytes(name="topic_name", default_value=b"A" * 1000, fuzzable=True, max_len=65535),
        )),
        Block("Payload", children=(
            Bytes(name="application_message", default_value=b"B" * 10000, fuzzable=True, max_len=100000),
        )),
    ))


def define_mqtt_invalid_type():
    """
    MQTT-Invalid-Type: Test reserved/invalid packet types.
    Packet types 0 and 15 are reserved.
    """
    return Request("MQTT-Invalid-Type", children=(
        Block("Fixed-Header", children=(
            Byte(name="packet_type", default_value=0x00, fuzzable=True),
            Byte(name="remaining_length", default_value=0x00, fuzzable=True),
        )),
    ))


def define_mqtt_duplicate_connect():
    """
    MQTT-Duplicate-CONNECT: Send CONNECT after already connected.
    Protocol violation per MQTT 3.1.1 Section 3.1.
    """
    return Request("MQTT-Duplicate-CONNECT", children=(
        Block("Fixed-Header", children=(
            Byte(name="packet_type", default_value=MQTT_CONNECT, fuzzable=True),
            Byte(name="remaining_length", default_value=0x10, fuzzable=True),
        )),
        Block("Variable-Header", children=(
            Word(name="protocol_name_length", default_value=0x0004, endian=BIG_ENDIAN, fuzzable=True),
            Static(name="protocol_name", default_value=MQTT_PROTOCOL_NAME),
            Byte(name="protocol_level", default_value=MQTT_PROTOCOL_LEVEL, fuzzable=True),
            Byte(name="connect_flags", default_value=0x02, fuzzable=True),
            Word(name="keep_alive", default_value=60, endian=BIG_ENDIAN, fuzzable=True),
        )),
        Block("Payload", children=(
            Word(name="client_id_length", default_value=0x0004, endian=BIG_ENDIAN, fuzzable=True),
            String(name="client_id", default_value="dup1", fuzzable=True),
        )),
    ))


# =============================================================================
# Session Configuration and Main
# =============================================================================

def create_session(host, port, fuzz_all=False):
    """
    Create a boofuzz session with all MQTT packet definitions.
    """
    session = Session(
        target=Target(
            connection=TCPSocketConnection(host, port),
        ),
        sleep_time=0.1,
        restart_sleep_time=0.5,
        web_port=26000,
        keep_web_open=True,
        crash_threshold_element=3,
        crash_threshold_request=10,
    )

    # Core protocol packets
    print("[*] Defining CONNECT packets...")
    session.connect(define_mqtt_connect())
    session.connect(define_mqtt_connect_full())

    print("[*] Defining PUBLISH packets...")
    session.connect(define_mqtt_publish_qos0())
    session.connect(define_mqtt_publish_qos1())
    session.connect(define_mqtt_publish_qos2())

    print("[*] Defining SUBSCRIBE/UNSUBSCRIBE packets...")
    session.connect(define_mqtt_subscribe())
    session.connect(define_mqtt_subscribe_multi())
    session.connect(define_mqtt_unsubscribe())

    print("[*] Defining control packets...")
    session.connect(define_mqtt_pingreq())
    session.connect(define_mqtt_disconnect())

    print("[*] Defining QoS handshake packets...")
    session.connect(define_mqtt_puback())
    session.connect(define_mqtt_pubrec())
    session.connect(define_mqtt_pubrel())
    session.connect(define_mqtt_pubcomp())

    if fuzz_all:
        print("[*] Defining edge case / malformed packets...")
        session.connect(define_mqtt_malformed_remaining_length())
        session.connect(define_mqtt_malformed_utf8())
        session.connect(define_mqtt_topic_wildcards())
        session.connect(define_mqtt_zero_length())
        session.connect(define_mqtt_oversized())
        session.connect(define_mqtt_invalid_type())
        session.connect(define_mqtt_duplicate_connect())

    return session


def main():
    parser = argparse.ArgumentParser(
        description="MQTT 3.1.1 Protocol Fuzzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -t localhost -p 1883
  %(prog)s -t 192.168.1.100 -p 1883 --all
  %(prog)s -t localhost -p 1883 -r MQTT-CONNECT

Recommended test setup:
  docker run -it --rm -p 1883:1883 eclipse-mosquitto:latest

Or with AddressSanitizer:
  docker build -f Dockerfile.mosquitto-asan -t mosquitto-asan .
  docker run -it --rm -p 1883:1883 mosquitto-asan
        """
    )

    parser.add_argument("-t", "--target", default="localhost",
                        help="Target MQTT broker host (default: localhost)")
    parser.add_argument("-p", "--port", type=int, default=MQTT_PORT,
                        help="Target MQTT broker port (default: 1883)")
    parser.add_argument("-a", "--all", action="store_true",
                        help="Include malformed/edge case packet definitions")
    parser.add_argument("-r", "--request", type=str,
                        help="Fuzz only a specific request by name")
    parser.add_argument("-l", "--list", action="store_true",
                        help="List available request names and exit")

    args = parser.parse_args()

    print("""
    ╔══════════════════════════════════════════════════════════════╗
    ║           MQTT 3.1.1 Protocol Fuzzer for boofuzz             ║
    ║                                                              ║
    ║  Target: {host}:{port:<5}                                    ║
    ║  Web UI: http://localhost:26000                              ║
    ╚══════════════════════════════════════════════════════════════╝
    """.format(host=args.target, port=args.port))

    session = create_session(args.target, args.port, fuzz_all=args.all)

    if args.list:
        print("\nAvailable requests:")
        for name in session.fuzz_node_names():
            print(f"  - {name}")
        return 0

    print(f"\n[*] Starting fuzzer against {args.target}:{args.port}")
    print("[*] Press Ctrl+C to stop\n")

    try:
        if args.request:
            session.fuzz(name=args.request)
        else:
            session.fuzz()
    except KeyboardInterrupt:
        print("\n[!] Fuzzing interrupted by user")
    except Exception as e:
        print(f"\n[!] Error: {e}")
        return 1

    print("\n[*] Fuzzing complete!")
    return 0


if __name__ == "__main__":
    sys.exit(main())
