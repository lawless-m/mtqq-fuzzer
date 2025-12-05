#!/usr/bin/env python3
"""
MQTT 3.1.1 Protocol Fuzzer for boofuzz

A comprehensive fuzzer for MQTT brokers implementing the OASIS MQTT 3.1.1 specification.
Designed for security testing of brokers like Mosquitto, NanoMQ, EMQX, etc.

Protocol reference: https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html

Author: Built with boofuzz
License: MIT
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
    DWord,
    String,
    Static,
    Size,
    Checksum,
    BitField,
    Group,
    s_initialize,
    s_block,
    s_byte,
    s_bytes,
    s_word,
    s_dword,
    s_string,
    s_static,
    s_size,
    s_bit_field,
    s_group,
    s_get,
)
import struct
import argparse
import sys


# =============================================================================
# MQTT 3.1.1 Constants
# =============================================================================

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
# Helper: Variable Length Encoding
# =============================================================================

def encode_remaining_length(length):
    """
    Encode remaining length per MQTT spec.
    Uses continuation bit (MSB) to indicate more bytes follow.
    """
    encoded = bytearray()
    while True:
        digit = length % 128
        length = length // 128
        if length > 0:
            digit |= 0x80
        encoded.append(digit)
        if length == 0:
            break
    return bytes(encoded)


def encode_utf8_string(s):
    """
    Encode a string as MQTT UTF-8 string (2-byte length prefix + data).
    """
    if isinstance(s, str):
        s = s.encode('utf-8')
    return struct.pack(">H", len(s)) + s


# =============================================================================
# Custom Encoder for Remaining Length
# =============================================================================

class MQTTRemainingLengthEncoder:
    """
    Custom encoder to produce MQTT variable-length encoding for the 
    Remaining Length field.
    """
    @staticmethod
    def encode(length_bytes):
        """Convert a length value to MQTT remaining length encoding."""
        if isinstance(length_bytes, bytes):
            length = int.from_bytes(length_bytes, 'big')
        else:
            length = int(length_bytes)
        return encode_remaining_length(length)


# =============================================================================
# MQTT Protocol Definitions
# =============================================================================

def define_connect(session):
    """
    CONNECT Packet - Client requests connection to Server
    
    Fixed Header:
        - Byte 1: Packet type (0x10) + Reserved (0x00)
        - Bytes 2+: Remaining Length (variable)
    
    Variable Header:
        - Protocol Name: UTF-8 "MQTT"
        - Protocol Level: 0x04 (v3.1.1)
        - Connect Flags: Clean Session, Will, Will QoS, Will Retain, Password, Username
        - Keep Alive: 2 bytes
    
    Payload:
        - Client Identifier (required)
        - Will Topic (if Will Flag set)
        - Will Message (if Will Flag set)
        - Username (if Username Flag set)
        - Password (if Password Flag set)
    """
    s_initialize("connect")
    
    # Fixed Header - Packet Type
    s_byte(0x10, name="packet_type", fuzzable=True)
    
    # We'll manually construct remaining length after the variable header + payload
    # For fuzzing, we include it as a fuzzable field
    with s_block("remaining_length"):
        # Remaining length - typically small for CONNECT, but let's fuzz it
        # Using a byte that can be fuzzed to test length parsing
        s_byte(0x00, name="remaining_len", fuzzable=True)
    
    with s_block("variable_header"):
        # Protocol Name Length (2 bytes, big-endian)
        s_word(0x0004, name="protocol_name_len", endian=">", fuzzable=True)
        
        # Protocol Name "MQTT"
        s_static(b"MQTT", name="protocol_name")
        
        # Protocol Level (0x04 for v3.1.1)
        s_byte(0x04, name="protocol_level", fuzzable=True)
        
        # Connect Flags
        # Bit 7: Username Flag
        # Bit 6: Password Flag  
        # Bit 5: Will Retain
        # Bits 4-3: Will QoS (0, 1, 2)
        # Bit 2: Will Flag
        # Bit 1: Clean Session
        # Bit 0: Reserved (must be 0)
        s_byte(0x02, name="connect_flags", fuzzable=True)  # Clean Session only
        
        # Keep Alive (seconds)
        s_word(60, name="keep_alive", endian=">", fuzzable=True)
    
    with s_block("payload"):
        # Client Identifier (UTF-8 encoded string)
        s_word(0x0007, name="client_id_len", endian=">", fuzzable=True)
        s_string("fuzzer1", name="client_id", fuzzable=True, max_len=65535)
    
    session.connect(s_get("connect"))


def define_connect_full(session):
    """
    CONNECT Packet with all optional fields - Username, Password, Will
    
    This tests the more complex parsing paths in brokers.
    """
    s_initialize("connect_full")
    
    s_byte(0x10, name="packet_type", fuzzable=True)
    
    # Remaining length - we'll use a larger value for full connect
    s_byte(0x00, name="remaining_len", fuzzable=True)
    
    with s_block("variable_header"):
        s_word(0x0004, name="protocol_name_len", endian=">", fuzzable=True)
        s_static(b"MQTT", name="protocol_name")
        s_byte(0x04, name="protocol_level", fuzzable=True)
        
        # Connect Flags with all features enabled
        # 0xF6 = Username(1) + Password(1) + Will Retain(1) + Will QoS 2(10) + Will(1) + Clean Session(1) + Reserved(0)
        # Actually: 11110110 = 0xF6
        s_byte(0xF6, name="connect_flags", fuzzable=True)
        
        s_word(60, name="keep_alive", endian=">", fuzzable=True)
    
    with s_block("payload"):
        # Client ID
        s_word(0x0008, name="client_id_len", endian=">", fuzzable=True)
        s_string("fuzzfull", name="client_id", fuzzable=True, max_len=65535)
        
        # Will Topic (because Will Flag is set)
        s_word(0x000A, name="will_topic_len", endian=">", fuzzable=True)
        s_string("will/topic", name="will_topic", fuzzable=True, max_len=65535)
        
        # Will Message
        s_word(0x000C, name="will_message_len", endian=">", fuzzable=True)
        s_string("will message", name="will_message", fuzzable=True, max_len=65535)
        
        # Username
        s_word(0x0008, name="username_len", endian=">", fuzzable=True)
        s_string("testuser", name="username", fuzzable=True, max_len=65535)
        
        # Password
        s_word(0x0008, name="password_len", endian=">", fuzzable=True)
        s_string("testpass", name="password", fuzzable=True, max_len=65535)
    
    session.connect(s_get("connect_full"))


def define_publish_qos0(session):
    """
    PUBLISH Packet - QoS 0 (at most once, fire and forget)
    
    Fixed Header:
        - Byte 1: Packet type (0x30) + DUP(0) + QoS(00) + RETAIN(0)
        - Bytes 2+: Remaining Length
    
    Variable Header:
        - Topic Name (UTF-8 string)
        - No Packet Identifier for QoS 0
    
    Payload:
        - Application Message (arbitrary bytes)
    """
    s_initialize("publish_qos0")
    
    # Fixed header: PUBLISH (3 << 4) + flags
    # Bits 3: DUP, Bits 2-1: QoS, Bit 0: RETAIN
    s_byte(0x30, name="packet_type", fuzzable=True)
    
    # Remaining length
    s_byte(0x00, name="remaining_len", fuzzable=True)
    
    with s_block("variable_header"):
        # Topic Name
        s_word(0x000A, name="topic_len", endian=">", fuzzable=True)
        s_string("test/topic", name="topic", fuzzable=True, max_len=65535)
    
    with s_block("payload"):
        # Application Message
        s_string("Hello MQTT", name="message", fuzzable=True, max_len=65535)
    
    session.connect(s_get("publish_qos0"))


def define_publish_qos1(session):
    """
    PUBLISH Packet - QoS 1 (at least once, requires PUBACK)
    
    Includes Packet Identifier in variable header.
    """
    s_initialize("publish_qos1")
    
    # PUBLISH + QoS 1 (0x32 = 0x30 | 0x02)
    s_byte(0x32, name="packet_type", fuzzable=True)
    
    s_byte(0x00, name="remaining_len", fuzzable=True)
    
    with s_block("variable_header"):
        s_word(0x000B, name="topic_len", endian=">", fuzzable=True)
        s_string("test/topic1", name="topic", fuzzable=True, max_len=65535)
        
        # Packet Identifier (required for QoS > 0)
        s_word(0x0001, name="packet_id", endian=">", fuzzable=True)
    
    with s_block("payload"):
        s_string("QoS 1 Message", name="message", fuzzable=True, max_len=65535)
    
    session.connect(s_get("publish_qos1"))


def define_publish_qos2(session):
    """
    PUBLISH Packet - QoS 2 (exactly once, full handshake)
    """
    s_initialize("publish_qos2")
    
    # PUBLISH + QoS 2 (0x34 = 0x30 | 0x04)
    s_byte(0x34, name="packet_type", fuzzable=True)
    
    s_byte(0x00, name="remaining_len", fuzzable=True)
    
    with s_block("variable_header"):
        s_word(0x000B, name="topic_len", endian=">", fuzzable=True)
        s_string("test/topic2", name="topic", fuzzable=True, max_len=65535)
        
        s_word(0x0002, name="packet_id", endian=">", fuzzable=True)
    
    with s_block("payload"):
        s_string("QoS 2 Message", name="message", fuzzable=True, max_len=65535)
    
    session.connect(s_get("publish_qos2"))


def define_subscribe(session):
    """
    SUBSCRIBE Packet - Client subscribes to topics
    
    Fixed Header:
        - Byte 1: 0x82 (SUBSCRIBE + reserved bits must be 0010)
        - Bytes 2+: Remaining Length
    
    Variable Header:
        - Packet Identifier (2 bytes)
    
    Payload:
        - List of (Topic Filter, Requested QoS) pairs
    """
    s_initialize("subscribe")
    
    # SUBSCRIBE packet type with required flags (0x82)
    s_byte(0x82, name="packet_type", fuzzable=True)
    
    s_byte(0x00, name="remaining_len", fuzzable=True)
    
    with s_block("variable_header"):
        # Packet Identifier
        s_word(0x0001, name="packet_id", endian=">", fuzzable=True)
    
    with s_block("payload"):
        # Topic Filter 1
        s_word(0x000A, name="topic_filter_len", endian=">", fuzzable=True)
        s_string("test/topic", name="topic_filter", fuzzable=True, max_len=65535)
        
        # Requested QoS (only bits 0-1 used, rest reserved)
        s_byte(0x00, name="requested_qos", fuzzable=True)
    
    session.connect(s_get("subscribe"))


def define_subscribe_multi(session):
    """
    SUBSCRIBE with multiple topic filters - tests list parsing
    """
    s_initialize("subscribe_multi")
    
    s_byte(0x82, name="packet_type", fuzzable=True)
    s_byte(0x00, name="remaining_len", fuzzable=True)
    
    with s_block("variable_header"):
        s_word(0x0002, name="packet_id", endian=">", fuzzable=True)
    
    with s_block("payload"):
        # Topic Filter 1
        s_word(0x0007, name="topic1_len", endian=">", fuzzable=True)
        s_string("topic/1", name="topic1", fuzzable=True, max_len=65535)
        s_byte(0x00, name="qos1", fuzzable=True)
        
        # Topic Filter 2
        s_word(0x0007, name="topic2_len", endian=">", fuzzable=True)
        s_string("topic/2", name="topic2", fuzzable=True, max_len=65535)
        s_byte(0x01, name="qos2", fuzzable=True)
        
        # Topic Filter 3 (with wildcard)
        s_word(0x0008, name="topic3_len", endian=">", fuzzable=True)
        s_string("topic/#", name="topic3", fuzzable=True, max_len=65535)
        s_byte(0x02, name="qos3", fuzzable=True)
    
    session.connect(s_get("subscribe_multi"))


def define_unsubscribe(session):
    """
    UNSUBSCRIBE Packet - Client unsubscribes from topics
    """
    s_initialize("unsubscribe")
    
    # UNSUBSCRIBE packet type with required flags (0xA2)
    s_byte(0xA2, name="packet_type", fuzzable=True)
    
    s_byte(0x00, name="remaining_len", fuzzable=True)
    
    with s_block("variable_header"):
        s_word(0x0001, name="packet_id", endian=">", fuzzable=True)
    
    with s_block("payload"):
        s_word(0x000A, name="topic_len", endian=">", fuzzable=True)
        s_string("test/topic", name="topic", fuzzable=True, max_len=65535)
    
    session.connect(s_get("unsubscribe"))


def define_pingreq(session):
    """
    PINGREQ Packet - Client ping to keep connection alive
    
    Minimal packet: just type + remaining length of 0
    """
    s_initialize("pingreq")
    
    s_byte(0xC0, name="packet_type", fuzzable=True)
    s_byte(0x00, name="remaining_len", fuzzable=True)
    
    session.connect(s_get("pingreq"))


def define_disconnect(session):
    """
    DISCONNECT Packet - Client graceful disconnect
    """
    s_initialize("disconnect")
    
    s_byte(0xE0, name="packet_type", fuzzable=True)
    s_byte(0x00, name="remaining_len", fuzzable=True)
    
    session.connect(s_get("disconnect"))


def define_puback(session):
    """
    PUBACK Packet - Acknowledgment for QoS 1 PUBLISH
    
    Normally sent by server, but let's test what happens if client sends it.
    """
    s_initialize("puback")
    
    s_byte(0x40, name="packet_type", fuzzable=True)
    s_byte(0x02, name="remaining_len", fuzzable=True)
    
    with s_block("variable_header"):
        s_word(0x0001, name="packet_id", endian=">", fuzzable=True)
    
    session.connect(s_get("puback"))


def define_pubrec(session):
    """
    PUBREC Packet - Part of QoS 2 handshake
    """
    s_initialize("pubrec")
    
    s_byte(0x50, name="packet_type", fuzzable=True)
    s_byte(0x02, name="remaining_len", fuzzable=True)
    
    with s_block("variable_header"):
        s_word(0x0001, name="packet_id", endian=">", fuzzable=True)
    
    session.connect(s_get("pubrec"))


def define_pubrel(session):
    """
    PUBREL Packet - Part of QoS 2 handshake
    
    Note: Fixed header flags MUST be 0010 (0x02)
    """
    s_initialize("pubrel")
    
    s_byte(0x62, name="packet_type", fuzzable=True)  # 0x60 | 0x02
    s_byte(0x02, name="remaining_len", fuzzable=True)
    
    with s_block("variable_header"):
        s_word(0x0001, name="packet_id", endian=">", fuzzable=True)
    
    session.connect(s_get("pubrel"))


def define_pubcomp(session):
    """
    PUBCOMP Packet - Final part of QoS 2 handshake
    """
    s_initialize("pubcomp")
    
    s_byte(0x70, name="packet_type", fuzzable=True)
    s_byte(0x02, name="remaining_len", fuzzable=True)
    
    with s_block("variable_header"):
        s_word(0x0001, name="packet_id", endian=">", fuzzable=True)
    
    session.connect(s_get("pubcomp"))


# =============================================================================
# Edge Case / Malformed Packet Definitions
# =============================================================================

def define_malformed_remaining_length(session):
    """
    Test remaining length edge cases:
    - Maximum value (268,435,455)
    - Invalid continuation bytes
    - Truncated encoding
    """
    s_initialize("malformed_remaining_length")
    
    s_byte(0x10, name="packet_type", fuzzable=True)
    
    # Fuzz the remaining length bytes directly
    # Valid: 1-4 bytes with continuation bits
    # Let's send potentially invalid encodings
    s_bytes(b"\xFF\xFF\xFF\x7F", name="remaining_len", fuzzable=True, max_len=8)
    
    session.connect(s_get("malformed_remaining_length"))


def define_malformed_utf8(session):
    """
    Test UTF-8 string handling edge cases:
    - Invalid UTF-8 sequences
    - Overlong encodings
    - Null characters
    - Length mismatches
    """
    s_initialize("malformed_utf8")
    
    s_byte(0x10, name="packet_type", fuzzable=True)
    s_byte(0x20, name="remaining_len", fuzzable=True)
    
    with s_block("variable_header"):
        s_word(0x0004, name="protocol_name_len", endian=">", fuzzable=True)
        # Potentially invalid UTF-8
        s_bytes(b"\xFF\xFE\x00\x00", name="protocol_name", fuzzable=True, max_len=256)
        s_byte(0x04, name="protocol_level", fuzzable=True)
        s_byte(0x02, name="connect_flags", fuzzable=True)
        s_word(60, name="keep_alive", endian=">", fuzzable=True)
    
    with s_block("payload"):
        # Client ID with invalid UTF-8
        s_word(0x0010, name="client_id_len", endian=">", fuzzable=True)
        s_bytes(b"\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8A\x8B\x8C\x8D\x8E\x8F",
                name="client_id", fuzzable=True, max_len=65535)
    
    session.connect(s_get("malformed_utf8"))


def define_topic_wildcards(session):
    """
    Test topic wildcard handling:
    - Single-level wildcard (+)
    - Multi-level wildcard (#)
    - Invalid wildcard positions
    - Mixed wildcards
    """
    s_initialize("topic_wildcards")
    
    s_byte(0x82, name="packet_type", fuzzable=True)
    s_byte(0x00, name="remaining_len", fuzzable=True)
    
    with s_block("variable_header"):
        s_word(0x0003, name="packet_id", endian=">", fuzzable=True)
    
    with s_block("payload"):
        # Various wildcard patterns
        s_word(0x0010, name="topic_len", endian=">", fuzzable=True)
        s_string("test/+/data/#/bad", name="topic", fuzzable=True, max_len=65535)
        s_byte(0x00, name="qos", fuzzable=True)
    
    session.connect(s_get("topic_wildcards"))


def define_zero_length_fields(session):
    """
    Test zero-length strings and fields
    """
    s_initialize("zero_length")
    
    s_byte(0x10, name="packet_type", fuzzable=True)
    s_byte(0x0C, name="remaining_len", fuzzable=True)
    
    with s_block("variable_header"):
        s_word(0x0004, name="protocol_name_len", endian=">", fuzzable=True)
        s_static(b"MQTT", name="protocol_name")
        s_byte(0x04, name="protocol_level", fuzzable=True)
        s_byte(0x02, name="connect_flags", fuzzable=True)
        s_word(60, name="keep_alive", endian=">", fuzzable=True)
    
    with s_block("payload"):
        # Zero-length client ID (allowed with Clean Session)
        s_word(0x0000, name="client_id_len", endian=">", fuzzable=True)
    
    session.connect(s_get("zero_length"))


def define_oversized_packet(session):
    """
    Test maximum packet size handling
    """
    s_initialize("oversized")
    
    s_byte(0x30, name="packet_type", fuzzable=True)
    
    # Maximum remaining length encoding
    s_bytes(b"\xFF\xFF\xFF\x7F", name="remaining_len", fuzzable=True, max_len=4)
    
    with s_block("variable_header"):
        s_word(0xFFFF, name="topic_len", endian=">", fuzzable=True)
        s_bytes(b"A" * 1000, name="topic", fuzzable=True, max_len=65535)
    
    with s_block("payload"):
        s_bytes(b"B" * 10000, name="message", fuzzable=True, max_len=100000)
    
    session.connect(s_get("oversized"))


def define_invalid_packet_type(session):
    """
    Test invalid/reserved packet types
    """
    s_initialize("invalid_type")
    
    # Packet type 0 and 15 are reserved
    s_byte(0x00, name="packet_type", fuzzable=True)
    s_byte(0x00, name="remaining_len", fuzzable=True)
    
    session.connect(s_get("invalid_type"))


def define_duplicate_connect(session):
    """
    Send CONNECT after already connected - protocol violation
    """
    s_initialize("duplicate_connect")
    
    s_byte(0x10, name="packet_type", fuzzable=True)
    s_byte(0x10, name="remaining_len", fuzzable=True)
    
    with s_block("variable_header"):
        s_word(0x0004, name="protocol_name_len", endian=">", fuzzable=True)
        s_static(b"MQTT", name="protocol_name")
        s_byte(0x04, name="protocol_level", fuzzable=True)
        s_byte(0x02, name="connect_flags", fuzzable=True)
        s_word(60, name="keep_alive", endian=">", fuzzable=True)
    
    with s_block("payload"):
        s_word(0x0004, name="client_id_len", endian=">", fuzzable=True)
        s_string("dup1", name="client_id", fuzzable=True)
    
    session.connect(s_get("duplicate_connect"))


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
        sleep_time=0.1,  # Small delay between test cases
        restart_sleep_time=0.5,
        # crash_threshold_request=10,  # Stop after 10 crashes on same request
        # crash_threshold_element=3,   # Stop after 3 crashes on same element
    )
    
    # Core protocol packets
    print("[*] Defining CONNECT packets...")
    define_connect(session)
    define_connect_full(session)
    
    print("[*] Defining PUBLISH packets...")
    define_publish_qos0(session)
    define_publish_qos1(session)
    define_publish_qos2(session)
    
    print("[*] Defining SUBSCRIBE/UNSUBSCRIBE packets...")
    define_subscribe(session)
    define_subscribe_multi(session)
    define_unsubscribe(session)
    
    print("[*] Defining control packets...")
    define_pingreq(session)
    define_disconnect(session)
    
    print("[*] Defining QoS handshake packets...")
    define_puback(session)
    define_pubrec(session)
    define_pubrel(session)
    define_pubcomp(session)
    
    if fuzz_all:
        print("[*] Defining edge case / malformed packets...")
        define_malformed_remaining_length(session)
        define_malformed_utf8(session)
        define_topic_wildcards(session)
        define_zero_length_fields(session)
        define_oversized_packet(session)
        define_invalid_packet_type(session)
        define_duplicate_connect(session)
    
    return session


def main():
    parser = argparse.ArgumentParser(
        description="MQTT 3.1.1 Protocol Fuzzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -H localhost -P 1883
  %(prog)s -H 192.168.1.100 -P 1883 --all
  %(prog)s -H localhost -P 1883 --request connect

Recommended test setup:
  docker run -it --rm -p 1883:1883 eclipse-mosquitto:latest
  
Or with AddressSanitizer:
  docker run -it --rm -p 1883:1883 mosquitto-asan:latest
        """
    )
    
    parser.add_argument("-H", "--host", default="localhost",
                        help="Target MQTT broker host (default: localhost)")
    parser.add_argument("-P", "--port", type=int, default=1883,
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
    ║  Target: {host}:{port}                                  
    ║  The S in IoT stands for Security                            ║
    ╚══════════════════════════════════════════════════════════════╝
    """.format(host=args.host, port=args.port))
    
    session = create_session(args.host, args.port, fuzz_all=args.all)
    
    if args.list:
        print("\nAvailable requests:")
        for name in session.fuzz_node_names():
            print(f"  - {name}")
        return 0
    
    print(f"\n[*] Starting fuzzer against {args.host}:{args.port}")
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
