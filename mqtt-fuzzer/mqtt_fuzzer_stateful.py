#!/usr/bin/env python3
"""
MQTT 3.1.1 Stateful Protocol Fuzzer

This version properly handles the MQTT connection lifecycle:
1. Establish connection with CONNECT
2. Wait for CONNACK
3. Fuzz subsequent packets in the established session
4. Handle reconnection on failure

This finds bugs that only manifest in authenticated/connected state.

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
    BIG_ENDIAN,
)
import struct
import socket
import argparse
import sys
import time


# =============================================================================
# MQTT 3.1.1 Constants (per OASIS specification)
# =============================================================================

MQTT_PORT = 1883

MQTT_CONNECT     = 0x10
MQTT_PUBLISH     = 0x30
MQTT_SUBSCRIBE   = 0x82
MQTT_UNSUBSCRIBE = 0xA2
MQTT_PINGREQ     = 0xC0
MQTT_PUBREL      = 0x62

MQTT_PROTOCOL_NAME = b"MQTT"
MQTT_PROTOCOL_LEVEL = 0x04


# =============================================================================
# MQTT Connection State Manager
# =============================================================================

class MQTTConnection:
    """
    Helper class to manage MQTT connection state.
    Handles the CONNECT/CONNACK handshake before fuzzing.
    """

    def __init__(self, host, port, client_id="boofuzz"):
        self.host = host
        self.port = port
        self.client_id = client_id
        self.sock = None
        self.connected = False

    def build_connect_packet(self):
        """Build a valid CONNECT packet per MQTT 3.1.1 Section 3.1."""
        # Variable header
        var_header = b""
        var_header += struct.pack(">H", 4) + MQTT_PROTOCOL_NAME
        var_header += bytes([MQTT_PROTOCOL_LEVEL])
        var_header += bytes([0x02])  # Clean Session
        var_header += struct.pack(">H", 60)

        # Payload
        payload = struct.pack(">H", len(self.client_id)) + self.client_id.encode()

        # Remaining length
        remaining = len(var_header) + len(payload)
        remaining_bytes = self._encode_remaining_length(remaining)

        # Fixed header
        fixed_header = bytes([MQTT_CONNECT]) + remaining_bytes

        return fixed_header + var_header + payload

    def _encode_remaining_length(self, length):
        """Encode remaining length per MQTT spec."""
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

    def connect(self):
        """Establish MQTT connection."""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(5.0)
            self.sock.connect((self.host, self.port))

            # Send CONNECT
            connect_packet = self.build_connect_packet()
            self.sock.sendall(connect_packet)

            # Wait for CONNACK
            response = self.sock.recv(4)
            if len(response) >= 4:
                packet_type = response[0] >> 4
                if packet_type == 2:  # CONNACK
                    return_code = response[3]
                    if return_code == 0:
                        self.connected = True
                        return True
                    else:
                        print(f"[!] CONNACK return code: {return_code}")

            return False

        except Exception as e:
            print(f"[!] Connection error: {e}")
            return False

    def disconnect(self):
        """Send DISCONNECT and close socket."""
        if self.sock:
            try:
                self.sock.sendall(bytes([0xE0, 0x00]))
            except:
                pass
            try:
                self.sock.close()
            except:
                pass
        self.sock = None
        self.connected = False

    def get_socket(self):
        """Return the connected socket for boofuzz to use."""
        return self.sock


# =============================================================================
# Callbacks for Stateful Protocols
# =============================================================================

def pre_send_connect(target, fuzz_data_logger, session, sock):
    """
    Callback that runs before each test case.
    Ensures we have a valid MQTT connection established.
    """
    mqtt = getattr(session, '_mqtt_connection', None)
    if mqtt is None:
        mqtt = MQTTConnection(
            target.connection.host,
            target.connection.port,
            client_id=f"fuzz_{int(time.time())}"
        )
        session._mqtt_connection = mqtt

    if not mqtt.connected:
        if mqtt.connect():
            fuzz_data_logger.log_info("MQTT connection established")
        else:
            fuzz_data_logger.log_error("Failed to establish MQTT connection")


def post_test_case_callback(target, fuzz_data_logger, session, sock):
    """
    Callback that runs after each test case.
    Check if connection is still alive.
    """
    mqtt = getattr(session, '_mqtt_connection', None)
    if mqtt and mqtt.sock:
        try:
            mqtt.sock.settimeout(1.0)
            mqtt.sock.sendall(bytes([MQTT_PINGREQ, 0x00]))
            response = mqtt.sock.recv(2)
            if len(response) == 2 and response[0] == 0xD0:
                return
        except:
            pass

        fuzz_data_logger.log_info("Connection lost, reconnecting...")
        mqtt.disconnect()
        mqtt.connected = False


# =============================================================================
# Protocol Definitions for Connected State (Object-Oriented Style)
# =============================================================================

def define_mqtt_publish_connected():
    """MQTT-PUBLISH-Connected: Publish after connection established."""
    return Request("MQTT-PUBLISH-Connected", children=(
        Block("Fixed-Header", children=(
            Byte(name="packet_type", default_value=MQTT_PUBLISH, fuzzable=True),
            Byte(name="remaining_length", default_value=0x00, fuzzable=True),
        )),
        Block("Variable-Header", children=(
            Word(name="topic_length", default_value=0x000A, endian=BIG_ENDIAN, fuzzable=True),
            String(name="topic_name", default_value="fuzz/topic", fuzzable=True, max_len=65535),
        )),
        Block("Payload", children=(
            String(name="application_message", default_value="fuzz_message", fuzzable=True, max_len=65535),
        )),
    ))


def define_mqtt_subscribe_connected():
    """MQTT-SUBSCRIBE-Connected: Subscribe after connection established."""
    return Request("MQTT-SUBSCRIBE-Connected", children=(
        Block("Fixed-Header", children=(
            Byte(name="packet_type", default_value=MQTT_SUBSCRIBE, fuzzable=True),
            Byte(name="remaining_length", default_value=0x00, fuzzable=True),
        )),
        Block("Variable-Header", children=(
            Word(name="packet_identifier", default_value=0x0001, endian=BIG_ENDIAN, fuzzable=True),
        )),
        Block("Payload", children=(
            Word(name="topic_filter_length", default_value=0x000A, endian=BIG_ENDIAN, fuzzable=True),
            String(name="topic_filter", default_value="fuzz/topic", fuzzable=True, max_len=65535),
            Byte(name="requested_qos", default_value=0x00, fuzzable=True),
        )),
    ))


def define_mqtt_unsubscribe_connected():
    """MQTT-UNSUBSCRIBE-Connected: Unsubscribe after connection established."""
    return Request("MQTT-UNSUBSCRIBE-Connected", children=(
        Block("Fixed-Header", children=(
            Byte(name="packet_type", default_value=MQTT_UNSUBSCRIBE, fuzzable=True),
            Byte(name="remaining_length", default_value=0x00, fuzzable=True),
        )),
        Block("Variable-Header", children=(
            Word(name="packet_identifier", default_value=0x0001, endian=BIG_ENDIAN, fuzzable=True),
        )),
        Block("Payload", children=(
            Word(name="topic_filter_length", default_value=0x000A, endian=BIG_ENDIAN, fuzzable=True),
            String(name="topic_filter", default_value="fuzz/topic", fuzzable=True),
        )),
    ))


def define_mqtt_publish_qos1_connected():
    """MQTT-PUBLISH-QoS1-Connected: QoS 1 publish expecting PUBACK."""
    return Request("MQTT-PUBLISH-QoS1-Connected", children=(
        Block("Fixed-Header", children=(
            # PUBLISH + QoS 1
            Byte(name="packet_type", default_value=0x32, fuzzable=True),
            Byte(name="remaining_length", default_value=0x00, fuzzable=True),
        )),
        Block("Variable-Header", children=(
            Word(name="topic_length", default_value=0x0006, endian=BIG_ENDIAN, fuzzable=True),
            String(name="topic_name", default_value="qos1/t", fuzzable=True),
            Word(name="packet_identifier", default_value=0x0001, endian=BIG_ENDIAN, fuzzable=True),
        )),
        Block("Payload", children=(
            String(name="application_message", default_value="qos1_msg", fuzzable=True),
        )),
    ))


def define_mqtt_publish_qos2_connected():
    """MQTT-PUBLISH-QoS2-Connected: QoS 2 publish starting 4-way handshake."""
    return Request("MQTT-PUBLISH-QoS2-Connected", children=(
        Block("Fixed-Header", children=(
            # PUBLISH + QoS 2
            Byte(name="packet_type", default_value=0x34, fuzzable=True),
            Byte(name="remaining_length", default_value=0x00, fuzzable=True),
        )),
        Block("Variable-Header", children=(
            Word(name="topic_length", default_value=0x0006, endian=BIG_ENDIAN, fuzzable=True),
            String(name="topic_name", default_value="qos2/t", fuzzable=True),
            Word(name="packet_identifier", default_value=0x0002, endian=BIG_ENDIAN, fuzzable=True),
        )),
        Block("Payload", children=(
            String(name="application_message", default_value="qos2_msg", fuzzable=True),
        )),
    ))


def define_mqtt_pubrel_connected():
    """MQTT-PUBREL-Connected: PUBREL without prior PUBREC (protocol violation)."""
    return Request("MQTT-PUBREL-Connected", children=(
        Block("Fixed-Header", children=(
            Byte(name="packet_type", default_value=MQTT_PUBREL, fuzzable=True),
            Byte(name="remaining_length", default_value=0x02, fuzzable=True),
        )),
        Block("Variable-Header", children=(
            Word(name="packet_identifier", default_value=0xFFFF, endian=BIG_ENDIAN, fuzzable=True),
        )),
    ))


def define_mqtt_pingreq_connected():
    """MQTT-PINGREQ-Connected: Ping with extra bytes (malformed)."""
    return Request("MQTT-PINGREQ-Connected", children=(
        Block("Fixed-Header", children=(
            Byte(name="packet_type", default_value=MQTT_PINGREQ, fuzzable=True),
            Byte(name="remaining_length", default_value=0x00, fuzzable=True),
        )),
        Block("Extra-Bytes", children=(
            Bytes(name="extra_data", default_value=b"", fuzzable=True, max_len=100),
        )),
    ))


def define_mqtt_second_connect():
    """MQTT-Second-CONNECT: Protocol violation - CONNECT on existing connection."""
    return Request("MQTT-Second-CONNECT", children=(
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
            Word(name="client_id_length", default_value=0x0006, endian=BIG_ENDIAN, fuzzable=True),
            String(name="client_id", default_value="second", fuzzable=True),
        )),
    ))


def define_mqtt_massive_topic():
    """MQTT-Massive-Topic: Publish with very long topic name."""
    return Request("MQTT-Massive-Topic", children=(
        Block("Fixed-Header", children=(
            Byte(name="packet_type", default_value=MQTT_PUBLISH, fuzzable=True),
            # Multi-byte remaining length
            Bytes(name="remaining_length", default_value=b"\x80\x80\x01", fuzzable=True, max_len=4),
        )),
        Block("Variable-Header", children=(
            Word(name="topic_length", default_value=0x4000, endian=BIG_ENDIAN, fuzzable=True),
            Bytes(name="topic_name", default_value=b"A" * 0x4000, fuzzable=True, max_len=0x10000),
        )),
    ))


def define_mqtt_subscribe_wildcards():
    """MQTT-SUBSCRIBE-Wildcards: Subscribe with invalid wildcard patterns."""
    return Request("MQTT-SUBSCRIBE-Wildcards", children=(
        Block("Fixed-Header", children=(
            Byte(name="packet_type", default_value=MQTT_SUBSCRIBE, fuzzable=True),
            Byte(name="remaining_length", default_value=0x00, fuzzable=True),
        )),
        Block("Variable-Header", children=(
            Word(name="packet_identifier", default_value=0x0005, endian=BIG_ENDIAN, fuzzable=True),
        )),
        Block("Payload", children=(
            Word(name="topic_filter_length", default_value=0x0017, endian=BIG_ENDIAN, fuzzable=True),
            # Invalid: multiple # wildcards, + adjacent to non-separator
            String(name="topic_filter", default_value="sport/+/+/#/invalid/+/#", fuzzable=True),
            Byte(name="requested_qos", default_value=0x02, fuzzable=True),
        )),
    ))


# =============================================================================
# Session Configuration and Main
# =============================================================================

def create_stateful_session(host, port):
    """Create a session for stateful fuzzing with callbacks."""
    session = Session(
        target=Target(
            connection=TCPSocketConnection(host, port),
        ),
        sleep_time=0.05,
        restart_sleep_time=0.5,
        web_port=26001,  # Different port from basic fuzzer
        keep_web_open=True,
        crash_threshold_element=3,
        crash_threshold_request=10,
        pre_send_callbacks=[pre_send_connect],
        post_test_case_callbacks=[post_test_case_callback],
    )

    print("[*] Defining connected-state packets...")
    session.connect(define_mqtt_publish_connected())
    session.connect(define_mqtt_subscribe_connected())
    session.connect(define_mqtt_unsubscribe_connected())
    session.connect(define_mqtt_publish_qos1_connected())
    session.connect(define_mqtt_publish_qos2_connected())
    session.connect(define_mqtt_pubrel_connected())
    session.connect(define_mqtt_pingreq_connected())
    session.connect(define_mqtt_second_connect())
    session.connect(define_mqtt_massive_topic())
    session.connect(define_mqtt_subscribe_wildcards())

    return session


def main():
    parser = argparse.ArgumentParser(
        description="MQTT 3.1.1 Stateful Protocol Fuzzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
This version establishes a valid MQTT connection before fuzzing.
Finds bugs that only manifest in authenticated/connected state.

Examples:
  %(prog)s -t localhost -p 1883
  %(prog)s -t 10.0.2.2 -p 1883 -r MQTT-PUBLISH-Connected

Protocol reference:
  https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html
        """
    )

    parser.add_argument("-t", "--target", default="localhost",
                        help="Target MQTT broker host")
    parser.add_argument("-p", "--port", type=int, default=MQTT_PORT,
                        help="Target MQTT broker port")
    parser.add_argument("-r", "--request", type=str,
                        help="Fuzz only a specific request")
    parser.add_argument("-l", "--list", action="store_true",
                        help="List available requests")

    args = parser.parse_args()

    print("""
    ╔══════════════════════════════════════════════════════════════╗
    ║       MQTT 3.1.1 Stateful Fuzzer (Connected State)           ║
    ║                                                              ║
    ║  Target: {host}:{port:<5}                                    ║
    ║  Web UI: http://localhost:26001                              ║
    ║                                                              ║
    ║  Establishes valid MQTT connection, then fuzzes packets      ║
    ║  in the authenticated session state.                         ║
    ╚══════════════════════════════════════════════════════════════╝
    """.format(host=args.target, port=args.port))

    session = create_stateful_session(args.target, args.port)

    if args.list:
        print("\nAvailable requests:")
        for name in session.fuzz_node_names():
            print(f"  - {name}")
        return 0

    print(f"[*] Target: {args.target}:{args.port}")
    print("[*] Press Ctrl+C to stop\n")

    try:
        if args.request:
            session.fuzz(name=args.request)
        else:
            session.fuzz()
    except KeyboardInterrupt:
        print("\n[!] Interrupted")

    return 0


if __name__ == "__main__":
    sys.exit(main())
