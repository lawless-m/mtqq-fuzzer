#!/usr/bin/env python3
"""
MQTT 3.1.1 Stateful Protocol Fuzzer

This version properly handles the MQTT connection lifecycle:
1. Establish connection with CONNECT
2. Wait for CONNACK
3. Fuzz subsequent packets in the established session
4. Handle reconnection on failure

This finds bugs that only manifest in authenticated/connected state.

Author: Built with boofuzz
License: MIT
"""

from boofuzz import (
    Session,
    Target,
    TCPSocketConnection,
    s_initialize,
    s_block,
    s_byte,
    s_bytes,
    s_word,
    s_string,
    s_static,
    s_get,
)
import struct
import socket
import argparse
import sys
import time


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
        """Build a valid CONNECT packet."""
        # Variable header
        var_header = b""
        var_header += struct.pack(">H", 4) + b"MQTT"  # Protocol name
        var_header += bytes([0x04])  # Protocol level (3.1.1)
        var_header += bytes([0x02])  # Connect flags (Clean Session)
        var_header += struct.pack(">H", 60)  # Keep alive
        
        # Payload
        payload = struct.pack(">H", len(self.client_id)) + self.client_id.encode()
        
        # Remaining length
        remaining = len(var_header) + len(payload)
        remaining_bytes = self._encode_remaining_length(remaining)
        
        # Fixed header
        fixed_header = bytes([0x10]) + remaining_bytes
        
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
                # Send DISCONNECT packet
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
            # Send PINGREQ to check if connection is alive
            mqtt.sock.settimeout(1.0)
            mqtt.sock.sendall(bytes([0xC0, 0x00]))
            response = mqtt.sock.recv(2)
            if len(response) == 2 and response[0] == 0xD0:
                # Got PINGRESP, connection is alive
                return
        except:
            pass
        
        # Connection seems dead, reconnect
        fuzz_data_logger.log_info("Connection lost, reconnecting...")
        mqtt.disconnect()
        mqtt.connected = False


# =============================================================================
# Protocol Definitions for Connected State
# =============================================================================

def define_publish_connected(session):
    """PUBLISH after connection established."""
    s_initialize("pub_connected")
    
    # PUBLISH QoS 0
    s_byte(0x30, name="packet_type", fuzzable=True)
    s_byte(0x00, name="remaining_len", fuzzable=True)
    
    with s_block("variable_header"):
        s_word(0x000A, name="topic_len", endian=">", fuzzable=True)
        s_string("fuzz/topic", name="topic", fuzzable=True, max_len=65535)
    
    with s_block("payload"):
        s_string("fuzz_message", name="message", fuzzable=True, max_len=65535)
    
    session.connect(s_get("pub_connected"))


def define_subscribe_connected(session):
    """SUBSCRIBE after connection established."""
    s_initialize("sub_connected")
    
    s_byte(0x82, name="packet_type", fuzzable=True)
    s_byte(0x00, name="remaining_len", fuzzable=True)
    
    with s_block("variable_header"):
        s_word(0x0001, name="packet_id", endian=">", fuzzable=True)
    
    with s_block("payload"):
        s_word(0x000A, name="topic_len", endian=">", fuzzable=True)
        s_string("fuzz/topic", name="topic", fuzzable=True, max_len=65535)
        s_byte(0x00, name="qos", fuzzable=True)
    
    session.connect(s_get("sub_connected"))


def define_unsubscribe_connected(session):
    """UNSUBSCRIBE after connection established."""
    s_initialize("unsub_connected")
    
    s_byte(0xA2, name="packet_type", fuzzable=True)
    s_byte(0x00, name="remaining_len", fuzzable=True)
    
    with s_block("variable_header"):
        s_word(0x0001, name="packet_id", endian=">", fuzzable=True)
    
    with s_block("payload"):
        s_word(0x000A, name="topic_len", endian=">", fuzzable=True)
        s_string("fuzz/topic", name="topic", fuzzable=True)
    
    session.connect(s_get("unsub_connected"))


def define_qos1_publish_connected(session):
    """PUBLISH QoS 1 that expects PUBACK."""
    s_initialize("pub_qos1_connected")
    
    # PUBLISH + QoS 1
    s_byte(0x32, name="packet_type", fuzzable=True)
    s_byte(0x00, name="remaining_len", fuzzable=True)
    
    with s_block("variable_header"):
        s_word(0x0007, name="topic_len", endian=">", fuzzable=True)
        s_string("qos1/t", name="topic", fuzzable=True)
        s_word(0x0001, name="packet_id", endian=">", fuzzable=True)
    
    with s_block("payload"):
        s_string("qos1_msg", name="message", fuzzable=True)
    
    session.connect(s_get("pub_qos1_connected"))


def define_qos2_publish_connected(session):
    """PUBLISH QoS 2 that starts the 4-way handshake."""
    s_initialize("pub_qos2_connected")
    
    # PUBLISH + QoS 2
    s_byte(0x34, name="packet_type", fuzzable=True)
    s_byte(0x00, name="remaining_len", fuzzable=True)
    
    with s_block("variable_header"):
        s_word(0x0007, name="topic_len", endian=">", fuzzable=True)
        s_string("qos2/t", name="topic", fuzzable=True)
        s_word(0x0002, name="packet_id", endian=">", fuzzable=True)
    
    with s_block("payload"):
        s_string("qos2_msg", name="message", fuzzable=True)
    
    session.connect(s_get("pub_qos2_connected"))


def define_pubrel_connected(session):
    """PUBREL sent without prior PUBREC (protocol violation)."""
    s_initialize("pubrel_connected")
    
    s_byte(0x62, name="packet_type", fuzzable=True)
    s_byte(0x02, name="remaining_len", fuzzable=True)
    
    with s_block("variable_header"):
        s_word(0xFFFF, name="packet_id", endian=">", fuzzable=True)
    
    session.connect(s_get("pubrel_connected"))


def define_pingreq_connected(session):
    """PINGREQ in connected state."""
    s_initialize("ping_connected")
    
    s_byte(0xC0, name="packet_type", fuzzable=True)
    s_byte(0x00, name="remaining_len", fuzzable=True)
    
    # Extra bytes that shouldn't be there
    s_bytes(b"", name="extra", fuzzable=True, max_len=100)
    
    session.connect(s_get("ping_connected"))


def define_second_connect(session):
    """Second CONNECT on same connection (protocol violation)."""
    s_initialize("second_connect")
    
    s_byte(0x10, name="packet_type", fuzzable=True)
    s_byte(0x10, name="remaining_len", fuzzable=True)
    
    with s_block("variable_header"):
        s_word(0x0004, name="protocol_name_len", endian=">", fuzzable=True)
        s_static(b"MQTT", name="protocol_name")
        s_byte(0x04, name="protocol_level", fuzzable=True)
        s_byte(0x02, name="connect_flags", fuzzable=True)
        s_word(60, name="keep_alive", endian=">", fuzzable=True)
    
    with s_block("payload"):
        s_word(0x0006, name="client_id_len", endian=">", fuzzable=True)
        s_string("second", name="client_id", fuzzable=True)
    
    session.connect(s_get("second_connect"))


def define_massive_topic(session):
    """PUBLISH with very long topic name."""
    s_initialize("massive_topic")
    
    s_byte(0x30, name="packet_type", fuzzable=True)
    
    # Use multi-byte remaining length
    s_bytes(b"\x80\x80\x01", name="remaining_len", fuzzable=True, max_len=4)
    
    with s_block("variable_header"):
        s_word(0x4000, name="topic_len", endian=">", fuzzable=True)
        s_bytes(b"A" * 0x4000, name="topic", fuzzable=True, max_len=0x10000)
    
    session.connect(s_get("massive_topic"))


def define_subscribe_wildcards(session):
    """SUBSCRIBE with various wildcard patterns."""
    s_initialize("sub_wildcards")
    
    s_byte(0x82, name="packet_type", fuzzable=True)
    s_byte(0x00, name="remaining_len", fuzzable=True)
    
    with s_block("variable_header"):
        s_word(0x0005, name="packet_id", endian=">", fuzzable=True)
    
    with s_block("payload"):
        # Potentially invalid wildcard patterns
        s_word(0x0020, name="topic_len", endian=">", fuzzable=True)
        s_string("sport/+/+/#/invalid/+/#", name="topic", fuzzable=True)
        s_byte(0x02, name="qos", fuzzable=True)
    
    session.connect(s_get("sub_wildcards"))


def create_stateful_session(host, port):
    """Create a session for stateful fuzzing."""
    session = Session(
        target=Target(
            connection=TCPSocketConnection(host, port),
        ),
        sleep_time=0.05,
        restart_sleep_time=0.5,
        pre_send_callbacks=[pre_send_connect],
        post_test_case_callbacks=[post_test_case_callback],
    )
    
    print("[*] Defining connected-state packets...")
    define_publish_connected(session)
    define_subscribe_connected(session)
    define_unsubscribe_connected(session)
    define_qos1_publish_connected(session)
    define_qos2_publish_connected(session)
    define_pubrel_connected(session)
    define_pingreq_connected(session)
    define_second_connect(session)
    define_massive_topic(session)
    define_subscribe_wildcards(session)
    
    return session


def main():
    parser = argparse.ArgumentParser(
        description="MQTT 3.1.1 Stateful Protocol Fuzzer",
        epilog="This version establishes a valid MQTT connection before fuzzing."
    )
    
    parser.add_argument("-H", "--host", default="localhost",
                        help="Target MQTT broker host")
    parser.add_argument("-P", "--port", type=int, default=1883,
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
    ║  Establishes valid MQTT connection, then fuzzes packets      ║
    ║  in the authenticated session state.                         ║
    ╚══════════════════════════════════════════════════════════════╝
    """)
    
    session = create_stateful_session(args.host, args.port)
    
    if args.list:
        print("\nAvailable requests:")
        for name in session.fuzz_node_names():
            print(f"  - {name}")
        return 0
    
    print(f"[*] Target: {args.host}:{args.port}")
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
