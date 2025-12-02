#!/usr/bin/env python3

import sys
import time
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parent))

from src.connection import Connection, TransferDirection
from src.packet import PktType, build_data_packet, build_ack_packet, parse_packet

def test_congestion_control():
    """Test basic congestion control logic"""
    print("Testing congestion control...")

    # Create a test upload connection
    peer_addr = ("127.0.0.1", 8000)
    chunk_hash = "test_hash"
    connection = Connection(peer_addr, chunk_hash, TransferDirection.UPLOAD)

    # Test initial state
    assert connection.cwnd == 1.0
    assert connection.ssthresh == 64
    assert connection.seq_num == 0
    assert connection.ack_num == 0
    print("✓ Initial state correct")

    # Test can_send_more logic
    assert connection.can_send_more()  # Should be able to send initially
    print("✓ Can send more initially")

    # Simulate sending a packet
    connection.seq_num = 1
    assert connection.can_send_more()  # Still can send (cwnd=1, in_flight=1)
    print("✓ Can send after first packet")

    # Simulate receiving ACK
    connection.handle_ack(1)
    assert connection.ack_num == 1
    assert connection.cwnd == 2.0  # Should increase by 1 in slow start
    print(f"✓ ACK processed, cwnd increased to {connection.cwnd}")

    # Test can send more with increased window
    assert connection.can_send_more()
    print("✓ Can send more after cwnd increase")

    # Simulate more ACKs to reach ssthresh
    connection.handle_ack(2)  # cwnd -> 3
    connection.handle_ack(3)  # cwnd -> 4
    print(f"✓ After more ACKs, cwnd = {connection.cwnd}")

    # Test congestion avoidance
    connection.ssthresh = 4  # Force into congestion avoidance
    connection.cwnd = 4.0
    connection.handle_ack(4)  # Should increase by 1/4
    assert connection.cwnd == 4.25  # 4 + 1/4
    print(f"✓ Congestion avoidance working, cwnd = {connection.cwnd}")

    # Test loss handling
    old_cwnd = connection.cwnd
    connection.update_cwnd_on_loss()
    assert connection.cwnd == 1.0  # Should reset to 1
    assert connection.ssthresh == max(int(old_cwnd / 2), 2)  # Should be halved
    print(f"✓ Loss handling working, cwnd reset to {connection.cwnd}, ssthresh = {connection.ssthresh}")

def test_data_packet_sequence():
    """Test data packet sequence number handling"""
    print("\nTesting data packet sequence handling...")

    # Test packet creation and parsing
    test_data = b"Hello, world!"
    seq_num = 5

    data_pkt = build_data_packet(seq_num, test_data)
    parsed = parse_packet(data_pkt)

    assert parsed.pkt_type == PktType.DATA
    assert parsed.seq_num == seq_num
    assert parsed.payload == test_data
    print("✓ Data packet creation and parsing correct")

    # Test ACK packet
    ack_pkt = build_ack_packet(seq_num)
    ack_parsed = parse_packet(ack_pkt)

    assert ack_parsed.pkt_type == PktType.ACK
    assert ack_parsed.ack_num == seq_num
    print("✓ ACK packet creation and parsing correct")

def test_connection_state_transitions():
    """Test connection state transitions"""
    print("\nTesting connection state transitions...")

    peer_addr = ("127.0.0.1", 8000)
    chunk_hash = "test_hash"
    connection = Connection(peer_addr, chunk_hash, TransferDirection.UPLOAD)

    # Test state transitions
    from src.connection import ConnectionState

    connection.update_state(ConnectionState.TRANSFER)
    assert connection.state == ConnectionState.TRANSFER
    assert connection.is_active()
    print("✓ Transfer state transition")

    connection.update_state(ConnectionState.COMPLETE)
    assert connection.state == ConnectionState.COMPLETE
    assert not connection.is_active()
    print("✓ Complete state transition")

if __name__ == "__main__":
    print("Running congestion control and protocol tests...\n")

    test_congestion_control()
    test_data_packet_sequence()
    test_connection_state_transitions()

    print("\n🎉 All tests passed! Basic protocol logic seems correct.")