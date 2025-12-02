#!/usr/bin/env python3

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parent.parent))

import pickle
import hashlib
from src.packet import (
    PktType, build_who_has_packet, build_i_have_packet, build_get_packet,
    build_data_packet, build_ack_packet, build_denied_packet, parse_packet,
    bytes_to_hex_string, hex_string_to_bytes
)

def test_packet_creation_and_parsing():
    """Test basic packet creation and parsing"""
    print("Testing packet creation and parsing...")

    # Test WHOHAS packet
    chunk_hashes = [b'a' * 20, b'b' * 20]  # Dummy hashes
    whohas_pkt = build_who_has_packet(chunk_hashes)
    parsed_whohas = parse_packet(whohas_pkt)
    assert parsed_whohas.pkt_type == PktType.WHOHAS
    assert len(parsed_whohas.payload) == 40
    print("✓ WHOHAS packet test passed")

    # Test IHAVE packet
    ihave_pkt = build_i_have_packet([b'c' * 20])
    parsed_ihave = parse_packet(ihave_pkt)
    assert parsed_ihave.pkt_type == PktType.IHAVE
    assert len(parsed_ihave.payload) == 20
    print("✓ IHAVE packet test passed")

    # Test GET packet
    chunk_hash = b'd' * 20
    get_pkt = build_get_packet(chunk_hash)
    parsed_get = parse_packet(get_pkt)
    assert parsed_get.pkt_type == PktType.GET
    assert parsed_get.payload == chunk_hash
    print("✓ GET packet test passed")

    # Test DATA packet
    data = b'Hello, world!'
    data_pkt = build_data_packet(1, data)
    parsed_data = parse_packet(data_pkt)
    assert parsed_data.pkt_type == PktType.DATA
    assert parsed_data.seq_num == 1
    assert parsed_data.payload == data
    print("✓ DATA packet test passed")

    # Test ACK packet
    ack_pkt = build_ack_packet(5)
    parsed_ack = parse_packet(ack_pkt)
    assert parsed_ack.pkt_type == PktType.ACK
    assert parsed_ack.ack_num == 5
    print("✓ ACK packet test passed")

    # Test DENIED packet
    denied_pkt = build_denied_packet()
    parsed_denied = parse_packet(denied_pkt)
    assert parsed_denied.pkt_type == PktType.DENIED
    print("✓ DENIED packet test passed")

    print("All packet tests passed!")

def test_hash_functions():
    """Test hash conversion functions"""
    print("\nTesting hash conversion functions...")

    # Test round-trip conversion
    original_hash = b'a' * 20
    hex_str = bytes_to_hex_string(original_hash)
    converted_back = hex_string_to_bytes(hex_str)

    assert original_hash == converted_back
    print("✓ Hash conversion round-trip test passed")

    # Test with actual SHA-1 hash
    test_data = b"Hello, P2P world!"
    sha1_hash = hashlib.sha1(test_data).digest()
    hex_str = bytes_to_hex_string(sha1_hash)
    converted_back = hex_string_to_bytes(hex_str)

    assert sha1_hash == converted_back
    print("✓ SHA-1 hash conversion test passed")

    print("All hash conversion tests passed!")

def test_chunk_operations():
    """Test chunk-related operations"""
    print("\nTesting chunk operations...")

    # Create test chunks
    chunk_data1 = b"This is chunk 1 data" * 1000  # Make it larger
    chunk_data2 = b"This is chunk 2 data" * 1000

    # Calculate hashes
    hash1 = hashlib.sha1(chunk_data1).digest()
    hash2 = hashlib.sha1(chunk_data2).digest()

    # Test chunk dict creation and saving
    chunks_dict = {
        bytes_to_hex_string(hash1): chunk_data1,
        bytes_to_hex_string(hash2): chunk_data2
    }

    # Test pickle save/load
    test_file = "test_chunks.pkl"
    with open(test_file, 'wb') as f:
        pickle.dump(chunks_dict, f)

    with open(test_file, 'rb') as f:
        loaded_chunks = pickle.load(f)

    assert chunks_dict == loaded_chunks
    print("✓ Chunk pickle save/load test passed")

    # Clean up
    import os
    os.remove(test_file)

    print("All chunk operation tests passed!")

if __name__ == "__main__":
    print("Running basic P2P file transfer tests...\n")

    test_packet_creation_and_parsing()
    test_hash_functions()
    test_chunk_operations()

    print("\n🎉 All basic tests passed! The implementation looks good.")