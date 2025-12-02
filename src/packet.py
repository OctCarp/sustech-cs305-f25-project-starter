import struct
import socket
import sys
from pathlib import Path
from typing import Tuple, Optional, List

# Add parent directory to path for utils imports
sys.path.append(str(Path(__file__).resolve().parent.parent))

from utils.simsocket import AddressType

# Constants
BUF_SIZE: int = 1400
HEADER_FMT: str = "BBHII"
HEADER_LEN: int = struct.calcsize(HEADER_FMT)
MAX_PAYLOAD_SIZE: int = BUF_SIZE - HEADER_LEN
CHUNK_SIZE: int = 512 * 1024  # 512KB


class PktType:
    """Packet type constants"""
    WHOHAS: int = 0
    IHAVE: int = 1
    GET: int = 2
    DATA: int = 3
    ACK: int = 4
    DENIED: int = 5


class PacketInfo:
    """Container for parsed packet information"""
    def __init__(self, pkt_type: int, header_len: int, pkt_len: int,
                 seq_num: int, ack_num: int, payload: bytes, from_addr: Optional[AddressType] = None):
        self.pkt_type = pkt_type
        self.header_len = header_len
        self.pkt_len = pkt_len
        self.seq_num = seq_num
        self.ack_num = ack_num
        self.payload = payload
        self.from_addr = from_addr

    def __str__(self) -> str:
        type_names = {
            PktType.WHOHAS: "WHOHAS",
            PktType.IHAVE: "IHAVE",
            PktType.GET: "GET",
            PktType.DATA: "DATA",
            PktType.ACK: "ACK",
            PktType.DENIED: "DENIED"
        }
        type_name = type_names.get(self.pkt_type, f"UNKNOWN({self.pkt_type})")
        return (f"Packet(type={type_name}, seq={self.seq_num}, ack={self.ack_num}, "
                f"payload_len={len(self.payload)}, from={self.from_addr})")


def build_who_has_packet(chunk_hashes: List[bytes]) -> bytes:
    """
    Build a WHOHAS packet to query for chunks

    :param chunk_hashes: List of chunk hashes (20 bytes each) to query
    :return: Complete WHOHAS packet as bytes
    """
    if not chunk_hashes:
        raise ValueError("WHOHAS packet must contain at least one chunk hash")

    # Concatenate all chunk hashes
    payload = b''.join(chunk_hashes)

    # Build header
    header = struct.pack(
        HEADER_FMT,
        PktType.WHOHAS,
        HEADER_LEN,
        socket.htons(HEADER_LEN + len(payload)),
        socket.htonl(0),  # SEQ number not used for WHOHAS
        socket.htonl(0)   # ACK number not used for WHOHAS
    )

    return header + payload


def build_i_have_packet(chunk_hashes: List[bytes]) -> bytes:
    """
    Build an IHAVE packet to announce available chunks

    :param chunk_hashes: List of chunk hashes (20 bytes each) that this peer has
    :return: Complete IHAVE packet as bytes
    """
    if not chunk_hashes:
        raise ValueError("IHAVE packet must contain at least one chunk hash")

    # Concatenate all chunk hashes
    payload = b''.join(chunk_hashes)

    # Build header
    header = struct.pack(
        HEADER_FMT,
        PktType.IHAVE,
        HEADER_LEN,
        socket.htons(HEADER_LEN + len(payload)),
        socket.htonl(0),  # SEQ number not used for IHAVE
        socket.htonl(0)   # ACK number not used for IHAVE
    )

    return header + payload


def build_get_packet(chunk_hash: bytes) -> bytes:
    """
    Build a GET packet to request a specific chunk

    :param chunk_hash: 20-byte SHA-1 hash of the requested chunk
    :return: Complete GET packet as bytes
    """
    if len(chunk_hash) != 20:
        raise ValueError("Chunk hash must be exactly 20 bytes (SHA-1)")

    # Build header
    header = struct.pack(
        HEADER_FMT,
        PktType.GET,
        HEADER_LEN,
        socket.htons(HEADER_LEN + len(chunk_hash)),
        socket.htonl(0),  # SEQ number not used for GET
        socket.htonl(0)   # ACK number not used for GET
    )

    return header + chunk_hash


def build_data_packet(seq_num: int, data: bytes) -> bytes:
    """
    Build a DATA packet containing chunk data

    :param seq_num: Sequence number of this packet
    :param data: Chunk data payload
    :return: Complete DATA packet as bytes
    """
    if len(data) > MAX_PAYLOAD_SIZE:
        raise ValueError(f"Data payload too large: {len(data)} > {MAX_PAYLOAD_SIZE}")

    # Build header
    header = struct.pack(
        HEADER_FMT,
        PktType.DATA,
        HEADER_LEN,
        socket.htons(HEADER_LEN + len(data)),
        socket.htonl(seq_num),
        socket.htonl(0)  # ACK number not used for DATA
    )

    return header + data


def build_ack_packet(ack_num: int) -> bytes:
    """
    Build an ACK packet to acknowledge received data

    :param ack_num: Sequence number being acknowledged
    :return: Complete ACK packet as bytes
    """
    # Build header
    header = struct.pack(
        HEADER_FMT,
        PktType.ACK,
        HEADER_LEN,
        socket.htons(HEADER_LEN),
        socket.htonl(0),  # SEQ number not used for ACK
        socket.htonl(ack_num)
    )

    return header


def build_denied_packet() -> bytes:
    """
    Build a DENIED packet to reject a WHOHAS request

    :return: Complete DENIED packet as bytes
    """
    # Build header
    header = struct.pack(
        HEADER_FMT,
        PktType.DENIED,
        HEADER_LEN,
        socket.htons(HEADER_LEN),
        socket.htonl(0),  # SEQ number not used for DENIED
        socket.htonl(0)   # ACK number not used for DENIED
    )

    return header


def parse_packet(packet: bytes, from_addr: Optional[AddressType] = None) -> PacketInfo:
    """
    Parse a received packet into its components

    :param packet: Raw packet bytes
    :param from_addr: Address of the sender (optional)
    :return: PacketInfo object with parsed data
    """
    if len(packet) < HEADER_LEN:
        raise ValueError(f"Packet too short: {len(packet)} < {HEADER_LEN}")

    # Unpack header
    pkt_type, header_len, pkt_len, seq_num, ack_num = struct.unpack(HEADER_FMT, packet[:HEADER_LEN])

    # Convert from network byte order
    pkt_len = socket.ntohs(pkt_len)
    seq_num = socket.ntohl(seq_num)
    ack_num = socket.ntohl(ack_num)

    # Validate packet length
    if len(packet) != pkt_len:
        raise ValueError(f"Packet length mismatch: expected {pkt_len}, got {len(packet)}")

    # Extract payload
    payload = packet[header_len:] if header_len < len(packet) else b''

    return PacketInfo(
        pkt_type=pkt_type,
        header_len=header_len,
        pkt_len=pkt_len,
        seq_num=seq_num,
        ack_num=ack_num,
        payload=payload,
        from_addr=from_addr
    )


def extract_chunk_hashes(payload: bytes) -> List[bytes]:
    """
    Extract chunk hashes from WHOHAS or IHAVE packet payload

    :param payload: Packet payload containing concatenated chunk hashes
    :return: List of individual chunk hashes
    """
    if len(payload) % 20 != 0:
        raise ValueError("Payload length must be multiple of 20 (SHA-1 hash size)")

    hashes = []
    for i in range(0, len(payload), 20):
        chunk_hash = payload[i:i+20]
        hashes.append(chunk_hash)

    return hashes


def validate_chunk_hash(hash_bytes: bytes) -> bool:
    """
    Validate that a chunk hash has the correct format

    :param hash_bytes: Bytes to validate
    :return: True if valid, False otherwise
    """
    return len(hash_bytes) == 20


def bytes_to_hex_string(hash_bytes: bytes) -> str:
    """
    Convert bytes hash to hexadecimal string

    :param hash_bytes: Hash bytes
    :return: Hexadecimal string representation
    """
    return hash_bytes.hex()


def hex_string_to_bytes(hex_string: str) -> bytes:
    """
    Convert hexadecimal string to bytes

    :param hex_string: Hexadecimal string
    :return: Hash bytes
    """
    # Remove any whitespace and convert to lowercase
    clean_hex = hex_string.strip().lower()
    return bytes.fromhex(clean_hex)