import time
import sys
from pathlib import Path
from typing import Optional, Dict, List, Set
from enum import Enum

# Add parent directory to path for utils imports
sys.path.append(str(Path(__file__).resolve().parent.parent))

from utils.simsocket import AddressType
from packet import PktType, PacketInfo


class ConnectionState(Enum):
    """Connection states"""
    IDLE = "idle"
    HANDSHAKE = "handshake"
    TRANSFER = "transfer"
    COMPLETE = "complete"
    ERROR = "error"


class TransferDirection(Enum):
    """Transfer direction"""
    UPLOAD = "upload"   # We are sending data to peer
    DOWNLOAD = "download"  # We are receiving data from peer


class Connection:
    """
    Manages a single peer-to-peer connection for transferring a chunk
    """

    def __init__(self, peer_addr: AddressType, chunk_hash: str, direction: TransferDirection):
        """
        Initialize a new connection

        :param peer_addr: Address of the peer (ip, port)
        :param chunk_hash: Hex string of the chunk hash being transferred
        :param direction: Direction of transfer (upload/download)
        """
        self.peer_addr = peer_addr
        self.chunk_hash = chunk_hash
        self.direction = direction
        self.state = ConnectionState.IDLE
        self.created_at = time.time()

        # Sequence and acknowledgment numbers
        self.seq_num = 0
        self.ack_num = 0

        # Buffers
        self.send_buffer = []  # List of (seq_num, data) tuples
        self.recv_buffer = {}  # Dict of {seq_num: data}
        self.chunk_data = b''  # Accumulated chunk data (for download)

        # Congestion control
        self.cwnd = 1.0  # Congestion window (in packets)
        self.ssthresh = 64  # Slow start threshold

        # RTT estimation
        self.estimated_rtt = 1.0  # Initial estimate
        self.dev_rtt = 0.5
        self.timeout_interval = self.estimated_rtt + 4 * self.dev_rtt

        # Retransmission state
        self.last_send_time = 0.0
        self.last_ack_time = 0.0
        self.duplicate_ack_count = 0
        self.retransmission_count = 0

        # Statistics
        self.packets_sent = 0
        self.packets_acked = 0
        self.packets_lost = 0
        self.bytes_transferred = 0

    def update_state(self, new_state: ConnectionState) -> None:
        """
        Update the connection state

        :param new_state: New connection state
        """
        old_state = self.state
        self.state = new_state
        print(f"Connection {self.peer_addr} {self.chunk_hash[:8]}... "
              f"state: {old_state.value} -> {new_state.value}")

    def is_active(self) -> bool:
        """
        Check if this connection is still active

        :return: True if connection is active, False otherwise
        """
        return self.state in [ConnectionState.HANDSHAKE, ConnectionState.TRANSFER]

    def is_upload(self) -> bool:
        """
        Check if this is an upload connection

        :return: True if uploading, False if downloading
        """
        return self.direction == TransferDirection.UPLOAD

    def is_download(self) -> bool:
        """
        Check if this is a download connection

        :return: True if downloading, False if uploading
        """
        return self.direction == TransferDirection.DOWNLOAD

    def get_age(self) -> float:
        """
        Get the age of this connection in seconds

        :return: Age in seconds
        """
        return time.time() - self.created_at

    def should_retransmit(self) -> bool:
        """
        Check if we should retransmit due to timeout

        :return: True if timeout occurred, False otherwise
        """
        current_time = time.time()
        return (current_time - self.last_send_time) > self.timeout_interval

    def update_timeout_on_ack(self, sample_rtt: float) -> None:
        """
        Update timeout estimation based on sample RTT

        :param sample_rtt: Measured round-trip time
        """
        alpha = 0.15
        beta = 0.3

        # Update EstimatedRTT
        self.estimated_rtt = (1 - alpha) * self.estimated_rtt + alpha * sample_rtt

        # Update DevRTT
        self.dev_rtt = (1 - beta) * self.dev_rtt + beta * abs(sample_rtt - self.estimated_rtt)

        # Update TimeoutInterval
        self.timeout_interval = self.estimated_rtt + 4 * self.dev_rtt

    def update_cwnd_on_ack(self) -> None:
        """
        Update congestion window when ACK is received
        """
        if self.cwnd < self.ssthresh:
            # Slow start
            self.cwnd += 1
        else:
            # Congestion avoidance
            self.cwnd += 1.0 / self.cwnd

    def update_cwnd_on_loss(self) -> None:
        """
        Update congestion window when loss is detected
        """
        self.ssthresh = max(int(self.cwnd / 2), 2)
        self.cwnd = 1

    def get_send_window(self) -> int:
        """
        Get the current send window size in packets

        :return: Number of packets that can be sent
        """
        return max(1, int(self.cwnd))

    def can_send_more(self) -> bool:
        """
        Check if we can send more packets based on congestion window

        :return: True if more packets can be sent, False otherwise
        """
        if self.is_upload():
            # For upload, check how many packets we can have in flight
            packets_in_flight = self.seq_num - self.ack_num
            return packets_in_flight < self.get_send_window()
        return False

    def add_to_send_buffer(self, seq_num: int, data: bytes) -> None:
        """
        Add data to send buffer

        :param seq_num: Sequence number
        :param data: Data to send
        """
        self.send_buffer.append((seq_num, data))

    def get_next_unacked_seq(self) -> Optional[int]:
        """
        Get the next unacknowledged sequence number

        :return: Next unacked sequence number or None
        """
        if not self.send_buffer:
            return None

        # Find the first packet with seq_num > ack_num
        for seq_num, _ in self.send_buffer:
            if seq_num > self.ack_num:
                return seq_num
        return None

    def get_packets_to_retransmit(self) -> List[int]:
        """
        Get list of packet sequence numbers that need retransmission

        :return: List of sequence numbers to retransmit
        """
        # For simplicity, retransmit the earliest unacked packet
        return [self.ack_num + 1] if self.ack_num < self.seq_num else []

    def handle_ack(self, ack_num: int) -> bool:
        """
        Handle received ACK

        :param ack_num: Acknowledgment number
        :return: True if this is a new ACK, False if duplicate
        """
        if ack_num > self.ack_num:
            # New ACK
            old_ack = self.ack_num
            self.ack_num = ack_num
            self.duplicate_ack_count = 0
            self.last_ack_time = time.time()

            # Remove acknowledged packets from send buffer
            self.send_buffer = [(s, d) for s, d in self.send_buffer if s > ack_num]

            # Update congestion window
            self.update_cwnd_on_ack()
            self.packets_acked += 1

            return True
        else:
            # Duplicate ACK
            self.duplicate_ack_count += 1
            return False

    def should_fast_retransmit(self) -> bool:
        """
        Check if we should trigger fast retransmit (3 duplicate ACKs)

        :return: True if fast retransmit should be triggered
        """
        return self.duplicate_ack_count >= 3

    def add_received_data(self, seq_num: int, data: bytes) -> bool:
        """
        Add received data to buffer (for download connections)

        :param seq_num: Sequence number of received data
        :param data: Received data
        :return: True if this is new data, False if duplicate
        """
        if self.direction != TransferDirection.DOWNLOAD:
            return False

        if seq_num not in self.recv_buffer:
            self.recv_buffer[seq_num] = data
            self.bytes_transferred += len(data)

            # Update expected ACK number (cumulative ACK)
            while self.ack_num + 1 in self.recv_buffer:
                self.chunk_data += self.recv_buffer[self.ack_num + 1]
                self.ack_num += 1

            return True
        return False

    def is_chunk_complete(self, expected_size: int) -> bool:
        """
        Check if we have received the complete chunk (for download)

        :param expected_size: Expected total size of the chunk
        :return: True if chunk is complete, False otherwise
        """
        if self.direction != TransferDirection.DOWNLOAD:
            return False
        return len(self.chunk_data) >= expected_size

    def get_chunk_data(self) -> bytes:
        """
        Get the complete chunk data (for download)

        :return: Chunk data
        """
        return self.chunk_data

    def get_statistics(self) -> Dict:
        """
        Get connection statistics

        :return: Dictionary of statistics
        """
        return {
            'peer_addr': self.peer_addr,
            'chunk_hash': self.chunk_hash,
            'direction': self.direction.value,
            'state': self.state.value,
            'age': self.get_age(),
            'packets_sent': self.packets_sent,
            'packets_acked': self.packets_acked,
            'packets_lost': self.packets_lost,
            'bytes_transferred': self.bytes_transferred,
            'cwnd': self.cwnd,
            'ssthresh': self.ssthresh,
            'estimated_rtt': self.estimated_rtt,
            'timeout_interval': self.timeout_interval
        }

    def __str__(self) -> str:
        return (f"Connection({self.direction.value} {self.peer_addr} "
                f"{self.chunk_hash[:8]}... {self.state.value} "
                f"cwnd={self.cwnd:.1f} seq={self.seq_num} ack={self.ack_num})")

    def __repr__(self) -> str:
        return self.__str__()