import time
import math
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Add parent directory to path for utils imports
sys.path.append(str(Path(__file__).resolve().parent.parent))

from utils.simsocket import SimSocket, AddressType
from utils.peer_context import PeerContext
from packet import (
    PktType, PacketInfo,
    build_data_packet, build_ack_packet,
    parse_packet, MAX_PAYLOAD_SIZE, CHUNK_SIZE
)
from connection import Connection, ConnectionState, TransferDirection


class ReliableTransfer:
    """
    Implements reliable data transfer protocol (similar to TCP)
    """

    def __init__(self, context: PeerContext, sock: SimSocket):
        """
        Initialize reliable transfer manager

        :param context: Peer context
        :param sock: SimSocket for communication
        """
        self.context = context
        self.sock = sock
        self.download_connections = {}  # {chunk_hash: Connection}
        self.upload_connections = {}    # {(peer_addr, chunk_hash): Connection}

        # Use custom timeout if provided
        self.custom_timeout = context.timeout if context.timeout > 0 else None

    def create_download_connection(self, chunk_hash: str, peer_addr: AddressType) -> Connection:
        """
        Create a new download connection for a chunk

        :param chunk_hash: Chunk hash string to download
        :param peer_addr: Address of the peer to download from
        :return: Created connection
        """
        connection = Connection(peer_addr, chunk_hash, TransferDirection.DOWNLOAD)

        # Set custom timeout if provided
        if self.custom_timeout:
            connection.timeout_interval = self.custom_timeout

        connection.update_state(ConnectionState.TRANSFER)
        self.download_connections[chunk_hash] = connection

        if self.context.verbose >= 2:
            print(f"Created download connection for chunk {chunk_hash[:8]}... from {peer_addr}")

        return connection

    def create_upload_connection(self, peer_addr: AddressType, chunk_hash: str) -> Connection:
        """
        Create a new upload connection for a chunk

        :param peer_addr: Address of the peer to upload to
        :param chunk_hash: Chunk hash string to upload
        :return: Created connection
        """
        connection_key = (peer_addr, chunk_hash)
        connection = Connection(peer_addr, chunk_hash, TransferDirection.UPLOAD)

        # Set custom timeout if provided
        if self.custom_timeout:
            connection.timeout_interval = self.custom_timeout

        # Prepare upload data
        chunk_data = self.context.has_chunks.get(chunk_hash)
        if not chunk_data:
            connection.update_state(ConnectionState.ERROR)
            return connection

        # Split chunk into packets
        for seq_num in range(0, math.ceil(len(chunk_data) / MAX_PAYLOAD_SIZE)):
            start = seq_num * MAX_PAYLOAD_SIZE
            end = min(start + MAX_PAYLOAD_SIZE, len(chunk_data))
            packet_data = chunk_data[start:end]
            connection.add_to_send_buffer(seq_num + 1, packet_data)  # seq starts from 1

        connection.update_state(ConnectionState.TRANSFER)
        self.upload_connections[connection_key] = connection

        if self.context.verbose >= 2:
            print(f"Created upload connection for chunk {chunk_hash[:8]}... to {peer_addr} "
                  f"({len(chunk_data)} bytes, {len(connection.send_buffer)} packets)")

        return connection

    def start_data_upload(self, peer_addr: AddressType, chunk_hash: str) -> bool:
        """
        Start uploading chunk data to a peer

        :param peer_addr: Address of the receiving peer
        :param chunk_hash: Chunk hash string to upload
        :return: True if upload started successfully, False otherwise
        """
        connection_key = (peer_addr, chunk_hash)
        connection = self.upload_connections.get(connection_key)

        if not connection or connection.state != ConnectionState.TRANSFER:
            if self.context.verbose >= 1:
                print(f"No valid upload connection found for {peer_addr}, chunk {chunk_hash[:8]}...")
            return False

        # Send initial data packets according to congestion window
        self.send_data_packets(connection)

        return True

    def send_data_packets(self, connection: Connection) -> None:
        """
        Send data packets based on congestion window

        :param connection: Upload connection
        """
        if not connection.can_send_more():
            return

        # Find the next sequence number to send
        next_seq = max(connection.seq_num, connection.ack_num + 1)

        # Make sure we don't exceed send buffer
        max_seq = len(connection.send_buffer)

        while next_seq <= max_seq and next_seq <= connection.ack_num + connection.get_send_window():
            # Get data from send buffer
            data = None
            for seq_num, packet_data in connection.send_buffer:
                if seq_num == next_seq:
                    data = packet_data
                    break

            if data is None:
                break  # No more data to send

            # Build and send DATA packet
            data_pkt = build_data_packet(next_seq, data)
            self.sock.sendto(data_pkt, connection.peer_addr)

            connection.last_send_time = time.time()
            connection.packets_sent += 1
            connection.seq_num = next_seq  # Update last sent sequence number

            if self.context.verbose >= 3:  # DEBUG level
                print(f"Sent DATA packet seq={next_seq} to {connection.peer_addr} "
                      f"({len(data)} bytes, cwnd={connection.cwnd:.1f})")

            next_seq += 1

    def handle_data_packet(self, pkt_info: PacketInfo, from_addr: AddressType) -> Optional[str]:
        """
        Handle received DATA packet

        :param pkt_info: Parsed DATA packet information
        :param from_addr: Address of the sender
        :return: Chunk hash if packet was processed successfully, None otherwise
        """
        # Find the corresponding download connection
        connection = None
        for chunk_hash, conn in self.download_connections.items():
            if conn.peer_addr == from_addr and conn.state == ConnectionState.TRANSFER:
                connection = conn
                break

        if not connection:
            if self.context.verbose >= 1:
                print(f"No download connection found for DATA packet from {from_addr}")
            return None

        # Process the data
        seq_num = pkt_info.seq_num
        data = pkt_info.payload

        # Check if this is new data
        if connection.add_received_data(seq_num, data):
            # Update RTT measurement
            current_time = time.time()
            if hasattr(connection, 'first_packet_time'):
                sample_rtt = current_time - connection.first_packet_time
                connection.update_timeout_on_ack(sample_rtt)
            else:
                connection.first_packet_time = current_time

            # Send ACK
            ack_pkt = build_ack_packet(connection.ack_num)
            self.sock.sendto(ack_pkt, from_addr)

            if self.context.verbose >= 3:
                print(f"Received DATA seq={seq_num} from {from_addr}, "
                      f"sent ACK {connection.ack_num} "
                      f"({len(data)} bytes, {len(connection.recv_buffer)} buffered)")

            # Check if chunk transfer is complete
            if connection.is_chunk_complete(CHUNK_SIZE):
                connection.update_state(ConnectionState.COMPLETE)
                chunk_data = connection.get_chunk_data()

                if self.context.verbose >= 2:
                    print(f"Download complete for chunk {connection.chunk_hash[:8]}... "
                          f"from {from_addr} ({len(chunk_data)} bytes)")

                return connection.chunk_hash
        else:
            # Duplicate data, just send ACK
            ack_pkt = build_ack_packet(connection.ack_num)
            self.sock.sendto(ack_pkt, from_addr)

            if self.context.verbose >= 3:
                print(f"Duplicate DATA seq={seq_num} from {from_addr}, sent ACK {connection.ack_num}")

        return None

    def handle_ack_packet(self, pkt_info: PacketInfo, from_addr: AddressType) -> Optional[str]:
        """
        Handle received ACK packet

        :param pkt_info: Parsed ACK packet information
        :param from_addr: Address of the sender
        :return: Chunk hash if ACK was processed successfully, None otherwise
        """
        # Find the corresponding upload connection
        connection_key = (from_addr, None)
        connection = None

        for key, conn in self.upload_connections.items():
            if key[0] == from_addr and conn.state == ConnectionState.TRANSFER:
                connection = conn
                connection_key = key
                break

        if not connection:
            if self.context.verbose >= 1:
                print(f"No upload connection found for ACK packet from {from_addr}")
            return None

        ack_num = pkt_info.ack_num
        is_new_ack = connection.handle_ack(ack_num)

        if is_new_ack:
            # Update RTT measurement
            current_time = time.time()
            if hasattr(connection, 'packet_times') and ack_num in connection.packet_times:
                sample_rtt = current_time - connection.packet_times[ack_num]
                connection.update_timeout_on_ack(sample_rtt)
                del connection.packet_times[ack_num]

            if self.context.verbose >= 3:
                print(f"Received ACK {ack_num} from {from_addr}, "
                      f"cwnd={connection.cwnd:.1f}, ssthresh={connection.ssthresh}")

            # Send more data if window allows
            self.send_data_packets(connection)

            # Check if upload is complete
            if connection.ack_num >= len(connection.send_buffer):
                connection.update_state(ConnectionState.COMPLETE)

                if self.context.verbose >= 2:
                    print(f"Upload complete for chunk {connection.chunk_hash[:8]}... "
                          f"to {from_addr}")

                return connection.chunk_hash
        else:
            # Duplicate ACK
            connection.duplicate_ack_count += 1

            if self.context.verbose >= 3:
                print(f"Duplicate ACK {ack_num} from {from_addr}, "
                      f"duplicate_count={connection.duplicate_ack_count}")

            # Check for fast retransmit
            if connection.should_fast_retransmit():
                self.trigger_fast_retransmit(connection)

        return None

    def trigger_fast_retransmit(self, connection: Connection) -> None:
        """
        Trigger fast retransmit for lost packet

        :param connection: Connection experiencing packet loss
        """
        connection.update_cwnd_on_loss()
        connection.retransmission_count += 1

        # Retransmit the lost packet
        lost_seq = connection.ack_num + 1
        for seq_num, data in connection.send_buffer:
            if seq_num == lost_seq:
                data_pkt = build_data_packet(seq_num, data)
                self.sock.sendto(data_pkt, connection.peer_addr)
                connection.last_send_time = time.time()

                if self.context.verbose >= 2:
                    print(f"Fast retransmit: resent DATA seq={seq_num} to {connection.peer_addr} "
                          f"(cwnd={connection.cwnd:.1f}, ssthresh={connection.ssthresh})")
                break

        # Reset duplicate ACK count to prevent multiple fast retransmits
        connection.duplicate_ack_count = 0

    def handle_timeouts(self) -> List[str]:
        """
        Check for and handle timeout events

        :return: List of chunk hashes that had timeout events
        """
        current_time = time.time()
        timeout_chunks = []

        # Check download connections
        for chunk_hash, connection in self.download_connections.items():
            if connection.is_active() and connection.should_retransmit():
                self.handle_download_timeout(connection)
                timeout_chunks.append(chunk_hash)

        # Check upload connections
        for connection_key, connection in self.upload_connections.items():
            if connection.is_active() and connection.should_retransmit():
                self.handle_upload_timeout(connection)
                timeout_chunks.append(connection.chunk_hash)

        return timeout_chunks

    def handle_download_timeout(self, connection: Connection) -> None:
        """
        Handle timeout for download connection

        :param connection: Download connection that timed out
        """
        connection.update_cwnd_on_loss()
        connection.packets_lost += 1

        # Send ACK for last successfully received packet
        ack_pkt = build_ack_packet(connection.ack_num)
        self.sock.sendto(ack_pkt, connection.peer_addr)

        if self.context.verbose >= 2:
            print(f"Download timeout for chunk {connection.chunk_hash[:8]}... "
                  f"from {connection.peer_addr}, sent ACK {connection.ack_num} "
                  f"(cwnd={connection.cwnd:.1f}, timeout={connection.timeout_interval:.2f}s)")

    def handle_upload_timeout(self, connection: Connection) -> None:
        """
        Handle timeout for upload connection

        :param connection: Upload connection that timed out
        """
        connection.update_cwnd_on_loss()
        connection.packets_lost += 1

        # Retransmit from the first unacknowledged packet
        if connection.ack_num < len(connection.send_buffer):
            resend_seq = connection.ack_num + 1
            for seq_num, data in connection.send_buffer:
                if seq_num >= resend_seq:
                    data_pkt = build_data_packet(seq_num, data)
                    self.sock.sendto(data_pkt, connection.peer_addr)
                    connection.last_send_time = time.time()

                    if self.context.verbose >= 2:
                        print(f"Upload timeout: retransmitted DATA seq={seq_num} to {connection.peer_addr} "
                              f"(cwnd={connection.cwnd:.1f})")
                    break

    def cleanup_finished_connections(self) -> List[str]:
        """
        Clean up finished connections

        :return: List of completed chunk hashes
        """
        completed_chunks = []

        # Clean up download connections
        finished_downloads = []
        for chunk_hash, connection in self.download_connections.items():
            if connection.state in [ConnectionState.COMPLETE, ConnectionState.ERROR]:
                finished_downloads.append(chunk_hash)
                if connection.state == ConnectionState.COMPLETE:
                    completed_chunks.append(chunk_hash)

        for chunk_hash in finished_downloads:
            connection = self.download_connections[chunk_hash]
            if self.context.verbose >= 2:
                print(f"Cleaning up download connection: {connection}")
            del self.download_connections[chunk_hash]

        # Clean up upload connections
        finished_uploads = []
        for connection_key, connection in self.upload_connections.items():
            if connection.state in [ConnectionState.COMPLETE, ConnectionState.ERROR]:
                finished_uploads.append(connection_key)

        for connection_key in finished_uploads:
            connection = self.upload_connections[connection_key]
            if self.context.verbose >= 2:
                print(f"Cleaning up upload connection: {connection}")
            del self.upload_connections[connection_key]

        return completed_chunks

    def get_connection_statistics(self) -> Dict:
        """
        Get statistics for all connections

        :return: Dictionary of connection statistics
        """
        stats = {
            'download_connections': len(self.download_connections),
            'upload_connections': len(self.upload_connections),
            'active_downloads': sum(1 for c in self.download_connections.values() if c.is_active()),
            'active_uploads': sum(1 for c in self.upload_connections.values() if c.is_active()),
            'completed_downloads': sum(1 for c in self.download_connections.values()
                                     if c.state == ConnectionState.COMPLETE),
            'completed_uploads': sum(1 for c in self.upload_connections.values()
                                   if c.state == ConnectionState.COMPLETE)
        }

        # Add per-connection statistics
        stats['downloads'] = {chunk_hash: conn.get_statistics()
                            for chunk_hash, conn in self.download_connections.items()}
        stats['uploads'] = {f"{peer_addr}:{chunk_hash}": conn.get_statistics()
                          for (peer_addr, chunk_hash), conn in self.upload_connections.items()}

        return stats