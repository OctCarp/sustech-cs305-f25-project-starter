import time
import sys
from pathlib import Path
from typing import List, Dict, Set, Optional, Tuple

# Add parent directory to path for utils imports
sys.path.append(str(Path(__file__).resolve().parent.parent))

from utils.simsocket import SimSocket, AddressType
from utils.peer_context import PeerContext
from packet import (
    PktType, PacketInfo,
    build_who_has_packet, build_i_have_packet, build_get_packet, build_denied_packet,
    parse_packet, extract_chunk_hashes, bytes_to_hex_string, hex_string_to_bytes
)
from connection import Connection, ConnectionState, TransferDirection


class HandshakeManager:
    """
    Manages P2P handshake process (WHOHAS/IHAVE/GET)
    """

    def __init__(self, context: PeerContext, sock: SimSocket):
        """
        Initialize handshake manager

        :param context: Peer context containing peer information
        :param sock: SimSocket for network communication
        """
        self.context = context
        self.sock = sock
        self.active_requests = {}  # {chunk_hash: (request_time, peer_responses)}
        self.upload_connections = {}  # {(peer_addr, chunk_hash): Connection}
        self.connection_limit = context.max_conn

    def send_who_has_request(self, chunk_hashes: List[str]) -> None:
        """
        Send WHOHAS request to all peers for specified chunks

        :param chunk_hashes: List of chunk hash strings to request
        """
        if not chunk_hashes:
            return

        # Convert hash strings to bytes
        hash_bytes_list = [hex_string_to_bytes(hash_str) for hash_str in chunk_hashes]

        # Build WHOHAS packet
        whohas_pkt = build_who_has_packet(hash_bytes_list)

        # Send to all known peers except ourselves
        for peer_info in self.context.peers:
            peer_id = int(peer_info[0])
            if peer_id != self.context.identity:
                peer_addr = (peer_info[1], int(peer_info[2]))
                self.sock.sendto(whohas_pkt, peer_addr)

                if self.context.verbose >= 2:  # INFO level
                    print(f"Sent WHOHAS for {len(chunk_hashes)} chunks to peer {peer_id} at {peer_addr}")

        # Track the request
        current_time = time.time()
        for chunk_hash in chunk_hashes:
            self.active_requests[chunk_hash] = (current_time, {})

    def handle_who_has_request(self, pkt_info: PacketInfo, from_addr: AddressType) -> None:
        """
        Handle incoming WHOHAS request

        :param pkt_info: Parsed WHOHAS packet information
        :param from_addr: Address of the requesting peer
        """
        try:
            # Extract requested chunk hashes
            requested_hashes = extract_chunk_hashes(pkt_info.payload)
            requested_hash_strings = [bytes_to_hex_string(h) for h in requested_hashes]

            if self.context.verbose >= 2:
                print(f"Received WHOHAS for {len(requested_hashes)} chunks from {from_addr}")

            # Check which chunks we have
            available_hashes = []
            for hash_str in requested_hash_strings:
                if hash_str in self.context.has_chunks:
                    available_hashes.append(hex_string_to_bytes(hash_str))

            # Check connection limit
            current_upload_count = len(self.upload_connections)

            if current_upload_count >= self.connection_limit:
                # Send DENIED packet
                denied_pkt = build_denied_packet()
                self.sock.sendto(denied_pkt, from_addr)

                if self.context.verbose >= 1:  # WARNING level
                    print(f"Connection limit reached ({current_upload_count}/{self.connection_limit}), "
                          f"sending DENIED to {from_addr}")
                return

            if available_hashes:
                # Send IHAVE packet with available chunks
                ihave_pkt = build_i_have_packet(available_hashes)
                self.sock.sendto(ihave_pkt, from_addr)

                if self.context.verbose >= 2:
                    print(f"Sent IHAVE for {len(available_hashes)} chunks to {from_addr}")
            else:
                # Send DENIED packet if we don't have any requested chunks
                denied_pkt = build_denied_packet()
                self.sock.sendto(denied_pkt, from_addr)

                if self.context.verbose >= 2:
                    print(f"None of requested chunks available, sending DENIED to {from_addr}")

        except Exception as e:
            if self.context.verbose >= 1:
                print(f"Error handling WHOHAS request from {from_addr}: {e}")

    def handle_i_have_response(self, pkt_info: PacketInfo, from_addr: AddressType) -> List[str]:
        """
        Handle IHAVE response to WHOHAS request

        :param pkt_info: Parsed IHAVE packet information
        :param from_addr: Address of the responding peer
        :return: List of chunk hash strings we can download from this peer
        """
        try:
            # Extract available chunk hashes
            available_hashes = extract_chunk_hashes(pkt_info.payload)
            available_hash_strings = [bytes_to_hex_string(h) for h in available_hashes]

            if self.context.verbose >= 2:
                print(f"Received IHAVE for {len(available_hashes)} chunks from {from_addr}")

            # Update active requests with peer responses
            for hash_str in available_hash_strings:
                if hash_str in self.active_requests:
                    request_time, peer_responses = self.active_requests[hash_str]
                    if from_addr not in peer_responses:
                        peer_responses[from_addr] = available_hash_strings

            return available_hash_strings

        except Exception as e:
            if self.context.verbose >= 1:
                print(f"Error handling IHAVE response from {from_addr}: {e}")
            return []

    def handle_denied_response(self, pkt_info: PacketInfo, from_addr: AddressType) -> None:
        """
        Handle DENIED response

        :param pkt_info: Parsed DENIED packet information
        :param from_addr: Address of the responding peer
        """
        if self.context.verbose >= 2:
            print(f"Received DENIED from {from_addr}")

    def send_get_request(self, chunk_hash: str, peer_addr: AddressType) -> bool:
        """
        Send GET request to download a specific chunk

        :param chunk_hash: Hash string of the chunk to download
        :param peer_addr: Address of the peer to request from
        :return: True if request sent successfully, False otherwise
        """
        try:
            # Convert hash string to bytes
            hash_bytes = hex_string_to_bytes(chunk_hash)

            # Build GET packet
            get_pkt = build_get_packet(hash_bytes)

            # Send GET request
            self.sock.sendto(get_pkt, peer_addr)

            if self.context.verbose >= 2:
                print(f"Sent GET for chunk {chunk_hash[:8]}... to {peer_addr}")

            return True

        except Exception as e:
            if self.context.verbose >= 1:
                print(f"Error sending GET request to {peer_addr}: {e}")
            return False

    def handle_get_request(self, pkt_info: PacketInfo, from_addr: AddressType) -> Optional[str]:
        """
        Handle GET request and prepare for upload

        :param pkt_info: Parsed GET packet information
        :param from_addr: Address of the requesting peer
        :return: Chunk hash string if we can serve this request, None otherwise
        """
        try:
            # Extract requested chunk hash
            if len(pkt_info.payload) != 20:
                if self.context.verbose >= 1:
                    print(f"Invalid GET packet payload size from {from_addr}: {len(pkt_info.payload)}")
                return None

            requested_hash = bytes_to_hex_string(pkt_info.payload)

            if self.context.verbose >= 2:
                print(f"Received GET for chunk {requested_hash[:8]}... from {from_addr}")

            # Check if we have this chunk
            if requested_hash not in self.context.has_chunks:
                if self.context.verbose >= 1:
                    print(f"Requested chunk {requested_hash[:8]}... not found")
                return None

            # Check connection limit
            current_upload_count = len(self.upload_connections)
            if current_upload_count >= self.connection_limit:
                if self.context.verbose >= 1:
                    print(f"Upload connection limit reached: {current_upload_count}/{self.connection_limit}")
                return None

            # Check if we already have an upload connection for this peer/chunk
            connection_key = (from_addr, requested_hash)
            if connection_key in self.upload_connections:
                if self.context.verbose >= 1:
                    print(f"Upload connection already exists for {from_addr}, chunk {requested_hash[:8]}...")
                return None

            # Create upload connection
            upload_conn = Connection(from_addr, requested_hash, TransferDirection.UPLOAD)
            upload_conn.update_state(ConnectionState.TRANSFER)
            self.upload_connections[connection_key] = upload_conn

            if self.context.verbose >= 2:
                print(f"Created upload connection for {from_addr}, chunk {requested_hash[:8]}...")

            return requested_hash

        except Exception as e:
            if self.context.verbose >= 1:
                print(f"Error handling GET request from {from_addr}: {e}")
            return None

    def get_download_candidates(self, chunk_hash: str) -> List[AddressType]:
        """
        Get list of peers that have the specified chunk

        :param chunk_hash: Chunk hash string
        :return: List of peer addresses that have this chunk
        """
        if chunk_hash not in self.active_requests:
            return []

        request_time, peer_responses = self.active_requests[chunk_hash]
        return list(peer_responses.keys())

    def cleanup_old_requests(self, timeout: float = 30.0) -> None:
        """
        Clean up old WHOHAS requests that have timed out

        :param timeout: Request timeout in seconds
        """
        current_time = time.time()
        expired_chunks = []

        for chunk_hash, (request_time, _) in self.active_requests.items():
            if current_time - request_time > timeout:
                expired_chunks.append(chunk_hash)

        for chunk_hash in expired_chunks:
            del self.active_requests[chunk_hash]
            if self.context.verbose >= 1:
                print(f"WHOHAS request for chunk {chunk_hash[:8]}... timed out")

    def cleanup_finished_connections(self) -> None:
        """
        Clean up finished upload connections
        """
        finished_connections = []

        for connection_key, connection in self.upload_connections.items():
            if connection.state in [ConnectionState.COMPLETE, ConnectionState.ERROR]:
                finished_connections.append(connection_key)

        for connection_key in finished_connections:
            connection = self.upload_connections[connection_key]
            if self.context.verbose >= 2:
                print(f"Cleaning up upload connection: {connection}")
            del self.upload_connections[connection_key]

    def get_upload_connection(self, peer_addr: AddressType, chunk_hash: str) -> Optional[Connection]:
        """
        Get upload connection for specific peer and chunk

        :param peer_addr: Peer address
        :param chunk_hash: Chunk hash string
        :return: Connection object if found, None otherwise
        """
        connection_key = (peer_addr, chunk_hash)
        return self.upload_connections.get(connection_key)

    def is_upload_connection_available(self) -> bool:
        """
        Check if we can accept more upload connections

        :return: True if we can accept more connections, False otherwise
        """
        return len(self.upload_connections) < self.connection_limit

    def get_handshake_statistics(self) -> Dict:
        """
        Get handshake manager statistics

        :return: Dictionary of statistics
        """
        return {
            'active_requests': len(self.active_requests),
            'upload_connections': len(self.upload_connections),
            'connection_limit': self.connection_limit,
            'available_upload_slots': self.connection_limit - len(self.upload_connections)
        }