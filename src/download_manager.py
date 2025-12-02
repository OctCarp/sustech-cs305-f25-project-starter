import time
import pickle
import sys
from pathlib import Path
from typing import Dict, List, Set, Optional, Tuple

# Add parent directory to path for utils imports
sys.path.append(str(Path(__file__).resolve().parent.parent))

from utils.simsocket import SimSocket, AddressType
from utils.peer_context import PeerContext
from packet import PktType, PacketInfo, parse_packet
from handshake import HandshakeManager
from reliable_transfer import ReliableTransfer
from connection import ConnectionState, TransferDirection


class DownloadTask:
    """
    Manages a single download task (one DOWNLOAD command)
    """

    def __init__(self, output_file: str, needed_chunks: List[str]):
        """
        Initialize download task

        :param output_file: Output file path
        :param needed_chunks: List of chunk hashes to download
        """
        self.output_file = output_file
        self.needed_chunks = set(needed_chunks)
        self.received_chunks = {}  # {chunk_hash: data}
        self.start_time = time.time()
        self.end_time = None
        self.completed = False

    def is_complete(self) -> bool:
        """
        Check if download task is complete

        :return: True if all chunks downloaded, False otherwise
        """
        return len(self.received_chunks) >= len(self.needed_chunks)

    def add_chunk(self, chunk_hash: str, data: bytes) -> bool:
        """
        Add a downloaded chunk

        :param chunk_hash: Chunk hash string
        :param data: Chunk data
        :return: True if chunk was added, False if duplicate or not needed
        """
        if chunk_hash in self.needed_chunks and chunk_hash not in self.received_chunks:
            self.received_chunks[chunk_hash] = data

            if self.is_complete() and not self.completed:
                self.completed = True
                self.end_time = time.time()

            return True
        return False

    def get_missing_chunks(self) -> List[str]:
        """
        Get list of chunks still needed

        :return: List of missing chunk hashes
        """
        return [chunk for chunk in self.needed_chunks if chunk not in self.received_chunks]

    def get_progress(self) -> float:
        """
        Get download progress (0.0 to 1.0)

        :return: Progress percentage
        """
        if not self.needed_chunks:
            return 1.0
        return len(self.received_chunks) / len(self.needed_chunks)

    def get_duration(self) -> float:
        """
        Get download duration in seconds

        :return: Duration if complete, elapsed time if still downloading
        """
        if self.end_time:
            return self.end_time - self.start_time
        else:
            return time.time() - self.start_time

    def save_to_file(self) -> bool:
        """
        Save downloaded chunks to output file

        :return: True if saved successfully, False otherwise
        """
        if not self.is_complete():
            return False

        try:
            with open(self.output_file, 'wb') as f:
                pickle.dump(self.received_chunks, f)
            return True
        except Exception as e:
            print(f"Error saving chunks to {self.output_file}: {e}")
            return False

    def get_statistics(self) -> Dict:
        """
        Get download task statistics

        :return: Dictionary of statistics
        """
        return {
            'output_file': self.output_file,
            'total_chunks': len(self.needed_chunks),
            'downloaded_chunks': len(self.received_chunks),
            'progress': self.get_progress(),
            'duration': self.get_duration(),
            'completed': self.completed,
            'missing_chunks': len(self.get_missing_chunks())
        }


class DownloadManager:
    """
    Manages multiple concurrent download tasks
    """

    def __init__(self, context: PeerContext, sock: SimSocket):
        """
        Initialize download manager

        :param context: Peer context
        :param sock: SimSocket for communication
        """
        self.context = context
        self.sock = sock
        self.handshake_manager = HandshakeManager(context, sock)
        self.reliable_transfer = ReliableTransfer(context, sock)

        self.download_tasks = {}  # {output_file: DownloadTask}
        self.active_downloads = {}  # {chunk_hash: DownloadTask}  # Reverse mapping
        self.chunk_sources = {}    # {chunk_hash: [(peer_addr, request_time), ...]}

        # Configuration
        self.max_concurrent_downloads = 10  # Max chunks to download simultaneously
        self.request_timeout = 30.0  # Timeout for WHOHAS requests
        self.download_timeout = 120.0  # Timeout for individual downloads

    def start_download(self, chunk_file: str, output_file: str) -> bool:
        """
        Start a new download task

        :param chunk_file: File containing chunk hashes to download
        :param output_file: Output file path
        :return: True if download started successfully, False otherwise
        """
        try:
            # Read chunk hashes from file
            needed_chunks = []
            with open(chunk_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        parts = line.split()
                        if len(parts) >= 2:
                            chunk_hash = parts[1]
                            # Skip chunks we already have
                            if chunk_hash not in self.context.has_chunks:
                                needed_chunks.append(chunk_hash)

            if not needed_chunks:
                if self.context.verbose >= 2:
                    print(f"All chunks already available, nothing to download for {output_file}")
                print(f"GOT {output_file}")
                return True

            # Create download task
            download_task = DownloadTask(output_file, needed_chunks)
            self.download_tasks[output_file] = download_task

            # Set up reverse mapping
            for chunk_hash in needed_chunks:
                self.active_downloads[chunk_hash] = download_task

            if self.context.verbose >= 2:
                print(f"Started download task for {output_file}: "
                      f"{len(needed_chunks)} chunks needed")

            # Start WHOHAS requests
            self.start_chunk_discovery(needed_chunks)

            return True

        except Exception as e:
            if self.context.verbose >= 1:
                print(f"Error starting download from {chunk_file}: {e}")
            return False

    def start_chunk_discovery(self, chunk_hashes: List[str]) -> None:
        """
        Send WHOHAS requests for missing chunks

        :param chunk_hashes: List of chunk hashes to discover
        """
        if not chunk_hashes:
            return

        # Send WHOHAS requests
        self.handshake_manager.send_who_has_request(chunk_hashes)

        if self.context.verbose >= 2:
            print(f"Sent WHOHAS requests for {len(chunk_hashes)} chunks")

    def schedule_downloads(self) -> None:
        """
        Schedule chunk downloads based on available peers
        """
        # Check each missing chunk
        for chunk_hash, download_task in self.active_downloads.items():
            if chunk_hash in download_task.received_chunks:
                continue  # Already downloaded

            # Check if we already have a download connection for this chunk
            if chunk_hash in self.reliable_transfer.download_connections:
                continue  # Already downloading

            # Get available peers for this chunk
            peer_candidates = self.handshake_manager.get_download_candidates(chunk_hash)

            if peer_candidates:
                # Select the best peer (simple round-robin for now)
                peer_addr = peer_candidates[0]

                # Create download connection
                connection = self.reliable_transfer.create_download_connection(chunk_hash, peer_addr)

                # Send GET request
                if self.handshake_manager.send_get_request(chunk_hash, peer_addr):
                    if self.context.verbose >= 2:
                        print(f"Started download of chunk {chunk_hash[:8]}... from {peer_addr}")

    def handle_incoming_packet(self, pkt_info: PacketInfo, from_addr: AddressType) -> Optional[str]:
        """
        Handle incoming packet and route to appropriate handler

        :param pkt_info: Parsed packet information
        :param from_addr: Address of the sender
        :return: Output file name if a download was completed, None otherwise
        """
        completed_output_file = None

        try:
            match pkt_info.pkt_type:
                case PktType.WHOHAS:
                    self.handshake_manager.handle_who_has_request(pkt_info, from_addr)

                case PktType.IHAVE:
                    self.handshake_manager.handle_i_have_response(pkt_info, from_addr)
                    # Schedule new downloads based on IHAVE responses
                    self.schedule_downloads()

                case PktType.DENIED:
                    self.handshake_manager.handle_denied_response(pkt_info, from_addr)

                case PktType.GET:
                    chunk_hash = self.handshake_manager.handle_get_request(pkt_info, from_addr)
                    if chunk_hash:
                        # Start upload
                        connection = self.reliable_transfer.create_upload_connection(from_addr, chunk_hash)
                        self.reliable_transfer.start_data_upload(from_addr, chunk_hash)

                case PktType.DATA:
                    chunk_hash = self.reliable_transfer.handle_data_packet(pkt_info, from_addr)
                    if chunk_hash and chunk_hash in self.active_downloads:
                        download_task = self.active_downloads[chunk_hash]
                        connection = self.reliable_transfer.download_connections.get(chunk_hash)

                        if connection and connection.is_chunk_complete(512 * 1024):
                            chunk_data = connection.get_chunk_data()
                            if download_task.add_chunk(chunk_hash, chunk_data):
                                if self.context.verbose >= 2:
                                    print(f"Added chunk {chunk_hash[:8]}... to download task "
                                          f"({download_task.get_progress():.1%} complete)")

                                # Check if download task is complete
                                if download_task.is_complete():
                                    if download_task.save_to_file():
                                        print(f"GOT {download_task.output_file}")
                                        completed_output_file = download_task.output_file
                                    else:
                                        if self.context.verbose >= 1:
                                            print(f"Failed to save {download_task.output_file}")

                case PktType.ACK:
                    self.reliable_transfer.handle_ack_packet(pkt_info, from_addr)

        except Exception as e:
            if self.context.verbose >= 1:
                print(f"Error handling packet from {from_addr}: {e}")

        return completed_output_file

    def handle_timeouts(self) -> List[str]:
        """
        Handle timeout events

        :return: List of completed output files
        """
        completed_files = []

        # Handle reliable transfer timeouts
        self.reliable_transfer.handle_timeouts()

        # Handle handshake timeouts
        self.handshake_manager.cleanup_old_requests(self.request_timeout)

        # Clean up finished connections
        completed_chunks = self.reliable_transfer.cleanup_finished_connections()
        self.handshake_manager.cleanup_finished_connections()

        # Check for completed downloads
        for chunk_hash in completed_chunks:
            if chunk_hash in self.active_downloads:
                download_task = self.active_downloads[chunk_hash]
                connection = self.reliable_transfer.download_connections.get(chunk_hash)

                if connection and connection.state == ConnectionState.COMPLETE:
                    chunk_data = connection.get_chunk_data()
                    if download_task.add_chunk(chunk_hash, chunk_data):
                        if self.context.verbose >= 2:
                            print(f"Added chunk {chunk_hash[:8]}... to download task "
                                  f"({download_task.get_progress():.1%} complete)")

                        # Check if download task is complete
                        if download_task.is_complete():
                            if download_task.save_to_file():
                                print(f"GOT {download_task.output_file}")
                                completed_files.append(download_task.output_file)
                            else:
                                if self.context.verbose >= 1:
                                    print(f"Failed to save {download_task.output_file}")

        return completed_files

    def get_statistics(self) -> Dict:
        """
        Get download manager statistics

        :return: Dictionary of statistics
        """
        handshake_stats = self.handshake_manager.get_handshake_statistics()
        transfer_stats = self.reliable_transfer.get_connection_statistics()

        # Download task statistics
        task_stats = {
            'total_tasks': len(self.download_tasks),
            'active_tasks': len([t for t in self.download_tasks.values() if not t.completed]),
            'completed_tasks': len([t for t in self.download_tasks.values() if t.completed]),
            'total_chunks_downloading': len(self.active_downloads),
            'total_chunks_completed': sum(len(t.received_chunks) for t in self.download_tasks.values())
        }

        # Individual task details
        task_details = {}
        for output_file, task in self.download_tasks.items():
            task_details[output_file] = task.get_statistics()

        return {
            'download_tasks': task_stats,
            'task_details': task_details,
            'handshake': handshake_stats,
            'transfer': transfer_stats
        }

    def cleanup_completed_tasks(self) -> None:
        """
        Clean up completed download tasks
        """
        completed_files = []

        for output_file, task in self.download_tasks.items():
            if task.completed:
                completed_files.append(output_file)

        for output_file in completed_files:
            task = self.download_tasks[output_file]
            if self.context.verbose >= 2:
                print(f"Cleaning up completed download task: {output_file} "
                      f"({task.get_duration():.1f}s)")

            # Remove from active_downloads mapping
            for chunk_hash in task.needed_chunks:
                if chunk_hash in self.active_downloads:
                    del self.active_downloads[chunk_hash]

            del self.download_tasks[output_file]