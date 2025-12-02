import sys
import select
import time
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parent.parent))

from utils import simsocket
from utils.simsocket import AddressType
from utils.peer_context import PeerContext

# Import our custom modules
from packet import parse_packet, PktType
from download_manager import DownloadManager

"""
CS305 P2P File Transfer Project

This is the main peer implementation that integrates all modules:
- Packet handling and parsing
- P2P handshake protocol (WHOHAS/IHAVE/GET)
- Reliable data transfer with congestion control
- Concurrent download management
- Connection limiting and DENIED packet handling

The peer operates in a single-threaded event-driven model using select()
for I/O multiplexing.
"""

BUF_SIZE: int = 1400


def process_download(
    download_manager: DownloadManager, chunk_file: str, output_file: str
) -> None:
    """
    Initiates and manages the download of one or more chunks.

    This function is called when a 'DOWNLOAD' command is received. It delegates
    to the download manager which handles the entire download process including
    WHOHAS discovery, GET requests, reliable data transfer, and file saving.

    :param download_manager: The DownloadManager instance handling downloads.
    :param chunk_file: Path to the file containing hashes of chunks to download.
    :param output_file: Path to the file to save the downloaded chunk data.
    """
    if not download_manager.start_download(chunk_file, output_file):
        if download_manager.context.verbose >= 1:
            print(f"Failed to start download from {chunk_file} to {output_file}")
    else:
        if download_manager.context.verbose >= 2:
            print(f"Started download: {chunk_file} -> {output_file}")


def process_inbound_udp(download_manager: DownloadManager) -> None:
    """
    Processes a single inbound packet received from the socket.

    This function receives data, parses the packet using the packet module,
    and routes it to the download manager which handles all packet types
    (WHOHAS, IHAVE, GET, DATA, ACK, DENIED).

    :param download_manager: The DownloadManager instance that will handle the packet.
    """
    try:
        # Receive packet
        sock = download_manager.sock
        pkt: bytes
        from_addr: AddressType
        pkt, from_addr = sock.recvfrom(BUF_SIZE)

        # Parse packet
        pkt_info = parse_packet(pkt, from_addr)

        # Route to download manager
        completed_file = download_manager.handle_incoming_packet(pkt_info, from_addr)

        # Handle completed downloads
        if completed_file:
            # Download manager already prints "GOT filename"
            if download_manager.context.verbose >= 3:
                print(f"Download completed: {completed_file}")

    except Exception as e:
        if download_manager.context.verbose >= 1:
            print(f"Error processing inbound packet: {e}")


def process_user_input(download_manager: DownloadManager) -> None:
    """
    Handles a single line of user input from ``sys.stdin``.

    Parses the input and, if the command is "DOWNLOAD", calls
    the download manager to start the download process.

    :param download_manager: The DownloadManager instance that will handle the download.
    """
    try:
        user_input = input().strip()
        if not user_input:
            return

        parts = user_input.split()
        if len(parts) < 3:
            if download_manager.context.verbose >= 1:
                print(f"Invalid command format: {user_input}")
            return

        command = parts[0]
        chunk_file = parts[1]
        output_file = parts[2]

        if command == "DOWNLOAD":
            process_download(download_manager, chunk_file, output_file)
        else:
            if download_manager.context.verbose >= 1:
                print(f"Unknown command: {command}")

    except (EOFError, KeyboardInterrupt):
        # Handle end of input gracefully
        return
    except Exception as e:
        if download_manager.context.verbose >= 1:
            print(f"Error processing user input: {e}")


def peer_run(context: PeerContext) -> None:
    """
    Runs the main event loop for the peer.

    Initializes the SimSocket and DownloadManager, then enters a loop
    that uses select.select to monitor both the socket for inbound packets
    and sys.stdin for user commands. Also handles periodic tasks like
    timeout checking and cleanup.

    :param context: The peer's configuration and state object.
    """
    addr: AddressType = (context.ip, context.port)
    sock = simsocket.SimSocket(context.identity, addr, verbose=context.verbose)

    # Initialize download manager
    download_manager = DownloadManager(context, sock)

    # Timing for periodic tasks
    last_cleanup_time = time.time()
    cleanup_interval = 5.0  # Cleanup every 5 seconds
    last_stats_time = time.time()
    stats_interval = 30.0   # Print stats every 30 seconds (if verbose)

    try:
        if context.verbose >= 2:
            print(f"Peer started: {context.identity} at {addr}")
            print(f"Initial chunks: {len(context.has_chunks)}")
            print(f"Max concurrent connections: {context.max_conn}")

        while True:
            # Check for ready sockets with short timeout
            ready: tuple[list, list, list] = select.select(
                [sock, sys.stdin], [], [], 0.1
            )
            read_ready: list = ready[0]

            # Handle network packets
            if sock in read_ready:
                process_inbound_udp(download_manager)

            # Handle user input
            if sys.stdin in read_ready:
                process_user_input(download_manager)

            # No immediate events - do periodic tasks
            current_time = time.time()

            # Handle timeouts and cleanup
            download_manager.handle_timeouts()

            # Periodic cleanup
            if current_time - last_cleanup_time > cleanup_interval:
                download_manager.cleanup_completed_tasks()
                download_manager.handshake_manager.cleanup_old_requests(30.0)
                last_cleanup_time = current_time

            # Schedule new downloads if needed
            download_manager.schedule_downloads()

            # Periodic statistics (if verbose)
            if context.verbose >= 2 and current_time - last_stats_time > stats_interval:
                stats = download_manager.get_statistics()
                print(f"Stats: {stats['download_tasks']}")
                last_stats_time = current_time

    except KeyboardInterrupt:
        if context.verbose >= 2:
            print("Received interrupt, shutting down...")
    except Exception as e:
        if context.verbose >= 1:
            print(f"Error in main loop: {e}")
    finally:
        # Final statistics
        if context.verbose >= 2:
            final_stats = download_manager.get_statistics()
            print(f"Final statistics: {final_stats}")

        sock.close()


def main() -> None:
    """
    Main entry point for the peer script.

    Parses command-line arguments, initializes the PeerContext,
    and starts the peer's main run loop.

    Command-line arguments:
    -i: ID, it is the index in nodes.map
    -p: Peer list file, it will be in the form "*.map" like nodes.map
    -c: Chunkfile, a dictionary dumped by pickle. It will be loaded automatically in peer_context
    -m: The max number of peer that you can send chunk to concurrently
    -v: verbose level for printing logs to stdout, 0 for no verbose, 1 for WARNING level, 2 for INFO, 3 for DEBUG
    -t: pre-defined timeout. If it is not set, you should estimate timeout via RTT
    """
    import argparse

    parser = argparse.ArgumentParser(
        description="CS305 P2P File Transfer Peer",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "-i",
        "--identity",
        dest="identity",
        type=int,
        required=True,
        help="Which peer # am I? (index in nodes.map)",
    )
    parser.add_argument(
        "-p",
        "--peer-file",
        dest="peer_file",
        type=str,
        default="nodes.map",
        help="The list of all peers",
    )
    parser.add_argument(
        "-c",
        "--chunk-file",
        dest="chunk_file",
        type=str,
        required=True,
        help="Pickle dumped dictionary {chunkhash: chunkdata}",
    )
    parser.add_argument(
        "-m",
        "--max-conn",
        dest="max_conn",
        type=int,
        required=True,
        help="Max # of concurrent sending connections",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        dest="verbose",
        type=int,
        choices=[0, 1, 2, 3],
        default=0,
        help="verbose level (0=no verbose, 1=WARNING, 2=INFO, 3=DEBUG)",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        dest="timeout",
        type=int,
        default=0,
        help="pre-defined timeout in seconds (0=auto-calculate based on RTT)",
    )
    args = parser.parse_args()

    try:
        # Initialize peer context
        context = PeerContext(args)

        # Print peer information if verbose
        if context.verbose >= 1:
            print(context)
            print(f"Loaded {len(context.has_chunks)} chunks")
            if context.timeout > 0:
                print(f"Using custom timeout: {context.timeout}s")

        # Start peer main loop
        peer_run(context)

    except KeyboardInterrupt:
        print("\nPeer shutdown requested by user")
    except Exception as e:
        print(f"Error starting peer: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
