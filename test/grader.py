import io
import os
import random
import select
import signal
import checkersocket
from threading import Thread
import subprocess
import time
import queue
import logging
from pathlib import Path

# import sys
# import atexit
# from concurrent.futures import ThreadPoolExecutor


os.chdir(Path(__file__).parent.parent)


class PeerProc:
    def __init__(
        self,
        identity: int,
        peer_file_loc: str,
        node_map_loc: str,
        has_chunk_loc: str,
        max_transmit: int = 1,
        timeout: int | None = None,
    ) -> None:
        self.id: int = identity
        self.peer_file_loc: str = peer_file_loc
        self.node_map_loc: str = node_map_loc
        self.has_chunk_loc: str = has_chunk_loc
        self.max_connection: int = max_transmit
        self.process: subprocess.Popen | None = None
        self.send_record: dict[tuple[str, int], dict[int, int]] = (
            {}
        )  # {to_id:{type:cnt}}
        self.recv_record: dict[tuple[str, int], dict[int, int]] = (
            {}
        )  # {from_id:{type:cnt}}
        self.timeout: int | None = timeout

    def _get_command_args(self) -> list[str]:
        module_name: str = self.peer_file_loc
        # if module_name.endswith(".py"):
        #     module_path = self.peer_file_loc.removesuffix(".py")
        #     module_name = module_path.replace(os.path.sep, ".")

        cmd_list = [
            "python3",
            "-u",
            # "-m",
            module_name,
            "-p",
            self.node_map_loc,
            "-c",
            self.has_chunk_loc,
            "-m",
            str(self.max_connection),
            "-i",
            str(self.id),
        ]

        if self.timeout:
            cmd_list.extend(["-t", str(self.timeout)])

        return cmd_list

    def start_peer(self) -> None:
        cmd_args: list[str] = self._get_command_args()

        self.process = subprocess.Popen(
            cmd_args,
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            text=True,
            bufsize=1,
        )
        # ensure peer is running
        time.sleep(1)

    def send_cmd(self, cmd: str) -> None:
        self.process.stdin.write(cmd)
        self.process.stdin.flush()

    def record_send_pkt(self, pkt_type: int, to_addr: tuple[str, int]) -> None:
        if to_addr not in self.send_record:
            self.send_record[to_addr] = {}
            for i in range(6):
                self.send_record[to_addr][i] = 0

        self.send_record[to_addr][pkt_type] += 1

    def record_recv_pkt(self, pkt_type: int, from_addr: tuple[str, int]) -> None:
        if from_addr not in self.recv_record:
            self.recv_record[from_addr] = {}
            for i in range(6):
                self.recv_record[from_addr][i] = 0

        self.recv_record[from_addr][pkt_type] += 1

    def terminate_peer(self) -> None:
        self.process.send_signal(signal.SIGINT)
        # self.process.terminate()
        self.process = None


class GradingSession:
    def __init__(
        self,
        grading_handler: object,
        latency: float = 0.05,
        spiffy: bool = False,
        topo_map: str = "test/tmp3/topo3.map",
        nodes_map: str = "test/tmp3/nodes3.map",
    ) -> None:
        self.peer_list: dict[tuple[str, int], PeerProc] = {}
        self.checker_ip: str = "127.0.0.1"
        self.checker_port: int = random.randint(40200, 50200)
        self.checker_sock: checkersocket.CheckerSocket | None = None
        self.checker_recv_queue: queue.Queue = queue.Queue()
        self.checker_send_queue: queue.Queue = queue.Queue()

        self._FINISH: bool = False
        self.latency: float = latency
        self.grading_handler: object = grading_handler
        self.sending_window: dict = {}
        self.spiffy: bool = spiffy

        self.topo: str = topo_map
        self.nodes: str = nodes_map

        self.simulator_process: subprocess.Popen | None = None
        self.checker_log_file: io.TextIOWrapper | None = None

    def recv_pkt(self) -> None:
        while not self._FINISH:
            ready: tuple[list, list, list] = select.select(
                [self.checker_sock], [], [], 0.1
            )
            read_ready: list = ready[0]
            if read_ready:
                pkt: checkersocket.StdPkt = self.checker_sock.recv_pkt_from()
                self.peer_list[pkt.from_addr].record_send_pkt(pkt.pkt_type, pkt.to_addr)
                self.checker_recv_queue.put(pkt)

    def send_pkt(self) -> None:
        while not self._FINISH:
            try:
                pkt: checkersocket.StdPkt = self.checker_send_queue.get(timeout=0.1)
            except:
                continue

            if pkt.to_addr in self.peer_list:
                self.peer_list[pkt.to_addr].record_recv_pkt(pkt.pkt_type, pkt.from_addr)

            # time.sleep(self.latency)
            self.checker_sock.sendto(pkt.pkt_bytes, pkt.to_addr)
            # self.delay_pool.submit(lambda arg: GradingSession.delay_send(*arg), [self, pkt])

    def delay_send(self, pkt: checkersocket.StdPkt) -> None:
        time.sleep(self.latency)
        self.checker_sock.sendto(pkt.pkt_bytes, pkt.to_addr)

    def stop_grader(self) -> None:
        self._FINISH = True
        if self.simulator_process:
            self.simulator_process.terminate()
            self.simulator_process = None
        if self.checker_log_file:
            self.checker_log_file.close()
            self.checker_log_file = None

    def add_peer(
        self,
        identity: int,
        peer_file_loc: str,
        nodes_map_loc: str,
        has_chunk_loc: str,
        max_connection: int,
        peer_addr: tuple[str, int],
        timeout: int | None = None,
    ) -> None:
        peer: PeerProc = PeerProc(
            identity,
            peer_file_loc,
            nodes_map_loc,
            has_chunk_loc,
            max_connection,
            timeout=timeout,
        )
        self.peer_list[peer_addr] = peer

    def run_grader(self) -> None:
        # set env
        os.environ["SIMULATOR"] = f"{self.checker_ip}:{self.checker_port}"
        test_env: str | None = os.getenv("SIMULATOR")
        if test_env is None:
            raise Exception("Void env!")

        # run workers
        if not self.spiffy:
            self.start_time: float = time.time()
            self.checker_sock = checkersocket.CheckerSocket(
                (self.checker_ip, self.checker_port)
            )
            recv_worker: Thread = Thread(
                target=GradingSession.recv_pkt,
                args=[
                    self,
                ],
                daemon=True,
            )
            recv_worker.start()
            send_worker: Thread = Thread(
                target=GradingSession.send_pkt,
                args=[
                    self,
                ],
                daemon=True,
            )
            send_worker.start()
            grading_worker: Thread = Thread(
                target=self.grading_handler,
                args=[
                    self.checker_recv_queue,
                    self.checker_send_queue,
                ],
                daemon=True,
            )
            grading_worker.start()
        else:
            self.start_time: float = time.time()
            # start simulator
            cmd_list: list[str] = [
                "perl",
                "utils/hupsim.pl",
                "-m",
                self.topo,
                "-n",
                self.nodes,
                "-p",
                str(self.checker_port),
                "-v",
                "3",
            ]

            self.checker_log_file = open("logs/Checker.log", "w")
            self.simulator_process: subprocess.Popen = subprocess.Popen(
                cmd_list,
                stdin=subprocess.PIPE,
                stdout=self.checker_log_file,
                stderr=self.checker_log_file,
                text=True,
                bufsize=1,
            )
            # ensure simulator starts
            time.sleep(5)

        # run peers
        for p in self.peer_list.values():
            p.start_peer()

        # wait for grading worker
        # grading_worker.join()
        # time.sleep(15)
        # grading_worker.join()
        # self._FINISH = True


def drop_handler(recv_queue: queue.Queue, send_queue: queue.Queue) -> None:
    dropped: bool = False
    last_pkt: int = 3
    sending_window: list[int] = []
    winsize_logger: logging.Logger = logging.getLogger("WinSize-LOGGER")
    winsize_logger.setLevel(logging.INFO)
    formatter: logging.Formatter = logging.Formatter(
        fmt="%(relativeCreated)d - %(message)s"
    )
    start_time: float = time.perf_counter()
    # check log dir
    log_dir: Path = Path("logs")
    log_dir.mkdir(parents=True, exist_ok=True)
    fh: logging.FileHandler = logging.FileHandler(
        filename=log_dir / "winsize.log", mode="w"
    )
    fh.setLevel(level=logging.INFO)
    fh.setFormatter(formatter)
    winsize_logger.addHandler(fh)
    winsize_logger.info("Winsize")

    cnt: int = 0

    while True:
        try:
            pkt: checkersocket.StdPkt = recv_queue.get(timeout=0.01)
        except:
            continue

        if pkt.pkt_type == 3:
            if pkt.seq not in sending_window:
                sending_window.append(pkt.seq)
            last_pkt = 3
            cnt += 1
        elif pkt.pkt_type == 4:
            if pkt.ack in sending_window:
                sending_window.remove(pkt.ack)
            elif len(sending_window) > 0 and pkt.ack < min(sending_window):
                sending_window.clear()
            if last_pkt == 3:
                winsize_logger.info(f"{len(sending_window)}")
                last_pkt = 4
        else:
            sending_window.clear()

        if pkt.pkt_type == 3 and cnt == 150 and not dropped:
            winsize_logger.info("Packet Dropped!")
            dropped = True
            continue

        send_queue.put(pkt)


def normal_handler(recv_queue: queue.Queue, send_queue: queue.Queue) -> None:
    start_time: float = time.time()
    while True:
        try:
            pkt: checkersocket.StdPkt = recv_queue.get(timeout=0.01)
        except:
            continue
        send_queue.put(pkt)
