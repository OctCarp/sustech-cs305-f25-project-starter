import time
import pickle
import hashlib
import shutil
from pathlib import Path

import pytest

import grader

"""
Initial fragments (Total 12 chunks):

data5-1: chunk 1            (Peer 1 has 1 chunk)
data5-2: chunk 2,3          (Peer 2 has 2 chunks)
data5-3: chunk 4,5,7        (Peer 3 has 3 chunks)
data5-4: chunk 6,7          (Peer 4 has 2 chunks)
data5-5: chunk 8,9          (Peer 5 has 2 chunks)
data5-6: chunk 10,11,12     (Peer 6 has 3 chunks)

-----------------------------
Topology (6 Peers, Ring with cross-link):
1-2-3-4-5-6-1
  |     |
  +-----+ (Link between 2 and 5)

-----------------------------
Targets:
# target#: chunks

target1: 8,9  (Peer 1 downloads from Peer 5)

target2: 1,7    (For 7, Peer 5 downloads from Peer 4 OR Peer 3)
                * Peer 5 starts downloading.
                * Peer 4 will CRASH.
                * Peer 5 must recover and download from Peer 3 via path 5-2-3.

target3: 3,9    (Peer 6 downloads from Peer 2 and Peer 5)

-----------------------------
Enter DOWNLOAD command after all peers run

python3 src/peer.py -p test/tmp5/nodes5.map -c test/tmp5/fragments/data5-1.fragment -m 100 -i 1
DOWNLOAD test/tmp5/targets/target1.chunkhash test/tmp5/results/result1.fragment

python3 src/peer.py -p test/tmp5/nodes5.map -c test/tmp5/fragments/data5-2.fragment -m 100 -i 2

python3 src/peer.py -p test/tmp5/nodes5.map -c test/tmp5/fragments/data5-3.fragment -m 100 -i 3

python3 src/peer.py -p test/tmp5/nodes5.map -c test/tmp5/fragments/data5-4.fragment -m 100 -i 4
(CTRL+C to terminate peer4 after 2 seconds)

python3 src/peer.py -p test/tmp5/nodes5.map -c test/tmp5/fragments/data5-5.fragment -m 100 -i 5
DOWNLOAD test/tmp5/targets/target2.chunkhash test/tmp5/results/result2.fragment

python3 src/peer.py -p test/tmp5/nodes5.map -c test/tmp5/fragments/data5-6.fragment -m 100 -i 6
DOWNLOAD test/tmp5/targets/target3.chunkhash test/tmp5/results/result3.fragment

"""


@pytest.fixture(scope="module")
def adv_1_session() -> tuple[grader.GradingSession, bool]:
    success: bool = False
    time_max: int = 400
    results_dir = Path("test/tmp5/results")
    if results_dir.exists():
        shutil.rmtree(results_dir, ignore_errors=True)
    results_dir.mkdir(parents=True, exist_ok=True)

    stime: float = time.perf_counter()
    adv_1_session: grader.GradingSession = grader.GradingSession(
        grader.normal_handler,
        latency=0.01,
        spiffy=True,
        topo_map="test/tmp5/topo5.map",
        nodes_map="test/tmp5/nodes5.map",
    )

    _PEER_FILE = "src/peer.py"
    _NODES_MAP = "test/tmp5/nodes5.map"
    _MAX_CONN = 100
    peer_args = [
        (1, "test/tmp5/fragments/data5-1.fragment", ("127.0.0.1", 58001)),
        (2, "test/tmp5/fragments/data5-2.fragment", ("127.0.0.1", 58002)),
        (3, "test/tmp5/fragments/data5-3.fragment", ("127.0.0.1", 58003)),
        (4, "test/tmp5/fragments/data5-4.fragment", ("127.0.0.1", 58004)),
        (5, "test/tmp5/fragments/data5-5.fragment", ("127.0.0.1", 58005)),
        (6, "test/tmp5/fragments/data5-6.fragment", ("127.0.0.1", 58006)),
    ]
    for peer_id, fragment_file, addr in peer_args:
        adv_1_session.add_peer(
            identity=peer_id,
            peer_file_loc=_PEER_FILE,
            nodes_map_loc=_NODES_MAP,
            has_chunk_loc=fragment_file,
            max_connection=_MAX_CONN,
            peer_addr=addr,
        )
    adv_1_session.run_grader()

    download_tasks = [
        (
            ("127.0.0.1", 58001),
            "test/tmp5/targets/target1.chunkhash",
            "test/tmp5/results/result1.fragment",
        ),
        (
            ("127.0.0.1", 58005),
            "test/tmp5/targets/target2.chunkhash",
            "test/tmp5/results/result2.fragment",
        ),
        (
            ("127.0.0.1", 58006),
            "test/tmp5/targets/target3.chunkhash",
            "test/tmp5/results/result3.fragment",
        ),
    ]
    for addr, target_file, result_file in download_tasks:
        cmd = f"DOWNLOAD {target_file} {result_file}\n"
        adv_1_session.peer_list[addr].send_cmd(cmd)

    time.sleep(1.5)
    # Crash Peer 4. Peer 5 (downloading target2) must switch to Peer 3.
    if ("127.0.0.1", 58004) in adv_1_session.peer_list:
        adv_1_session.peer_list[("127.0.0.1", 58004)].terminate_peer()

    result_paths = [
        results_dir / "result1.fragment",
        results_dir / "result2.fragment",
        results_dir / "result3.fragment",
    ]

    while True:
        if all(p.exists() for p in result_paths):
            success = True
            break
        elif time.perf_counter() - stime > time_max:
            # Reached max transmission time, abort
            success = False
            break

        time.sleep(1)

    for p in adv_1_session.peer_list.values():
        if p.process is not None:
            p.terminate_peer()

    return adv_1_session, success


def test_finish(adv_1_session: tuple[grader.GradingSession, bool]) -> None:
    session, success = adv_1_session
    assert success, "Fail to complete transfer or timeout"


def test_content() -> None:
    check_target_result(
        "test/tmp5/targets/target1.chunkhash", "test/tmp5/results/result1.fragment"
    )
    check_target_result(
        "test/tmp5/targets/target2.chunkhash", "test/tmp5/results/result2.fragment"
    )
    check_target_result(
        "test/tmp5/targets/target3.chunkhash", "test/tmp5/results/result3.fragment"
    )


def check_target_result(target_file: str, result_file: str) -> None:
    target_hash: list[str] = []

    target_path = Path(target_file)
    result_path = Path(result_file)
    assert result_path.exists(), f"result file {result_file} does not exist"

    with target_path.open("r") as tf:
        while True:
            line: str = tf.readline()
            if not line:
                break
            index: str
            hash_str: str
            index, hash_str = line.split(" ")
            hash_str = hash_str.strip()
            target_hash.append(hash_str)

    with result_path.open("rb") as rf:
        result_fragments: dict[str, bytes] = pickle.load(rf)

    for th in target_hash:
        assert (
            th in result_fragments
        ), f"download hash mismatch for target {target_file}, target: {th}, has: {result_fragments.keys()}"

        sha1 = hashlib.sha1()
        sha1.update(result_fragments[th])
        received_hash_str: str = sha1.hexdigest()
        assert (
            th.strip() == received_hash_str.strip()
        ), f"received data mismatch for target {target_file}, expect hash: {target_hash}, actual: {received_hash_str}"
