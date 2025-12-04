import time
import pickle
import hashlib
import shutil
from pathlib import Path

import pytest

import grader

"""
The topology in topo6.map may contain nodes that do not hold chunks.
These nodes can be considered as ordinary routing nodes that only participate in packet transmission.

Initial fragments:

data6-1: chunk 1,2
data6-2: chunk 3,4
data6-3: chunk 5,6
data6-4: chunk 7,8
data6-5: chunk 9,10
data6-6: chunk 11,13,15
data6-7: chunk 12,14,16
data6-8: chunk 17,18,19,20

-----------------------------
Targets:
# target#: chunks

target1: 4

target2: 7,12

target3: 11

target4: 8,16

-----------------------------
This testing script is equivalent to run the following commands in different shells (remember to export SIMULATOR in each shell):
Enter DOWNLOAD command after all peers run

perl utils/hupsim.pl -m test/tmp6/topo6.map -n test/tmp6/nodes6.map -p {port_number} -v 3

python3 src/peer.py -p test/tmp6/nodes6.map -c test/tmp6/fragments/data6-1.fragment -m 100 -i 1
DOWNLOAD test/tmp6/targets/target1.chunkhash test/tmp6/results/result1.fragment

python3 src/peer.py -p test/tmp6/nodes6.map -c test/tmp6/fragments/data6-2.fragment -m 100 -i 2

python3 src/peer.py -p test/tmp6/nodes6.map -c test/tmp6/fragments/data6-3.fragment -m 100 -i 7
DOWNLOAD test/tmp6/targets/target2.chunkhash test/tmp6/results/result2.fragment

python3 src/peer.py -p test/tmp6/nodes6.map -c test/tmp6/fragments/data6-4.fragment -m 100 -i 14

python3 src/peer.py -p test/tmp6/nodes6.map -c test/tmp6/fragments/data6-5.fragment -m 100 -i 10
DOWNLOAD test/tmp6/targets/target3.chunkhash test/tmp6/results/result3.fragment

python3 src/peer.py -p test/tmp6/nodes6.map -c test/tmp6/fragments/data6-6.fragment -m 100 -i 15

python3 src/peer.py -p test/tmp6/nodes6.map -c test/tmp6/fragments/data6-7.fragment -m 100 -i 12

python3 src/peer.py -p test/tmp6/nodes6.map -c test/tmp6/fragments/data6-8.fragment -m 100 -i 13
DOWNLOAD test/tmp6/targets/target4.chunkhash test/tmp6/results/result4.fragment


The default tasks in this file may run around 100s. Note that there will be packet loss in the simulator.
-----------------------------
You can design your own networks and tasks using this scripts!
And you can visualize your network using net-visual.py

"""


@pytest.fixture(scope="module")
def adv_2_session() -> tuple[grader.GradingSession, bool]:
    success: bool = False
    time_max: int = 640
    results_dir = Path("test/tmp6/results")
    if results_dir.exists():
        shutil.rmtree(results_dir, ignore_errors=True)
    results_dir.mkdir(parents=True, exist_ok=True)

    stime: float = time.perf_counter()
    adv_2_session: grader.GradingSession = grader.GradingSession(
        grader.normal_handler,
        latency=0.01,
        spiffy=True,
        topo_map="test/tmp6/topo6.map",
        nodes_map="test/tmp6/nodes6.map",
    )

    _PEER_FILE = "src/peer.py"
    _NODES_MAP = "test/tmp6/nodes6.map"
    _MAX_CONN = 100
    peer_args = [
        (1, "test/tmp6/fragments/data6-1.fragment", ("127.0.0.1", 58001)),
        (2, "test/tmp6/fragments/data6-2.fragment", ("127.0.0.1", 58002)),
        (7, "test/tmp6/fragments/data6-3.fragment", ("127.0.0.1", 58003)),
        (14, "test/tmp6/fragments/data6-4.fragment", ("127.0.0.1", 58004)),
        (10, "test/tmp6/fragments/data6-5.fragment", ("127.0.0.1", 58005)),
        (15, "test/tmp6/fragments/data6-6.fragment", ("127.0.0.1", 58006)),
        (12, "test/tmp6/fragments/data6-7.fragment", ("127.0.0.1", 58007)),
        (13, "test/tmp6/fragments/data6-8.fragment", ("127.0.0.1", 58008)),
    ]
    for peer_id, fragment_file, addr in peer_args:
        adv_2_session.add_peer(
            identity=peer_id,
            peer_file_loc=_PEER_FILE,
            nodes_map_loc=_NODES_MAP,
            has_chunk_loc=fragment_file,
            max_connection=_MAX_CONN,
            peer_addr=addr,
        )
    adv_2_session.run_grader()

    download_tasks = [
        (
            ("127.0.0.1", 58001),
            "test/tmp6/targets/target1.chunkhash",
            "test/tmp6/results/result1.fragment",
        ),
        (
            ("127.0.0.1", 58003),
            "test/tmp6/targets/target2.chunkhash",
            "test/tmp6/results/result2.fragment",
        ),
        (
            ("127.0.0.1", 58005),
            "test/tmp6/targets/target3.chunkhash",
            "test/tmp6/results/result3.fragment",
        ),
        (
            ("127.0.0.1", 58008),
            "test/tmp6/targets/target4.chunkhash",
            "test/tmp6/results/result4.fragment",
        ),
    ]
    for addr, target_file, result_file in download_tasks:
        cmd = f"DOWNLOAD {target_file} {result_file}\n"
        adv_2_session.peer_list[addr].send_cmd(cmd)

    result_paths = [
        results_dir / "result1.fragment",
        results_dir / "result2.fragment",
        results_dir / "result3.fragment",
        results_dir / "result4.fragment",
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

    for p in adv_2_session.peer_list.values():
        p.terminate_peer()

    return adv_2_session, success


def test_finish(adv_2_session: tuple[grader.GradingSession, bool]) -> None:
    session, success = adv_2_session
    assert success, "Fail to complete transfer or timeout"


def test_content() -> None:
    check_target_result(
        "test/tmp6/targets/target1.chunkhash", "test/tmp6/results/result1.fragment"
    )
    check_target_result(
        "test/tmp6/targets/target2.chunkhash", "test/tmp6/results/result2.fragment"
    )
    check_target_result(
        "test/tmp6/targets/target3.chunkhash", "test/tmp6/results/result3.fragment"
    )
    check_target_result(
        "test/tmp6/targets/target4.chunkhash", "test/tmp6/results/result4.fragment"
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
