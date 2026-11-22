#!/usr/bin/env python3
"""Compare offline processing time on deterministic synthetic SYN captures."""

import argparse
import statistics
import struct
import subprocess
import tempfile
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def synthetic_syn(packet_number: int, varied: bool) -> bytes:
    frame = bytearray(74)
    frame[12:14] = b"\x08\x00"

    frame[14] = 0x45
    frame[16:18] = struct.pack("!H", 60)
    frame[18:20] = struct.pack("!H", packet_number % 65536 if varied else 0x1234)
    frame[20:22] = b"\x40\x00"
    frame[22] = 64
    frame[23] = 6
    frame[26:30] = bytes((192, 0, 2, 10))
    frame[30:34] = bytes((198, 51, 100, 20))

    tcp = memoryview(frame)[34:]
    tcp[0:2] = struct.pack("!H", 49152)
    tcp[2:4] = struct.pack("!H", 443)
    tcp[4:8] = struct.pack("!I", packet_number if varied else 100)
    tcp[12] = 10 << 4
    tcp[13] = 0x02
    tcp[14:16] = struct.pack("!H", 29200)
    tcp[20:40] = bytes((2, 4, 5, 180, 1, 3, 3, 7, 4, 2, 8, 10, 0, 0, 0, 1, 0, 0, 0, 0))
    return bytes(frame)


def write_capture(path: Path, packet_count: int, varied: bool) -> None:
    with path.open("wb") as capture:
        capture.write(b"\xd4\xc3\xb2\xa1")
        capture.write(struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1))
        for index in range(packet_count):
            frame = synthetic_syn(index, varied)
            capture.write(struct.pack("<IIII", index // 1_000_000, index % 1_000_000, len(frame), len(frame)))
            capture.write(frame)


def elapsed(command: list[str], output_path: Path | None = None) -> float:
    started = time.perf_counter()
    if output_path is None:
        result = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    else:
        with output_path.open("wb") as output:
            result = subprocess.run(command, stdout=output, stderr=subprocess.PIPE, text=True)
    duration = time.perf_counter() - started
    if result.returncode:
        raise RuntimeError(f"{' '.join(command)} failed:\n{result.stderr}")
    return duration


def count_quietprint_results(path: Path) -> int:
    with path.open() as output:
        return sum(1 for line in output if line.strip())


def count_p0f_results(path: Path) -> int:
    with path.open() as output:
        return sum(1 for line in output if "mod=syn|" in line)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--quietprint", type=Path, default=ROOT / "target/release/quietprint")
    parser.add_argument("--p0f", default="p0f")
    parser.add_argument("--packets", type=int, default=500_000)
    parser.add_argument("--runs", type=int, default=5)
    args = parser.parse_args()

    if args.packets < 1 or args.runs < 1:
        parser.error("--packets and --runs must be positive")
    if not args.quietprint.is_file():
        parser.error(f"Quietprint binary not found: {args.quietprint}; run cargo build --release")

    with tempfile.TemporaryDirectory(prefix="quietprint-bench-") as directory:
        temporary = Path(directory)
        for workload, varied in (("identical", False), ("retransmissions", True)):
            capture = temporary / f"{workload}.pcap"
            write_capture(capture, args.packets, varied)
            quietprint_times = []
            p0f_times = []
            quietprint_result_counts = []
            p0f_result_counts = []
            for run in range(args.runs):
                quietprint_output = temporary / f"quietprint-{workload}-{run}.json"
                p0f_output = temporary / f"p0f-{workload}-{run}.log"
                quietprint_times.append(
                    elapsed(
                        [
                            str(args.quietprint),
                            "analyze",
                            str(capture),
                            "--json",
                            "--aggregate",
                        ],
                        quietprint_output,
                    )
                )
                p0f_times.append(
                    elapsed([args.p0f, "-r", str(capture), "-o", str(p0f_output)])
                )
                quietprint_result_counts.append(count_quietprint_results(quietprint_output))
                p0f_result_counts.append(count_p0f_results(p0f_output))

            quietprint_median = statistics.median(quietprint_times)
            p0f_median = statistics.median(p0f_times)
            print(f"{workload}: {args.packets:,} packets, {args.runs} runs")
            for tool, duration in (("Quietprint", quietprint_median), ("p0f", p0f_median)):
                print(f"  {tool}: {duration:.3f}s ({args.packets / duration:,.0f} packets/s)")
            quietprint_count = quietprint_result_counts[-1]
            p0f_count = p0f_result_counts[-1]
            print(f"  Results: Quietprint {quietprint_count:,}; p0f {p0f_count:,}")
            if quietprint_count == p0f_count:
                print(f"  Quietprint/p0f throughput ratio: {p0f_median / quietprint_median:.2f}x")
            else:
                print("  Ratio omitted: result counts differ.")


if __name__ == "__main__":
    main()
