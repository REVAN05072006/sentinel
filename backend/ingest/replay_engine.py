import time
from dataclasses import dataclass
from typing import Callable, Iterable

from backend.ingest.stream import PacketRecord
from backend.ingest.stream_processor import (
    SentinelStreamProcessor,
    StreamingResult,
)


@dataclass(frozen=True)
class ReplayMetrics:
    packets_processed: int
    replay_duration: float
    processing_duration: float
    average_latency_ms: float
    maximum_latency_ms: float
    packets_per_second: float


class TrafficReplayEngine:
    """
    Timestamp-aware passive PCAP replay engine.

    Modes:

        realtime
            Preserve the original packet timing.

        accelerated
            Preserve relative timing multiplied by
            the configured acceleration factor.

        maximum
            Process packets without intentional replay delay.

    The replay engine only feeds previously captured packets
    into Sentinel's analytical pipeline. It never transmits
    packets onto a network.
    """

    def __init__(
        self,
        processor: SentinelStreamProcessor | None = None,
    ):
        self.processor = (
            processor
            if processor is not None
            else SentinelStreamProcessor()
        )

    def replay(
        self,
        packets: Iterable[PacketRecord],
        mode: str = "maximum",
        speed: float = 1.0,
        callback: Callable[
            [StreamingResult],
            None
        ] | None = None,
    ) -> tuple[
        list[StreamingResult],
        ReplayMetrics,
    ]:
        """
        Replay packets through Sentinel.

        speed applies to realtime and accelerated modes.

        For example:

            speed=2.0
                twice as fast as captured timing

            speed=10.0
                ten times as fast

        maximum mode ignores timing delays.
        """

        if mode not in {
            "realtime",
            "accelerated",
            "maximum",
        }:
            raise ValueError(
                "mode must be realtime, accelerated, "
                "or maximum"
            )

        if speed <= 0:
            raise ValueError(
                "speed must be greater than zero"
            )

        results = []

        previous_timestamp = None

        replay_start = time.perf_counter()

        processing_start = None
        processing_end = None

        latencies = []

        for packet in packets:

            if (
                mode != "maximum"
                and previous_timestamp is not None
            ):
                delay = (
                    packet.timestamp
                    - previous_timestamp
                )

                if delay > 0:
                    time.sleep(
                        delay / speed
                    )

            previous_timestamp = (
                packet.timestamp
            )

            if processing_start is None:
                processing_start = (
                    time.perf_counter()
                )

            packet_start = (
                time.perf_counter()
            )

            result = (
                self.processor.process_packet(
                    packet
                )
            )

            packet_end = (
                time.perf_counter()
            )

            latency_ms = (
                packet_end
                - packet_start
            ) * 1000.0

            latencies.append(
                latency_ms
            )

            results.append(
                result
            )

            if callback is not None:
                callback(result)

            processing_end = packet_end

        replay_end = time.perf_counter()

        packets_processed = len(
            results
        )

        replay_duration = (
            replay_end
            - replay_start
        )

        if (
            processing_start is not None
            and processing_end is not None
        ):
            processing_duration = (
                processing_end
                - processing_start
            )
        else:
            processing_duration = 0.0

        average_latency_ms = (
            sum(latencies)
            / len(latencies)
            if latencies
            else 0.0
        )

        maximum_latency_ms = (
            max(latencies)
            if latencies
            else 0.0
        )

        packets_per_second = (
            packets_processed
            / processing_duration
            if processing_duration > 0
            else 0.0
        )

        metrics = ReplayMetrics(
            packets_processed=(
                packets_processed
            ),
            replay_duration=(
                replay_duration
            ),
            processing_duration=(
                processing_duration
            ),
            average_latency_ms=(
                round(
                    average_latency_ms,
                    4,
                )
            ),
            maximum_latency_ms=(
                round(
                    maximum_latency_ms,
                    4,
                )
            ),
            packets_per_second=(
                round(
                    packets_per_second,
                    2,
                )
            ),
        )

        return results, metrics