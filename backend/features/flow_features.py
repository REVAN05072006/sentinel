from dataclasses import dataclass

from backend.ingest.flow import FlowRecord


@dataclass
class FlowFeatures:
    """
    Numerical features derived from a single observed network flow.
    """

    flow_id: tuple

    duration: float
    packet_count: int
    byte_count: int

    packets_per_second: float
    bytes_per_second: float

    syn_count: int
    syn_ratio: float

    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str


class FlowFeatureExtractor:
    """
    Converts FlowRecord objects into numerical features.

    The extractor is purely analytical and does not interact
    with the network.
    """

    @staticmethod
    def extract(flow: FlowRecord) -> FlowFeatures:
        duration = max(flow.end_time - flow.start_time, 0.000001)

        packets_per_second = flow.packet_count / duration
        bytes_per_second = flow.byte_count / duration

        if flow.packet_count > 0:
            syn_ratio = flow.syn_count / flow.packet_count
        else:
            syn_ratio = 0.0

        return FlowFeatures(
            flow_id=flow.flow_id,

            duration=duration,
            packet_count=flow.packet_count,
            byte_count=flow.byte_count,

            packets_per_second=packets_per_second,
            bytes_per_second=bytes_per_second,

            syn_count=flow.syn_count,
            syn_ratio=syn_ratio,

            src_ip=flow.src_ip,
            dst_ip=flow.dst_ip,
            src_port=flow.src_port,
            dst_port=flow.dst_port,
            protocol=flow.protocol,
        )