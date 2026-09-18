import numpy as np

from backend.features.window import WindowFeatures


class TrafficFeatureBuilder:
    """
    Converts Sentinel window-level traffic features into
    numerical feature vectors suitable for ML models.

    The feature order is fixed so that training and inference
    always use the same representation.

    This component is analytical and read-only.
    """

    FEATURE_NAMES = [
        "packet_count",
        "byte_count",
        "packets_per_second",
        "bytes_per_second",
        "syn_count",
        "syns_per_second",
        "syn_ratio",
        "unique_src_ips",
        "unique_dst_ips",
        "unique_dst_ports",
        "source_ip_entropy",
    ]

    @classmethod
    def from_window(
        cls,
        features: WindowFeatures,
    ) -> np.ndarray:
        """
        Convert one WindowFeatures object into a
        one-row numerical feature matrix.
        """

        values = [
            features.packet_count,
            features.byte_count,
            features.packets_per_second,
            features.bytes_per_second,
            features.syn_count,
            features.syns_per_second,
            features.syn_ratio,
            features.unique_src_ips,
            features.unique_dst_ips,
            features.unique_dst_ports,
            features.source_ip_entropy,
        ]

        return np.asarray(
            [values],
            dtype=float,
        )

    @classmethod
    def from_windows(
        cls,
        windows: list[WindowFeatures],
    ) -> np.ndarray:
        """
        Convert multiple WindowFeatures objects into
        a numerical feature matrix.
        """

        if not windows:
            raise ValueError(
                "windows must contain at least one item"
            )

        return np.vstack(
            [
                cls.from_window(window)
                for window in windows
            ]
        )

    @classmethod
    def feature_names(cls) -> list[str]:
        """
        Return the feature names in the exact order
        used by the feature vector.
        """

        return list(cls.FEATURE_NAMES)