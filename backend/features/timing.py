from dataclasses import dataclass
from statistics import mean, pstdev
from typing import Iterable


@dataclass
class TimingFeatures:
    """
    Temporal features derived from repeated network observations.
    """

    observation_count: int
    mean_interval: float
    interval_stddev: float
    periodicity_score: float


class TimingFeatureExtractor:
    """
    Extracts temporal features used for detecting periodic network
    communication such as botnet C2 beaconing.

    This component is purely analytical and operates only on
    passively observed timestamps.
    """

    @staticmethod
    def extract(timestamps: Iterable[float]) -> TimingFeatures:
        times = sorted(timestamps)

        if len(times) < 2:
            return TimingFeatures(
                observation_count=len(times),
                mean_interval=0.0,
                interval_stddev=0.0,
                periodicity_score=0.0,
            )

        intervals = [
            current - previous
            for previous, current in zip(times, times[1:])
            if current >= previous
        ]

        if not intervals:
            return TimingFeatures(
                observation_count=len(times),
                mean_interval=0.0,
                interval_stddev=0.0,
                periodicity_score=0.0,
            )

        mean_interval = mean(intervals)

        if len(intervals) > 1:
            interval_stddev = pstdev(intervals)
        else:
            interval_stddev = 0.0

        if mean_interval <= 0:
            periodicity_score = 0.0
        else:
            variation = interval_stddev / mean_interval
            periodicity_score = max(0.0, min(1.0, 1.0 - variation))

        return TimingFeatures(
            observation_count=len(times),
            mean_interval=mean_interval,
            interval_stddev=interval_stddev,
            periodicity_score=periodicity_score,
        )