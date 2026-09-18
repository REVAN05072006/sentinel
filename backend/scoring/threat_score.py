from dataclasses import dataclass


@dataclass(frozen=True)
class ThreatScore:
    detector_score: float
    ml_score: float
    correlation_score: float
    progression_score: float
    unified_score: float
    risk_level: str


class ThreatScoreEngine:
    """
    Combines Sentinel's detector, ML, and correlation evidence
    into one explainable threat score.

    Score components:

        50% detector confidence
        25% ML behavioral anomaly
        15% correlation quality
        10% attack progression

    All inputs and outputs are normalized to [0, 1].

    This engine performs analytical scoring only. It does not
    transmit, modify, block, or mitigate traffic.
    """

    DETECTOR_WEIGHT = 0.50
    ML_WEIGHT = 0.25
    CORRELATION_WEIGHT = 0.15
    PROGRESSION_WEIGHT = 0.10

    def __init__(
        self,
        critical_threshold: float = 0.85,
        high_threshold: float = 0.70,
        medium_threshold: float = 0.50,
    ):
        if not (
            0.0
            <= medium_threshold
            <= high_threshold
            <= critical_threshold
            <= 1.0
        ):
            raise ValueError(
                "Thresholds must satisfy "
                "0 <= medium <= high <= critical <= 1"
            )

        self.critical_threshold = critical_threshold
        self.high_threshold = high_threshold
        self.medium_threshold = medium_threshold

    def calculate(
        self,
        detector_score: float,
        ml_score: float = 0.0,
        correlation_score: float = 0.0,
        progression_score: float = 0.0,
    ) -> ThreatScore:
        detector_score = self._validate_score(
            detector_score,
            "detector_score",
        )

        ml_score = self._validate_score(
            ml_score,
            "ml_score",
        )

        correlation_score = self._validate_score(
            correlation_score,
            "correlation_score",
        )

        progression_score = self._validate_score(
            progression_score,
            "progression_score",
        )

        unified_score = (
            self.DETECTOR_WEIGHT * detector_score
            + self.ML_WEIGHT * ml_score
            + self.CORRELATION_WEIGHT * correlation_score
            + self.PROGRESSION_WEIGHT * progression_score
        )

        unified_score = min(
            max(unified_score, 0.0),
            1.0,
        )

        risk_level = self._risk_level(
            unified_score
        )

        return ThreatScore(
            detector_score=round(
                detector_score,
                4,
            ),
            ml_score=round(
                ml_score,
                4,
            ),
            correlation_score=round(
                correlation_score,
                4,
            ),
            progression_score=round(
                progression_score,
                4,
            ),
            unified_score=round(
                unified_score,
                4,
            ),
            risk_level=risk_level,
        )

    def _risk_level(
        self,
        score: float,
    ) -> str:
        if score >= self.critical_threshold:
            return "CRITICAL"

        if score >= self.high_threshold:
            return "HIGH"

        if score >= self.medium_threshold:
            return "MEDIUM"

        return "LOW"

    @staticmethod
    def _validate_score(
        value: float,
        name: str,
    ) -> float:
        try:
            value = float(value)
        except (
            TypeError,
            ValueError,
        ) as exc:
            raise ValueError(
                f"{name} must be numeric"
            ) from exc

        if not 0.0 <= value <= 1.0:
            raise ValueError(
                f"{name} must be between 0 and 1"
            )

        return value