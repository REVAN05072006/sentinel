from dataclasses import dataclass

import numpy as np

from backend.features.window import WindowFeatures
from backend.models.anomaly_detector import (
    AnomalyResult,
    TrafficAnomalyDetector,
)
from backend.models.feature_builder import TrafficFeatureBuilder


@dataclass
class MLPipelineResult:
    anomaly_score: float
    is_anomaly: bool
    feature_vector: list[float]


class TrafficMLPipeline:
    """
    Connects Sentinel's window-level traffic features
    to the machine-learning anomaly detector.

    Processing flow:

        WindowFeatures
            ↓
        TrafficFeatureBuilder
            ↓
        Isolation Forest
            ↓
        AnomalyResult

    This component is analytical and read-only. It does not
    transmit, modify, block, or otherwise interact with traffic.
    """

    def __init__(
        self,
        contamination: float = 0.05,
        random_state: int = 42,
    ):
        self.feature_builder = TrafficFeatureBuilder()

        self.detector = TrafficAnomalyDetector(
            contamination=contamination,
            random_state=random_state,
        )

        self._fitted = False

    def fit(
        self,
        windows: list[WindowFeatures],
    ) -> None:
        """
        Learn the normal traffic baseline from window features.
        """

        features = self.feature_builder.from_windows(
            windows
        )

        self.detector.fit(features)

        self._fitted = True

    def predict(
        self,
        window: WindowFeatures,
    ) -> MLPipelineResult:
        """
        Convert one Sentinel traffic window into an ML result.
        """

        if not self._fitted:
            raise RuntimeError(
                "ML pipeline must be fitted before prediction"
            )

        feature_vector = (
            self.feature_builder.from_window(window)
        )

        results = self.detector.predict(
            feature_vector
        )

        result: AnomalyResult = results[0]

        return MLPipelineResult(
            anomaly_score=result.anomaly_score,
            is_anomaly=result.is_anomaly,
            feature_vector=[
                float(value)
                for value in feature_vector[0]
            ],
        )

    def predict_windows(
        self,
        windows: list[WindowFeatures],
    ) -> list[MLPipelineResult]:
        """
        Run ML anomaly detection across multiple
        Sentinel traffic windows.
        """

        if not self._fitted:
            raise RuntimeError(
                "ML pipeline must be fitted before prediction"
            )

        features = self.feature_builder.from_windows(
            windows
        )

        results = self.detector.predict(
            features
        )

        return [
            MLPipelineResult(
                anomaly_score=result.anomaly_score,
                is_anomaly=result.is_anomaly,
                feature_vector=[
                    float(value)
                    for value in feature_vector
                ],
            )
            for result, feature_vector in zip(
                results,
                features,
            )
        ]

    def feature_names(self) -> list[str]:
        """
        Return the feature names used by the ML pipeline.
        """

        return self.feature_builder.feature_names()