from dataclasses import dataclass

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import RobustScaler


@dataclass
class AnomalyResult:
    anomaly_score: float
    is_anomaly: bool


class TrafficAnomalyDetector:
    """
    Robust unsupervised anomaly detector for Sentinel traffic windows.

    The detector combines:
    1. Isolation Forest structural anomaly detection.
    2. Robust statistical deviation using median/MAD.

    Features are transformed using log1p for highly skewed traffic
    quantities and RobustScaler for scale normalization.

    The model is trained only on trusted baseline traffic and is
    immutable after fitting unless a new detector instance is created.
    """

    def __init__(
        self,
        contamination: float = 0.05,
        random_state: int = 42,
        ensemble_weight: float = 0.70,
        mad_threshold: float = 3.5,
    ):
        if not 0.0 < contamination < 0.5:
            raise ValueError(
                "contamination must be between 0 and 0.5"
            )

        if not 0.0 <= ensemble_weight <= 1.0:
            raise ValueError(
                "ensemble_weight must be between 0 and 1"
            )

        if mad_threshold <= 0:
            raise ValueError(
                "mad_threshold must be greater than zero"
            )

        self.contamination = contamination
        self.random_state = random_state
        self.ensemble_weight = ensemble_weight
        self.statistical_weight = 1.0 - ensemble_weight
        self.mad_threshold = mad_threshold

        self.model = IsolationForest(
            contamination=contamination,
            random_state=random_state,
            n_estimators=300,
            max_samples="auto",
            max_features=1.0,
            bootstrap=False,
            n_jobs=-1,
        )

        self.scaler = RobustScaler()

        self._fitted = False

        self._score_min = 0.0
        self._score_max = 0.0

        self._baseline_median: np.ndarray | None = None
        self._baseline_mad: np.ndarray | None = None

    def fit(self, features):
        """
        Fit the detector exclusively on trusted normal traffic.
        """

        data = self._validate_features(features)

        transformed = self._transform_features(data)

        scaled = self.scaler.fit_transform(transformed)

        self.model.fit(scaled)

        baseline_scores = self.model.decision_function(
            scaled
        )

        self._score_min = float(
            np.min(baseline_scores)
        )

        self._score_max = float(
            np.max(baseline_scores)
        )

        self._baseline_median = np.median(
            scaled,
            axis=0,
        )

        raw_mad = np.median(
            np.abs(
                scaled - self._baseline_median
            ),
            axis=0,
        )

        self._baseline_mad = np.maximum(
            raw_mad,
            1e-6,
        )

        self._fitted = True

    def predict(self, features):
        """
        Produce continuous ensemble anomaly scores.

        The final score combines:

            Isolation Forest anomaly score
            +
            robust statistical deviation score

        The result is normalized to [0, 1].
        """

        if not self._fitted:
            raise RuntimeError(
                "Detector must be fitted before prediction"
            )

        data = self._validate_features(features)

        transformed = self._transform_features(data)

        scaled = self.scaler.transform(
            transformed
        )

        isolation_scores = self.model.decision_function(
            scaled
        )

        isolation_anomaly_scores = (
            self._normalize_isolation_scores(
                isolation_scores
            )
        )

        statistical_scores = (
            self._statistical_anomaly_scores(
                scaled
            )
        )

        ensemble_scores = (
            self.ensemble_weight
            * isolation_anomaly_scores
            + self.statistical_weight
            * statistical_scores
        )

        predictions = []

        for score in ensemble_scores:
            score = float(
                np.clip(
                    score,
                    0.0,
                    1.0,
                )
            )

            predictions.append(
                AnomalyResult(
                    anomaly_score=round(
                        score,
                        4,
                    ),
                    is_anomaly=score >= 0.70,
                )
            )

        return predictions

    def score_samples(self, features):
        """
        Return continuous ensemble anomaly scores.
        """

        if not self._fitted:
            raise RuntimeError(
                "Detector must be fitted before prediction"
            )

        return np.asarray(
            [
                result.anomaly_score
                for result in self.predict(features)
            ],
            dtype=float,
        )

    def feature_deviation(self, features):
        """
        Return robust feature deviations for each sample.

        Deviation is calculated as:

            |x - median| / MAD

        Larger values indicate stronger deviation from
        the learned normal baseline.
        """

        if not self._fitted:
            raise RuntimeError(
                "Detector must be fitted before prediction"
            )

        data = self._validate_features(features)

        transformed = self._transform_features(data)

        scaled = self.scaler.transform(
            transformed
        )

        deviations = np.abs(
            scaled - self._baseline_median
        ) / self._baseline_mad

        return deviations

    def strongest_feature_deviations(
        self,
        features,
        feature_names=None,
        top_k: int = 5,
    ):
        """
        Return the strongest feature deviations for each sample.

        This is intended for Sentinel's explainable evidence layer.

        Example output:

            [
                {
                    "feature": "packet_count",
                    "deviation": 12.4
                },
                ...
            ]
        """

        if top_k <= 0:
            raise ValueError(
                "top_k must be greater than zero"
            )

        deviations = self.feature_deviation(
            features
        )

        feature_count = deviations.shape[1]

        if feature_names is None:
            feature_names = [
                f"feature_{index}"
                for index in range(feature_count)
            ]

        if len(feature_names) != feature_count:
            raise ValueError(
                "feature_names length must match feature count"
            )

        results = []

        for sample_deviations in deviations:
            ranked_indices = np.argsort(
                sample_deviations
            )[::-1]

            sample_results = []

            for index in ranked_indices[:top_k]:
                sample_results.append(
                    {
                        "feature": feature_names[index],
                        "deviation": round(
                            float(
                                sample_deviations[index]
                            ),
                            4,
                        ),
                    }
                )

            results.append(
                sample_results
            )

        return results

    @staticmethod
    def _validate_features(features):
        data = np.asarray(
            features,
            dtype=float,
        )

        if data.ndim == 1:
            data = data.reshape(
                1,
                -1,
            )

        if data.ndim != 2:
            raise ValueError(
                "features must be a 2D array"
            )

        if data.shape[0] == 0:
            raise ValueError(
                "features cannot be empty"
            )

        if data.shape[1] == 0:
            raise ValueError(
                "features must contain at least one column"
            )

        if not np.isfinite(data).all():
            raise ValueError(
                "features must contain only finite values"
            )

        return data

    @staticmethod
    def _transform_features(data):
        """
        Apply log1p to non-negative traffic magnitude features.

        Sentinel's standard 11-feature vector contains:

        0  packet_count
        1  byte_count
        2  packets_per_second
        3  bytes_per_second
        4  syn_count
        5  syns_per_second
        6  syn_ratio
        7  unique_src_ips
        8  unique_dst_ips
        9  unique_dst_ports
        10 source_ip_entropy

        Standalone detector tests may use fewer features.
        Only columns that actually exist are transformed.
        """

        transformed = data.copy()

        log_columns = [
            0,
            1,
            2,
            3,
            4,
            5,
            7,
            8,
            9,
        ]

        available_columns = [
            column
            for column in log_columns
            if column < transformed.shape[1]
        ]

        for column in available_columns:
            transformed[:, column] = np.log1p(
                np.maximum(
                    transformed[:, column],
                    0.0,
                )
            )

        return transformed

    def _normalize_isolation_scores(
        self,
        decision_scores,
    ):
        """
        Convert Isolation Forest decision scores into
        anomaly scores where:

            0.0 = least anomalous
            1.0 = most anomalous
        """

        scores = np.asarray(
            decision_scores,
            dtype=float,
        )

        if self._score_max == self._score_min:
            return np.zeros_like(scores)

        normalized = (
            self._score_max - scores
        ) / (
            self._score_max - self._score_min
        )

        return np.clip(
            normalized,
            0.0,
            1.0,
        )

    def _statistical_anomaly_scores(
        self,
        scaled_features,
    ):
        """
        Calculate a robust statistical anomaly score
        using median absolute deviation.

        Individual feature deviations are capped at the
        configured MAD threshold before being averaged.
        """

        deviations = np.abs(
            scaled_features
            - self._baseline_median
        ) / self._baseline_mad

        capped = np.minimum(
            deviations / self.mad_threshold,
            1.0,
        )

        return np.mean(
            capped,
            axis=1,
        )

    def is_fitted(self) -> bool:
        return self._fitted