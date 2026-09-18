from dataclasses import dataclass

from backend.features.window import WindowFeatures
from backend.models.ml_pipeline import TrafficMLPipeline


@dataclass
class BaselineStatus:
    fitted: bool
    sample_count: int
    minimum_samples: int


class TrafficBaselineManager:
    """
    Manages the normal-traffic baseline used by Sentinel's
    unsupervised ML anomaly detector.

    The baseline is trained only from passively observed
    traffic features that are designated as normal.

    This component is analytical and read-only.
    """

    def __init__(
        self,
        minimum_samples: int = 20,
        contamination: float = 0.05,
        random_state: int = 42,
    ):
        if minimum_samples <= 0:
            raise ValueError(
                "minimum_samples must be greater than zero"
            )

        self.minimum_samples = minimum_samples

        self.ml_pipeline = TrafficMLPipeline(
            contamination=contamination,
            random_state=random_state,
        )

        self._windows: list[WindowFeatures] = []
        self._fitted = False

    def add_window(
        self,
        window: WindowFeatures,
    ) -> None:
        """
        Add one normal traffic window to the baseline dataset.
        """

        if self._fitted:
            raise RuntimeError(
                "Cannot add baseline samples after fitting"
            )

        self._windows.append(window)

    def add_windows(
        self,
        windows: list[WindowFeatures],
    ) -> None:
        """
        Add multiple normal traffic windows to the baseline dataset.
        """

        if self._fitted:
            raise RuntimeError(
                "Cannot add baseline samples after fitting"
            )

        if not windows:
            return

        self._windows.extend(windows)

    def fit(self) -> None:
        """
        Train the ML pipeline using the collected normal
        traffic baseline.
        """

        if len(self._windows) < self.minimum_samples:
            raise RuntimeError(
                f"Insufficient baseline samples: "
                f"{len(self._windows)} available, "
                f"{self.minimum_samples} required"
            )

        self.ml_pipeline.fit(
            self._windows
        )

        self._fitted = True

    def predict(
        self,
        window: WindowFeatures,
    ):
        """
        Score one traffic window against the learned baseline.
        """

        if not self._fitted:
            raise RuntimeError(
                "Baseline must be fitted before prediction"
            )

        return self.ml_pipeline.predict(
            window
        )

    def predict_windows(
        self,
        windows: list[WindowFeatures],
    ):
        """
        Score multiple traffic windows against the learned baseline.
        """

        if not self._fitted:
            raise RuntimeError(
                "Baseline must be fitted before prediction"
            )

        return self.ml_pipeline.predict_windows(
            windows
        )

    def status(self) -> BaselineStatus:
        """
        Return the current baseline state.
        """

        return BaselineStatus(
            fitted=self._fitted,
            sample_count=len(self._windows),
            minimum_samples=self.minimum_samples,
        )

    def sample_count(self) -> int:
        """
        Return the number of collected baseline samples.
        """

        return len(self._windows)

    def is_fitted(self) -> bool:
        """
        Return whether the baseline has been successfully trained.
        """

        return self._fitted

    def reset(self) -> None:
        """
        Clear the current baseline and return to the
        untrained state.
        """

        self._windows.clear()

        self.ml_pipeline = TrafficMLPipeline(
            contamination=self.ml_pipeline.detector.contamination,
            random_state=42,
        )

        self._fitted = False