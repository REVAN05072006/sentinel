import numpy as np

from backend.models.anomaly_detector import TrafficAnomalyDetector


normal_features = np.array([
    [10, 1000, 20, 5, 0.1],
    [11, 1100, 21, 5, 0.1],
    [9, 950, 19, 4, 0.2],
    [10, 1050, 20, 5, 0.1],
    [12, 1150, 22, 6, 0.1],
    [11, 1080, 21, 5, 0.2],
    [10, 1020, 20, 5, 0.1],
    [9, 980, 19, 4, 0.2],
    [11, 1070, 21, 5, 0.1],
    [10, 1010, 20, 5, 0.1],
    [12, 1120, 22, 6, 0.2],
    [9, 970, 19, 4, 0.1],
    [10, 1030, 20, 5, 0.1],
    [11, 1060, 21, 5, 0.2],
    [10, 1005, 20, 5, 0.1],
    [9, 990, 19, 4, 0.2],
    [11, 1090, 21, 5, 0.1],
    [10, 1040, 20, 5, 0.1],
    [12, 1110, 22, 6, 0.2],
    [10, 1025, 20, 5, 0.1],
])


anomalous_features = np.array([
    [1000, 1000000, 5000, 500, 50],
    [1500, 1500000, 8000, 800, 80],
])


detector = TrafficAnomalyDetector(
    contamination=0.05,
    random_state=42,
)


detector.fit(normal_features)

normal_results = detector.predict(normal_features)
anomalous_results = detector.predict(anomalous_features)


print(
    "NORMAL SAMPLES:",
    len(normal_results),
)

print(
    "ANOMALOUS SAMPLES:",
    len(anomalous_results),
)


print(
    "NORMAL ANOMALY SCORES:",
    [result.anomaly_score for result in normal_results],
)

print(
    "ANOMALOUS ANOMALY SCORES:",
    [result.anomaly_score for result in anomalous_results],
)


normal_anomaly_count = sum(
    result.is_anomaly
    for result in normal_results
)

anomalous_anomaly_count = sum(
    result.is_anomaly
    for result in anomalous_results
)


print(
    "NORMAL ANOMALIES DETECTED:",
    normal_anomaly_count,
)

print(
    "ANOMALOUS ANOMALIES DETECTED:",
    anomalous_anomaly_count,
)


normal_average_score = sum(
    result.anomaly_score
    for result in normal_results
) / len(normal_results)

anomalous_average_score = sum(
    result.anomaly_score
    for result in anomalous_results
) / len(anomalous_results)


print(
    "NORMAL AVERAGE SCORE:",
    round(normal_average_score, 4),
)

print(
    "ANOMALOUS AVERAGE SCORE:",
    round(anomalous_average_score, 4),
)


scores_are_valid = all(
    0.0 <= result.anomaly_score <= 1.0
    for result in normal_results + anomalous_results
)


anomaly_score_separation = (
    anomalous_average_score
    > normal_average_score
)


if (
    len(normal_results) == len(normal_features)
    and len(anomalous_results) == len(anomalous_features)
    and scores_are_valid
    and anomaly_score_separation
):
    print("ANOMALY DETECTOR TEST: PASSED")
else:
    print("ANOMALY DETECTOR TEST: FAILED")