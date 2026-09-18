from backend.scoring.risk_policy import RiskPolicy
from backend.scoring.threat_score import ThreatScoreEngine


engine = ThreatScoreEngine()

policy = RiskPolicy()


critical = engine.calculate(
    detector_score=1.0,
    ml_score=1.0,
    correlation_score=1.0,
    progression_score=1.0,
)

print(
    "CRITICAL SCORE:",
    critical.unified_score,
)

print(
    "CRITICAL LEVEL:",
    critical.risk_level,
)


detector_only = engine.calculate(
    detector_score=1.0,
    ml_score=0.0,
    correlation_score=0.0,
    progression_score=0.0,
)

print(
    "DETECTOR-ONLY SCORE:",
    detector_only.unified_score,
)

print(
    "DETECTOR-ONLY LEVEL:",
    detector_only.risk_level,
)


combined = engine.calculate(
    detector_score=0.90,
    ml_score=0.85,
    correlation_score=0.80,
    progression_score=1.0,
)

print(
    "COMBINED SCORE:",
    combined.unified_score,
)

print(
    "COMBINED LEVEL:",
    combined.risk_level,
)


low = engine.calculate(
    detector_score=0.20,
    ml_score=0.10,
    correlation_score=0.0,
    progression_score=0.0,
)

print(
    "LOW SCORE:",
    low.unified_score,
)

print(
    "LOW LEVEL:",
    low.risk_level,
)


decision = policy.evaluate(
    combined
)

print(
    "ALERT REQUIRED:",
    decision.requires_alert,
)

print(
    "ANALYST PRIORITY:",
    decision.analyst_priority,
)

print(
    "RATIONALE:",
    decision.rationale,
)


assert critical.unified_score == 1.0
assert critical.risk_level == "CRITICAL"

assert detector_only.unified_score == 0.50
assert detector_only.risk_level == "MEDIUM"

assert combined.unified_score > 0.85
assert combined.risk_level == "CRITICAL"

assert low.unified_score < 0.50
assert low.risk_level == "LOW"

assert decision.requires_alert is True
assert decision.analyst_priority == 1

assert 0.0 <= critical.unified_score <= 1.0
assert 0.0 <= combined.unified_score <= 1.0
assert 0.0 <= low.unified_score <= 1.0


try:
    engine.calculate(
        detector_score=1.5,
        ml_score=0.0,
        correlation_score=0.0,
        progression_score=0.0,
    )

    raise AssertionError(
        "Invalid score was accepted"
    )

except ValueError:
    pass


print(
    "THREAT SCORE TEST: PASSED"
)