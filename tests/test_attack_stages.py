from backend.correlation.stages import AttackStageModel


tests = [
    ("RECONNAISSANCE", "PORT_SCANNING", False),
    ("DGA_DOMAIN", "C2_BEACONING", True),
    ("C2_BEACONING", "ENCRYPTED_MALWARE", True),
    ("ENCRYPTED_MALWARE", "DATA_EXFILTRATION", True),
    ("DATA_EXFILTRATION", "DGA_DOMAIN", False),
]


passed = True

for previous, current, expected in tests:
    result = AttackStageModel.is_progression(
        previous,
        current,
    )

    score = AttackStageModel.progression_score(
        previous,
        current,
    )

    print(
        previous,
        "->",
        current,
        "| PROGRESSION:",
        result,
        "| SCORE:",
        score,
    )

    if result != expected:
        passed = False


if passed:
    print("ATTACK STAGE TEST: PASSED")
else:
    print("ATTACK STAGE TEST: FAILED")
