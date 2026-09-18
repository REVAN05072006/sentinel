from dataclasses import dataclass


@dataclass(frozen=True)
class AttackStage:
    threat_class: str
    stage: int
    description: str


ATTACK_STAGES = {
    "RECONNAISSANCE": AttackStage(
        threat_class="RECONNAISSANCE",
        stage=1,
        description="Host or network discovery",
    ),
    "PORT_SCANNING": AttackStage(
        threat_class="PORT_SCANNING",
        stage=1,
        description="Service and port enumeration",
    ),
    "DGA_DOMAIN": AttackStage(
        threat_class="DGA_DOMAIN",
        stage=2,
        description="Suspicious algorithmically generated domain activity",
    ),
    "DNS_TUNNELLING": AttackStage(
        threat_class="DNS_TUNNELLING",
        stage=2,
        description="Potential covert DNS communication",
    ),
    "C2_BEACONING": AttackStage(
        threat_class="C2_BEACONING",
        stage=3,
        description="Periodic command-and-control communication",
    ),
    "ENCRYPTED_MALWARE": AttackStage(
        threat_class="ENCRYPTED_MALWARE",
        stage=4,
        description="Suspicious encrypted communication behavior",
    ),
    "DATA_EXFILTRATION": AttackStage(
        threat_class="DATA_EXFILTRATION",
        stage=5,
        description="Potential outbound data transfer",
    ),
}


class AttackStageModel:
    """
    Provides deterministic attack-stage relationships for
    threat classes observed by Sentinel.

    This component is analytical and read-only.
    """

    @staticmethod
    def get_stage(threat_class: str) -> AttackStage | None:
        return ATTACK_STAGES.get(threat_class)

    @staticmethod
    def is_progression(
        previous_threat: str,
        current_threat: str,
    ) -> bool:
        previous = ATTACK_STAGES.get(previous_threat)
        current = ATTACK_STAGES.get(current_threat)

        if previous is None or current is None:
            return False

        return current.stage > previous.stage

    @staticmethod
    def progression_score(
        previous_threat: str,
        current_threat: str,
    ) -> float:
        previous = ATTACK_STAGES.get(previous_threat)
        current = ATTACK_STAGES.get(current_threat)

        if previous is None or current is None:
            return 0.0

        difference = current.stage - previous.stage

        if difference <= 0:
            return 0.0

        if difference == 1:
            return 1.0

        if difference == 2:
            return 0.75

        return 0.5
