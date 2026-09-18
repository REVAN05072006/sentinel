from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class ThreatAlert(BaseModel):
    timestamp: datetime

    flow_id: tuple | None = None

    threat_class: str
    confidence: float = Field(ge=0.0, le=1.0)
    severity: str

    source_ip: str | None = None
    destination_ip: str | None = None
    source_port: int | None = None
    destination_port: int | None = None
    protocol: str | None = None

    evidence: dict[str, Any] = Field(default_factory=dict)