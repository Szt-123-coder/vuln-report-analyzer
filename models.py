from enum import Enum
from typing import Any, List

from pydantic import BaseModel, ConfigDict, Field, field_validator


class Severity(str, Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class VulnerabilityAnalysis(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str = Field(..., min_length=3, max_length=200)
    summary: str = Field(..., min_length=10)
    vulnerability_type: str = Field(..., min_length=2, max_length=120)
    affected_component: str = Field(..., min_length=2, max_length=200)
    severity: Severity
    impact: str = Field(..., min_length=10)
    evidence: List[str] = Field(default_factory=list)
    remediation: str = Field(..., min_length=10)
    confidence: float = Field(..., ge=0.0, le=1.0)

    @field_validator("remediation", mode="before")
    @classmethod
    def normalize_remediation(cls, value: Any) -> Any:
        if isinstance(value, list):
            return "\n".join(str(item).strip() for item in value if str(item).strip())
        return value

    @field_validator(
        "title",
        "summary",
        "vulnerability_type",
        "affected_component",
        "impact",
        "remediation",
    )
    @classmethod
    def strip_required_text(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("field cannot be empty")
        return cleaned

    @field_validator("evidence", mode="before")
    @classmethod
    def normalize_evidence(cls, value: Any) -> Any:
        if value is None:
            return []
        if isinstance(value, str):
            return [value]
        return value

    @field_validator("evidence")
    @classmethod
    def strip_evidence(cls, value: List[str]) -> List[str]:
        return [item.strip() for item in value if item.strip()]
