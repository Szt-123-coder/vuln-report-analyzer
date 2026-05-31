from enum import Enum
from typing import Any, List

from pydantic import BaseModel, ConfigDict, Field, field_validator


EVIDENCE_NOT_IDENTIFIED = "Evidence not identified"


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
    summary_evidence: str = Field(default=EVIDENCE_NOT_IDENTIFIED)
    severity_evidence: str = Field(default=EVIDENCE_NOT_IDENTIFIED)
    impact_evidence: str = Field(default=EVIDENCE_NOT_IDENTIFIED)
    remediation_evidence: str = Field(default=EVIDENCE_NOT_IDENTIFIED)
    affected_component_evidence: str = Field(default=EVIDENCE_NOT_IDENTIFIED)
    confidence: float = Field(..., ge=0.0, le=1.0)
    confidence_score: float = Field(default=0.0, ge=0.0, le=1.0)
    review_required: bool = False
    review_reason: str = Field(default="No review required.")

    @field_validator("remediation", mode="before")
    @classmethod
    def normalize_remediation(cls, value: Any) -> Any:
        if isinstance(value, list):
            return "\n".join(str(item).strip() for item in value if str(item).strip())
        return value

    @field_validator(
        "summary_evidence",
        "severity_evidence",
        "impact_evidence",
        "remediation_evidence",
        "affected_component_evidence",
        mode="before",
    )
    @classmethod
    def normalize_field_evidence(cls, value: Any) -> str:
        if value is None:
            return EVIDENCE_NOT_IDENTIFIED
        if isinstance(value, list):
            value = " ".join(str(item).strip() for item in value if str(item).strip())
        cleaned = str(value).strip()
        return cleaned or EVIDENCE_NOT_IDENTIFIED

    @field_validator(
        "title",
        "summary",
        "vulnerability_type",
        "affected_component",
        "impact",
        "remediation",
        "review_reason",
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
