from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal
from pydantic import BaseModel, Field, field_validator

Severity = Literal["info", "low", "medium", "high", "critical"]


class EventIn(BaseModel):
    external_id: str | None = Field(default=None, max_length=128)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source: str = Field(default="socforge-simulator", min_length=1, max_length=80)
    event_type: str = Field(min_length=1, max_length=80)
    severity: Severity = "info"
    host: str | None = Field(default=None, max_length=255)
    src_ip: str | None = Field(default=None, max_length=64)
    dst_ip: str | None = Field(default=None, max_length=64)
    username: str | None = Field(default=None, max_length=128)
    process: str | None = Field(default=None, max_length=255)
    message: str = Field(default="", max_length=2000)
    cvss: float | None = Field(default=None, ge=0, le=10)
    attributes: dict[str, Any] = Field(default_factory=dict)

    @field_validator("timestamp")
    @classmethod
    def timestamp_must_be_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value


class EventEnvelope(BaseModel):
    event: EventIn


class AlertAction(BaseModel):
    actor: str = Field(default="soc-analyst", min_length=1, max_length=100)
    note: str = Field(default="", max_length=2000)


class IncidentCreate(BaseModel):
    title: str = Field(min_length=3, max_length=200)
    severity: Severity = "medium"
    description: str = Field(default="", max_length=4000)
    owner: str = Field(default="unassigned", max_length=100)
    alert_ids: list[int] = Field(default_factory=list)
    actor: str = Field(default="soc-analyst", max_length=100)


class IncidentStatusUpdate(BaseModel):
    status: Literal["open", "investigating", "contained", "resolved", "closed"]
    note: str = Field(default="", max_length=2000)
    actor: str = Field(default="soc-analyst", max_length=100)


class VulnerabilityIn(BaseModel):
    asset: str = Field(min_length=1, max_length=255)
    cve: str | None = Field(default=None, max_length=40)
    title: str = Field(min_length=3, max_length=255)
    cvss: float = Field(ge=0, le=10)
    package: str | None = Field(default=None, max_length=255)
    status: Literal["open", "in_progress", "remediated", "accepted"] = "open"
    remediation: str = Field(default="", max_length=2000)
    actor: str = Field(default="vulnerability-analyst", max_length=100)


class VulnerabilityStatusUpdate(BaseModel):
    status: Literal["open", "in_progress", "remediated", "accepted"]
    note: str = Field(default="", max_length=2000)
    actor: str = Field(default="vulnerability-analyst", max_length=100)
