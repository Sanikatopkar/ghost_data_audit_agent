"""Typed data structures used by the deletion audit pipeline."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class IdentityGraph:
    user_id: str | None
    identifiers: set[str] = field(default_factory=set)
    emails: set[str] = field(default_factory=set)
    phones: set[str] = field(default_factory=set)
    names: set[str] = field(default_factory=set)
    email_hashes: set[str] = field(default_factory=set)
    evidence_ids: set[str] = field(default_factory=set)
    resource_ids: set[str] = field(default_factory=set)
    ambiguous: bool = False

    def add(self, value: Any, kind: str = "other") -> None:
        if value is None:
            return
        text = str(value).strip()
        if not text or text.casefold() in {"nan", "none", "null", "n/a", "unknown"}:
            return
        self.identifiers.add(text)
        target = {
            "email": self.emails,
            "phone": self.phones,
            "name": self.names,
            "email_hash": self.email_hashes,
        }.get(kind)
        if target is not None:
            target.add(text)


@dataclass
class EvidenceObservation:
    file_id: str
    captured_at: str
    observed_at: str
    system_id: str
    resource_id: str
    data_category: str
    state: str
    fields: dict[str, Any] = field(default_factory=dict)
    raw_text: str = ""

    def searchable_text(self) -> str:
        import json
        return " ".join((self.raw_text, json.dumps(self.fields, ensure_ascii=False, default=str)))


@dataclass
class SnapshotCoverage:
    file_id: str
    captured_at: str
    system_id: str
    data_category: str
    resource_ids: set[str] = field(default_factory=set)
    store_id: str = ""


@dataclass(frozen=True)
class AuditStep:
    step_no: int
    phase: str
    system_id: str
    resource_id: str
    operation: str
    state: str
    evidence_id: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "step_no": self.step_no,
            "phase": self.phase,
            "system_id": self.system_id,
            "resource_id": self.resource_id,
            "operation": self.operation,
            "state": self.state,
            "evidence_id": self.evidence_id,
        }


@dataclass
class AuditResult:
    case_id: str
    deletion_status: str
    steps: list[AuditStep] = field(default_factory=list)
    diagnostics: list[str] = field(default_factory=list)

    def to_csv_row(self) -> dict[str, str]:
        import json
        return {
            "case_id": self.case_id,
            "deletion_status": self.deletion_status,
            "steps_json": json.dumps([s.as_dict() for s in self.steps], separators=(",", ":"), ensure_ascii=False),
        }



