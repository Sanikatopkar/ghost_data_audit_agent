"""Policy evaluation from the challenge's supplied treatment rules."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

import pandas as pd

from .models import EvidenceObservation, IdentityGraph
from .normalization import at_or_before, contains_exact, clean, norm, parse_time

DIRECT_FIELDS = {
    "name", "full_name", "first_name", "last_name", "given_name", "family_name",
    "email", "email_address", "requester_email", "customer_email", "phone", "phone_number",
    "requester_phone", "email_hash", "email_sha256", "hashed_email", "address", "street_address",
}

CATEGORY_ACTION_FALLBACK = {
    "USER_PROFILE": "DELETE", "SECONDARY_IDENTIFIER": "DELETE", "SEARCH_INDEX_ENTRY": "DELETE",
    "CACHE_ENTRY": "DELETE", "SUPPORT_ATTACHMENT": "DELETE", "SUPPORT_MESSAGE": "REDACT",
    "ANALYTICS_PROFILE": "ANONYMIZE", "PRODUCT_TELEMETRY": "ANONYMIZE", "USER_EXPORT": "DELETE",
    "MARKETING_PROFILE": "DELETE", "EMAIL_DELIVERY_LOG": "REDACT", "SECURITY_AUDIT_LOG": "RETAIN",
    "LEGAL_HOLD_RECORD": "RETAIN", "BACKUP_ARCHIVE": "RETAIN", "ACCOUNT_TOMBSTONE": "REDACT",
}


@dataclass
class ResourceAssessment:
    system_id: str
    resource_id: str
    data_category: str
    required_action: str
    state: str
    compliant: bool
    evidence_id: str
    evidence: EvidenceObservation | None = None
    reason: str = ""
    violation_operation: str = ""
    remediation_operation: str = ""
    remediation_state: str = ""
    verification_operation: str = ""
    verification_state: str = ""
    current_copy_states: list[str] = field(default_factory=list)


class PolicyEngine:
    def __init__(self, rules: pd.DataFrame):
        self.rule_actions: dict[str, str] = {}
        for _, row in rules.iterrows():
            category = clean(row.get("data_category")).upper()
            action = clean(row.get("required_action")).upper()
            if category and action:
                self.rule_actions[category] = action

    def assess(
        self,
        observations: Iterable[EvidenceObservation],
        graph: IdentityGraph,
        audit_at: str,
        extra_resource_ids: set[str] | None = None,
    ) -> list[ResourceAssessment]:
        ids = set(graph.identifiers)
        resources = set(graph.resource_ids) | (extra_resource_ids or set())
        matched: list[EvidenceObservation] = []
        for observation in observations:
            if not at_or_before(observation.captured_at, audit_at):
                continue
            if observation.observed_at and not at_or_before(observation.observed_at, audit_at):
                continue
            if observation.resource_id in resources:
                matched.append(observation)

        grouped: dict[tuple[str, str], list[EvidenceObservation]] = {}
        for item in matched:
            grouped.setdefault((item.system_id, item.resource_id), []).append(item)

        results: list[ResourceAssessment] = []
        for (system, resource), items in grouped.items():
            latest_by_store: dict[str, EvidenceObservation] = {}
            for item in items:
                store = clean(item.fields.get("_storage_location")) or item.data_category
                previous = latest_by_store.get(store)
                rank = parse_time(item.observed_at) or parse_time(item.captured_at)
                old_rank = (parse_time(previous.observed_at) or parse_time(previous.captured_at)) if previous else None
                if previous is None or (rank and old_rank and rank >= old_rank) or (rank and not old_rank):
                    latest_by_store[store] = item
            current = list(latest_by_store.values())
            chosen = max(current, key=lambda x: parse_time(x.observed_at) or parse_time(x.captured_at) or parse_time("1970-01-01T00:00:00Z"))
            category = chosen.data_category
            action = self.rule_actions.get(category, CATEGORY_ACTION_FALLBACK.get(category, "REVIEW"))
            state = self._combined_state(current, category)
            prohibited = self._prohibited_fields(current, category, graph)
            compliant, reason, violation, remediation, rem_state, verification, ver_state = self._decision(category, action, state, prohibited, current)
            witness = self._witness(current, category, action, compliant, prohibited)
            results.append(ResourceAssessment(
                system_id=system,
                resource_id=resource,
                data_category=category,
                required_action=action,
                state=state,
                compliant=compliant,
                evidence_id=witness.file_id if witness else "",
                evidence=witness,
                reason=reason,
                violation_operation=violation,
                remediation_operation=remediation,
                remediation_state=rem_state,
                verification_operation=verification,
                verification_state=ver_state,
                current_copy_states=[o.state for o in current],
            ))
        results.sort(key=lambda x: (x.system_id, x.resource_id))
        return results

    @staticmethod
    def _combined_state(items: list[EvidenceObservation], category: str) -> str:
        states = {item.state for item in items}
        if category == "DATA_FLOW":
            return "ACTIVE" if "ACTIVE" in states else "DISABLED" if "DISABLED" in states else (next(iter(states)) if states else "UNKNOWN")
        if category == "BACKUP_ARCHIVE":
            return "ACTIVE" if "ACTIVE" in states else "BLOCKED" if "BLOCKED" in states else (next(iter(states)) if states else "UNKNOWN")
        if "PRESENT" in states:
            return "PRESENT"
        for state in ("REDACTED", "ANONYMIZED", "ABSENT", "BLOCKED", "DISABLED"):
            if state in states:
                return state
        return next(iter(states), "UNKNOWN")

    @staticmethod
    def _prohibited_fields(items: list[EvidenceObservation], category: str, graph: IdentityGraph) -> list[str]:
        fields: set[str] = set()
        for item in items:
            for path, value in item.fields.items():
                key = path.split(".")[-1].split("[")[0].casefold()
                if value is None or not clean(value):
                    continue
                if key in DIRECT_FIELDS:
                    fields.add(key)
                elif category in {"ANALYTICS_PROFILE", "PRODUCT_TELEMETRY"} and key in {"user_id", "customer_reference", "subject_reference"}:
                    if clean(value) in graph.identifiers:
                        fields.add(key)
                elif category == "ACCOUNT_TOMBSTONE" and key in {"user_id", "subject_reference", "customer_reference"}:
                    continue
        return sorted(fields)

    @staticmethod
    def _decision(category: str, action: str, state: str, prohibited: list[str], items: list[EvidenceObservation]) -> tuple[bool, str, str, str, str, str, str]:
        if category == "DATA_FLOW":
            if state == "ACTIVE":
                return False, "An active data flow is linked to the subject.", "REPORT_ACTIVE_DATA_FLOW", "DISABLE_DATA_FLOW", "DISABLED", "VERIFY_DATA_FLOW_DISABLED", "DISABLED"
            return True, "No active data flow is evidenced.", "", "", "", "VERIFY_DATA_FLOW_DISABLED", "DISABLED"
        if category == "BACKUP_ARCHIVE":
            if state == "ACTIVE":
                return False, "A retained backup can still be restored.", "REPORT_RESTORE_RISK", "BLOCK_RESTORE", "BLOCKED", "VERIFY_RESTORE_BLOCKED", "BLOCKED"
            return True, "The retained backup is not restorable.", "", "", "", "VERIFY_RESTORE_BLOCKED", "BLOCKED"
        if action == "DELETE":
            if state == "ABSENT":
                return True, "The policy requires removal and the evidence shows the record absent.", "", "", "", "VERIFY_RECORD_ABSENT", "ABSENT"
            return False, "The policy requires deletion, but the record is present or lacks absence evidence.", "REPORT_REMAINING_RECORD", "DELETE_RECORD", "ABSENT", "VERIFY_RECORD_ABSENT", "ABSENT"
        if action == "REDACT":
            if prohibited:
                return False, "The retained record still exposes prohibited identifying fields: " + ", ".join(prohibited), "REPORT_EXPOSED_PII", "REDACT_RECORD", "REDACTED", "VERIFY_RECORD_REDACTED", "REDACTED"
            return True, "Required identifying fields are not exposed.", "", "", "", "VERIFY_RECORD_REDACTED", "REDACTED"
        if action == "ANONYMIZE":
            if prohibited or state == "PRESENT" and any(clean(v) for i in items for k, v in i.fields.items() if k.split(".")[-1] in {"user_id", "customer_reference", "subject_reference"}):
                return False, "The record remains attributable or exposes prohibited identifiers.", "REPORT_EXPOSED_PII", "ANONYMIZE_RECORD", "ANONYMIZED", "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED"
            return True, "The record is not attributable to the subject.", "", "", "", "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED"
        if action == "RETAIN":
            if state in {"PRESENT", "REDACTED", "ANONYMIZED", "BLOCKED"}:
                return True, "The policy-required retained record is present.", "", "", "", "VERIFY_RECORD_PRESENT", "PRESENT"
            return False, "A policy-required retained record is not evidenced.", "REPORT_REMAINING_RECORD", "", "", "VERIFY_RECORD_PRESENT", "PRESENT"
        return False, "No supplied rule resolves this record category.", "REPORT_EXPOSED_PII", "REDACT_RECORD", "REDACTED", "VERIFY_RECORD_REDACTED", "REDACTED"

    @staticmethod
    def _witness(items: list[EvidenceObservation], category: str, action: str, compliant: bool, prohibited: list[str]) -> EvidenceObservation | None:
        candidates = items
        if not compliant:
            candidates = [item for item in items if item.state not in {"ABSENT", "REDACTED", "ANONYMIZED", "DISABLED", "BLOCKED"}] or items
        return max(candidates, key=lambda item: parse_time(item.observed_at) or parse_time(item.captured_at) or parse_time("1970-01-01T00:00:00Z")) if candidates else None
