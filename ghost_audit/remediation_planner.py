"""Build ordered challenge-contract steps without mutating external systems."""
from __future__ import annotations
from .models import AuditStep
from .policy_engine import ResourceAssessment

PHASE_ORDER = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}
OPERATION_ORDER = {
    "REPORT_REMAINING_RECORD": 0, "REPORT_EXPOSED_PII": 1, "REPORT_ACTIVE_DATA_FLOW": 2, "REPORT_RESTORE_RISK": 3,
    "DISABLE_DATA_FLOW": 0, "BLOCK_RESTORE": 1, "DELETE_RECORD": 2, "REDACT_RECORD": 3, "ANONYMIZE_RECORD": 4,
    "VERIFY_RECORD_ABSENT": 0, "VERIFY_RECORD_PRESENT": 1, "VERIFY_RECORD_REDACTED": 2,
    "VERIFY_RECORD_ANONYMIZED": 3, "VERIFY_DATA_FLOW_DISABLED": 4, "VERIFY_RESTORE_BLOCKED": 5,
}


class RemediationPlanner:
    def generate(self, assessments: list[ResourceAssessment], deletion_status: str) -> list[AuditStep]:
        if deletion_status == "NOT_APPLICABLE":
            return []
        raw: list[tuple[str, str, str, str, str, str, str]] = []
        incomplete = deletion_status == "INCOMPLETE"
        for item in assessments:
            if incomplete and not item.compliant and item.violation_operation:
                raw.append(("FINDING", item.system_id, item.resource_id, item.violation_operation,
                            "ACTIVE" if item.violation_operation in {"REPORT_ACTIVE_DATA_FLOW", "REPORT_RESTORE_RISK"} else "PRESENT",
                            item.evidence_id, item.required_action))
            if incomplete and not item.compliant and item.remediation_operation:
                raw.append(("REMEDIATION", item.system_id, item.resource_id, item.remediation_operation,
                            item.remediation_state, "", item.required_action))
            if item.verification_operation:
                evidence_id = item.evidence_id if not incomplete and item.compliant else ""
                # A COMPLETE result must be justified by a current observation. An
                # incomplete case's checks describe future work and cite no evidence.
                if not incomplete and not evidence_id:
                    continue
                raw.append(("VERIFICATION", item.system_id, item.resource_id, item.verification_operation,
                            item.verification_state, evidence_id, item.required_action))

        raw.sort(key=lambda row: (
            PHASE_ORDER[row[0]], OPERATION_ORDER.get(row[3], 99), row[1].casefold(), row[2].casefold()
        ))
        result: list[AuditStep] = []
        seen: set[tuple[str, str, str, str, str]] = set()
        for phase, system, resource, operation, state, evidence_id, _action in raw:
            key = (phase, system, resource, operation, state)
            if key in seen:
                continue
            seen.add(key)
            result.append(AuditStep(len(result) + 1, phase, system, resource, operation, state, evidence_id))
        return result
