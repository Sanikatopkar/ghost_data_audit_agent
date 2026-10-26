"""Load challenge inputs and produce the exact output.csv contract."""
from __future__ import annotations

from pathlib import Path
from typing import Any
import pandas as pd
import re

from .audit_classifier import AuditClassifier
from .evidence_reader import EvidenceReader
from .identifier_resolver import IdentifierResolver
from .models import AuditResult, EvidenceObservation
from .normalization import at_or_before, clean, norm, parse_time
from .policy_engine import PolicyEngine
from .remediation_planner import RemediationPlanner
from .resurrection_detector import ResurrectionDetector

OUTPUT_COLUMNS = ["case_id", "deletion_status", "steps_json"]


class AuditEngine:
    def __init__(self, dataset_dir: str | Path = "dataset"):
        self.dataset_dir = Path(dataset_dir).resolve()
        self.requests = self._read("deletion_requests.csv")
        self.identities = self._read("user_identities.csv")
        self.audit_log = self._read("user_audit_log.csv")
        self.activity = self._read("system_activity.csv")
        self.rules = self._read("deletion_rules.csv")
        self.manifest = self._read("evidence_files.csv")
        self.sample_requests = self._read("sample_deletion_requests.csv", required=False)
        self.sample_output = self._read("sample_output.csv", required=False)
        self.reader = EvidenceReader(self.dataset_dir)
        self.observations = self.reader.read_all(self.manifest)
        self._search_text = {id(item): norm(item.searchable_text()) for item in self.observations}
        self.resolver = IdentifierResolver()
        self.classifier = AuditClassifier()
        self.policy = PolicyEngine(self.rules)
        self.resurrection = ResurrectionDetector()
        self.planner = RemediationPlanner()

    def _read(self, filename: str, required: bool = True) -> pd.DataFrame:
        path = self.dataset_dir / filename
        if not path.exists():
            if required:
                raise FileNotFoundError(f"Required challenge input is missing: {path}")
            return pd.DataFrame()
        return pd.read_csv(path, dtype=str, keep_default_na=False, encoding="utf-8-sig")

    def audit_case(self, case: dict[str, Any]) -> AuditResult:
        case_id = clean(case.get("case_id"))
        if not self.classifier.authorizes_deletion(clean(case.get("request_text"))):
            return AuditResult(case_id, "NOT_APPLICABLE", [])

        graph = self.resolver.resolve(
            clean(case.get("email")), clean(case.get("audit_at")),
            self.identities, self.audit_log, self.activity,
        )
        resources = self.resurrection.link_case_resources(case, graph, self.activity)
        eligible = [o for o in self.observations if at_or_before(o.captured_at, case.get("audit_at")) and (not o.observed_at or at_or_before(o.observed_at, case.get("audit_at")))]
        identity_pattern = self._identity_pattern(graph)
        direct = [o for o in eligible if o.resource_id in graph.resource_ids or (identity_pattern is not None and identity_pattern.search(self._search_text.get(id(o), "")) is not None)]
        resources.update(o.resource_id for o in direct)
        resources.update(graph.resource_ids)

        synthetic = self._absence_observations(resources, case.get("audit_at"))
        candidate_observations = eligible + synthetic
        assessments = self.policy.assess(candidate_observations, graph, clean(case.get("audit_at")), resources)
        account_absent = any(a.data_category == "USER_PROFILE" and a.state == "ABSENT" for a in assessments)
        has_violations = any(not a.compliant for a in assessments)
        status = self.classifier.status(has_violations, account_absent, graph.ambiguous or graph.user_id is None)
        steps = self.planner.generate(assessments, status)
        diagnostics = []
        if graph.user_id is None:
            diagnostics.append("No unique user_id was resolved from participant identity history.")
        if not account_absent:
            diagnostics.append("No account-profile absence evidence was found by audit_at.")
        if graph.ambiguous:
            diagnostics.append("Multiple user_id values matched the request email.")
        return AuditResult(case_id, status, steps, diagnostics)

    @staticmethod
    def _identity_pattern(graph):
        needles = sorted({norm(value) for value in graph.identifiers - graph.names if len(norm(value)) > 2}, key=len, reverse=True)
        if not needles:
            return None
        pattern = r"(?<![\w])(?:" + "|".join(re.escape(value) for value in needles) + r")(?![\w])"
        return re.compile(pattern, flags=re.UNICODE)

    def _absence_observations(self, resources: set[str], audit_at: str) -> list[EvidenceObservation]:
        latest: dict[tuple[str, str, str], Any] = {}
        for coverage in self.reader.coverage:
            if not at_or_before(coverage.captured_at, audit_at):
                continue
            key = (coverage.system_id, coverage.data_category, coverage.store_id)
            previous = latest.get(key)
            from .normalization import parse_time
            moment = parse_time(coverage.captured_at)
            old = parse_time(previous.captured_at) if previous else None
            if previous is None or (moment and old and moment >= old):
                latest[key] = coverage
        resource_categories: dict[str, set[str]] = {}
        for item in self.observations:
            resource_categories.setdefault(item.resource_id, set()).add(item.data_category)
        default_category = {
            "account": "USER_PROFILE", "search": "SEARCH_INDEX_ENTRY", "analytics": "ANALYTICS_PROFILE",
            "data": "DATA_FLOW", "backup": "BACKUP_ARCHIVE", "audit": "SECURITY_AUDIT_LOG",
            "tombstone": "ACCOUNT_TOMBSTONE", "export": "USER_EXPORT", "marketing": "MARKETING_PROFILE",
            "cache": "CACHE_ENTRY", "object": "SUPPORT_ATTACHMENT", "email": "EMAIL_DELIVERY_LOG",
        }
        result: list[EvidenceObservation] = []
        for coverage in latest.values():
            for resource in sorted(resources - coverage.resource_ids):
                allowed_categories = resource_categories.get(resource)
                if not allowed_categories:
                    prefix = resource.split("_", 1)[0].casefold()
                    allowed_categories = {default_category.get(prefix, "UNKNOWN")}
                if coverage.data_category not in allowed_categories:
                    continue
                result.append(EvidenceObservation(
                    file_id=coverage.file_id,
                    captured_at=coverage.captured_at,
                    observed_at=coverage.captured_at,
                    system_id=coverage.system_id,
                    resource_id=resource,
                    data_category=coverage.data_category,
                    state="ABSENT",
                    fields={"_storage_location": coverage.store_id, "_snapshot_absence": True},
                    raw_text=f"Complete {coverage.store_id} snapshot at {coverage.captured_at} does not contain {resource}.",
                ))
        return result

    def audit_all(self) -> list[AuditResult]:
        if len(self.requests) != 518:
            raise ValueError(f"Expected 518 deletion requests, found {len(self.requests)}.")
        results = [self.audit_case(row.to_dict()) for _, row in self.requests.iterrows()]
        results.sort(key=lambda item: item.case_id)
        return results

    def export_csv(self, results: list[AuditResult], output_path: str | Path = "output.csv") -> pd.DataFrame:
        rows = [result.to_csv_row() for result in results]
        out = pd.DataFrame(rows, columns=OUTPUT_COLUMNS)
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        out.to_csv(path, index=False, encoding="utf-8", lineterminator="\n")
        return out

    def validate_output(self, path: str | Path, results: list[AuditResult] | None = None) -> list[str]:
        import csv, json
        target = Path(path)
        errors: list[str] = []
        with target.open("r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            if reader.fieldnames != OUTPUT_COLUMNS:
                errors.append(f"Unexpected output header: {reader.fieldnames}")
            rows = list(reader)
        expected = self.requests.case_id.tolist()
        actual = [row.get("case_id", "") for row in rows]
        if actual != sorted(expected):
            errors.append("Output case IDs are missing, duplicated, or not sorted as required.")
        if len(rows) != 518:
            errors.append(f"Expected 518 output rows, found {len(rows)}.")
        allowed = {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"}
        for row in rows:
            if row.get("deletion_status") not in allowed:
                errors.append(f"Invalid status for {row.get('case_id')}: {row.get('deletion_status')}")
            try:
                steps = json.loads(row.get("steps_json", ""))
            except json.JSONDecodeError:
                errors.append(f"Invalid steps_json for {row.get('case_id')}")
                continue
            if not isinstance(steps, list):
                errors.append(f"steps_json is not an array for {row.get('case_id')}")
                continue
            if [step.get("step_no") for step in steps] != list(range(1, len(steps) + 1)):
                errors.append(f"Non-consecutive step numbers for {row.get('case_id')}")
            if row.get("deletion_status") == "NOT_APPLICABLE" and steps:
                errors.append(f"NOT_APPLICABLE case has steps: {row.get('case_id')}")
            if row.get("deletion_status") == "COMPLETE" and any(step.get("phase") != "VERIFICATION" for step in steps):
                errors.append(f"COMPLETE case has non-verification steps: {row.get('case_id')}")
            if row.get("deletion_status") == "INCOMPLETE":
                phase_order = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}
                phases = [phase_order.get(step.get("phase"), 99) for step in steps]
                if phases != sorted(phases):
                    errors.append(f"Unordered phases for {row.get('case_id')}")
        return errors

