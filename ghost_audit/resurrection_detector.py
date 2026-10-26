"""Connect request-scoped resources to participant-provided activity records."""
from __future__ import annotations
from datetime import timedelta
from typing import Any
import re
import pandas as pd
from .models import IdentityGraph, EvidenceObservation
from .normalization import clean, contains_exact, norm, parse_time


class ResurrectionDetector:
    PROCESS_CATEGORIES = {"DATA_FLOW", "BACKUP_ARCHIVE"}

    def link_case_resources(self, case: dict[str, Any], graph: IdentityGraph, activity: pd.DataFrame) -> set[str]:
        resources = set(graph.resource_ids)
        if activity.empty:
            return resources
        cutoff = parse_time(case.get("audit_at"))
        ids = set(graph.identifiers)
        for _, row in activity.iterrows():
            event_time = parse_time(row.get("event_time"))
            if not event_time or not cutoff or event_time > cutoff:
                continue
            event_type = clean(row.get("event_type")).upper()
            details = clean(row.get("details"))
            resource = clean(row.get("resource_id"))
            if event_type == "LINK_RESOURCE_IDENTITY":
                if graph.user_id and graph.user_id.casefold() in details.casefold() or any(contains_exact(details, value) for value in graph.emails):
                    if resource:
                        resources.add(resource)
            elif any(contains_exact(details, value) for value in ids if len(norm(value)) > 2):
                if resource:
                    resources.add(resource)

        # The deletion worker event adjacent to reported_at identifies the account
        # resource under investigation. It is used only as a lookup anchor; reported
        # results are never accepted as proof of resource state.
        reported_at = parse_time(case.get("reported_at"))
        if reported_at and cutoff and reported_at <= cutoff:
            candidates = []
            for _, row in activity.iterrows():
                if clean(row.get("event_type")).upper() != "DELETE_RECORD":
                    continue
                if clean(row.get("source_system")).casefold() != "deletion_worker":
                    continue
                if clean(row.get("target_system")).casefold() != "account_service":
                    continue
                when = parse_time(row.get("event_time"))
                if not when or when > cutoff:
                    continue
                delta = abs((when - reported_at).total_seconds())
                if delta <= 30 * 60:
                    candidates.append((delta, clean(row.get("resource_id"))))
            if candidates:
                candidates.sort()
                if len(candidates) == 1 or candidates[0][0] < candidates[1][0]:
                    resources.add(candidates[0][1])
        return {resource for resource in resources if resource}

    def related_activity(self, case: dict[str, Any], graph: IdentityGraph, resources: set[str], activity: pd.DataFrame) -> list[dict[str, Any]]:
        cutoff = parse_time(case.get("audit_at"))
        if activity.empty or not cutoff:
            return []
        related = []
        ids = set(graph.identifiers)
        for _, row in activity.iterrows():
            when = parse_time(row.get("event_time"))
            if not when or when > cutoff:
                continue
            resource = clean(row.get("resource_id"))
            details = clean(row.get("details"))
            linked = resource in resources or (graph.user_id and graph.user_id.casefold() in details.casefold())
            linked = linked or any(contains_exact(details, value) for value in ids if len(norm(value)) > 2)
            if linked:
                related.append(row.to_dict())
        return related

    def assess(self, observations: list[EvidenceObservation]) -> list[EvidenceObservation]:
        """Return active process and restorable backup evidence only."""
        return [item for item in observations if item.data_category in self.PROCESS_CATEGORIES and item.state in {"ACTIVE", "BLOCKED", "DISABLED"}]
