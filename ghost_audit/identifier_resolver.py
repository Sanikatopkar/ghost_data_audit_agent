"""Resolve request email to an identity using exact current and historical mappings."""
from __future__ import annotations

from typing import Any
import pandas as pd

from .models import IdentityGraph
from .normalization import clean, norm, parse_time


class IdentifierResolver:
    def resolve(
        self,
        email: str,
        audit_at: str,
        identities: pd.DataFrame,
        audit_log: pd.DataFrame,
        activity: pd.DataFrame,
    ) -> IdentityGraph:
        target = norm(email)
        matches: set[str] = set()

        for _, row in identities.iterrows():
            if norm(row.get("email")) == target and self._within(row.get("updated_at"), audit_at):
                uid = clean(row.get("user_id"))
                if uid:
                    matches.add(uid)

        for _, row in audit_log.iterrows():
            if not self._within(row.get("event_time"), audit_at):
                continue
            if norm(row.get("field_name")) == "email" and target in {norm(row.get("old_value")), norm(row.get("new_value"))}:
                uid = clean(row.get("user_id"))
                if uid:
                    matches.add(uid)

        # A catalog link is explicit participant evidence and can resolve identities
        # whose current snapshot is no longer available at the audit cutoff.
        if not activity.empty:
            for _, row in activity.iterrows():
                if clean(row.get("event_type")).upper() != "LINK_RESOURCE_IDENTITY":
                    continue
                if not self._within(row.get("event_time"), audit_at):
                    continue
                details = clean(row.get("details"))
                if target and target in norm(details):
                    match = __import__("re").search(r"\buser_[A-Za-z0-9_-]+\b", details, flags=__import__("re").I)
                    if match:
                        matches.add(match.group(0))

        graph = IdentityGraph(user_id=next(iter(matches)) if len(matches) == 1 else None, ambiguous=len(matches) > 1)
        graph.add(email, "email")
        if graph.user_id is None:
            return graph

        uid = graph.user_id
        graph.add(uid)

        eligible = []
        for _, row in identities.iterrows():
            if clean(row.get("user_id")) == uid and self._within(row.get("updated_at"), audit_at):
                eligible.append(row)
        if eligible:
            eligible.sort(key=lambda row: parse_time(row.get("updated_at")) or parse_time("1970-01-01T00:00:00Z"))
            current = eligible[-1]
            graph.add(current.get("name"), "name")
            graph.add(current.get("email"), "email")
            graph.add(current.get("phone"), "phone")
            graph.add(current.get("email_hash"), "email_hash")

        for _, row in audit_log.iterrows():
            if clean(row.get("user_id")) != uid or not self._within(row.get("event_time"), audit_at):
                continue
            field = norm(row.get("field_name"))
            kind = "email" if "email" in field and "hash" not in field else "phone" if "phone" in field else "email_hash" if "hash" in field else "name" if "name" in field else "other"
            graph.add(row.get("old_value"), kind)
            graph.add(row.get("new_value"), kind)
            if clean(row.get("audit_id")):
                graph.evidence_ids.add(clean(row.get("audit_id")))

        if not activity.empty:
            for _, row in activity.iterrows():
                if clean(row.get("event_type")).upper() != "LINK_RESOURCE_IDENTITY" or not self._within(row.get("event_time"), audit_at):
                    continue
                details = clean(row.get("details"))
                if uid.casefold() in details.casefold():
                    resource = clean(row.get("resource_id"))
                    if resource:
                        graph.resource_ids.add(resource)
        return graph

    @staticmethod
    def _within(value: Any, cutoff: Any) -> bool:
        moment, bound = parse_time(value), parse_time(cutoff)
        return bool(moment and bound and moment <= bound)
