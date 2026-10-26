"""Extract structured observations from participant-facing evidence artifacts."""
from __future__ import annotations

import json
import re
import sqlite3
from pathlib import Path
from typing import Any, Iterable

import pandas as pd

from .models import EvidenceObservation, SnapshotCoverage
from .normalization import clean, flatten_scalars, parse_time

CATEGORY_MAP = {
    "customer_profiles": "USER_PROFILE",
    "user_profiles": "USER_PROFILE",
    "secondary_identifiers": "SECONDARY_IDENTIFIER",
    "customer_search_documents": "SEARCH_INDEX_ENTRY",
    "search_index_entries": "SEARCH_INDEX_ENTRY",
    "cache_entries": "CACHE_ENTRY",
    "support_messages": "SUPPORT_MESSAGE",
    "support_tickets": "SUPPORT_MESSAGE",
    "support_attachments": "SUPPORT_ATTACHMENT",
    "customer_analytics_reports": "ANALYTICS_PROFILE",
    "analytics_profiles": "ANALYTICS_PROFILE",
    "product_telemetry": "PRODUCT_TELEMETRY",
    "customer_exports": "USER_EXPORT",
    "customer_export_jobs": "USER_EXPORT",
    "marketing_profiles": "MARKETING_PROFILE",
    "email_delivery_logs": "EMAIL_DELIVERY_LOG",
    "security_audit_events": "SECURITY_AUDIT_LOG",
    "security_audit_records": "SECURITY_AUDIT_LOG",
    "legal_hold_records": "LEGAL_HOLD_RECORD",
    "backup_archives": "BACKUP_ARCHIVE",
    "deleted_customer_references": "ACCOUNT_TOMBSTONE",
    "connector_configurations": "DATA_FLOW",
    "data_flows": "DATA_FLOW",
}

RESOURCE_RE = re.compile(r"\b(?:account|search|support|analytics|data_flow|backup|audit_record|tombstone|export|marketing|object|email_delivery|cache|telemetry)_\d+\b", re.I)
KV_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)=([^\s]+)")


def infer_system(explicit: Any = "", category: str = "", resource_id: str = "") -> str:
    system = clean(explicit)
    aliases = {
        "support_replica": "support_platform", "support_platform": "support_platform",
        "account_service": "account_service", "search_service": "search_service",
        "analytics_platform": "analytics_platform", "integration_service": "integration_service",
        "backup_service": "backup_service", "security_service": "security_service",
        "identity_service": "identity_service", "export_service": "export_service",
        "marketing_platform": "marketing_platform", "object_storage": "object_storage",
        "email_delivery_service": "email_delivery_service", "cache_service": "cache_service",
    }
    if system:
        return aliases.get(system.casefold(), system)
    prefix = resource_id.split("_", 1)[0].lower()
    return {
        "account": "account_service", "search": "search_service", "support": "support_platform",
        "analytics": "analytics_platform", "data": "integration_service", "backup": "backup_service",
        "audit": "security_service", "tombstone": "identity_service", "export": "export_service",
        "marketing": "marketing_platform", "object": "object_storage", "email": "email_delivery_service",
        "cache": "cache_service", "telemetry": "analytics_platform",
    }.get(prefix, "unknown_system")


def infer_category(explicit: Any = "", collection: Any = "", system: Any = "", resource_id: str = "") -> str:
    raw = clean(explicit).upper().replace("-", "_").replace(" ", "_")
    allowed = set(CATEGORY_MAP.values()) | {"DATA_FLOW", "RESTORE_RISK"}
    if raw in allowed:
        return raw
    key = clean(collection).casefold().replace("-", "_").replace(" ", "_")
    if key in CATEGORY_MAP:
        return CATEGORY_MAP[key]
    for label, mapped in CATEGORY_MAP.items():
        if label in key:
            return mapped
    text = f"{clean(system)} {resource_id} {key}".casefold()
    if "support_attachment" in text or "delivery_correction_attachment" in text:
        return "SUPPORT_ATTACHMENT"
    if "tombstone" in text or "deleted_customer_reference" in text:
        return "ACCOUNT_TOMBSTONE"
    if "backup" in text:
        return "BACKUP_ARCHIVE"
    if "data_flow" in text or "integration" in text or "connector" in text:
        return "DATA_FLOW"
    if "search" in text:
        return "SEARCH_INDEX_ENTRY"
    if "analytics" in text:
        return "ANALYTICS_PROFILE"
    if "support" in text or "object_storage" in text:
        return "SUPPORT_ATTACHMENT" if "object" in text else "SUPPORT_MESSAGE"
    if "export" in text:
        return "USER_EXPORT"
    if "marketing" in text:
        return "MARKETING_PROFILE"
    if "audit" in text or "security" in text:
        return "SECURITY_AUDIT_LOG"
    if "email_delivery" in text:
        return "EMAIL_DELIVERY_LOG"
    if "cache" in text:
        return "CACHE_ENTRY"
    if "account" in text or "profile" in text:
        return "USER_PROFILE"
    return "UNKNOWN"


def infer_state(fields: dict[str, Any], category: str, raw_text: str = "") -> str:
    normalized = {str(k).split(".")[-1].split("[")[0].casefold(): clean(v).casefold() for k, v in fields.items()}
    text = raw_text.casefold()
    for key in ("observed_state", "record_state", "state", "result", "status", "lookup_result"):
        value = normalized.get(key, "").upper()
        if value in {"NOT_FOUND", "ABSENT", "MISSING", "NOT_PRESENT", "404", "MISS", "ROWS=0"}:
            return "ABSENT"
        if value in {"REDACTED", "MASKED"}:
            return "REDACTED"
        if value in {"ANONYMIZED", "ANONYMISED"}:
            return "ANONYMIZED"
        if value in {"BLOCKED", "DISABLED", "INACTIVE", "STOPPED"}:
            return "DISABLED" if category == "DATA_FLOW" else "BLOCKED"
        if value in {"ACTIVE", "ENABLED", "RUNNING"}:
            return "ACTIVE" if category in {"DATA_FLOW", "BACKUP_ARCHIVE"} else "PRESENT"
        if value in {"FOUND", "PRESENT", "IDENTIFIABLE", "HIT"}:
            return "PRESENT"
    if normalized.get("http_status") == "404" or normalized.get("status_code") == "404" or normalized.get("rows") == "0":
        return "ABSENT"
    if category == "DATA_FLOW":
        if normalized.get("enabled") in {"false", "0", "no"}:
            return "DISABLED"
        if normalized.get("enabled") in {"true", "1", "yes"}:
            return "ACTIVE"
    if category == "BACKUP_ARCHIVE":
        if normalized.get("restore_allowed") in {"false", "0", "no"}:
            return "BLOCKED"
        if normalized.get("restore_allowed") in {"true", "1", "yes"}:
            return "ACTIVE"
    if any(normalized.get(k) == "hit" for k in ("result", "lookup_result")):
        return "PRESENT"
    if any(term in text for term in ("result=hit", "rows=1", "http_status=200", "result=found")):
        return "PRESENT"
    return "PRESENT"


class EvidenceReader:
    def __init__(self, dataset_dir: Path):
        self.dataset_dir = dataset_dir
        self._ocr_engine = None
        self.warnings: list[str] = []
        self.coverage: list[SnapshotCoverage] = []

    def read_all(self, manifest: pd.DataFrame) -> list[EvidenceObservation]:
        observations: list[EvidenceObservation] = []
        for _, item in manifest.iterrows():
            file_id = clean(item.get("file_id"))
            relative = clean(item.get("file_path"))
            capture = clean(item.get("captured_at"))
            path = (self.dataset_dir / relative).resolve()
            if not path.is_relative_to(self.dataset_dir.resolve()):
                self.warnings.append(f"Ignored path outside dataset: {relative}")
                continue
            if not path.is_file():
                self.warnings.append(f"Missing evidence file: {relative}")
                continue
            suffix = path.suffix.casefold()
            try:
                if suffix == ".json":
                    observations.extend(self._read_json(path, file_id, capture))
                elif suffix == ".sql":
                    observations.extend(self._read_sql(path, file_id, capture))
                elif suffix == ".log":
                    observations.extend(self._read_log(path, file_id, capture))
                elif suffix == ".txt":
                    observations.extend(self._read_text(path, file_id, capture))
                elif suffix == ".pdf":
                    observations.extend(self._read_pdf(path, file_id, capture))
                elif suffix == ".png":
                    observations.extend(self._read_image(path, file_id, capture))
            except Exception as exc:
                self.warnings.append(f"Could not parse {relative}: {type(exc).__name__}: {exc}")
        return observations

    def _observation(self, file_id: str, capture: str, system: Any, resource: Any, category: Any, fields: dict[str, Any], raw: str, observed: Any = "", store: str = "") -> EvidenceObservation | None:
        resource_id = clean(resource)
        if not resource_id or not RESOURCE_RE.fullmatch(resource_id):
            return None
        system_id = infer_system(system, clean(category), resource_id)
        data_category = infer_category(category, store, system_id, resource_id)
        flat = flatten_scalars(fields)
        state = infer_state(flat, data_category, raw)
        moment = clean(observed) or capture
        if store:
            flat["_storage_location"] = store
        return EvidenceObservation(file_id, capture, moment, system_id, resource_id, data_category, state, flat, raw)

    def _read_json(self, path: Path, file_id: str, capture: str) -> list[EvidenceObservation]:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
        out: list[EvidenceObservation] = []
        def walk(node: Any, context: dict[str, Any]) -> None:
            if isinstance(node, dict):
                ctx = dict(context)
                for key in ("data_store", "origin_system", "system", "collection", "record_type", "data_category", "captured_at", "snapshot_at", "exported_at"):
                    if key in node and not isinstance(node[key], (dict, list)):
                        ctx[key] = node[key]
                records = node.get("records")
                collection = clean(node.get("collection") or ctx.get("collection"))
                if isinstance(records, list) and collection:
                    system = node.get("data_store") or node.get("origin_system") or node.get("system") or ctx.get("data_store") or ctx.get("system")
                    category = infer_category("", collection, system)
                    ids = {clean(record.get("resource_id") or record.get("record_id")) for record in records if isinstance(record, dict)}
                    ids.discard("")
                    self.coverage.append(SnapshotCoverage(file_id, clean(node.get("captured_at") or ctx.get("captured_at") or ctx.get("snapshot_at") or capture), infer_system(system, category), category, ids, collection))
                resource = node.get("resource_id") or node.get("record_id")
                if resource:
                    system = node.get("system") or node.get("data_store") or node.get("origin_system") or ctx.get("system") or ctx.get("data_store")
                    category = node.get("data_category") or node.get("record_type") or node.get("record_category") or ctx.get("record_type") or ctx.get("collection")
                    obs = self._observation(file_id, capture, system, resource, category, node, json.dumps(node, ensure_ascii=False), node.get("observed_at") or node.get("updated_at") or node.get("captured_at") or ctx.get("captured_at") or ctx.get("snapshot_at") or ctx.get("exported_at"), str(ctx.get("collection", "")))
                    if obs:
                        out.append(obs)
                for value in node.values():
                    walk(value, ctx)
            elif isinstance(node, list):
                for value in node:
                    walk(value, context)
        walk(data, {})
        return out

    def _read_sql(self, path: Path, file_id: str, capture: str) -> list[EvidenceObservation]:
        con = sqlite3.connect(":memory:")
        out: list[EvidenceObservation] = []
        try:
            con.executescript(path.read_text(encoding="utf-8-sig", errors="replace"))
            tables = [row[0] for row in con.execute("SELECT name FROM sqlite_master WHERE type='table'")]
            for table in tables:
                columns = [row[1] for row in con.execute(f'PRAGMA table_info("{table}")')]
                table_resources: dict[tuple[str, str], set[str]] = {}
                for values in con.execute(f'SELECT * FROM "{table}"'):
                    record = dict(zip(columns, values))
                    payload = record.get("record_json")
                    if isinstance(payload, str):
                        try:
                            body = json.loads(payload)
                        except json.JSONDecodeError:
                            body = {"record_json": payload}
                    else:
                        body = {}
                    fields = {**record, **body}
                    system = record.get("origin_system") or body.get("system")
                    category = record.get("collection_name") or body.get("record_type") or body.get("data_category")
                    store = table
                    observed = body.get("observed_at") or body.get("updated_at") or record.get("updated_at") or capture
                    obs = self._observation(file_id, capture, system, record.get("resource_id") or body.get("resource_id"), category, fields, json.dumps(fields, ensure_ascii=False, default=str), observed, store)
                    if obs:
                        out.append(obs)
                        table_resources.setdefault((obs.system_id, obs.data_category), set()).add(obs.resource_id)
                for (system_id, category), resource_ids in table_resources.items():
                    self.coverage.append(SnapshotCoverage(file_id, capture, system_id, category, resource_ids, table))
        finally:
            con.close()
        return out

    def _read_log(self, path: Path, file_id: str, capture: str) -> list[EvidenceObservation]:
        out: list[EvidenceObservation] = []
        for line in path.read_text(encoding="utf-8-sig", errors="replace").splitlines():
            fields: dict[str, Any] = {key: value.strip('"\' ,') for key, value in KV_RE.findall(line)}
            match = RESOURCE_RE.search(line)
            resource = fields.get("resource_id") or (match.group(0) if match else "")
            if not resource:
                continue
            system = fields.get("service") or fields.get("system") or ""
            event_time = re.match(r"^(\d{4}-\d\d-\d\dT[^ ]+)", line)
            observed = event_time.group(1) if event_time else capture
            category = infer_category("", "", system, resource)
            obs = self._observation(file_id, capture, system, resource, category, fields, line, observed, path.name)
            if obs:
                event = fields.get("event", "").casefold()
                if "lookup_completed" in event and fields.get("rows") == "0":
                    obs.state = "ABSENT"
                elif "lookup_completed" in event and fields.get("rows") not in {"0", ""}:
                    obs.state = "PRESENT"
                elif "index_query_completed" in event:
                    obs.state = "PRESENT" if fields.get("result", "").casefold() == "hit" else "ABSENT"
                out.append(obs)
        return out

    def _read_text(self, path: Path, file_id: str, capture: str) -> list[EvidenceObservation]:
        out: list[EvidenceObservation] = []
        for line in path.read_text(encoding="utf-8-sig", errors="replace").splitlines():
            if "|" not in line:
                continue
            parts = [part.strip(" -*") for part in line.split("|")]
            if len(parts) < 5:
                continue
            ts, system, resource, category, state = parts[:5]
            fields = {"record_type": category, "state": state, "details": " | ".join(parts[5:])}
            obs = self._observation(file_id, capture, system, resource, category, fields, line, ts, path.name)
            if obs:
                out.append(obs)
        return out

    def _read_pdf(self, path: Path, file_id: str, capture: str) -> list[EvidenceObservation]:
        try:
            from pypdf import PdfReader
        except ImportError:
            self.warnings.append("PDF extraction skipped; install pypdf to read PDF evidence.")
            return []
        text = "\n".join(page.extract_text() or "" for page in PdfReader(str(path)).pages)
        return self._observations_from_document(text, path, file_id, capture)

    def _read_image(self, path: Path, file_id: str, capture: str) -> list[EvidenceObservation]:
        text = ""
        try:
            from rapidocr_onnxruntime import RapidOCR
            if self._ocr_engine is None:
                self._ocr_engine = RapidOCR()
            result, _elapsed = self._ocr_engine(str(path))
            text = "\n".join(str(item[1]) for item in (result or []))
        except Exception as exc:
            self.warnings.append(f"Image OCR unavailable for {path.name}: {type(exc).__name__}; install rapidocr_onnxruntime or Tesseract.")
            return []
        return self._observations_from_document(text, path, file_id, capture)

    def _observations_from_document(self, text: str, path: Path, file_id: str, capture: str) -> list[EvidenceObservation]:
        matches = list(RESOURCE_RE.finditer(text))
        if not matches:
            return []
        ids = list(dict.fromkeys(match.group(0) for match in matches))
        out: list[EvidenceObservation] = []
        for resource in ids:
            positions = [match.start() for match in matches if match.group(0) == resource]
            start = max(0, min(positions) - 600)
            end = min(len(text), max(positions) + len(resource) + 600)
            local_text = text[start:end]
            category = infer_category("", path.stem, "", resource)
            system = infer_system("", category, resource)
            obs = self._observation(file_id, capture, system, resource, category, {"document_text": local_text}, local_text, capture, path.name)
            if obs:
                out.append(obs)
        return out


