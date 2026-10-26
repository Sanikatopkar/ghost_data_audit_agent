"""Normalization helpers for exact, auditable identity matching."""
from __future__ import annotations

import re
import unicodedata
from datetime import datetime, timezone
from typing import Any, Iterable


NULL_VALUES = {"", "nan", "none", "null", "n/a", "unknown", "<na>"}


def clean(value: Any) -> str:
    if value is None:
        return ""
    text = str(value).strip()
    return "" if text.casefold() in NULL_VALUES else text


def norm(value: Any) -> str:
    text = unicodedata.normalize("NFKC", clean(value)).casefold()
    return "".join(ch for ch in unicodedata.normalize("NFKD", text) if not unicodedata.combining(ch))


def parse_time(value: Any) -> datetime | None:
    text = clean(value)
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def at_or_before(value: Any, cutoff: Any) -> bool:
    moment = parse_time(value)
    bound = parse_time(cutoff)
    return bool(moment and bound and moment <= bound)


def contains_exact(haystack: str, needle: str) -> bool:
    """Match an identifier as a whole token, avoiding name substrings."""
    h, n = norm(haystack), norm(needle)
    if not h or not n:
        return False
    if "@" in n or re.fullmatch(r"[0-9a-f]{32,}", n):
        return n in h
    escaped = re.escape(n)
    return re.search(rf"(?<![\w]){escaped}(?![\w])", h, flags=re.UNICODE) is not None


def flatten_scalars(value: Any, prefix: str = "") -> dict[str, Any]:
    result: dict[str, Any] = {}
    if isinstance(value, dict):
        for key, child in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            if isinstance(child, (dict, list)):
                result.update(flatten_scalars(child, path))
            else:
                result[path] = child
    elif isinstance(value, list):
        for index, child in enumerate(value):
            result.update(flatten_scalars(child, f"{prefix}[{index}]"))
    elif prefix:
        result[prefix] = value
    return result


def scalar_values(values: Iterable[Any]) -> set[str]:
    return {clean(value) for value in values if clean(value)}
