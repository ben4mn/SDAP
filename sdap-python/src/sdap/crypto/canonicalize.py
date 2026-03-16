"""JSON Canonical Serialization (JCS) — RFC 8785."""

from __future__ import annotations

import json
import math


def canonicalize(obj: dict) -> bytes:
    """Return RFC 8785 canonical JSON bytes for *obj*.

    Rules:
    - Keys sorted lexicographically (Unicode code-point order), recursively
    - No insignificant whitespace
    - Strings encoded as UTF-8 with standard JSON escaping
    - Numbers: no trailing zeros in fractions; integers have no decimal point;
      special floats (inf, nan) are not permitted
    - null → ``null``, booleans → ``true`` / ``false``
    """
    return _serialize(obj).encode("utf-8")


def _serialize(value: object) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            raise ValueError("JCS does not support NaN or Infinity")
        # Use Python's repr-level precision, strip unnecessary trailing zeros
        return _serialize_float(value)
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, (list, tuple)):
        items = ",".join(_serialize(v) for v in value)
        return f"[{items}]"
    if isinstance(value, dict):
        pairs = ",".join(
            f"{json.dumps(k, ensure_ascii=False)}:{_serialize(v)}"
            for k, v in sorted(value.items())
        )
        return "{" + pairs + "}"
    raise TypeError(f"Unsupported type for JCS: {type(value)}")


def _serialize_float(value: float) -> str:
    """Serialize a float following ES2019 / RFC 8785 numeric rules."""
    # Use repr for round-trip fidelity; strip trailing zeros after decimal
    s = repr(value)
    if "e" in s or "E" in s:
        # Normalize scientific notation to lowercase e, strip leading zeros in exponent
        return _normalize_exp(s)
    if "." in s:
        # Strip trailing zeros but keep at least one decimal digit
        s = s.rstrip("0").rstrip(".")
        if "." not in s:
            return s
        return s
    return s


def _normalize_exp(s: str) -> str:
    """Normalize Python float scientific notation to JCS format."""
    # Python uses e+06 style; JCS uses e+6
    import re
    s = s.lower()
    s = re.sub(r"e([+-])0*(\d+)", lambda m: f"e{m.group(1)}{m.group(2)}", s)
    return s
