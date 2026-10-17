"""Versioned, language-neutral QBC canonical encoding (not used by v0.1 consensus).

QBC-CJSON-V1 intentionally accepts a small JSON subset. Consensus callers must
opt in explicitly; do not replace models.canonical_json or v0.1 hashing with it.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any

_MIN_INT = -(2**63)
_MAX_INT = 2**63 - 1
_DOMAIN_RE = re.compile(r"[a-z0-9][a-z0-9._/-]{0,63}\Z")
_HASH_PREFIX = b"QBC-CJSON-V1\x00"


def _encode_string(value: str) -> bytes:
    """Encode a Unicode scalar string using QBC-CJSON-V1 escaping rules."""
    pieces: list[str] = ['"']
    for char in value:
        codepoint = ord(char)
        if 0xD800 <= codepoint <= 0xDFFF:
            raise ValueError("Strings must not contain Unicode surrogate code points.")
        if char == '"':
            pieces.append('\\\"')
        elif char == "\\":
            pieces.append("\\\\")
        elif codepoint < 0x20:
            pieces.append(f"\\u{codepoint:04x}")
        else:
            pieces.append(char)
    pieces.append('"')
    return "".join(pieces).encode("utf-8")


def _encode(value: Any) -> bytes:
    if value is None:
        return b"null"
    if value is True:
        return b"true"
    if value is False:
        return b"false"
    if isinstance(value, int):
        if not _MIN_INT <= value <= _MAX_INT:
            raise ValueError("Integers must fit in signed 64-bit range.")
        return str(value).encode("ascii")
    if isinstance(value, str):
        return _encode_string(value)
    if isinstance(value, list):
        return b"[" + b",".join(_encode(item) for item in value) + b"]"
    if isinstance(value, dict):
        for key in value:
            if not isinstance(key, str):
                raise ValueError("Object keys must be strings.")
            _encode_string(key)  # Validate Unicode before sorting/encoding.
        keys = sorted(value, key=lambda key: key.encode("utf-8"))
        members = (
            _encode_string(key) + b":" + _encode(value[key])
            for key in keys
        )
        return b"{" + b",".join(members) + b"}"
    if isinstance(value, float):
        raise ValueError("Floating-point values are forbidden in QBC-CJSON-V1.")
    raise ValueError(f"Unsupported QBC-CJSON-V1 value type: {type(value).__name__}.")


def canonical_json_v1(value: Any) -> bytes:
    """Return canonical UTF-8 bytes under the QBC-CJSON-V1 profile.

    Allowed values: null, booleans, signed 64-bit integers, Unicode scalar
    strings, arrays, and objects with string keys. Tuples and floats are rejected.
    """
    return _encode(value)


def hash_canonical_v1(domain: str, value: Any) -> str:
    """Return a lowercase SHA-256 hex digest with explicit domain separation."""
    if not isinstance(domain, str) or not _DOMAIN_RE.fullmatch(domain):
        raise ValueError("Domain must be a 1-64 character lowercase ASCII token.")
    preimage = _HASH_PREFIX + domain.encode("ascii") + b"\x00" + canonical_json_v1(value)
    return hashlib.sha256(preimage).hexdigest()
