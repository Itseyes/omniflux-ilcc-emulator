from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Dict, Optional


# Genesis hash for the PCKT chain.
# Kept as a 32-byte SHA-256 hex string for consistency.
GENESIS_HASH = "0" * 64


def canonical_json_bytes(obj: Any) -> bytes:
    """Deterministic canonical JSON encoding (UTF-8)."""
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


@dataclass(frozen=True)
class PCKT:
    """Proof-Carrying Kernel Transition (atomic unit of governance)."""

    prev_hash: str
    action: Dict[str, Any]
    witness: Dict[str, Any]
    timestamp: float
    signature: Optional[bytes] = None  # C-Engine signature over serialize_unsigned()

    def serialize_unsigned(self) -> bytes:
        """Canonical JSON payload for signing & hashing (excludes signature)."""
        payload = {
            "h_prev": self.prev_hash,
            "action": self.action,
            "witness": self.witness,
            "ts": self.timestamp,
        }
        return canonical_json_bytes(payload)

    def get_hash(self) -> str:
        """Deterministic SHA-256 chain hash of the unsigned payload."""
        return hashlib.sha256(self.serialize_unsigned()).hexdigest()
