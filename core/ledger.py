from __future__ import annotations

import hashlib
from typing import Any, Dict, List, Optional

from core.primitives import PCKT, canonical_json_bytes


class EvidenceLedger:
    """Append-only evidence ledger with an internal SHA-256 hash chain.

    Every append (success or failure) produces an entry with:
    - ledger_prev: previous ledger entry hash (or GENESIS)
    - ledger_hash: SHA-256 of the entry content (excluding ledger_hash)

    This provides a cryptographic "scar" for failure conditions.
    """

    LEDGER_GENESIS = "0" * 64

    def __init__(self):
        self._entries: List[Dict[str, Any]] = []
        self._last_hash: str = self.LEDGER_GENESIS

    def _append(self, entry: Dict[str, Any]) -> str:
        entry_with_prev = {
            "ledger_prev": self._last_hash,
            **entry,
        }
        ledger_hash = hashlib.sha256(canonical_json_bytes(entry_with_prev)).hexdigest()
        entry_with_prev["ledger_hash"] = ledger_hash

        self._entries.append(entry_with_prev)
        self._last_hash = ledger_hash
        return ledger_hash

    def append_pckt(self, pckt: PCKT) -> str:
        if pckt.signature is None:
            # Fail-closed: accepted transitions must always be signed.
            raise ValueError("Refusing to ledger an unsigned PCKT")

        return self._append(
            {
                "type": "pckt_accept",
                "h_prev": pckt.prev_hash,
                "h_curr": pckt.get_hash(),
                "action": pckt.action,
                "witness": pckt.witness,
                "ts": pckt.timestamp,
                "pckt_sig_sha256": hashlib.sha256(pckt.signature).hexdigest(),
            }
        )

    def append_event(self, event_type: str, details: Dict[str, Any], *, exc: Optional[BaseException] = None) -> str:
        entry: Dict[str, Any] = {
            "type": event_type,
            "details": details,
        }
        if exc is not None:
            entry["exception"] = {
                "type": exc.__class__.__name__,
                "msg": str(exc),
            }
        return self._append(entry)

    def dump(self) -> List[Dict[str, Any]]:
        return list(self._entries)

    @property
    def last_hash(self) -> str:
        return self._last_hash
