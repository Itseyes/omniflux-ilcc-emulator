from __future__ import annotations

from typing import Optional

from core.crypto_utils import verify_ec
from core.ledger import EvidenceLedger
from core.primitives import PCKT, GENESIS_HASH


class ILCCShim:
    """ILCC driver shim (TRL-3).

    Fail-closed rules enforced here:
    - Hash chain must be continuous
    - C-Engine signature must verify

    Any violation halts immediately and records a ledger scar.
    """

    def __init__(self, c_engine_pub_key, *, ledger: Optional[EvidenceLedger] = None):
        self._c_engine_pub_key = c_engine_pub_key
        self._last_hash = GENESIS_HASH
        self._step = 0
        self.ledger = ledger or EvidenceLedger()

    @property
    def last_hash(self) -> str:
        return self._last_hash

    def launch_kernel(self, pckt: PCKT) -> None:
        self._step += 1

        # 1) Chain integrity
        if pckt.prev_hash != self._last_hash:
            self.ledger.append_event(
                "chain_break",
                {"expected": self._last_hash, "got": pckt.prev_hash, "step": self._step},
            )
            raise RuntimeError(f"Chain broken at step {self._step}")

        # 2) Signature presence
        if pckt.signature is None:
            self.ledger.append_event(
                "missing_signature",
                {"step": self._step, "h_prev": pckt.prev_hash, "h_curr": pckt.get_hash()},
            )
            raise RuntimeError(f"Missing PCKT signature at step {self._step}")

        # 3) Signature verification
        try:
            verify_ec(self._c_engine_pub_key, pckt.signature, pckt.serialize_unsigned())
        except Exception as exc:
            self.ledger.append_event(
                "invalid_c_engine_signature",
                {"step": self._step, "h_prev": pckt.prev_hash, "h_curr": pckt.get_hash()},
                exc=exc,
            )
            raise RuntimeError(f"Invalid C-Engine signature at step {self._step}") from exc

        # 4) Accept + record evidence
        self.ledger.append_pckt(pckt)
        self._last_hash = pckt.get_hash()
