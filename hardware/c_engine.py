from __future__ import annotations

import hashlib
from typing import Any, Dict

import yaml

from core.crypto_utils import generate_ec_key, sign_ec, verify_ec
from core.primitives import PCKT, canonical_json_bytes


class ConstraintEngine:
    """Mock Constraint Engine (TRL-3).

    Responsibilities (fail-closed):
    - Verify enclave telemetry signature
    - Enforce invariants
    - Emit signed PCKTs

    This module must not "best effort" any verification step.
    """

    def __init__(self, enclave_pub_key, *, invariants_path: str = "config/invariants.yaml"):
        self._private_key, self.public_key = generate_ec_key()
        self._enclave_pub_key = enclave_pub_key

        self._invariants = self._load_invariants(invariants_path)
        self._max_temp_c = float(self._invariants["thermal"]["max_temp_c"])

    @staticmethod
    def _load_invariants(path: str) -> Dict[str, Any]:
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
        except Exception as exc:
            raise RuntimeError(f"Invariant load failure: {path}") from exc

        if not isinstance(data, dict):
            raise RuntimeError("Invariant load failure: expected a mapping")
        if "thermal" not in data or not isinstance(data["thermal"], dict):
            raise RuntimeError("Invariant load failure: missing 'thermal'")
        if "max_temp_c" not in data["thermal"]:
            raise RuntimeError("Invariant load failure: missing thermal.max_temp_c")

        return data

    def request_transition(
        self,
        prev_hash: str,
        proposed_action: Dict[str, Any],
        telemetry: Dict[str, Any],
        *,
        timestamp: float,
    ) -> PCKT:
        # 1) Structure checks
        if "payload" not in telemetry or "signature" not in telemetry:
            raise ValueError("Suspicious telemetry: missing payload/signature")
        payload = telemetry["payload"]
        signature = telemetry["signature"]
        if not isinstance(payload, dict) or not isinstance(signature, (bytes, bytearray)):
            raise ValueError("Suspicious telemetry: invalid types")

        # 2) Verify enclave signature over canonical JSON
        payload_bytes = canonical_json_bytes(payload)
        verify_ec(self._enclave_pub_key, bytes(signature), payload_bytes)

        # 3) Invariant checks (fail-closed)
        if "temp_die_c" not in payload:
            raise ValueError("Suspicious telemetry: missing temp_die_c")
        temp_c = float(payload["temp_die_c"])
        if temp_c > self._max_temp_c:
            raise ValueError(f"INVARIANT VIOLATION: temp_die_c {temp_c:.2f} > {self._max_temp_c:.2f}")

        # 4) Build witness
        telemetry_hash = hashlib.sha256(payload_bytes).hexdigest()
        witness = {
            "telemetry_hash": telemetry_hash,
            "invariant_id": "thermal.max_temp_c",
        }

        # 5) Emit signed PCKT
        pckt_unsigned = PCKT(
            prev_hash=prev_hash,
            action=proposed_action,
            witness=witness,
            timestamp=float(timestamp),
            signature=None,
        )
        pckt_sig = sign_ec(self._private_key, pckt_unsigned.serialize_unsigned())

        return PCKT(
            prev_hash=pckt_unsigned.prev_hash,
            action=pckt_unsigned.action,
            witness=pckt_unsigned.witness,
            timestamp=pckt_unsigned.timestamp,
            signature=pckt_sig,
        )
