from __future__ import annotations

import random
from typing import Any, Dict, Optional

from cryptography.hazmat.primitives.asymmetric import ec

from core.crypto_utils import sign_ec
from core.primitives import canonical_json_bytes


class MockEnclave:
    """Mock hardware enclave (TRL-3).

    - Owns an ECDSA P-256 private key (root of trust)
    - Produces signed, canonical-JSON telemetry

    Determinism note:
    A local PRNG with an explicit seed is used so emulator runs are repeatable.
    """

    def __init__(self, *, seed: int = 0):
        self._private_key = ec.generate_private_key(ec.SECP256R1())
        self.public_key = self._private_key.public_key()

        self._rng = random.Random(seed)

        # Physics state (simple, deterministic dynamics)
        self.temp_die_c = 45.0
        self.power_draw_w = 250.0

    def read_telemetry(self) -> Dict[str, Any]:
        # Crude thermal/power dynamics
        self.temp_die_c += self._rng.uniform(-1.0, 2.5)
        self.power_draw_w += self._rng.uniform(-5.0, 10.0)

        payload = {
            "temp_die_c": round(self.temp_die_c, 2),
            "power_draw_w": round(self.power_draw_w, 2),
        }
        payload_bytes = canonical_json_bytes(payload)
        signature = sign_ec(self._private_key, payload_bytes)

        return {
            "payload": payload,
            "signature": signature,
        }

    def force_thermal_event(self, *, temp_die_c: float = 95.0) -> None:
        self.temp_die_c = float(temp_die_c)
