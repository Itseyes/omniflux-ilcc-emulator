# omniflux-ilcc-emulator (TRL-3)

Invariant-Locked Compute Cluster (ILCC-α) — TRL-3 Python emulator.

This repo demonstrates the Canon primitive:

> No kernel step can execute unless it carries a valid, cryptographically signed proof that the current physical state satisfies the invariant.

## Components

- **Mock Enclave**: produces signed telemetry (canonical JSON) using ECDSA P-256.
- **Mock Constraint Engine**: verifies telemetry signatures, enforces invariants, issues signed PCKTs.
- **ILCC Driver Shim**: enforces the PCKT hash chain and verifies Constraint Engine signatures.
- **Evidence Ledger**: append-only, hash-chained record of accepted transitions and failure scars.

## Determinism

- Canonical JSON is used for all signed/hashed payloads.
- SHA-256 is used for all hashes.
- ECDSA P-256 with SHA-256 is used for signatures.
- The emulator physics uses a local PRNG with a fixed seed.

## Run

```bash
pip install -r requirements.txt
python -m simulation.run_agu_loop
```

Expected behavior:

- Cycles 1–5: accepted transitions; chain advances.
- Cycle 6: thermal fault triggers an invariant violation; the system fails closed (no PCKT, no dispatch) and the ledger records a cryptographic scar.
