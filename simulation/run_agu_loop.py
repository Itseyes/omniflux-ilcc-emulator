from __future__ import annotations

from core.ledger import EvidenceLedger
from core.primitives import GENESIS_HASH, PCKT
from driver.shim import ILCCShim
from hardware.c_engine import ConstraintEngine
from hardware.enclave import MockEnclave


def run_simulation() -> None:
    print("=== NORMAL: AGU loop under invariants (TRL-3) ===")

    enclave = MockEnclave(seed=0)
    c_engine = ConstraintEngine(enclave.public_key)

    ledger = EvidenceLedger()
    shim = ILCCShim(c_engine.public_key, ledger=ledger)

    current_hash = GENESIS_HASH

    for cycle in range(1, 10):
        print(f"\n--- Cycle {cycle} ---")
        action = {"name": "matmul_fp16", "size": "1024x1024"}

        if cycle == 6:
            print("!!! INJECTING THERMAL FAULT !!!")
            enclave.force_thermal_event(temp_die_c=95.0)

        telemetry = enclave.read_telemetry()
        temp_c = telemetry["payload"]["temp_die_c"]
        print(f"[Physics] temp_die_c={temp_c:.2f}C")

        # Deterministic timestamp: cycle index
        try:
            pckt = c_engine.request_transition(
                current_hash,
                action,
                telemetry,
                timestamp=float(cycle),
            )
        except Exception as exc:
            print(f"🛑 C-ENGINE BLOCK: {exc}")
            ledger.append_event(
                "c_engine_block",
                {"cycle": cycle, "temp_die_c": temp_c, "prev_hash": current_hash},
                exc=exc,
            )
            print("System fails closed: no PCKT, no kernel dispatch.")
            break

        try:
            shim.launch_kernel(pckt)
            current_hash = shim.last_hash
            print("✅ ACCEPTED: dispatch allowed")
            print(f"   h={current_hash}")
        except Exception as exc:
            print(f"🛑 SHIM HALT: {exc}")
            break

    print("\n=== Evidence ledger (hash-chained) ===")
    for entry in ledger.dump():
        print(entry)


def run_negative_signature_test() -> None:
    print("\n\n=== NEGATIVE TEST: Signature Corruption ===")

    enclave = MockEnclave(seed=0)
    c_engine = ConstraintEngine(enclave.public_key)
    ledger = EvidenceLedger()
    shim = ILCCShim(c_engine.public_key, ledger=ledger)

    telemetry = enclave.read_telemetry()
    action = {"name": "matmul_fp16", "size": "1024x1024"}

    pckt = c_engine.request_transition(
        GENESIS_HASH,
        action,
        telemetry,
        timestamp=1.0,
    )

    if pckt.signature is None:
        raise RuntimeError("Unexpected: ConstraintEngine emitted an unsigned PCKT")

    # Deliberately corrupt the signature (flip one bit).
    sig = bytearray(pckt.signature)
    sig[0] ^= 0x01
    corrupted = PCKT(
        prev_hash=pckt.prev_hash,
        action=pckt.action,
        witness=pckt.witness,
        timestamp=pckt.timestamp,
        signature=bytes(sig),
    )

    try:
        shim.launch_kernel(corrupted)
    except Exception as exc:
        print(f"[Shim] REJECTED corrupted signature: {exc}")
        # Explicit test scar (in addition to shim's own rejection event)
        ledger.append_event(
            "invalid_signature_test",
            {"status": "shim_rejected_corrupted_signature"},
            exc=exc,
        )
        print("[NEGATIVE] Signature test: shim correctly rejected corrupted PCKT.")
        print("\nLedger entries for signature test:")
        for entry in ledger.dump():
            print(entry)
        return

    # If we got here, Canon was violated: invalid PCKT was accepted.
    ledger.append_event(
        "invalid_signature_test_failed",
        {"note": "shim accepted corrupted signature (governance breach)"},
    )
    raise RuntimeError("Governance breach: shim accepted a corrupted signature")


def run_negative_chain_test() -> None:
    print("\n\n=== NEGATIVE TEST: Chain Break ===")

    enclave = MockEnclave(seed=0)
    c_engine = ConstraintEngine(enclave.public_key)
    ledger = EvidenceLedger()
    shim = ILCCShim(c_engine.public_key, ledger=ledger)

    action = {"name": "matmul_fp16", "size": "1024x1024"}

    # Step 1: establish a valid last_hash via a legitimate transition.
    telemetry1 = enclave.read_telemetry()
    pckt1 = c_engine.request_transition(
        GENESIS_HASH,
        action,
        telemetry1,
        timestamp=1.0,
    )
    shim.launch_kernel(pckt1)

    # Step 2: obtain another valid PCKT, then break the chain at the shim.
    telemetry2 = enclave.read_telemetry()
    pckt2 = c_engine.request_transition(
        pckt1.get_hash(),
        action,
        telemetry2,
        timestamp=2.0,
    )

    # Deliberately break the chain without touching PCKT payload/signature.
    # This ensures the failure is due to chain enforcement (not signature failure).
    shim._last_hash = "f" * 64  # audit-visible test mutation

    try:
        shim.launch_kernel(pckt2)
    except Exception as exc:
        print(f"[Shim] REJECTED broken chain: {exc}")
        ledger.append_event(
            "chain_break_test",
            {"status": "shim_rejected_broken_chain"},
            exc=exc,
        )
        print("[NEGATIVE] Chain test: shim correctly rejected broken chain.")
        print("\nLedger entries for chain test:")
        for entry in ledger.dump():
            print(entry)
        return

    ledger.append_event(
        "chain_break_test_failed",
        {"note": "shim accepted broken chain (governance breach)"},
    )
    raise RuntimeError("Governance breach: shim accepted a broken chain")


if __name__ == "__main__":
    run_simulation()

    print("\n\n============================")
    print("Running explicit negative tests")
    print("============================")

    run_negative_signature_test()
    run_negative_chain_test()
