from __future__ import annotations

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


def generate_ec_key():
    """Generate an ECDSA P-256 keypair."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    return private_key, private_key.public_key()


def sign_ec(private_key, payload: bytes) -> bytes:
    """Sign payload with ECDSA(SHA-256)."""
    return private_key.sign(payload, ec.ECDSA(hashes.SHA256()))


def verify_ec(public_key, signature: bytes, payload: bytes) -> None:
    """Verify ECDSA signature; raises on failure."""
    public_key.verify(signature, payload, ec.ECDSA(hashes.SHA256()))


def serialize_pubkey_hex(public_key) -> str:
    """Hex-encode an uncompressed EC point (optional for inspection)."""
    return public_key.public_bytes(
        encoding=Encoding.X962,
        format=PublicFormat.UncompressedPoint,
    ).hex()
