"""SHA-256, canonical JSON and ECDSA P-256 (the primitives the README's circuit is built on)."""

import hashlib
import json
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

ECDSA_P256 = ec.ECDSA(hashes.SHA256())  # ECDSA.sign/verify hash the message with SHA-256 first


def H(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def new_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def sign(key: ec.EllipticCurvePrivateKey, message: bytes) -> bytes:
    return key.sign(message, ECDSA_P256)


def verify(public_key: ec.EllipticCurvePublicKey, signature: bytes, message: bytes) -> bool:
    try:
        public_key.verify(signature, message, ECDSA_P256)
        return True
    except (InvalidSignature, ValueError):
        return False


def pk_bytes(public_key: ec.EllipticCurvePublicKey) -> bytes:
    """Uncompressed SEC1 point (65 bytes): the encoding hashed into the registries, H(pk)."""
    return public_key.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)


def pk_from_bytes(data: bytes) -> ec.EllipticCurvePublicKey:
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), data)


def save_key(key: ec.EllipticCurvePrivateKey, path: Path) -> None:
    path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                       serialization.NoEncryption()))
    path.chmod(0o600)


def load_key(path: Path) -> ec.EllipticCurvePrivateKey:
    return serialization.load_pem_private_key(path.read_bytes(), password=None)
