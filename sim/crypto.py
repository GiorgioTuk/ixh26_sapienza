import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

ECDSA_P256 = ec.ECDSA(hashes.SHA256())


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def new_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def sign(key: ec.EllipticCurvePrivateKey, data: bytes) -> str:
    return key.sign(data, ECDSA_P256).hex()


def verify(public_key: ec.EllipticCurvePublicKey, signature_hex: str, data: bytes) -> bool:
    try:
        public_key.verify(bytes.fromhex(signature_hex), data, ECDSA_P256)
        return True
    except (InvalidSignature, ValueError):
        return False


def save_key(key: ec.EllipticCurvePrivateKey, path: Path) -> None:
    path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ))
    path.chmod(0o600)


def load_key(path: Path) -> ec.EllipticCurvePrivateKey:
    return serialization.load_pem_private_key(path.read_bytes(), password=None)


def issue_cert(subject: str, subject_key: ec.EllipticCurvePublicKey, issuer: str,
               issuer_key: ec.EllipticCurvePrivateKey, is_ca: bool = False) -> x509.Certificate:
    now = datetime.now(timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer)]))
        .public_key(subject_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
        .sign(issuer_key, hashes.SHA256())
    )


def cert_pem(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def load_cert(pem: str) -> x509.Certificate:
    return x509.load_pem_x509_certificate(pem.encode())
