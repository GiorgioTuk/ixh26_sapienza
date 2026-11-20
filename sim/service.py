"""Simulated reference-signing service: composite ML-DSA-87 + RSA-3072-PSS-SHA512, as in Apple's final signature.
The composite is valid only if BOTH signatures verify, so it stays secure while either algorithm holds."""

import base64
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import mldsa, padding, rsa

from sim.config import OUT_DIR
from sim.crypto import canonical, load_key, save_key, sha256_hex

SERVICE_DIR = OUT_DIR / "service"
PUBLIC_FILE = SERVICE_DIR / "service_public.json"
SCHEME = "MLDSA87-RSA3072-PSS-SHA512"
PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA512()), salt_length=padding.PSS.DIGEST_LENGTH)


def _public_pem(key) -> str:
    return key.public_key().public_bytes(serialization.Encoding.PEM,
                                         serialization.PublicFormat.SubjectPublicKeyInfo).decode()


def load_or_create_keys() -> dict:
    SERVICE_DIR.mkdir(parents=True, exist_ok=True)
    paths = {"mldsa87": SERVICE_DIR / "mldsa87.key.pem", "rsa3072": SERVICE_DIR / "rsa3072.key.pem"}
    if all(p.exists() for p in paths.values()):
        return {name: load_key(p) for name, p in paths.items()}
    keys = {"mldsa87": mldsa.MLDSA87PrivateKey.generate(),
            "rsa3072": rsa.generate_private_key(public_exponent=65537, key_size=3072)}
    for name, key in keys.items():
        save_key(key, paths[name])
    public = {"scheme": SCHEME, **{name: _public_pem(key) for name, key in keys.items()}}
    public["key_id"] = sha256_hex(canonical(public))[:16]
    PUBLIC_FILE.write_text(json.dumps(public, indent=2))
    return keys


def load_public() -> dict:
    public = json.loads(PUBLIC_FILE.read_text())
    return {"key_id": public["key_id"],
            **{name: serialization.load_pem_public_key(public[name].encode()) for name in ("mldsa87", "rsa3072")}}


def sign(keys: dict, message: bytes) -> dict:
    return {
        "scheme": SCHEME,
        "key_id": json.loads(PUBLIC_FILE.read_text())["key_id"],
        "mldsa87": base64.b64encode(keys["mldsa87"].sign(message)).decode(),
        "rsa3072_pss_sha512": base64.b64encode(keys["rsa3072"].sign(message, PSS, hashes.SHA512())).decode(),
    }


def verify(public: dict, message: bytes, signature: dict) -> bool:
    if signature.get("scheme") != SCHEME or signature.get("key_id") != public["key_id"]:
        return False
    try:
        public["mldsa87"].verify(base64.b64decode(signature["mldsa87"]), message)
        public["rsa3072"].verify(base64.b64decode(signature["rsa3072_pss_sha512"]), message, PSS, hashes.SHA512())
        return True
    except (InvalidSignature, ValueError, KeyError):
        return False
