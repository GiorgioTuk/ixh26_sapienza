"""Prepaid blind tokens (README, Capture: "paying the fee with a prepaid blind token").

RSA blind signatures, RFC 9474, variant RSABSSA-SHA384-PSS-Deterministic: the proxy signs blinded token
nonces when they are bought, the user unblinds them, and at redemption the proxy sees a valid signature it
cannot link to any purchase. The final token signature is a standard RSASSA-PSS signature (SHA-384, MGF1-SHA-384,
48-byte salt), so it is verified with the standard library call."""

import hashlib
import math
import os
import secrets

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

H_LEN = S_LEN = 48
PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA384()), salt_length=S_LEN)


def _mgf1(seed: bytes, length: int) -> bytes:
    return b"".join(hashlib.sha384(seed + i.to_bytes(4, "big")).digest()
                    for i in range(math.ceil(length / H_LEN)))[:length]


def _emsa_pss_encode(msg: bytes, em_bits: int) -> bytes:
    em_len = math.ceil(em_bits / 8)
    m_hash, salt = hashlib.sha384(msg).digest(), os.urandom(S_LEN)
    h = hashlib.sha384(bytes(8) + m_hash + salt).digest()
    db = bytes(em_len - S_LEN - H_LEN - 2) + b"\x01" + salt
    masked = bytearray(a ^ b for a, b in zip(db, _mgf1(h, em_len - H_LEN - 1)))
    masked[0] &= 0xFF >> (8 * em_len - em_bits)
    return bytes(masked) + h + b"\xbc"


def new_issuer_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def blind(pk: rsa.RSAPublicKey, msg: bytes) -> tuple[bytes, int]:
    """User: returns the blinded message for the proxy and the secret needed to unblind."""
    n, e = pk.public_numbers().n, pk.public_numbers().e
    k = (n.bit_length() + 7) // 8
    m = int.from_bytes(_emsa_pss_encode(msg, n.bit_length() - 1), "big")
    while True:
        r = secrets.randbelow(n - 1) + 1
        if math.gcd(r, n) == 1:
            break
    return (m * pow(r, e, n) % n).to_bytes(k, "big"), pow(r, -1, n)


def blind_sign(sk: rsa.RSAPrivateKey, blinded: bytes) -> bytes:
    """Proxy: signs without seeing the message."""
    nums = sk.private_numbers()
    n, d, e = nums.public_numbers.n, nums.d, nums.public_numbers.e
    z = int.from_bytes(blinded, "big")
    if z >= n:
        raise ValueError("blinded message out of range")
    s = pow(z, d, n)
    if pow(s, e, n) != z:
        raise ValueError("signing failure")
    return s.to_bytes((n.bit_length() + 7) // 8, "big")


def finalize(pk: rsa.RSAPublicKey, msg: bytes, blind_sig: bytes, inv: int) -> bytes:
    """User: unblinds; the result is a standard RSA-PSS signature on msg."""
    n = pk.public_numbers().n
    sig = (int.from_bytes(blind_sig, "big") * inv % n).to_bytes((n.bit_length() + 7) // 8, "big")
    if not verify(pk, msg, sig):
        raise ValueError("invalid blind signature")
    return sig


def verify(pk: rsa.RSAPublicKey, msg: bytes, sig: bytes) -> bool:
    try:
        pk.verify(sig, msg, PSS, hashes.SHA384())
        return True
    except InvalidSignature:
        return False
