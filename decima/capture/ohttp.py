"""Oblivious HTTP (RFC 9458) for sending C anonymously (README, Capture: "anonymously (over OHTTP)").

The client encrypts a Binary HTTP request (RFC 9292) to the gateway's HPKE key and sends it through a relay:
the relay sees the client's address but only ciphertext, the gateway sees the request but only the relay's
address. HPKE (RFC 9180) is implemented here in base mode with DHKEM(X25519, HKDF-SHA256), HKDF-SHA256,
AES-128-GCM, because OHTTP needs the HPKE secret export to encrypt the response, which the one-shot HPKE API
of `cryptography` does not expose. Interoperability with that API is checked in the tests."""

import hashlib
import hmac
import os
import struct

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEM_ID, KDF_ID, AEAD_ID = 0x0020, 0x0001, 0x0001
NK, NN, NH = 16, 12, 32
KEY_ID = 1
REQUEST_LABEL, RESPONSE_LABEL = b"message/bhttp request", b"message/bhttp response"


# --- HPKE (RFC 9180), base mode -------------------------------------------------------------------------

def _extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt or bytes(NH), ikm, hashlib.sha256).digest()


def _expand(prk: bytes, info: bytes, length: int) -> bytes:
    out, block, i = b"", b"", 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([i]), hashlib.sha256).digest()
        out, i = out + block, i + 1
    return out[:length]


def _labeled_extract(suite: bytes, salt: bytes, label: bytes, ikm: bytes) -> bytes:
    return _extract(salt, b"HPKE-v1" + suite + label + ikm)


def _labeled_expand(suite: bytes, prk: bytes, label: bytes, info: bytes, length: int) -> bytes:
    return _expand(prk, struct.pack(">H", length) + b"HPKE-v1" + suite + label + info, length)


_KEM_SUITE = b"KEM" + struct.pack(">H", KEM_ID)
_HPKE_SUITE = b"HPKE" + struct.pack(">HHH", KEM_ID, KDF_ID, AEAD_ID)


def _raw(pk: x25519.X25519PublicKey) -> bytes:
    return pk.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _shared_secret(dh: bytes, enc: bytes, pk_r: bytes) -> bytes:
    prk = _labeled_extract(_KEM_SUITE, b"", b"eae_prk", dh)
    return _labeled_expand(_KEM_SUITE, prk, b"shared_secret", enc + pk_r, NH)


class Context:
    def __init__(self, shared_secret: bytes, info: bytes):
        s = _HPKE_SUITE
        ctx = b"\x00" + _labeled_extract(s, b"", b"psk_id_hash", b"") + _labeled_extract(s, b"", b"info_hash", info)
        secret = _labeled_extract(s, shared_secret, b"secret", b"")
        self.key = _labeled_expand(s, secret, b"key", ctx, NK)
        self.nonce = _labeled_expand(s, secret, b"base_nonce", ctx, NN)  # sequence number 0: single message
        self.exporter = _labeled_expand(s, secret, b"exp", ctx, NH)

    def seal(self, aad: bytes, pt: bytes) -> bytes:
        return AESGCM(self.key).encrypt(self.nonce, pt, aad)

    def open(self, aad: bytes, ct: bytes) -> bytes:
        return AESGCM(self.key).decrypt(self.nonce, ct, aad)

    def export(self, context: bytes, length: int) -> bytes:
        return _labeled_expand(_HPKE_SUITE, self.exporter, b"sec", context, length)


def setup_sender(pk_r: x25519.X25519PublicKey, info: bytes) -> tuple[bytes, Context]:
    sk_e = x25519.X25519PrivateKey.generate()
    enc = _raw(sk_e.public_key())
    return enc, Context(_shared_secret(sk_e.exchange(pk_r), enc, _raw(pk_r)), info)


def setup_receiver(enc: bytes, sk_r: x25519.X25519PrivateKey, info: bytes) -> Context:
    dh = sk_r.exchange(x25519.X25519PublicKey.from_public_bytes(enc))
    return Context(_shared_secret(dh, enc, _raw(sk_r.public_key())), info)


# --- Binary HTTP (RFC 9292), known-length messages --------------------------------------------------------

def _varint(n: int) -> bytes:
    for prefix, size in ((0, 1), (1, 2), (2, 4), (3, 8)):
        if n < 1 << (8 * size - 2):
            return (n | prefix << (8 * size - 2)).to_bytes(size, "big")
    raise ValueError("varint too large")


def _read_varint(b: bytes, i: int) -> tuple[int, int]:
    size = 1 << (b[i] >> 6)
    return int.from_bytes(bytes([b[i] & 0x3F]) + b[i + 1:i + size], "big"), i + size


def _lp(data: bytes) -> bytes:
    return _varint(len(data)) + data


def _read_lp(b: bytes, i: int) -> tuple[bytes, int]:
    n, i = _read_varint(b, i)
    return b[i:i + n], i + n


def _fields(headers: dict) -> bytes:
    return _lp(b"".join(_lp(k.encode()) + _lp(v.encode()) for k, v in headers.items()))


def bhttp_request(method: str, authority: str, path: str, headers: dict, body: bytes) -> bytes:
    return (_varint(0) + _lp(method.encode()) + _lp(b"https") + _lp(authority.encode()) + _lp(path.encode())
            + _fields(headers) + _lp(body) + _varint(0))


def parse_bhttp_request(b: bytes) -> dict:
    framing, i = _read_varint(b, 0)
    if framing != 0:
        raise ValueError("not a known-length request")
    method, i = _read_lp(b, i)
    _, i = _read_lp(b, i)
    authority, i = _read_lp(b, i)
    path, i = _read_lp(b, i)
    _, i = _read_lp(b, i)
    body, i = _read_lp(b, i)
    return {"method": method.decode(), "authority": authority.decode(), "path": path.decode(), "body": body}


def bhttp_response(status: int, body: bytes) -> bytes:
    return _varint(1) + _varint(status) + _fields({"content-type": "application/json"}) + _lp(body) + _varint(0)


def parse_bhttp_response(b: bytes) -> tuple[int, bytes]:
    framing, i = _read_varint(b, 0)
    if framing != 1:
        raise ValueError("not a known-length response")
    status, i = _read_varint(b, i)
    _, i = _read_lp(b, i)
    body, _ = _read_lp(b, i)
    return status, body


# --- OHTTP (RFC 9458) -------------------------------------------------------------------------------------

def _header() -> bytes:
    return struct.pack(">BHHH", KEY_ID, KEM_ID, KDF_ID, AEAD_ID)


def encapsulate_request(pk_gateway: x25519.X25519PublicKey, request: bytes) -> tuple[bytes, Context, bytes]:
    hdr = _header()
    enc, ctx = setup_sender(pk_gateway, REQUEST_LABEL + b"\x00" + hdr)
    return hdr + enc + ctx.seal(b"", request), ctx, enc


def decapsulate_request(sk_gateway: x25519.X25519PrivateKey, message: bytes) -> tuple[bytes, Context, bytes]:
    hdr, enc, ct = message[:7], message[7:39], message[39:]
    if hdr != _header():
        raise ValueError("unknown OHTTP key configuration")
    ctx = setup_receiver(enc, sk_gateway, REQUEST_LABEL + b"\x00" + hdr)
    return ctx.open(b"", ct), ctx, enc


def _response_keys(ctx: Context, enc: bytes, response_nonce: bytes) -> tuple[bytes, bytes]:
    secret = ctx.export(RESPONSE_LABEL, max(NN, NK))
    prk = _extract(enc + response_nonce, secret)
    return _expand(prk, b"key", NK), _expand(prk, b"nonce", NN)


def encapsulate_response(ctx: Context, enc: bytes, response: bytes) -> bytes:
    response_nonce = os.urandom(max(NN, NK))
    key, nonce = _response_keys(ctx, enc, response_nonce)
    return response_nonce + AESGCM(key).encrypt(nonce, response, b"")


def decapsulate_response(ctx: Context, enc: bytes, message: bytes) -> bytes:
    response_nonce, ct = message[:max(NN, NK)], message[max(NN, NK):]
    key, nonce = _response_keys(ctx, enc, response_nonce)
    return AESGCM(key).decrypt(nonce, ct, b"")


class Relay:
    """Forwards encapsulated requests: knows who sends, cannot read what."""

    def __init__(self, gateway):
        self.gateway, self.log = gateway, []

    def forward(self, client_address: str, message: bytes) -> bytes:
        self.log.append(f"relay   saw client {client_address}, {len(message)} encrypted bytes, content unreadable")
        return self.gateway.handle("relay", message)
