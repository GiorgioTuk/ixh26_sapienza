"""SHA-256 that can stop after the full 64-byte blocks of a message and resume later from its 32-byte state.

README, Attestation: S is the state right after the last full block of pixels and tail the remaining pixel
bytes; the verifier computes (S, tail) from raw_pix, the circuit resumes from S over tail || metadata.
hashlib does not expose the internal state, so the compression function (FIPS 180-4) is written out here;
results are checked against hashlib in the tests."""

import math
import struct


def _icbrt(n: int) -> int:
    x = 1 << ((n.bit_length() + 2) // 3)
    while True:
        y = (2 * x + n // (x * x)) // 3
        if y >= x:
            return x
        x = y


_PRIMES = [p for p in range(2, 312) if all(p % q for q in range(2, math.isqrt(p) + 1))][:64]
_K = [_icbrt(p << 96) & 0xFFFFFFFF for p in _PRIMES]                 # cube roots of the first 64 primes
IV = bytes(b for p in _PRIMES[:8] for b in (math.isqrt(p << 64) & 0xFFFFFFFF).to_bytes(4, "big"))
_M = 0xFFFFFFFF


def _compress(state: tuple, block: bytes) -> tuple:
    w = list(struct.unpack(">16I", block))
    for i in range(16, 64):
        x, y = w[i - 15], w[i - 2]
        s0 = ((x >> 7 | x << 25) ^ (x >> 18 | x << 14) ^ (x >> 3)) & _M
        s1 = ((y >> 17 | y << 15) ^ (y >> 19 | y << 13) ^ (y >> 10)) & _M
        w.append((w[i - 16] + s0 + w[i - 7] + s1) & _M)
    a, b, c, d, e, f, g, h = state
    for i in range(64):
        t1 = (h + ((e >> 6 | e << 26) ^ (e >> 11 | e << 21) ^ (e >> 25 | e << 7)) + ((e & f) ^ (~e & g))
              + _K[i] + w[i]) & _M
        t2 = (((a >> 2 | a << 30) ^ (a >> 13 | a << 19) ^ (a >> 22 | a << 10)) + ((a & b) ^ (a & c) ^ (b & c))) & _M
        a, b, c, d, e, f, g, h = (t1 + t2) & _M, a, b, c, (d + t1) & _M, e, f, g
    return tuple((s + v) & _M for s, v in zip(state, (a, b, c, d, e, f, g, h)))


def midstate(data: bytes) -> tuple[bytes, bytes]:
    """(S, tail): state after the full blocks of data, and the remaining bytes (fewer than 64)."""
    state = struct.unpack(">8I", IV)
    full = len(data) - len(data) % 64
    view = memoryview(data)
    for i in range(0, full, 64):
        state = _compress(state, view[i:i + 64].tobytes())
    return struct.pack(">8I", *state), data[full:]


def resume(state: bytes, processed: int, rest: bytes) -> bytes:
    """SHA-256 digest of a message whose first `processed` bytes (a multiple of 64) led to `state`,
    followed by `rest`."""
    if processed % 64 or len(state) != 32:
        raise ValueError("state must follow whole blocks")
    total = processed + len(rest)
    padded = rest + b"\x80" + bytes((55 - total) % 64) + struct.pack(">Q", total * 8)
    s = struct.unpack(">8I", state)
    for i in range(0, len(padded), 64):
        s = _compress(s, padded[i:i + 64])
    return struct.pack(">8I", *s)
