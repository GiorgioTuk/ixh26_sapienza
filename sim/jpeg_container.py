"""Embed or strip the reference signature in a JPEG APP11 segment (Apple embeds its final signature in the JPEG).
The signed commitment is SHA-256 of the JPEG without this segment."""

APP0, APP11, SOS = 0xE0, 0xEB, 0xDA
TAG = b"IXH26-SIG\x00"


def _header_segments(jpeg: bytes):
    if jpeg[:2] != b"\xff\xd8":
        raise ValueError("not a JPEG")
    i = 2
    while i + 4 <= len(jpeg) and jpeg[i] == 0xFF and jpeg[i + 1] != SOS:
        end = i + 2 + int.from_bytes(jpeg[i + 2:i + 4], "big")
        yield i, end, jpeg[i + 1]
        i = end


def embed(jpeg: bytes, payload: bytes) -> bytes:
    body = TAG + payload
    if len(body) + 2 > 0xFFFF:
        raise ValueError("payload too large for one JPEG segment")
    segment = bytes([0xFF, APP11]) + (len(body) + 2).to_bytes(2, "big") + body
    first = next(_header_segments(jpeg), None)
    at = first[1] if first and first[2] == APP0 else 2  # keep the JFIF APP0 segment first
    return jpeg[:at] + segment + jpeg[at:]


def extract(jpeg: bytes) -> tuple[bytes, bytes | None]:
    for start, end, marker in _header_segments(jpeg):
        if marker == APP11 and jpeg[start + 4:start + 4 + len(TAG)] == TAG:
            return jpeg[:start] + jpeg[end:], jpeg[start + 4 + len(TAG):end]
    return jpeg, None
