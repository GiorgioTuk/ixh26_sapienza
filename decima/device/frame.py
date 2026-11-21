"""Raw frame layout (README, Capture and Attestation).

The sensor streams pixels first and metadata after, and signs exactly that: σs = ECDSA(sk_s, e) with
e = SHA256(raw_pix || metadata).
- raw_pix: 12-bit RGGB pixels as little-endian uint16, row-major (width * height * 2 bytes).
- metadata: fixed binary layout below, so dev_fields and digest_slot are fixed offsets. dev_fields hold the
  dev_params, the only fields that can be revealed: model-level values needed to develop the pixels.
  The other fields are per capture or per device and stay private; digest_slot holds
  H(T0 || dev_manifest || boot_manifest)."""

import struct

META_MAGIC = b"IXMD"
META_FIELDS = [  # (name, struct format), big-endian, after the 4-byte magic
    ("width", "H"), ("height", "H"), ("cfa", "4s"), ("bit_depth", "B"), ("black_level", "H"),
    ("white_level", "H"),                                                   # dev_fields
    ("frame_counter", "I"), ("exposure_us", "I"), ("analog_gain_q8", "H"),  # private, per capture
    ("digest_slot", "32s"),                                                 # private, device-bound
]
DEV_FIELDS = ["width", "height", "cfa", "bit_depth", "black_level", "white_level"]
_FORMAT = ">4s" + "".join(f for _, f in META_FIELDS)
META_SIZE = struct.calcsize(_FORMAT)
DIGEST_SLOT = slice(META_SIZE - 32, META_SIZE)  # fixed offset of the digest inside metadata

MODEL = "SimCam-1"
SENSOR_PARAMS = {"cfa": "RGGB", "bit_depth": 12, "black_level": 256, "white_level": 4095}
MODEL_DEV_PARAMS = {"width": 1920, "height": 1080, **SENSOR_PARAMS}  # what the trust root admits for the model


def pack_metadata(fields: dict) -> bytes:
    values = [fields[n].encode() if n == "cfa" else fields[n] for n, _ in META_FIELDS]
    return struct.pack(_FORMAT, META_MAGIC, *values)


def unpack_metadata(metadata: bytes) -> dict:
    magic, *values = struct.unpack(_FORMAT, metadata)
    if magic != META_MAGIC:
        raise ValueError("not a raw frame metadata block")
    fields = dict(zip([n for n, _ in META_FIELDS], values))
    fields["cfa"] = fields["cfa"].decode()
    return fields


def dev_params_of(metadata: bytes) -> dict:
    fields = unpack_metadata(metadata)
    return {n: fields[n] for n in DEV_FIELDS}


def pixel_bytes(dev_params: dict) -> int:
    """Length of raw_pix: uint16 per pixel."""
    return dev_params["width"] * dev_params["height"] * 2
