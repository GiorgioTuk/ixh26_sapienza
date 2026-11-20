"""Exact bytes each entity signs or commits to; capture and verification must both use these."""

import numpy as np

from sim.crypto import canonical, sha256_hex

BUNDLE_FORMAT = "ixh26-secure-negative/1"
COMMITMENT_MEMO_TYPE = "ixh26/capture-commitment"


def embedded_digest(t0: dict, device_manifest: dict, boot_manifest: dict) -> str:
    """The only input the sensor accepts before capture: binds T0, device and boot state."""
    return sha256_hex(canonical({
        "t0": t0,
        "device_manifest_sha256": sha256_hex(canonical(device_manifest)),
        "secure_boot_manifest_sha256": sha256_hex(canonical(boot_manifest)),
    }))


def sensor_payload(raw: np.ndarray, frame_meta: dict) -> bytes:
    return raw.astype("<u2").tobytes() + canonical(frame_meta)


def enclave_payload(sigma_s: str, os_meta: dict) -> bytes:
    return canonical({"sigma_s_sha256": sha256_hex(bytes.fromhex(sigma_s)), "os_meta": os_meta})


def commitment(sigma_e: str) -> str:
    """What the device anchors on the ledger to obtain the upper-bound timestamp T1."""
    return sha256_hex(bytes.fromhex(sigma_e))
