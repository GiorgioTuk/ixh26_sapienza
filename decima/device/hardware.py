"""Photo sensor and Secure Enclave of a provisioned device (README, Capture: "as in Apple").

- The OS computes D = H(T0 || dev_manifest || boot_manifest) and gives it to the sensor.
- The sensor digitises the scene, writes D in the metadata digest slot and signs e = SHA256(raw_pix || metadata).
- The Secure Enclave signs H(σs) together with the OS-derived metadata (σe)."""

import json
from pathlib import Path

import numpy as np

from decima.core.config import OUT_DIR
from decima.core.crypto import H, canonical, load_key, sign
from decima.device.frame import SENSOR_PARAMS, pack_metadata

DEVICES_DIR = OUT_DIR / "devices"
ILLUMINANT = np.array([0.55, 1.0, 0.75])  # per-channel sensor response to the scene light
READ_NOISE_DN = 6.0


def pick_device(device_id: str | None) -> Path:
    if device_id:
        path = DEVICES_DIR / device_id
        if not path.is_dir():
            raise SystemExit(f"device {device_id} not found in {DEVICES_DIR}")
        return path
    devices = sorted(DEVICES_DIR.glob("*/dev_manifest.json"), key=lambda p: p.stat().st_mtime)
    if not devices:
        raise SystemExit("no device yet: run python -m decima.setup device")
    return devices[-1].parent


class Device:
    def __init__(self, path: Path):
        self.path, self.id = path, path.name
        self.sensor_key = load_key(path / "sensor.key.pem")
        self.enclave_key = load_key(path / "enclave.key.pem")
        self.dev_manifest = (path / "dev_manifest.json").read_bytes()
        self.manifest_sig = (path / "dev_manifest.sig").read_bytes()
        self.boot_manifest = (path / "boot_manifest.json").read_bytes()

    def _next_frame_counter(self) -> int:
        state = json.loads((self.path / "state.json").read_text())
        state["frame_counter"] += 1
        (self.path / "state.json").write_text(json.dumps(state))
        return state["frame_counter"]

    def embedded_digest(self, t0: bytes) -> bytes:
        """D = H(T0 || dev_manifest || boot_manifest), computed by the OS and given to the sensor."""
        return H(t0 + self.dev_manifest + self.boot_manifest)

    def sensor_capture(self, scene: np.ndarray, digest: bytes, rng: np.random.Generator) -> dict:
        """Inside the sensor: digitise, stream raw_pix then metadata (with D), sign e = SHA256(raw_pix || metadata)."""
        h, w, _ = scene.shape
        black, white = SENSOR_PARAMS["black_level"], SENSOR_PARAMS["white_level"]
        cfa = np.empty((h, w))
        cfa[0::2, 0::2] = scene[0::2, 0::2, 0] * ILLUMINANT[0]
        cfa[0::2, 1::2] = scene[0::2, 1::2, 1] * ILLUMINANT[1]
        cfa[1::2, 0::2] = scene[1::2, 0::2, 1] * ILLUMINANT[1]
        cfa[1::2, 1::2] = scene[1::2, 1::2, 2] * ILLUMINANT[2]
        signal = cfa * (white - black) * 0.9
        signal = signal + rng.normal(0, 1, signal.shape) * np.sqrt(np.maximum(signal, 0) * 0.25 + READ_NOISE_DN ** 2)
        raw_pix = np.clip(np.round(signal + black), 0, white).astype("<u2")
        metadata = pack_metadata({"width": w, "height": h, **SENSOR_PARAMS,
                                  "frame_counter": self._next_frame_counter(), "exposure_us": 8333,
                                  "analog_gain_q8": 256, "digest_slot": digest})
        return {"raw_pix": raw_pix, "metadata": metadata, "sigma_s": sign(self.sensor_key, raw_pix.tobytes() + metadata)}

    def enclave_bind(self, sigma_s: bytes, os_meta: bytes) -> bytes:
        """σe: the Secure Enclave signs H(σs) together with the OS-derived metadata."""
        return sign(self.enclave_key, H(sigma_s) + os_meta)


def os_metadata() -> bytes:
    """Metadata from outside the sensor (lens, zoom, exposure, ISO), signed by the Secure Enclave."""
    return canonical({"lens": "wide", "zoom": 1.0, "exposure_ms": 8.333, "iso": 100})
