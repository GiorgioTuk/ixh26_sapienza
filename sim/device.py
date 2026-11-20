"""Phase 1 entities: the photo sensor and the Secure Enclave each keep their own key, the device OS drives them."""

import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

from sim.crypto import load_key, sign
from sim.protocol import embedded_digest, enclave_payload, sensor_payload

CFA = "RGGB"
BIT_DEPTH = 12
BLACK_LEVEL = 256
WHITE_LEVEL = 2 ** BIT_DEPTH - 1
# Warm illuminant cast: Phase 2 has to white-balance it away.
ILLUMINANT = np.array([0.55, 1.0, 0.75])
READ_NOISE_DN = 6.0


class Sensor:
    def __init__(self, key):
        self._key = key
        self._rng = np.random.default_rng()

    def capture(self, scene: np.ndarray, digest: str) -> tuple[np.ndarray, dict, str]:
        h, w = scene.shape[0] // 2 * 2, scene.shape[1] // 2 * 2
        light = scene[:h, :w] * ILLUMINANT
        mosaic = np.empty((h, w))
        mosaic[0::2, 0::2] = light[0::2, 0::2, 0]
        mosaic[0::2, 1::2] = light[0::2, 1::2, 1]
        mosaic[1::2, 0::2] = light[1::2, 0::2, 1]
        mosaic[1::2, 1::2] = light[1::2, 1::2, 2]
        signal = mosaic * (WHITE_LEVEL - BLACK_LEVEL) * 0.8
        noise = self._rng.normal(0, 1, mosaic.shape) * np.sqrt(signal + READ_NOISE_DN ** 2)
        raw = np.clip(np.round(BLACK_LEVEL + signal + noise), 0, WHITE_LEVEL).astype("<u2")
        meta = {"width": w, "height": h, "cfa": CFA, "bit_depth": BIT_DEPTH,
                "black_level": BLACK_LEVEL, "white_level": WHITE_LEVEL, "dtype": "<u2",
                "embedded_digest": digest}
        return raw, meta, sign(self._key, sensor_payload(raw, meta))


class SecureEnclave:
    def __init__(self, key):
        self._key = key

    def bind(self, sigma_s: str, os_meta: dict) -> str:
        return sign(self._key, enclave_payload(sigma_s, os_meta))


@dataclass
class Device:
    device_id: str
    sensor: Sensor
    enclave: SecureEnclave
    manifest: dict
    boot_manifest: dict

    @classmethod
    def load(cls, device_dir: Path) -> "Device":
        return cls(
            device_id=device_dir.name,
            sensor=Sensor(load_key(device_dir / "sensor.key.pem")),
            enclave=SecureEnclave(load_key(device_dir / "enclave.key.pem")),
            manifest=json.loads((device_dir / "device_manifest.json").read_text()),
            boot_manifest=json.loads((device_dir / "secure_boot_manifest.json").read_text()),
        )

    def capture(self, scene: np.ndarray, t0: dict) -> tuple[np.ndarray, dict]:
        digest = embedded_digest(t0, self.manifest, self.boot_manifest)
        raw, frame, sigma_s = self.sensor.capture(scene, digest)
        os_meta = {"capture_id": uuid.uuid4().hex[:12], "lens": "main", "zoom": 1.0,
                   "exposure_ms": 8.0, "iso": 100,
                   "local_time": datetime.now(timezone.utc).isoformat(timespec="seconds")}
        sigma_e = self.enclave.bind(sigma_s, os_meta)
        record = {"device_id": self.device_id, "t0": t0, "frame": frame, "os_meta": os_meta,
                  "device_manifest": self.manifest, "secure_boot_manifest": self.boot_manifest,
                  "signatures": {"sensor": sigma_s, "enclave": sigma_e}}
        return raw, record
