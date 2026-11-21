"""Factory provisioning (README, Setup: keys and manifest "certified by the hardware manufacturers and
assemblers"). The sensor and the Secure Enclave generate their own key pairs; the assembler signs the device
manifest that binds the two public keys, σ_man = ECDSA(sk_man, H(manifest))."""

import json
import uuid
from pathlib import Path

from decima.core.config import OUT_DIR
from decima.core.crypto import H, canonical, load_key, new_key, pk_bytes, save_key, sign
from decima.device.frame import MODEL
from decima.device.hardware import DEVICES_DIR

MAKERS_DIR = OUT_DIR / "makers"
OS_NAME = "SimOS 1.0"


def assembler_key():
    """The assembler's manifest-signing key; its public half is pk_man."""
    MAKERS_DIR.mkdir(parents=True, exist_ok=True)
    path = MAKERS_DIR / "assembler.key.pem"
    if not path.exists():
        save_key(new_key(), path)
    return load_key(path)


def provision() -> Path:
    device_id = uuid.uuid4().hex[:12]
    d = DEVICES_DIR / device_id
    d.mkdir(parents=True)
    sensor_key, enclave_key = new_key(), new_key()
    dev_manifest = canonical({"model": MODEL, "serial": device_id,
                              "pk_s": pk_bytes(sensor_key.public_key()).hex(),
                              "pk_e": pk_bytes(enclave_key.public_key()).hex()})
    boot_manifest = canonical({"os": OS_NAME, "os_sha256": H(OS_NAME.encode()).hex(), "secure_boot": True})
    save_key(sensor_key, d / "sensor.key.pem")
    save_key(enclave_key, d / "enclave.key.pem")
    (d / "dev_manifest.json").write_bytes(dev_manifest)
    (d / "dev_manifest.sig").write_bytes(sign(assembler_key(), dev_manifest))
    (d / "boot_manifest.json").write_bytes(boot_manifest)
    (d / "state.json").write_text(json.dumps({"frame_counter": 0}))
    return d


def device_key_hashes(device_dir: Path) -> dict:
    """H(pk_s) and H(pk_e), the registry leaves of a device."""
    manifest = json.loads((device_dir / "dev_manifest.json").read_bytes())
    return {"sensor": H(bytes.fromhex(manifest["pk_s"])), "enclave": H(bytes.fromhex(manifest["pk_e"]))}
