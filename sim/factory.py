"""Simulated factory: three CAs, then one provisioned device per run (sensor key, enclave key, manifest)."""

import json
import uuid
from datetime import datetime, timezone

from sim.config import OUT_DIR
from sim.crypto import (canonical, cert_pem, issue_cert, load_cert, load_key, new_key, save_key,
                        sha256_hex, sign)

FACTORY_DIR = OUT_DIR / "factory"
DEVICES_DIR = OUT_DIR / "devices"

CAS = {
    "sensor-ca": "CA 1: certifies photo-sensor keys",
    "attestation-ca": "CA 2: certifies Secure Enclave keys",
    "manifest-ca": "CA 3: signs device manifests binding sensor and enclave",
}
MODEL = "SimCam-1"
FIRMWARE = "SimOS 1.0"


def load_or_create_cas() -> dict:
    FACTORY_DIR.mkdir(parents=True, exist_ok=True)
    cas = {}
    for name in CAS:
        key_path, cert_path = FACTORY_DIR / f"{name}.key.pem", FACTORY_DIR / f"{name}.cert.pem"
        if key_path.exists():
            cas[name] = (load_key(key_path), load_cert(cert_path.read_text()))
            continue
        key = new_key()
        cert = issue_cert(name, key.public_key(), name, key, is_ca=True)
        save_key(key, key_path)
        cert_path.write_text(cert_pem(cert))
        cas[name] = (key, cert)
    return cas


def provision_device(cas: dict) -> str:
    device_id = uuid.uuid4().hex[:12]
    device_dir = DEVICES_DIR / device_id
    device_dir.mkdir(parents=True)

    sensor_key, enclave_key = new_key(), new_key()
    sensor_ca_key, _ = cas["sensor-ca"]
    attestation_ca_key, _ = cas["attestation-ca"]
    manifest_ca_key, _ = cas["manifest-ca"]

    manifest = {
        "device_id": device_id,
        "model": MODEL,
        "sensor_cert": cert_pem(issue_cert(f"sensor:{device_id}", sensor_key.public_key(),
                                           "sensor-ca", sensor_ca_key)),
        "enclave_cert": cert_pem(issue_cert(f"enclave:{device_id}", enclave_key.public_key(),
                                            "attestation-ca", attestation_ca_key)),
        "issued_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    signed_manifest = {"manifest": manifest, "signer": "manifest-ca",
                       "signature": sign(manifest_ca_key, canonical(manifest))}
    boot_manifest = {"firmware": FIRMWARE, "firmware_sha256": sha256_hex(FIRMWARE.encode()),
                     "secure_boot": True}

    save_key(sensor_key, device_dir / "sensor.key.pem")
    save_key(enclave_key, device_dir / "enclave.key.pem")
    (device_dir / "device_manifest.json").write_text(json.dumps(signed_manifest, indent=2))
    (device_dir / "secure_boot_manifest.json").write_text(json.dumps(boot_manifest, indent=2))
    return device_id


def main() -> None:
    cas = load_or_create_cas()
    device_id = provision_device(cas)
    print("Certificate authorities (out/factory/):")
    for name, role in CAS.items():
        print(f"  {name:<15} {role}")
    print(f"\nProvisioned device {device_id} ({MODEL}) in out/devices/{device_id}/")


if __name__ == "__main__":
    main()
