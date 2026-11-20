"""Phase 2a: open verifier replacing Apple's PCC checks. Needs only the CA root certificates and a ledger node."""

from datetime import datetime, timezone
from pathlib import Path

import numpy as np
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.x509.oid import NameOID
from xrpl.clients import JsonRpcClient

from sim.crypto import canonical, load_cert, sha256_hex, verify
from sim.factory import CAS, FACTORY_DIR
from sim.protocol import BUNDLE_FORMAT, embedded_digest, enclave_payload, sensor_payload
from sim.report import FAIL, OK, SKIP, WARN, Check, check
from sim.timestamps import verify_window


def load_trust_roots(directory: Path = FACTORY_DIR) -> dict[str, x509.Certificate]:
    return {name: load_cert((directory / f"{name}.cert.pem").read_text()) for name in CAS}


def check_leaf(name: str, cert: x509.Certificate, root: x509.Certificate, expected_subject: str) -> Check:
    try:
        cert.verify_directly_issued_by(root)
    except (InvalidSignature, ValueError, TypeError):
        return Check(name, FAIL, f"not issued by {root.subject.rfc4514_string()}")
    now = datetime.now(timezone.utc)
    if not cert.not_valid_before_utc <= now <= cert.not_valid_after_utc:
        return Check(name, FAIL, "certificate expired or not yet valid")
    subject = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    if subject != expected_subject:
        return Check(name, FAIL, f"subject {subject}, expected {expected_subject}")
    if cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
        return Check(name, FAIL, "leaf certificate is marked as a CA")
    return Check(name, OK, subject)


def verify_capture(bundle: dict, raw: np.ndarray, roots: dict[str, x509.Certificate],
                   client: JsonRpcClient | None) -> list[Check]:
    frame, sigs, signed = bundle["frame"], bundle["signatures"], bundle["device_manifest"]
    manifest = signed["manifest"]
    device_id = manifest["device_id"]
    sensor_cert, enclave_cert = load_cert(manifest["sensor_cert"]), load_cert(manifest["enclave_cert"])

    checks = [
        check("Bundle format", bundle.get("format") == BUNDLE_FORMAT, BUNDLE_FORMAT,
              f"unknown format {bundle.get('format')}"),
        check("Raw frame matches metadata",
              raw.dtype == np.dtype("<u2") and raw.shape == (frame["height"], frame["width"]),
              f"{frame['width']}x{frame['height']} {frame['cfa']} {frame['bit_depth']}-bit",
              f"raw is {raw.shape} {raw.dtype}"),
        check("Raw SHA-256", bundle["raw_sha256"] == sha256_hex(raw.astype("<u2").tobytes()),
              detail_fail="raw frame differs from the recorded hash"),
        check("Manifest signed by CA 3",
              signed.get("signer") == "manifest-ca"
              and verify(roots["manifest-ca"].public_key(), signed["signature"], canonical(manifest)),
              f"device {device_id}", "manifest signature invalid"),
        check_leaf("Sensor cert by CA 1", sensor_cert, roots["sensor-ca"], f"sensor:{device_id}"),
        check_leaf("Enclave cert by CA 2", enclave_cert, roots["attestation-ca"], f"enclave:{device_id}"),
        check("Same-device binding", bundle["device_id"] == device_id,
              f"sensor and enclave both belong to device {device_id}",
              f"bundle claims device {bundle['device_id']}, manifest is for {device_id}"),
        check("Embedded digest (T0 + manifests)",
              frame["embedded_digest"] == embedded_digest(bundle["t0"], signed, bundle["secure_boot_manifest"]),
              "sensor was given this T0, device and boot state",
              "T0 or manifests differ from what the sensor was given"),
        check("σs sensor signature",
              verify(sensor_cert.public_key(), sigs["sensor"], sensor_payload(raw, frame)),
              "raw frame + metadata signed by the sensor", "sensor signature does not match raw frame"),
        check("σe enclave signature",
              verify(enclave_cert.public_key(), sigs["enclave"], enclave_payload(sigs["sensor"], bundle["os_meta"])),
              "σs + OS metadata signed by the enclave", "enclave signature does not match σs + OS metadata"),
    ]
    if client is None:
        checks.append(Check("Time window (T0, T1)", WARN, "offline verification: capture time not checked"))
    else:
        checks += verify_window(client, bundle["t0"], bundle["t1"], sigs["enclave"])
    checks.append(Check("Revocation", SKIP, "not implemented yet (task 6)"))
    return checks
