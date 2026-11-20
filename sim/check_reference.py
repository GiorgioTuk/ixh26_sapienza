"""Client-side check of a reference JPEG, as Apple's viewer does before display: commitment, GUID and composite
signature. If the secure negative is available it also re-develops the raw and compares the pixels bit for bit."""

import argparse
import io
import json
import uuid
from pathlib import Path

import numpy as np
from PIL import Image

from sim import service
from sim.capture import CAPTURES_DIR
from sim.crypto import sha256_hex
from sim.develop import develop
from sim.jpeg_container import extract
from sim.report import SKIP, Check, check, verdict


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("target", help="capture id or path to a reference JPEG")
    args = parser.parse_args()
    path = Path(args.target)
    if not path.is_file():
        path = CAPTURES_DIR / args.target / "reference.jpg"
    if not path.is_file():
        raise SystemExit(f"no reference JPEG at {path}")

    stripped, payload = extract(path.read_bytes())
    if payload is None:
        raise SystemExit("no reference signature in this JPEG")
    sig = json.loads(payload)
    commitment = sha256_hex(stripped)
    meta = json.loads(Image.open(io.BytesIO(stripped)).info.get("comment", b"{}"))

    checks = [
        check("Commitment = SHA-256(JPEG)", sig["commitment"] == commitment, commitment[:16] + "...",
              "JPEG bytes changed after signing"),
        check("GUID from commitment bits", sig["guid"] == str(uuid.UUID(commitment[:32])), sig["guid"],
              "GUID does not match the commitment"),
        check("Composite signature", service.verify(service.load_public(), bytes.fromhex(commitment), sig["signature"]),
              f"{sig['signature']['scheme']}: ML-DSA-87 and RSA-3072 both valid",
              "composite signature invalid for this JPEG"),
    ]
    neg = CAPTURES_DIR / meta.get("capture_id", "") / "capture.json"
    if meta.get("capture_id") and neg.is_file():
        bundle = json.loads(neg.read_text())
        raw = np.load(neg.parent / "raw.npy", allow_pickle=False)
        pixels, _ = develop(raw, bundle["frame"])
        checks.append(check("Re-development reproducible",
                            sha256_hex(pixels.tobytes()) == meta["pixels_sha256"]
                            and bundle["raw_sha256"] == meta["raw_sha256"],
                            "same raw -> bit-identical pixels", "pixels differ from the signed development"))
    else:
        checks.append(Check("Re-development reproducible", SKIP, "secure negative not available"))
    checks.append(Check("Revocation", SKIP, "not implemented yet"))

    print(f"Checking {path}")
    for c in checks:
        print(f"  {c.status:<4}  {c.name:<30} {c.detail}")
    print(f"  captured between {meta.get('captured_after')} and {meta.get('captured_before')}")
    print(f"\nVerdict: {verdict(checks)}")


if __name__ == "__main__":
    main()
