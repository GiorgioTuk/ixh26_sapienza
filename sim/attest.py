"""Phase 2 attestation (replaces Apple's PCC + signing service): verify the secure negative, develop it,
then sign the reference JPEG's commitment with the composite post-quantum signature and embed it in the JPEG."""

import argparse
import io
import json
import time
import uuid
from datetime import datetime, timezone

import numpy as np
from PIL import Image

from sim import service
from sim.crypto import canonical, sha256_hex
from sim.develop import develop
from sim.jpeg_container import embed
from sim.ledger import get_client
from sim.report import FAIL, OK
from sim.timestamps import T0_ONCHAIN, T1_CLAIMS, TIME_CHECKS
from sim.verify import resolve_capture, run_verification

REFERENCE_FORMAT = "ixh26-reference/1"
# Apple's fallbacks: a bad lower bound becomes the feature's launch date, a missing upper bound the development time.
LOWER_BOUND_FALLBACK = "2026-03-31T00:00:00Z"
JPEG_QUALITY = 92


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("capture", nargs="?", help="capture id (default: latest original capture)")
    parser.add_argument("--offline", action="store_true", help="skip on-chain checks (time bounds fall back)")
    args = parser.parse_args()

    cap_dir = resolve_capture(args.capture)
    _, checks = run_verification(cap_dir, None if args.offline else get_client())
    failed = [c for c in checks if c.status == FAIL and c.name not in TIME_CHECKS]
    if failed:
        raise SystemExit(f"{cap_dir.name}: not developed, integrity checks failed: "
                         + ", ".join(c.name for c in failed))

    bundle = json.loads((cap_dir / "capture.json").read_text())
    raw = np.load(cap_dir / "raw.npy", allow_pickle=False)
    status = {c.name: c.status for c in checks}
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    captured_after = bundle["t0"]["close_time"] if status.get(T0_ONCHAIN) == OK else LOWER_BOUND_FALLBACK
    captured_before = bundle["t1"]["close_time"] if status.get(T1_CLAIMS) == OK else now

    t_start = time.perf_counter()
    pixels, development = develop(raw, bundle["frame"])
    t_developed = time.perf_counter()
    meta = {"format": REFERENCE_FORMAT, "capture_id": bundle["capture_id"],
            "captured_after": captured_after, "captured_before": captured_before,
            "development": development, "pixels_sha256": sha256_hex(pixels.tobytes()),
            "raw_sha256": bundle["raw_sha256"]}
    buf = io.BytesIO()
    Image.fromarray(pixels).save(buf, "JPEG", quality=JPEG_QUALITY, comment=canonical(meta))
    jpeg = buf.getvalue()
    commitment = sha256_hex(jpeg)
    guid = str(uuid.UUID(commitment[:32]))
    t_encoded = time.perf_counter()

    signature = service.sign(service.load_or_create_keys(), bytes.fromhex(commitment))
    final = embed(jpeg, canonical({"guid": guid, "commitment": commitment, "signature": signature}))
    t_signed = time.perf_counter()

    (cap_dir / "reference.jpg").write_bytes(final)
    record = {"guid": guid, "commitment": commitment, "reference": meta, "signature_scheme": signature["scheme"],
              "service_key_id": signature["key_id"], "confidence_score": None, "revocation": "not checked",
              "timings_s": {"develop": round(t_developed - t_start, 3), "jpeg": round(t_encoded - t_developed, 3),
                            "sign": round(t_signed - t_encoded, 3)}}
    (cap_dir / "reference.json").write_text(json.dumps(record, indent=2))

    h, w = pixels.shape[:2]
    print(f"Reference image for capture {bundle['capture_id']}")
    print(f"  developed   {w}x{h} with {development['profile']} in {record['timings_s']['develop']}s"
          f" (WB gains Q12 {development['wb_gains_q12']})")
    print(f"  captured    between {captured_after} and {captured_before}")
    print(f"  commitment  SHA-256(JPEG) = {commitment[:16]}...  GUID {guid}")
    print(f"  signature   {signature['scheme']} (key {signature['key_id']}) embedded in the JPEG,"
          f" {record['timings_s']['sign']}s")
    print("  not yet     confidence score, revocation check")
    print(f"  output      out/captures/{cap_dir.name}/reference.jpg ({len(final) / 1e6:.2f} MB), reference.json")


if __name__ == "__main__":
    main()
