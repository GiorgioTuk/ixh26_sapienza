"""Verify a capture bundle (Phase 2a): prints every check and writes verification.json next to the bundle."""

import argparse
import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
from xrpl.clients import JsonRpcClient

from sim.capture import CAPTURES_DIR
from sim.ledger import get_client
from sim.report import FAIL, Check, verdict
from sim.verifier import load_trust_roots, verify_capture


def resolve_capture(name: str | None) -> Path:
    if name:
        path = CAPTURES_DIR / name
        if not (path / "capture.json").exists():
            raise SystemExit(f"capture {name} not found in {CAPTURES_DIR}")
        return path
    originals = [p.parent for p in CAPTURES_DIR.glob("*/capture.json") if "-" not in p.parent.name]
    if not originals:
        raise SystemExit("no capture yet: run python -m sim.capture")
    return max(originals, key=lambda p: (p / "capture.json").stat().st_mtime)


def run_verification(cap_dir: Path, client: JsonRpcClient | None) -> tuple[str, list[Check]]:
    bundle = json.loads((cap_dir / "capture.json").read_text())
    raw = np.load(cap_dir / "raw.npy", allow_pickle=False)
    try:
        checks = verify_capture(bundle, raw, load_trust_roots(), client)
    except (KeyError, ValueError, TypeError) as e:
        checks = [Check("Bundle parsing", FAIL, f"malformed bundle: {e!r}")]
    result = verdict(checks)
    report = {"capture": cap_dir.name, "verdict": result,
              "verified_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
              "checks": [asdict(c) for c in checks]}
    (cap_dir / "verification.json").write_text(json.dumps(report, indent=2, ensure_ascii=False))
    return result, checks


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("capture", nargs="?", help="capture id (default: latest original capture)")
    parser.add_argument("--offline", action="store_true", help="skip the on-chain T0/T1 checks")
    args = parser.parse_args()

    cap_dir = resolve_capture(args.capture)
    result, checks = run_verification(cap_dir, None if args.offline else get_client())
    print(f"Verifying {cap_dir.name}")
    for c in checks:
        print(f"  {c.status:<4}  {c.name:<34} {c.detail}")
    print(f"\nVerdict: {result}   (report: out/captures/{cap_dir.name}/verification.json)")
    if result == "REJECTED":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
