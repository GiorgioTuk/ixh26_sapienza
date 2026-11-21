"""README, Verification: check a package the user sent.

  python -m decima.verification [capture-id | folder] [--mode current-status|capture-time]"""

import argparse
from pathlib import Path

from decima.core.config import PUBLISHED_DIR
from decima.core.ledger import get_client
from decima.verification.verifier import MODES, verify_package


def main() -> None:
    parser = argparse.ArgumentParser(prog="python -m decima.verification", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("target", nargs="?", help="capture id in out/published/ or a folder (default: latest)")
    parser.add_argument("--mode", choices=MODES, default="current-status",
                        help="revocation roots to require (default: current-status)")
    args = parser.parse_args()
    if args.target and Path(args.target).is_dir():
        folder = Path(args.target)
    elif args.target:
        folder = PUBLISHED_DIR / args.target
    else:
        packages = sorted(PUBLISHED_DIR.glob("*/proof.json"), key=lambda p: p.stat().st_mtime)
        folder = packages[-1].parent if packages else None
    if folder is None or not (folder / "proof.json").exists():
        raise SystemExit("nothing to verify: run python -m decima.attestation")
    checks = verify_package(folder, get_client(), args.mode)
    print(f"Verifying {folder} ({args.mode} verification)")
    for name, ok, detail in checks:
        print(f"  {'OK' if ok else 'FAIL':<4}  {name:<52} {detail}")
    verdict = all(ok for _, ok, _ in checks)
    print(f"\nVerdict: {'VERIFIED' if verdict else 'REJECTED'}")
    if not verdict:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
