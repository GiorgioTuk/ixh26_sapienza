"""Tampered copies of a capture, to show what the verifier catches; `all` runs every attack and verifies it."""

import argparse
import copy
import json
from pathlib import Path

import numpy as np
from xrpl.clients import JsonRpcClient
from xrpl.models.requests import Ledger

from sim.capture import CAPTURES_DIR
from sim.crypto import cert_pem, issue_cert, new_key, sha256_hex
from sim.device import Sensor
from sim.ledger import get_client
from sim.report import FAIL
from sim.scene import load_image
from sim.verify import resolve_capture, run_verification

ATTACKS = {
    "raw-bit": "flip one bit of the raw frame (pixel edit)",
    "os-meta": "change OS metadata after signing (zoom 1x -> 2x)",
    "backdate": "claim a real but older T0 ledger (backdating)",
    "fake-sensor": "edited image re-signed with an uncertified sensor key",
    "replay-t1": "reuse the T1 anchor of another capture",
}


def apply_attack(attack: str, bundle: dict, raw: np.ndarray, cap_dir: Path,
                 client: JsonRpcClient) -> tuple[dict, np.ndarray]:
    b, r = copy.deepcopy(bundle), raw.copy()
    if attack == "raw-bit":
        r[100, 100] ^= 1
    elif attack == "os-meta":
        b["os_meta"]["zoom"] = 2.0
    elif attack == "backdate":
        old = client.request(Ledger(ledger_index=b["t0"]["ledger_index"] - 1000)).result["ledger"]
        b["t0"] = {"ledger_index": int(old["ledger_index"]), "ledger_hash": old["ledger_hash"],
                   "close_time": old["close_time_iso"]}
    elif attack == "fake-sensor":
        attacker = new_key()
        fake_cert = issue_cert(f"sensor:{b['device_id']}", attacker.public_key(), "sensor-ca", attacker)
        edited_scene = np.fliplr(load_image(cap_dir / "debug_scene.png"))
        r, b["frame"], b["signatures"]["sensor"] = Sensor(attacker).capture(edited_scene, b["frame"]["embedded_digest"])
        b["device_manifest"]["manifest"]["sensor_cert"] = cert_pem(fake_cert)
        b["raw_sha256"] = sha256_hex(r.tobytes())
    elif attack == "replay-t1":
        others = [p for p in CAPTURES_DIR.glob("*/capture.json")
                  if "-" not in p.parent.name and p.parent != cap_dir and json.loads(p.read_text())["t1"]]
        if not others:
            raise SystemExit("replay-t1 needs a second anchored capture: run python -m sim.capture")
        b["t1"] = json.loads(others[0].read_text())["t1"]
    return b, r


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("attack", choices=[*ATTACKS, "all"])
    parser.add_argument("--capture", help="capture id to attack (default: latest original capture)")
    args = parser.parse_args()

    cap_dir = resolve_capture(args.capture)
    bundle = json.loads((cap_dir / "capture.json").read_text())
    raw = np.load(cap_dir / "raw.npy", allow_pickle=False)
    client = get_client()

    original, _ = run_verification(cap_dir, client)
    print(f"Original {cap_dir.name}: {original}\n")
    for attack in ATTACKS if args.attack == "all" else [args.attack]:
        b, r = apply_attack(attack, bundle, raw, cap_dir, client)
        out = CAPTURES_DIR / f"{cap_dir.name}-{attack}"
        out.mkdir(exist_ok=True)
        np.save(out / "raw.npy", r, allow_pickle=False)
        (out / "capture.json").write_text(json.dumps(b, indent=2))
        result, checks = run_verification(out, client)
        failed = ", ".join(c.name for c in checks if c.status == FAIL)
        print(f"{attack:<12} {ATTACKS[attack]}")
        print(f"{'':<12} -> {result}: {failed or 'nothing detected'}\n")
    print("Details: python -m sim.verify <capture>-<attack>")


if __name__ == "__main__":
    main()
