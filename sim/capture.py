"""Phase 1 capture: T0 from the latest validated ledger, sensor + enclave signatures, T1 anchored on XRPL."""

import argparse
import json
from pathlib import Path

import numpy as np
from xrpl.wallet import Wallet

from sim.config import EXPLORER_TX_URL, OUT_DIR, role_seed
from sim.crypto import sha256_hex
from sim.device import Device
from sim.factory import DEVICES_DIR
from sim.ledger import get_client
from sim.protocol import BUNDLE_FORMAT
from sim.scene import load_image, save_srgb, synthetic_scene
from sim.timestamps import acquire_t0, anchor_t1

CAPTURES_DIR = OUT_DIR / "captures"


def pick_device(device_id: str | None) -> Path:
    if device_id:
        path = DEVICES_DIR / device_id
        if not path.is_dir():
            raise SystemExit(f"device {device_id} not found in {DEVICES_DIR}")
        return path
    devices = sorted(DEVICES_DIR.glob("*/device_manifest.json"), key=lambda p: p.stat().st_mtime)
    if not devices:
        raise SystemExit("no device yet: run python -m sim.factory")
    return devices[-1].parent


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--device", help="device id (default: last provisioned)")
    parser.add_argument("--image", type=Path, help="photo to use as the scene (default: synthetic)")
    parser.add_argument("--size", default="1920x1080",
                        help="raw frame WxH, even numbers (default Full HD; e.g. 5664x4248 for ~24 MP 4:3)")
    parser.add_argument("--no-anchor", action="store_true", help="simulate an offline capture: no T1")
    args = parser.parse_args()

    width, height = (int(v) for v in args.size.lower().split("x"))
    if width % 2 or height % 2:
        raise SystemExit("--size must use even numbers (2x2 Bayer pattern)")
    device = Device.load(pick_device(args.device))
    client = get_client()
    scene = load_image(args.image, width, height) if args.image else synthetic_scene(height, width)

    t0 = acquire_t0(client)
    raw, record = device.capture(scene, t0)

    if args.no_anchor:
        record["t1"] = None
    else:
        seed = role_seed("device")
        if not seed:
            raise SystemExit("device wallet missing: run python -m sim.setup_wallets")
        record["t1"] = anchor_t1(client, Wallet.from_seed(seed), record["signatures"]["enclave"])

    capture_id = record["os_meta"]["capture_id"]
    out = CAPTURES_DIR / capture_id
    out.mkdir(parents=True)
    np.save(out / "raw.npy", raw, allow_pickle=False)
    bundle = {"format": BUNDLE_FORMAT, "capture_id": capture_id, "raw_file": "raw.npy",
              "raw_sha256": sha256_hex(raw.tobytes()), **record}
    (out / "capture.json").write_text(json.dumps(bundle, indent=2))
    save_srgb(scene, out / "debug_scene.png")

    f = record["frame"]
    print(f"Capture {capture_id} by device {device.device_id}")
    print(f"  raw      {f['width']}x{f['height']} {f['cfa']} {f['bit_depth']}-bit")
    print(f"  T0       ledger {t0['ledger_index']} closed {t0['close_time']}")
    if record["t1"]:
        t1 = record["t1"]
        print(f"  T1       ledger {t1['ledger_index']} closed {t1['close_time']}")
        print(f"  anchor   {EXPLORER_TX_URL}{t1['tx_hash']}")
    else:
        print("  T1       none (offline capture)")
    print(f"  bundle   out/captures/{capture_id}/  (capture.json, raw.npy, debug_scene.png)")


if __name__ == "__main__":
    main()
