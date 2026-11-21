"""README, Capture.

T0 is the hash of the latest validated ledger N. The OS computes D = H(T0 || dev_manifest || boot_manifest);
the sensor streams raw_pix then metadata (with D in the digest slot) and signs σs = ECDSA(sk_s, e) with
e = SHA256(raw_pix || metadata); the Secure Enclave signs H(σs) with the OS metadata (σe). C = H(σe) goes to
the proxy over OHTTP, paid with a prepaid blind token; the proxy publishes it, and the ledger M that includes
it, within x ledgers of N, is T1. Finally the DNG file is generated.

  python -m decima.capture [--device ID] [--image photo.jpg] [--size 1920x1080]"""

import argparse
import json
import uuid

import numpy as np

from decima.capture import ohttp
from decima.capture.dng import write as write_dng
from decima.capture.proxy import Proxy, gateway_key
from decima.capture.tokens import take_token
from decima.core.config import CAPTURES_DIR, EXPLORER_TX_URL, X_LEDGERS
from decima.core.crypto import H
from decima.core.ledger import get_client, latest_validated_ledger
from decima.device.frame import dev_params_of
from decima.device.hardware import Device, os_metadata, pick_device
from decima.device.scene import load_scene, synthetic_scene

CLIENT_ADDRESS = "198.51.100.23"  # the device's network address, as the relay sees it (documentation range)


def send_commitment_over_ohttp(commitment: bytes, token: dict) -> tuple[dict, list[str]]:
    """Client -> relay -> gateway -> proxy, with an RFC 9458 encapsulated request; returns the proxy's answer."""
    proxy = Proxy()
    relay = ohttp.Relay(proxy)
    body = json.dumps({"C": commitment.hex(), "token": token}).encode()
    request = ohttp.bhttp_request("POST", "proxy.ixh26.example", "/anchor", {"content-type": "application/json"}, body)
    message, ctx, enc = ohttp.encapsulate_request(gateway_key().public_key(), request)
    status, response = ohttp.parse_bhttp_response(ohttp.decapsulate_response(ctx, enc,
                                                                              relay.forward(CLIENT_ADDRESS, message)))
    if status != 200:
        raise SystemExit(f"proxy refused the commitment: {response.decode()}")
    return json.loads(response), relay.log + proxy.log


def main() -> None:
    parser = argparse.ArgumentParser(prog="python -m decima.capture", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--device", help="device id (default: latest provisioned)")
    parser.add_argument("--image", help="photo to use as the scene (default: synthetic)")
    parser.add_argument("--size", default="1920x1080", help="WxH, even numbers (default: the model's Full HD)")
    args = parser.parse_args()
    width, height = (int(v) for v in args.size.lower().split("x"))
    if width % 2 or height % 2:
        raise SystemExit("--size must be even in both dimensions (RGGB)")

    client = get_client()
    device = Device(pick_device(args.device))
    scene = load_scene(args.image, width, height) if args.image else synthetic_scene(width, height)

    n = latest_validated_ledger(client)                                    # T0 = hash of ledger N
    t0 = bytes.fromhex(n["hash"])
    digest = device.embedded_digest(t0)                                    # D, given to the sensor
    frame = device.sensor_capture(scene, digest, np.random.default_rng())  # raw_pix, metadata, σs
    os_meta = os_metadata()
    sigma_e = device.enclave_bind(frame["sigma_s"], os_meta)               # σe
    commitment = H(sigma_e)                                                # C = H(σe)

    published, log = send_commitment_over_ohttp(commitment, take_token())
    m = published["ledger_index"]                                          # T1 = ledger M
    within = 0 < m - n["index"] <= X_LEDGERS

    capture_id = uuid.uuid4().hex[:12]
    out = CAPTURES_DIR / capture_id
    out.mkdir(parents=True)
    private = {"metadata": frame["metadata"].hex(), "sigma_s": frame["sigma_s"].hex(), "sigma_e": sigma_e.hex(),
               "os_meta": os_meta.decode(), "dev_manifest": device.dev_manifest.decode(),
               "boot_manifest": device.boot_manifest.decode(), "sigma_man": device.manifest_sig.hex(),
               "T0": {"ledger_index": n["index"], "hash": n["hash"]}, "C": commitment.hex(),
               "T1": {"ledger_index": m, "tx": published["tx"]}}
    write_dng(out / "capture.dng", frame["raw_pix"], dev_params_of(frame["metadata"]), private)

    print(f"Capture {capture_id} with device {device.id}, {width}x{height}")
    print(f"  T0      hash of ledger N = {n['index']}: {n['hash'][:16]}...")
    print(f"  D       H(T0 || dev_manifest || boot_manifest) = {digest.hex()[:16]}... in the digest slot")
    print(f"  σs      ECDSA(sk_s, e), e = SHA256(raw_pix || metadata), pixels streamed first "
          f"({frame['raw_pix'].nbytes} B + {len(frame['metadata'])} B)")
    print("  σe      Secure Enclave signature over H(σs) || OS metadata")
    print(f"  C       H(σe) = {commitment.hex()[:16]}..., sent over OHTTP with a prepaid blind token:")
    for line in log:
        print(f"            {line}")
    print(f"  T1      ledger M = {m}: {EXPLORER_TX_URL}{published['tx']}")
    print(f"  window  M - N = {m - n['index']} ledgers, 0 < M - N <= x = {X_LEDGERS}: {'yes' if within else 'NO'}")
    print(f"  DNG     out/captures/{capture_id}/capture.dng")


if __name__ == "__main__":
    main()
