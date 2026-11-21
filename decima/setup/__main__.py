"""README, Setup: manufacturers certify keys at the factory and the roots of trust are on-chain.

  python -m decima.setup trust-root                 bootstrap the pre-existing trust root (once)
  python -m decima.setup device [--no-register]     factory: provision a device, makers register its keys
  python -m decima.setup revoke <device> sensor|enclave   the maker revokes that key
  python -m decima.setup status                     roots of trust as read from the ledger"""

import argparse
import json

from decima.core.config import EXPLORER_TX_URL
from decima.core.crypto import pk_bytes
from decima.core.ledger import get_client
from decima.core.wallets import wallet
from decima.device.frame import MODEL_DEV_PARAMS
from decima.device.hardware import DEVICES_DIR
from decima.setup.factory import assembler_key, device_key_hashes, provision
from decima.setup.registry import (load_maker, publish_pk_man, publish_trust_root, read_pk_man, read_trust_root,
                                   register_keys, revoke_keys)

MAKER_ROLE = {"sensor": "sensor_maker", "enclave": "enclave_maker"}


def receipt_line(who: str, what: str, r: dict) -> str:
    return f"  {who:<13} {what:<22} ledger {r['ledger_index']}  {EXPLORER_TX_URL}{r['hash']}"


def cmd_trust_root(client) -> None:
    from decima.attestation.proof_system import CIRCUIT_ID
    from decima.pipeline.develop import PIPELINE_ID
    doc = {"manufacturers": {"sensor": [wallet("sensor_maker").address],
                             "enclave": [wallet("enclave_maker").address],
                             "assembler": [wallet("assembler").address]},
           "circuits": [CIRCUIT_ID], "pipelines": [PIPELINE_ID], "dev_params": [MODEL_DEV_PARAMS]}
    if read_trust_root(client, wallet("trust_root").address) == doc:
        print("Trust root already on-chain and up to date.")
        return
    r = publish_trust_root(client, wallet("trust_root"), doc)
    print("Trust root (assumed pre-existing, bootstrapped for the simulation)")
    print(json.dumps(doc, indent=2))
    print(receipt_line("trust_root", "DIDSet", r))


def cmd_device(client, register: bool) -> None:
    d = provision()
    print(f"Provisioned device {d.name}: sensor key, enclave key, manifest signed by the assembler")
    if not register:
        print("Not registered on-chain (--no-register)")
        return
    r = publish_pk_man(client, wallet("assembler"), assembler_key().public_key())
    if r:
        print(receipt_line("assembler", "pk_man published", r))
    for kind, key_hash in device_key_hashes(d).items():
        for r in register_keys(client, wallet(MAKER_ROLE[kind]), kind, [key_hash]):
            print(receipt_line(MAKER_ROLE[kind], f"H(pk_{kind[0]}) registered", r))


def cmd_revoke(client, device_id: str, kind: str) -> None:
    key_hash = device_key_hashes(DEVICES_DIR / device_id)[kind]
    r = revoke_keys(client, wallet(MAKER_ROLE[kind]), kind, [key_hash])
    print(receipt_line(MAKER_ROLE[kind], f"H(pk_{kind[0]}) revoked", r) if r else "Already revoked.")


def cmd_status(client) -> None:
    doc = read_trust_root(client, wallet("trust_root").address)
    if doc is None:
        raise SystemExit("no trust root on-chain: run python -m decima.setup trust-root")
    print(f"Trust root {wallet('trust_root').address}")
    print(f"  circuits {doc['circuits']}, pipelines {doc['pipelines']}, dev_params {doc['dev_params']}")
    for kind in ("sensor", "enclave"):
        for address in doc["manufacturers"][kind]:
            reg = load_maker(client, address)
            print(f"  {kind:<8} {address}  R = {reg.tree_root.hex()[:16]}... ({len(reg.leaves)} keys)  "
                  f"R_rev = {reg.rev_tree.root().hex()[:16]}... ({len(reg.revoked)} revoked)  "
                  f"{'consistent with DID' if reg.consistent else 'INCONSISTENT with DID'}")
    for address in doc["manufacturers"]["assembler"]:
        pk = read_pk_man(client, address)
        print(f"  assembler {address}  pk_man = {pk_bytes(pk).hex()[:20] + '...' if pk else 'not published'}")


def main() -> None:
    parser = argparse.ArgumentParser(prog="python -m decima.setup", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("trust-root")
    sub.add_parser("device").add_argument("--no-register", action="store_true")
    p = sub.add_parser("revoke")
    p.add_argument("device")
    p.add_argument("kind", choices=["sensor", "enclave"])
    sub.add_parser("status")
    args = parser.parse_args()
    client = get_client()
    {"trust-root": lambda: cmd_trust_root(client), "device": lambda: cmd_device(client, not args.no_register),
     "revoke": lambda: cmd_revoke(client, args.device, args.kind), "status": lambda: cmd_status(client)}[args.cmd]()


if __name__ == "__main__":
    main()
