"""README, Attestation: the user generates the zero-knowledge proof and prepares what to send.

S and tail are computed from the pixels; the roots and pk_man are read from the ledger; metadata, manifests,
signatures and Merkle paths stay in the witness. Output, in out/published/<capture>/ (README, Verification:
"the JPEG photo, the raw pixels, dev_params, T1 and the proof"):
  photo.jpg     developed with the admitted pipeline
  raw.dng       the pixels with only the dev_params tags: the metadata never leaves the device
  proof.json    the proof and its public inputs
  package.json  dev_params, declared pipeline, T1 (the transaction containing C)

Revocation roots (README, Verification): with --roots current (default) the proof uses the current R_rev_s,
R_rev_e and passes both verification modes, but it must be regenerated after any new revocation; with
--roots capture-time it uses the roots valid at ledger M (T1), never expires, and passes capture-time
verification only.

  python -m decima.attestation [capture-id] [--roots current|capture-time]"""

import argparse
import json

from decima.attestation import proof_system, statement
from decima.capture.dng import read as read_dng, write as write_dng
from decima.core import merkle, sha256
from decima.core.config import CAPTURES_DIR, PUBLISHED_DIR
from decima.core.crypto import H, pk_bytes, verify
from decima.core.ledger import get_client
from decima.core.wallets import wallet
from decima.device.frame import dev_params_of
from decima.pipeline.develop import PIPELINE_ID, develop
from decima.setup.registry import load_maker, read_pk_man, read_trust_root


def latest_capture() -> str:
    caps = sorted(CAPTURES_DIR.glob("*/capture.dng"), key=lambda p: p.stat().st_mtime)
    if not caps:
        raise SystemExit("no capture yet: run python -m decima.capture")
    return caps[-1].parent.name


def find_registry(client, makers: list[str], key_hash: bytes):
    for address in makers:
        reg = load_maker(client, address)
        if reg.consistent and key_hash in reg.leaves:
            return reg
    raise SystemExit("key not in any admitted registry: this device cannot produce a proof")


def membership(reg, key_hash: bytes) -> dict:
    i = reg.leaves.index(key_hash)
    return {"index": i, "path": [x.hex() for x in merkle.path(reg.leaves, i)]}


def main() -> None:
    parser = argparse.ArgumentParser(prog="python -m decima.attestation", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("capture", nargs="?", help="capture id (default: latest)")
    parser.add_argument("--roots", choices=["current", "capture-time"], default="current",
                        help="revocation roots to prove against (default: current)")
    args = parser.parse_args()
    capture_id = args.capture or latest_capture()
    raw_pix, _, private = read_dng(CAPTURES_DIR / capture_id / "capture.dng")
    if private is None:
        raise SystemExit("this DNG has no secure-negative data")

    client = get_client()
    trust = read_trust_root(client, wallet("trust_root").address)
    metadata = bytes.fromhex(private["metadata"])
    manifest_bytes = private["dev_manifest"].encode()
    manifest = json.loads(manifest_bytes)
    sigma_man = bytes.fromhex(private["sigma_man"])
    pk_man = next((pk for a in trust["manufacturers"]["assembler"]
                   if (pk := read_pk_man(client, a)) and verify(pk, sigma_man, manifest_bytes)), None)
    if pk_man is None:
        raise SystemExit("no admitted assembler's pk_man verifies the manifest")
    hs, he = H(bytes.fromhex(manifest["pk_s"])), H(bytes.fromhex(manifest["pk_e"]))
    reg_s = find_registry(client, trust["manufacturers"]["sensor"], hs)
    reg_e = find_registry(client, trust["manufacturers"]["enclave"], he)
    m = private["T1"]["ledger_index"]
    if args.roots == "capture-time":
        rev_s, rev_e = (merkle.IndexedTree.from_inserts([v for v, at in zip(r.revoked, r.revoked_ledgers) if at <= m])
                        for r in (reg_s, reg_e))
    else:
        rev_s, rev_e = reg_s.rev_tree, reg_e.rev_tree
    try:
        nonmem_s, nonmem_e = rev_s.non_membership_witness(hs), rev_e.non_membership_witness(he)
    except KeyError:
        raise SystemExit(f"a device key is revoked ({args.roots} roots): H(pk) ∉ R_rev cannot be proven, no proof")

    S, tail = sha256.midstate(raw_pix.tobytes())   # the pixels are hashed outside the circuit
    dev_params = dev_params_of(metadata)
    public = {"S": S.hex(), "tail": tail.hex(), "dev_params": dev_params, "T0": private["T0"]["hash"],
              "C": private["C"], "pk_man": pk_bytes(pk_man).hex(), "R_s": reg_s.onchain_root.hex(),
              "R_e": reg_e.onchain_root.hex(), "R_rev_s": rev_s.root().hex(),
              "R_rev_e": rev_e.root().hex()}
    witness = {"metadata": metadata, "dev_manifest": manifest_bytes, "boot_manifest": private["boot_manifest"].encode(),
               "os_meta": private["os_meta"].encode(), "sigma_s": bytes.fromhex(private["sigma_s"]),
               "sigma_e": bytes.fromhex(private["sigma_e"]), "sigma_man": sigma_man,
               "mem_s": membership(reg_s, hs), "mem_e": membership(reg_e, he),
               "nonmem_s": nonmem_s, "nonmem_e": nonmem_e}
    proof = proof_system.prove(public, witness)

    out = PUBLISHED_DIR / capture_id
    out.mkdir(parents=True, exist_ok=True)
    (out / "photo.jpg").write_bytes(develop(raw_pix, dev_params))
    write_dng(out / "raw.dng", raw_pix, dev_params, private=None)
    (out / "proof.json").write_text(json.dumps(proof, indent=2))
    (out / "package.json").write_text(json.dumps({"dev_params": dev_params, "pipeline": PIPELINE_ID,
                                                  "T1": private["T1"]["tx"]}, indent=2))

    print(f"Attestation of capture {capture_id}")
    for name, ok in statement.relation(public, witness):
        print(f"  {'OK' if ok else 'FAIL':<4}  {name}")
    print(f"\n  proof    {proof['system']}, circuit {proof['circuit']}, {args.roots} revocation roots"
          f"{' (ledger M = ' + str(m) + ')' if args.roots == 'capture-time' else ''}")
    print(f"  public   S {public['S'][:16]}..., tail {len(tail)} B, dev_params {dev_params}")
    print(f"           T0 {public['T0'][:16]}..., C {public['C'][:16]}..., pk_man {public['pk_man'][:16]}...")
    print(f"           R_s {public['R_s'][:16]}..., R_e {public['R_e'][:16]}..., "
          f"R_rev_s {public['R_rev_s'][:16]}..., R_rev_e {public['R_rev_e'][:16]}...")
    print("  private  metadata, manifests, σs, σe, σ_man, Merkle paths: not in the package")
    print(f"  package  out/published/{capture_id}/: photo.jpg, raw.dng (pixels only), proof.json, package.json")


if __name__ == "__main__":
    main()
