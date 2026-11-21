"""README, Verification. The user sends the JPEG photo, the raw pixels, dev_params, T1 and the proof; the
verifier runs SHA-256 over the pixels up to state S and checks that:
- the proof is valid for the public inputs, with S and tail computed by the verifier itself;
- the circuit hash, pk_man and roots R_s, R_e are the valid ones on-chain, and R_rev_s, R_rev_e are the
  revocation roots required by the chosen verification mode;
- T0 is the hash of ledger N, C is in a transaction of ledger M (T1) and 0 < M - N <= x;
- dev_params and the declared pipeline are among the admitted ones, and developing the pixels with them
  yields exactly the JPEG photo.

"Valid on-chain": the circuit, the pipeline and the dev_params must be listed in the trust root; pk_man must
be the key in an admitted assembler's DID; R_s / R_e must be a root an admitted maker published (registries
are append-only, so a key in an older root is still registered).

Verification modes (chosen by the verifier, same circuit):
- current-status: R_rev_s / R_rev_e must be the maker's current revocation roots, so revocations made after
  the capture also apply;
- capture-time: R_rev_s / R_rev_e must be the roots valid at ledger M, or any later ones: revocations are
  only added, so a key absent from a later set was absent at M too (this is why a proof made against the
  current roots passes both modes)."""

import json
from pathlib import Path

from decima.attestation import proof_system
from decima.capture.dng import read as read_dng
from decima.core import sha256
from decima.core.config import X_LEDGERS
from decima.core.crypto import pk_bytes
from decima.core.ledger import ledger_by_hash, lookup_tx, memos
from decima.core.wallets import wallet
from decima.pipeline.develop import PIPELINE_ID, develop
from decima.setup.registry import load_maker, read_pk_man, read_trust_root


MODES = ("current-status", "capture-time")


def verify_package(folder: Path, client, mode: str = "current-status") -> list[tuple[str, bool, str]]:
    proof = json.loads((folder / "proof.json").read_text())
    package = json.loads((folder / "package.json").read_text())
    pub = proof["public_inputs"]
    raw_pix, _, _ = read_dng(folder / "raw.dng")
    photo = (folder / "photo.jpg").read_bytes()
    trust = read_trust_root(client, wallet("trust_root").address)
    checks = []

    # 1. proof valid for the public inputs, with S and tail computed by the verifier itself
    S, tail = sha256.midstate(raw_pix.tobytes())
    own = pub["S"] == S.hex() and pub["tail"] == tail.hex() and pub["dev_params"] == package["dev_params"]
    checks.append(("Proof valid", proof_system.verify(proof), proof["system"]))
    checks.append(("S and tail computed by the verifier match the proof", own, f"S {S.hex()[:16]}..., tail {len(tail)} B"))

    # T1 is needed first: capture-time verification depends on its ledger M
    tx = lookup_tx(client, package["T1"])
    in_tx = tx is not None and tx["meta"]["TransactionResult"] == "tesSUCCESS" and any(
        data == bytes.fromhex(pub["C"]) for _, data in memos(tx.get("tx_json", tx)))
    m = tx["ledger_index"] if in_tx else None

    # 2. circuit hash, pk_man and roots valid on-chain
    checks.append(("Circuit hash valid on-chain", proof["circuit"] in trust["circuits"], proof["circuit"]))
    assembler = next((a for a in trust["manufacturers"]["assembler"]
                      if (pk := read_pk_man(client, a)) and pk_bytes(pk).hex() == pub["pk_man"]), None)
    checks.append(("pk_man valid on-chain", assembler is not None, f"DID of {assembler}" if assembler else "no match"))
    for kind, r, r_rev in (("sensor", "R_s", "R_rev_s"), ("enclave", "R_e", "R_rev_e")):
        maker = next((reg for a in trust["manufacturers"][kind]
                      if bytes.fromhex(pub[r]) in (reg := load_maker(client, a)).historic_roots), None)
        checks.append((f"{r} valid on-chain", maker is not None,
                       f"published by {maker.address}" if maker else "never published by an admitted maker"))
        if mode == "current-status":
            ok = maker is not None and maker.rev_tree.root().hex() == pub[r_rev]
            detail = "the maker's current revocation root" if ok else "not the current revocation root"
        else:
            ok = maker is not None and m is not None and bytes.fromhex(pub[r_rev]) in maker.rev_roots_since(m)
            detail = f"valid at ledger M = {m} or later" if ok else "not a revocation root valid at or after M"
        checks.append((f"{r_rev} valid on-chain ({mode})", ok, detail))

    # 3. T0 is the hash of ledger N, C is in the transaction T1 of ledger M, 0 < M - N <= x
    n = ledger_by_hash(client, pub["T0"])
    checks.append(("T0 is the hash of ledger N", n is not None, f"N = {n['index']}" if n else "no validated ledger"))
    checks.append(("C is in transaction T1 of ledger M", in_tx, f"M = {m}, tx {package['T1'][:16]}..." if in_tx
                   else "T1 not validated or without C"))
    if n and in_tx:
        checks.append((f"0 < M - N <= x = {X_LEDGERS}", 0 < m - n["index"] <= X_LEDGERS, f"M - N = {m - n['index']}"))

    # 4. dev_params and pipeline admitted, developing the pixels yields exactly the JPEG
    checks.append(("dev_params admitted", package["dev_params"] in trust["dev_params"], str(package["dev_params"])))
    admitted = package["pipeline"] in trust["pipelines"] and package["pipeline"] == PIPELINE_ID
    checks.append(("Declared pipeline admitted", admitted, package["pipeline"]))
    same = admitted and develop(raw_pix, package["dev_params"]) == photo
    checks.append(("Developing the pixels yields exactly the JPEG", same, "byte-identical" if same else "different JPEG"))
    return checks
