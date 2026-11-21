"""The statement of the zero-knowledge proof, exactly as in the README (Attestation).

Public inputs: S, tail, dev_params, T0, C, pk_man, R_s, R_e, R_rev_s, R_rev_e.
Private (never revealed): metadata, keys, manifests, σs, σe, σ_man, Merkle paths.

relation() is the circuit: it returns every claim with its truth value. It is independent of the proof system
(see proof_system.py), so a real Longfellow circuit must implement exactly these claims."""

import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

from decima.core import merkle, sha256
from decima.core.crypto import H, pk_from_bytes
from decima.device.frame import DIGEST_SLOT, META_SIZE, dev_params_of, pixel_bytes

PUBLIC_INPUTS = ["S", "tail", "dev_params", "T0", "C", "pk_man", "R_s", "R_e", "R_rev_s", "R_rev_e"]
PRIVATE_INPUTS = ["metadata", "dev_manifest", "boot_manifest", "os_meta", "sigma_s", "sigma_e", "sigma_man",
                  "mem_s", "mem_e", "nonmem_s", "nonmem_e"]  # keys pk_s, pk_e are inside dev_manifest


def verify_prehashed(public_key, signature: bytes, digest: bytes) -> bool:
    """ECDSA P-256 verification on a given SHA-256 digest (README: "σs is valid on e", "ECDSA.verify(pk, H(m), σ)")."""
    try:
        public_key.verify(signature, digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        return True
    except (InvalidSignature, ValueError):
        return False


def resumed_digest(pub: dict, metadata: bytes) -> bytes | None:
    """e = SHA-256 resumed from state S over tail || metadata. The pixel length follows from dev_params."""
    S, tail = bytes.fromhex(pub["S"]), bytes.fromhex(pub["tail"])
    n_pix = pixel_bytes(pub["dev_params"])
    if len(S) != 32 or len(tail) != n_pix % 64 or len(metadata) != META_SIZE:
        return None
    return sha256.resume(S, n_pix - len(tail), tail + metadata)


def relation(pub: dict, w: dict) -> list[tuple[str, bool]]:
    metadata = w["metadata"]
    manifest = json.loads(w["dev_manifest"])
    pk_s, pk_e = bytes.fromhex(manifest["pk_s"]), bytes.fromhex(manifest["pk_e"])
    e = resumed_digest(pub, metadata)
    return [
        ("e = SHA-256 resumed from state S over tail ‖ metadata", e is not None),
        ("metadata[dev_fields] = dev_params", dev_params_of(metadata) == pub["dev_params"]),
        ("metadata[digest_slot] = H(T0 ‖ dev_manifest ‖ boot_manifest)",
         metadata[DIGEST_SLOT] == H(bytes.fromhex(pub["T0"]) + w["dev_manifest"] + w["boot_manifest"])),
        ("σs is valid on e under the sensor key in the manifest",
         e is not None and verify_prehashed(pk_from_bytes(pk_s), w["sigma_s"], e)),
        ("σe is valid under the enclave key in the same manifest",
         verify_prehashed(pk_from_bytes(pk_e), w["sigma_e"], H(H(w["sigma_s"]) + w["os_meta"]))),
        ("ECDSA.verify(pk_man, H(manifest), σ_man)",
         verify_prehashed(pk_from_bytes(bytes.fromhex(pub["pk_man"])), w["sigma_man"], H(w["dev_manifest"]))),
        ("C = H(σe)", H(w["sigma_e"]).hex() == pub["C"]),
        ("H(pk_s) ∈ R_s (Merkle tree)",
         merkle.verify_path(H(pk_s), w["mem_s"]["index"], [bytes.fromhex(x) for x in w["mem_s"]["path"]],
                            bytes.fromhex(pub["R_s"]))),
        ("H(pk_e) ∈ R_e (Merkle tree)",
         merkle.verify_path(H(pk_e), w["mem_e"]["index"], [bytes.fromhex(x) for x in w["mem_e"]["path"]],
                            bytes.fromhex(pub["R_e"]))),
        ("H(pk_s) ∉ R_rev_s (indexed Merkle tree)",
         merkle.verify_non_membership(H(pk_s), w["nonmem_s"], bytes.fromhex(pub["R_rev_s"]))),
        ("H(pk_e) ∉ R_rev_e (indexed Merkle tree)",
         merkle.verify_non_membership(H(pk_e), w["nonmem_e"], bytes.fromhex(pub["R_rev_e"]))),
    ]
