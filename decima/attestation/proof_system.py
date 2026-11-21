"""The proof system, SIMULATED. This is the only file a real Longfellow (Ligero) backend has to replace.

Interface:   prove(public, witness) -> proof      verify(proof) -> bool      CIRCUIT_ID
The simulation runs statement.relation() on the witness and emits a proof only if every claim holds; the proof
is an HMAC over the circuit ID and the public inputs under a simulator key. It reveals nothing about the
witness, but it is NOT a zero-knowledge proof: verifying needs the simulator key, and whoever holds that key
could forge proofs. A real backend is publicly verifiable and needs no key."""

import hashlib
import hmac
import secrets
import struct
from pathlib import Path

from decima.attestation import statement
from decima.core import merkle, sha256
from decima.core.config import OUT_DIR
from decima.core.crypto import canonical
from decima.device.frame import META_FIELDS

SYSTEM = "Longfellow (SIMULATED)"
# The circuit is identified by the code that defines the statement; the trust root lists the valid IDs.
_SOURCES = [Path(statement.__file__), Path(merkle.__file__), Path(sha256.__file__)]
CIRCUIT_ID = "longfellow-sim/" + hashlib.sha256(
    b"".join(p.read_bytes() for p in _SOURCES) + repr(META_FIELDS).encode()).hexdigest()[:16]
SIM_KEY_FILE = OUT_DIR / "zk" / "simulator.key"


class ProofError(Exception):
    pass


def _sim_key() -> bytes:
    if not SIM_KEY_FILE.exists():
        SIM_KEY_FILE.parent.mkdir(parents=True, exist_ok=True)
        SIM_KEY_FILE.write_bytes(secrets.token_bytes(32))
        SIM_KEY_FILE.chmod(0o600)
    return SIM_KEY_FILE.read_bytes()


def _tag(circuit: str, public: dict) -> str:
    return hmac.new(_sim_key(), circuit.encode() + canonical(public), hashlib.sha256).hexdigest()


def prove(public: dict, witness: dict) -> dict:
    if sorted(public) != sorted(statement.PUBLIC_INPUTS) or sorted(witness) != sorted(statement.PRIVATE_INPUTS):
        raise ProofError("inputs differ from the statement")
    try:
        failed = [name for name, ok in statement.relation(public, witness) if not ok]
    except (KeyError, ValueError, TypeError, IndexError, struct.error) as exc:
        raise ProofError(f"malformed witness, no proof ({exc.__class__.__name__})") from exc
    if failed:
        raise ProofError("statement false, no proof: " + "; ".join(failed))
    return {"system": SYSTEM, "circuit": CIRCUIT_ID, "public_inputs": public, "proof": _tag(CIRCUIT_ID, public)}


def verify(proof: dict) -> bool:
    return (sorted(proof.get("public_inputs", {})) == sorted(statement.PUBLIC_INPUTS)
            and hmac.compare_digest(proof.get("proof", ""), _tag(proof["circuit"], proof["public_inputs"])))
