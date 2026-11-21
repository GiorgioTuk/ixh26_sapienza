"""On-chain roots of trust (README, Setup): admitted manufacturers and key registries, readable by anyone.

Trust root (assumed pre-existing, out of scope): one account whose DID holds the hash of a document listing
the admitted manufacturers, the valid circuit hashes, the admitted development pipelines and the admitted
dev_params. The document itself is in the memo of the same DIDSet.

Manufacturers: each one writes only its own account.
- Sensor / enclave maker: registry R (Merkle tree of H(pk)) and revocation registry R_rev (indexed Merkle tree
  of H(pk)). Every DIDSet carries the added leaves in a memo (public history) and both roots in the DID.
- Assembler: its manifest key pk_man in the DID.

DID Data layouts (XRPL caps Data at 128 bytes):
  trust root  "IXT2" | SHA-256 of the trust-root document (32)
  registry    "IXR2" | kind b"S"/b"E" | size (4, big-endian) | R (32) | revoked count (4) | R_rev (32)
  assembler   "IXA2" | pk_man, compressed P-256 point (33)"""

from dataclasses import dataclass, field

from xrpl.clients import JsonRpcClient
from xrpl.models.transactions import DIDSet
from xrpl.wallet import Wallet

from decima.core import merkle
from decima.core.crypto import H, canonical, pk_bytes, pk_from_bytes
from decima.core.ledger import account_history, ledger_entry, memo, memos, submit

TRUST_MAGIC, REGISTRY_MAGIC, ASSEMBLER_MAGIC = b"IXT2", b"IXR2", b"IXA2"
TRUST_MEMO, ADD_MEMO, REVOKE_MEMO = "ixh26/trust-root", "ixh26/registry-add", "ixh26/revocation-add"
KIND_CODES = {"sensor": b"S", "enclave": b"E"}
LEAVES_PER_TX = 24  # memos are capped at 1 KB per transaction


def _did_data(client: JsonRpcClient, address: str) -> bytes:
    node = ledger_entry(client, did=address)
    return bytes.fromhex(node["Data"]) if node and node.get("Data") else b""


# --- trust root (pre-existing) ----------------------------------------------------------------------------

def publish_trust_root(client: JsonRpcClient, root_wallet: Wallet, document: dict) -> dict:
    doc = canonical(document)
    tx = DIDSet(account=root_wallet.address, data=(TRUST_MAGIC + H(doc)).hex(), memos=[memo(TRUST_MEMO, doc)])
    return submit(client, tx, root_wallet)


def read_trust_root(client: JsonRpcClient, address: str) -> dict | None:
    """The document whose hash is currently in the trust root's DID."""
    import json
    data = _did_data(client, address)
    if len(data) != 36 or data[:4] != TRUST_MAGIC:
        return None
    for entry in reversed(account_history(client, address)):
        for memo_type, payload in memos(entry["tx"]):
            if memo_type == TRUST_MEMO and H(payload) == data[4:]:
                return json.loads(payload)
    return None


# --- sensor / enclave registries --------------------------------------------------------------------------

@dataclass
class MakerRegistry:
    address: str
    kind: str | None = None
    leaves: list[bytes] = field(default_factory=list)          # H(pk), in registration order
    revoked: list[bytes] = field(default_factory=list)         # H(pk), in revocation order
    revoked_ledgers: list[int] = field(default_factory=list)   # ledger index of each revocation
    onchain_root: bytes | None = None
    onchain_rev_root: bytes | None = None
    historic_roots: set[bytes] = field(default_factory=set)    # every R this maker ever published

    @property
    def tree_root(self) -> bytes:
        return merkle.root(self.leaves)

    @property
    def rev_tree(self) -> merkle.IndexedTree:
        return merkle.IndexedTree.from_inserts(self.revoked)

    def rev_root_at(self, ledger: int) -> bytes:
        """R_rev as it was at a given ledger: only the revocations validated up to it."""
        return merkle.IndexedTree.from_inserts(
            [v for v, at in zip(self.revoked, self.revoked_ledgers) if at <= ledger]).root()

    def rev_roots_since(self, ledger: int) -> set[bytes]:
        """R_rev valid at the ledger and every later R_rev. Revocations are only added, so a key absent from a
        later set was also absent at that ledger."""
        roots = {self.rev_root_at(ledger)}
        for at in self.revoked_ledgers:
            if at > ledger:
                roots.add(self.rev_root_at(at))
        return roots

    @property
    def consistent(self) -> bool:
        """The roots in the DID must match the trees rebuilt from every published leaf."""
        return self.onchain_root == self.tree_root and self.onchain_rev_root == self.rev_tree.root()


def _encode_registry(kind: str, leaves: list[bytes], revoked: list[bytes]) -> bytes:
    return (REGISTRY_MAGIC + KIND_CODES[kind] + len(leaves).to_bytes(4, "big") + merkle.root(leaves)
            + len(revoked).to_bytes(4, "big") + merkle.IndexedTree.from_inserts(revoked).root())


def _decode_registry(data: bytes) -> tuple[str, bytes, bytes] | None:
    if len(data) != 77 or data[:4] != REGISTRY_MAGIC:
        return None
    kind = {v: k for k, v in KIND_CODES.items()}.get(data[4:5])
    return (kind, data[9:41], data[45:77]) if kind else None


def load_maker(client: JsonRpcClient, address: str) -> MakerRegistry:
    reg = MakerRegistry(address)
    for entry in account_history(client, address):
        tx = entry["tx"]
        if tx.get("TransactionType") != "DIDSet":
            continue
        decoded = _decode_registry(bytes.fromhex(tx.get("Data", "")))
        if decoded:
            reg.historic_roots.add(decoded[1])
        for memo_type, payload in memos(tx):
            if memo_type == ADD_MEMO:
                start, batch = int.from_bytes(payload[:4], "big"), payload[4:]
                if start != len(reg.leaves) or len(batch) % 32:
                    raise ValueError(f"registry {address}: leaves out of order")
                reg.leaves += [batch[i:i + 32] for i in range(0, len(batch), 32)]
            elif memo_type == REVOKE_MEMO:
                new = [payload[i:i + 32] for i in range(0, len(payload), 32)]
                reg.revoked += new
                reg.revoked_ledgers += [int(entry["ledger_index"])] * len(new)
    decoded = _decode_registry(_did_data(client, address))
    if decoded:
        reg.kind, reg.onchain_root, reg.onchain_rev_root = decoded
    return reg


def register_keys(client: JsonRpcClient, maker: Wallet, kind: str, key_hashes: list[bytes]) -> list[dict]:
    """Append H(pk) leaves: one DIDSet per batch, leaves in the memo, new roots in the DID."""
    reg = load_maker(client, maker.address)
    leaves, receipts = list(reg.leaves), []
    pending = [k for k in key_hashes if k not in leaves]
    for i in range(0, len(pending), LEAVES_PER_TX):
        batch, start = pending[i:i + LEAVES_PER_TX], len(leaves)
        leaves += batch
        tx = DIDSet(account=maker.address, data=_encode_registry(kind, leaves, reg.revoked).hex(),
                    memos=[memo(ADD_MEMO, start.to_bytes(4, "big") + b"".join(batch))])
        receipts.append(submit(client, tx, maker))
    return receipts


def revoke_keys(client: JsonRpcClient, maker: Wallet, kind: str, key_hashes: list[bytes]) -> dict | None:
    reg = load_maker(client, maker.address)
    new = [k for k in key_hashes if k not in reg.revoked]
    if not new:
        return None
    tx = DIDSet(account=maker.address, data=_encode_registry(kind, reg.leaves, reg.revoked + new).hex(),
                memos=[memo(REVOKE_MEMO, b"".join(new))])
    return submit(client, tx, maker)


# --- assembler --------------------------------------------------------------------------------------------

def publish_pk_man(client: JsonRpcClient, assembler: Wallet, public_key) -> dict | None:
    from cryptography.hazmat.primitives import serialization
    compressed = public_key.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)
    current = read_pk_man(client, assembler.address)
    if current is not None and pk_bytes(current) == pk_bytes(public_key):
        return None
    return submit(client, DIDSet(account=assembler.address, data=(ASSEMBLER_MAGIC + compressed).hex()), assembler)


def read_pk_man(client: JsonRpcClient, address: str):
    data = _did_data(client, address)
    if len(data) != 37 or data[:4] != ASSEMBLER_MAGIC:
        return None
    return pk_from_bytes(data[4:])
