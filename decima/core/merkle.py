"""Merkle trees for the key registries (README: "Merkle tree") and the revocation registries
(README: "indexed Merkle tree").

Both are fixed-depth binary SHA-256 trees, so a proof always has DEPTH siblings and the circuit has a single
shape. Leaves and inner nodes are domain-separated (0x00 / 0x01); empty positions hold precomputed zero
subtrees.

Indexed Merkle tree: every leaf is (value, next_value), and the leaves form a linked list sorted by value,
starting from the sentinel (0, 0); next_value = 0 means "no larger value". A value x is NOT in the set iff
there is a leaf (low, next) with low < x and (x < next or next = 0): one membership proof of that leaf proves
non-membership of x."""

import hashlib
from dataclasses import dataclass

DEPTH = 20  # 2^20 ~ 1M entries per registry
_LEAF, _NODE = b"\x00", b"\x01"


def _h(*parts: bytes) -> bytes:
    return hashlib.sha256(b"".join(parts)).digest()


def leaf_hash(leaf: bytes) -> bytes:
    return _h(_LEAF, leaf)


ZERO = [leaf_hash(b"")]  # ZERO[d]: root of an empty subtree of height d
for _ in range(DEPTH):
    ZERO.append(_h(_NODE, ZERO[-1], ZERO[-1]))


def _levels(leaves: list[bytes]) -> list[list[bytes]]:
    if len(leaves) > 2 ** DEPTH:
        raise ValueError("tree full")
    level = [leaf_hash(v) for v in leaves]
    levels = [level]
    for d in range(DEPTH):
        level = [_h(_NODE, level[i], level[i + 1] if i + 1 < len(level) else ZERO[d])
                 for i in range(0, len(level), 2)]
        levels.append(level)
    return levels


def root(leaves: list[bytes]) -> bytes:
    return _levels(leaves)[-1][0] if leaves else ZERO[DEPTH]


def path(leaves: list[bytes], index: int) -> list[bytes]:
    levels, siblings = _levels(leaves), []
    for d in range(DEPTH):
        sibling = index ^ 1
        siblings.append(levels[d][sibling] if sibling < len(levels[d]) else ZERO[d])
        index //= 2
    return siblings


def verify_path(leaf: bytes, index: int, siblings: list[bytes], expected_root: bytes) -> bool:
    if len(siblings) != DEPTH or not 0 <= index < 2 ** DEPTH:
        return False
    node = leaf_hash(leaf)
    for sibling in siblings:
        node = _h(_NODE, sibling, node) if index & 1 else _h(_NODE, node, sibling)
        index //= 2
    return node == expected_root


# --- indexed Merkle tree ---------------------------------------------------------------------------------

@dataclass
class IndexedTree:
    """Insertion-ordered leaves; each leaf encodes (value, next_value) as 64 bytes."""
    values: list[bytes]
    nexts: list[bytes]

    @classmethod
    def empty(cls) -> "IndexedTree":
        return cls([bytes(32)], [bytes(32)])

    @classmethod
    def from_inserts(cls, inserted: list[bytes]) -> "IndexedTree":
        tree = cls.empty()
        for value in inserted:
            tree.insert(value)
        return tree

    def leaves(self) -> list[bytes]:
        return [v + n for v, n in zip(self.values, self.nexts)]

    def root(self) -> bytes:
        return root(self.leaves())

    def low_leaf(self, value: bytes) -> int:
        """Index of the leaf (low, next) with low < value and (value < next or next = 0)."""
        for i, (low, nxt) in enumerate(zip(self.values, self.nexts)):
            if low < value and (value < nxt or nxt == bytes(32)):
                return i
        raise KeyError("value already in the set")

    def insert(self, value: bytes) -> None:
        if value == bytes(32) or value in self.values:
            raise ValueError("value zero or already present")
        i = self.low_leaf(value)
        self.values.append(value)
        self.nexts.append(self.nexts[i])
        self.nexts[i] = value

    def non_membership_witness(self, value: bytes) -> dict:
        i = self.low_leaf(value)
        return {"index": i, "low": self.values[i].hex(), "next": self.nexts[i].hex(),
                "path": [s.hex() for s in path(self.leaves(), i)]}


def verify_non_membership(value: bytes, witness: dict, expected_root: bytes) -> bool:
    low, nxt = bytes.fromhex(witness["low"]), bytes.fromhex(witness["next"])
    in_gap = low < value and (value < nxt or nxt == bytes(32))
    return in_gap and verify_path(low + nxt, witness["index"], [bytes.fromhex(s) for s in witness["path"]],
                                  expected_root)
