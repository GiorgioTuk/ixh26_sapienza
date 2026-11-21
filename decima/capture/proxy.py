"""The proxy that publishes the commitments C (README, Capture).

- Sells prepaid tokens: the user pays on-chain, the proxy blind-signs the user's blinded nonces.
- Behind an OHTTP gateway, receives {C, token}: checks the token signature and that it was never spent,
  then publishes C on-chain from its own account. It never learns who sent C (OHTTP) nor which payment
  funded it (blind signature); on-chain, every C comes from the same proxy account.
The ledger M containing the proxy's transaction is T1."""

import json

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from xrpl.models.transactions import AccountSet

from decima.capture import blind_tokens as blind, ohttp
from decima.core.config import OUT_DIR, TOKEN_PRICE_DROPS
from decima.core.ledger import get_client, lookup_tx, memo, submit
from decima.core.wallets import wallet

PROXY_DIR = OUT_DIR / "proxy"
COMMITMENT_MEMO = "ixh26/commitment"


def _load_or_create(path, create, load):
    PROXY_DIR.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        path.write_bytes(create())
        path.chmod(0o600)
    return load(path.read_bytes())


def issuer_key():
    return _load_or_create(PROXY_DIR / "issuer.key.pem",
                           lambda: blind.new_issuer_key().private_bytes(
                               serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                               serialization.NoEncryption()),
                           lambda b: serialization.load_pem_private_key(b, password=None))


def gateway_key() -> x25519.X25519PrivateKey:
    return _load_or_create(PROXY_DIR / "ohttp.key",
                           lambda: x25519.X25519PrivateKey.generate().private_bytes(
                               serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                               serialization.NoEncryption()),
                           x25519.X25519PrivateKey.from_private_bytes)


def _state(name: str) -> list:
    path = PROXY_DIR / name
    return json.loads(path.read_text()) if path.exists() else []


def _save_state(name: str, items: list) -> None:
    (PROXY_DIR / name).write_text(json.dumps(items))


class Proxy:
    def __init__(self):
        self.client, self.wallet = get_client(), wallet("proxy")
        self.log = []

    # --- token sale -------------------------------------------------------------------------------------
    def issue_tokens(self, payment_tx: str, blinded: list[bytes]) -> list[bytes]:
        used = _state("payments.json")
        tx = lookup_tx(self.client, payment_tx)
        if tx is None or payment_tx in used:
            raise PermissionError("payment not found, not validated or already used")
        tx_json = tx.get("tx_json", tx)
        paid = int(tx["meta"].get("delivered_amount", "0")) if isinstance(tx["meta"].get("delivered_amount"), str) else 0
        if tx_json.get("TransactionType") != "Payment" or tx_json.get("Destination") != self.wallet.address \
                or paid < len(blinded) * TOKEN_PRICE_DROPS:
            raise PermissionError("payment does not cover the tokens")
        _save_state("payments.json", used + [payment_tx])
        return [blind.blind_sign(issuer_key(), b) for b in blinded]

    # --- OHTTP gateway ----------------------------------------------------------------------------------
    def handle(self, source: str, message: bytes) -> bytes:
        request, ctx, enc = ohttp.decapsulate_request(gateway_key(), message)
        req = ohttp.parse_bhttp_request(request)
        self.log.append(f"gateway saw request from {source} (not the client): {req['method']} {req['path']}")
        if req["path"] == "/anchor":
            status, body = self.anchor(json.loads(req["body"]))
        else:
            status, body = 404, {"error": "not found"}
        return ohttp.encapsulate_response(ctx, enc, ohttp.bhttp_response(status, json.dumps(body).encode()))

    def anchor(self, body: dict) -> tuple[int, dict]:
        nonce, sig = bytes.fromhex(body["token"]["nonce"]), bytes.fromhex(body["token"]["sig"])
        spent = _state("spent.json")
        if not blind.verify(issuer_key().public_key(), nonce, sig):
            return 402, {"error": "invalid token"}
        if nonce.hex() in spent:
            return 402, {"error": "token already spent"}
        _save_state("spent.json", spent + [nonce.hex()])
        commitment = bytes.fromhex(body["C"])
        r = submit(self.client, AccountSet(account=self.wallet.address, memos=[memo(COMMITMENT_MEMO, commitment)]),
                   self.wallet)
        self.log.append("proxy   redeemed a valid unspent token, published C from its own account")
        return 200, {"tx": r["hash"], "ledger_index": r["ledger_index"]}
