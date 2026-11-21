"""Buy prepaid blind tokens from the proxy (README, Capture: "paying the fee with a prepaid blind token").

  python -m decima.capture.tokens buy <n>    pay n tokens on-chain, get them blind-signed
  python -m decima.capture.tokens list       unspent tokens held by the user

The purchase is linkable to the user's account, the redemption is not: the proxy signed blinded nonces."""

import argparse
import json
import os

from xrpl.models.transactions import Payment

from decima.capture import blind_tokens as blind
from decima.core.config import EXPLORER_TX_URL, OUT_DIR, TOKEN_PRICE_DROPS
from decima.core.ledger import get_client, submit
from decima.capture.proxy import Proxy, issuer_key
from decima.core.wallets import wallet

TOKENS_FILE = OUT_DIR / "user" / "tokens.json"


def load_tokens() -> list[dict]:
    return json.loads(TOKENS_FILE.read_text()) if TOKENS_FILE.exists() else []


def save_tokens(tokens: list[dict]) -> None:
    TOKENS_FILE.parent.mkdir(parents=True, exist_ok=True)
    TOKENS_FILE.write_text(json.dumps(tokens, indent=1))


def take_token() -> dict:
    tokens = load_tokens()
    if not tokens:
        raise SystemExit("no prepaid token left: run python -m decima.capture.tokens buy 5")
    save_tokens(tokens[1:])
    return tokens[0]


def buy(n: int) -> None:
    client, user, proxy = get_client(), wallet("user"), Proxy()
    pk = issuer_key().public_key()  # the proxy's published token key
    nonces = [os.urandom(32) for _ in range(n)]
    blinded = [blind.blind(pk, x) for x in nonces]
    payment = submit(client, Payment(account=user.address, destination=proxy.wallet.address,
                                     amount=str(n * TOKEN_PRICE_DROPS)), user)
    blind_sigs = proxy.issue_tokens(payment["hash"], [b for b, _ in blinded])
    new = [{"nonce": x.hex(), "sig": blind.finalize(pk, x, s, inv).hex()}
           for x, (_, inv), s in zip(nonces, blinded, blind_sigs)]
    save_tokens(load_tokens() + new)
    print(f"Bought {n} tokens for {n * TOKEN_PRICE_DROPS} drops: {EXPLORER_TX_URL}{payment['hash']}")
    print(f"  {len(load_tokens())} unspent tokens in {TOKENS_FILE.relative_to(OUT_DIR.parent)}")


def main() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("buy").add_argument("n", type=int)
    sub.add_parser("list")
    args = parser.parse_args()
    if args.cmd == "buy":
        buy(args.n)
    else:
        print(f"{len(load_tokens())} unspent tokens")


if __name__ == "__main__":
    main()
