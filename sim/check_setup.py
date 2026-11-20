"""Check dependencies, Testnet connectivity and role wallets; --anchor also sends a test memo."""

import argparse
import hashlib
import platform
from datetime import datetime, timezone
from importlib.metadata import version

from xrpl.account import does_account_exist, get_balance
from xrpl.utils import drops_to_xrp
from xrpl.wallet import Wallet

from sim.config import ROLES, RPC_URL, role_seed
from sim.ledger import anchor_memo, get_client, lookup_tx, server_status

PACKAGES = ["xrpl-py", "cryptography", "numpy", "pillow", "rawpy", "python-dotenv"]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--anchor", action="store_true", help="send a test memo from the verifier wallet")
    args = parser.parse_args()

    print(f"Python {platform.python_version()}")
    print("  " + ", ".join(f"{p} {version(p)}" for p in PACKAGES))

    client = get_client()
    s = server_status(client)
    print(f"\nTestnet {RPC_URL}")
    print(f"  rippled {s['build']} | validated ledger {s['ledger_index']} ({s['ledger_age_s']}s ago)"
          f" | reserve {s['reserve_base_xrp']} + {s['reserve_inc_xrp']} XRP/object")

    print("\nWallets")
    wallets = {}
    for role in ROLES:
        seed = role_seed(role)
        if not seed:
            print(f"  {role:<13} missing: run python -m sim.setup_wallets")
            continue
        wallet = Wallet.from_seed(seed)
        if not does_account_exist(wallet.address, client):
            print(f"  {role:<13} {wallet.address}  not on ledger: run python -m sim.setup_wallets")
            continue
        wallets[role] = wallet
        print(f"  {role:<13} {wallet.address}  {drops_to_xrp(str(get_balance(wallet.address, client)))} XRP")

    if not args.anchor:
        return
    if "verifier" not in wallets:
        raise SystemExit("\nverifier wallet not ready")

    payload = f"ixh26 setup check {datetime.now(timezone.utc).isoformat()}"
    digest = hashlib.sha256(payload.encode()).hexdigest()
    sent = anchor_memo(client, wallets["verifier"], "ixh26/setup-check", digest)
    found = lookup_tx(client, sent["hash"])
    print(f"\nTest anchor: {sent['result']} | validated {found['validated']} | ledger {found['ledger_index']}"
          f" | close time {found['close_time']}")
    print(f"  tx {found['hash']}")
    print(f"  memo matches: {found['memos'] == [{'type': 'ixh26/setup-check', 'data': digest}]}")


if __name__ == "__main__":
    main()
