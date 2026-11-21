"""Testnet wallets, one per role (seeds in .env, git-ignored).

  python -m decima.core.wallets     create or reuse one funded Testnet wallet per role"""

from dotenv import set_key
from xrpl.account import does_account_exist, get_balance
from xrpl.utils import drops_to_xrp
from xrpl.wallet import Wallet, generate_faucet_wallet

from decima.core.config import ENV_FILE, ROLES, role_seed, seed_var
from decima.core.ledger import get_client


def wallet(role: str) -> Wallet:
    seed = role_seed(role)
    if not seed:
        raise SystemExit(f"no {role} wallet: run python -m decima.core.wallets")
    return Wallet.from_seed(seed)


def main() -> None:
    client = get_client()
    ENV_FILE.touch(mode=0o600, exist_ok=True)
    for role in ROLES:
        seed = role_seed(role)
        if seed:
            w = Wallet.from_seed(seed)
            if not does_account_exist(w.address, client):
                generate_faucet_wallet(client, w, usage_context="ixh26 simulation")
            status = "reused"
        else:
            w = generate_faucet_wallet(client, usage_context="ixh26 simulation")
            set_key(ENV_FILE, seed_var(role), w.seed)
            status = "created"
        print(f"{role:<13} {status:<8} {w.address}  {drops_to_xrp(str(get_balance(w.address, client)))} XRP")


if __name__ == "__main__":
    main()
