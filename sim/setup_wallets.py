"""Create or reuse one funded Testnet wallet per on-chain role; seeds are stored in .env."""

from dotenv import set_key
from xrpl.account import does_account_exist, get_balance
from xrpl.utils import drops_to_xrp
from xrpl.wallet import Wallet, generate_faucet_wallet

from sim.config import ENV_FILE, ROLES, role_seed, seed_var
from sim.ledger import get_client


def main() -> None:
    client = get_client()
    ENV_FILE.touch(mode=0o600, exist_ok=True)
    for role in ROLES:
        seed = role_seed(role)
        if seed:
            wallet = Wallet.from_seed(seed)
            if not does_account_exist(wallet.address, client):
                generate_faucet_wallet(client, wallet, usage_context="ixh26 simulation")
            status = "reused"
        else:
            wallet = generate_faucet_wallet(client, usage_context="ixh26 simulation")
            set_key(ENV_FILE, seed_var(role), wallet.seed)
            status = "created"
        balance = drops_to_xrp(str(get_balance(wallet.address, client)))
        print(f"{role:<13} {status:<8} {wallet.address}  {balance} XRP")


if __name__ == "__main__":
    main()
