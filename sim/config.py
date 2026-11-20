import os
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
ENV_FILE = ROOT / ".env"
OUT_DIR = ROOT / "out"
load_dotenv(ENV_FILE)

RPC_URL = os.getenv("XRPL_RPC_URL", "https://s.altnet.rippletest.net:51234/")
EXPLORER_TX_URL = "https://testnet.xrpl.org/transactions/"

# On-chain roles that replace Apple's centralised services.
ROLES = {
    "manufacturer": "Issues and revokes device credentials (replaces the factory CAs).",
    "device": "Camera device identity; anchors capture commitments on the ledger.",
    "verifier": "Open attestation service; publishes reference-image records (replaces PCC).",
}


def seed_var(role: str) -> str:
    return f"{role.upper()}_SEED"


def role_seed(role: str) -> str | None:
    return os.getenv(seed_var(role)) or None
