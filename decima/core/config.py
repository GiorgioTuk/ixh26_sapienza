"""Network, roles and protocol parameters shared by every sector."""

import os
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[2]
ENV_FILE = ROOT / ".env"
OUT_DIR = ROOT / "out"  # simulation state and outputs (keys, devices, captures, packages); git-ignored
CAPTURES_DIR = OUT_DIR / "captures"    # secure negatives (DNG with private data), stay on the device
PUBLISHED_DIR = OUT_DIR / "published"  # what the user sends to verifiers
load_dotenv(ENV_FILE)

RPC_URL = os.getenv("XRPL_RPC_URL", "https://s.altnet.rippletest.net:51234/")
EXPLORER_TX_URL = "https://testnet.xrpl.org/transactions/"

# XRPL accounts used by the simulation. The trust root is assumed pre-existing (out of scope): the simulation
# only bootstraps it once so that verifiers have something on-chain to read.
ROLES = {
    "trust_root": "Pre-existing trust root: admitted manufacturers, circuit hashes, pipelines and dev_params",
    "sensor_maker": "Sensor manufacturer: registry R_s of H(pk_s) and revocation registry R_rev_s",
    "enclave_maker": "Secure Enclave manufacturer: registry R_e of H(pk_e) and revocation registry R_rev_e",
    "assembler": "Device assembler: signs device manifests with pk_man",
    "proxy": "Receives C over OHTTP, redeems the prepaid blind token, publishes C on-chain",
    "user": "Device owner: buys prepaid blind tokens",
}

# Capture: C must be included in a ledger M with 0 < M - N <= X_LEDGERS, N being the ledger whose hash is T0.
# 20 ledgers is about one minute on XRPL (3-4 s per ledger): enough for OHTTP + proxy publication.
X_LEDGERS = 20

TOKEN_PRICE_DROPS = 10_000  # price of one prepaid token paid to the proxy (0.01 XRP)


def seed_var(role: str) -> str:
    return f"{role.upper()}_SEED"


def role_seed(role: str) -> str | None:
    return os.getenv(seed_var(role)) or None
