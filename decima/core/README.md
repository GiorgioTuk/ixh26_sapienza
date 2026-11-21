# core

Building blocks shared by every sector. No protocol logic lives here.

| File | Contents |
|---|---|
| `config.py` | Testnet URL, output folders, XRPL roles, protocol parameters (`X_LEDGERS` = x, token price) |
| `wallets.py` | One funded Testnet wallet per role, seeds in `.env` (git-ignored); `wallet(role)` |
| `crypto.py` | SHA-256 `H`, canonical JSON, ECDSA P-256 keys and signatures, public-key encoding |
| `sha256.py` | Resumable SHA-256: `midstate(data)` gives (S, tail), `resume(S, n, rest)` finishes the hash |
| `merkle.py` | Fixed-depth Merkle tree (registries) and indexed Merkle tree (revocations, non-membership) |
| `ledger.py` | XRPL access: validated ledgers, transactions, ledger objects, account history, memos |

```bash
python -m decima.core.wallets     # create or reuse the Testnet wallets
```
