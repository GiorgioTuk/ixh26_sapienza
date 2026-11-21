# verification

README, Verification: everything the verifier checks, using only the package the user sent and the ledger.

| File | Contents |
|---|---|
| `verifier.py` | `verify_package(folder, client)`: the four groups of checks of the README |
| `__main__.py` | Command line, prints each check and the verdict |

```bash
python -m decima.verification [capture-id | folder]
```

1. The proof is valid, with S and tail recomputed from the received pixels.
2. Circuit hash, pk_man, R_s, R_e (any root an admitted maker published) and R_rev_s, R_rev_e (the current ones) are valid on-chain.
3. T0 is the hash of a validated ledger N, C is in the validated transaction T1 of ledger M, and 0 < M − N ≤ x.
4. dev_params and the pipeline are admitted, and developing the pixels gives exactly the JPEG.
