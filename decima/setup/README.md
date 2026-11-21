# setup

README, Setup: keys and manifest certified at the factory, roots of trust published on-chain.

| File | Contents |
|---|---|
| `factory.py` | Provisioning: sensor and Secure Enclave key pairs, device manifest signed by the assembler (σ_man) |
| `registry.py` | On-chain roots of trust: trust-root document, key registries R_s / R_e and revocation registries R_rev_s / R_rev_e in the makers' DIDs (leaves in memos), pk_man in the assembler's DID |
| `__main__.py` | Command line |

```bash
python -m decima.setup trust-root                    # bootstrap the pre-existing trust root
python -m decima.setup device [--no-register]        # provision a device; makers register its keys
python -m decima.setup revoke <device> sensor|enclave
python -m decima.setup status                        # roots of trust read from the ledger
```

`trust-root` must be re-run after any change to the statement or the pipeline, because their hashes are the IDs the trust root admits.
