# attestation

README, Attestation: the zero-knowledge proof and the package the user sends.

| File | Contents |
|---|---|
| `statement.py` | The circuit: public inputs (S, tail, dev_params, T0, C, pk_man, R_s, R_e, R_rev_s, R_rev_e), private inputs, and every claim of the README |
| `proof_system.py` | The proof backend: `prove`, `verify`, `CIRCUIT_ID`. **Simulated** Longfellow (HMAC under a simulator key) |
| `__main__.py` | Builds public inputs (S and tail from the pixels, roots and pk_man from the ledger) and the witness, proves, writes the package |

```bash
python -m decima.attestation [capture-id] [--roots current|capture-time]
```

`--roots current` (default) proves against the current revocation roots and passes both verification modes; `--roots capture-time` proves against the roots valid at ledger M and never expires.

Output in `out/published/<id>/`: `photo.jpg`, `raw.dng` (pixels only), `proof.json`, `package.json` (dev_params, pipeline, T1).

**Plugging in Longfellow:** replace `proof_system.py` keeping its interface. The circuit must implement exactly `statement.relation`; publish its circuit ID in the trust root (`python -m decima.setup trust-root`).
