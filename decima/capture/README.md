# capture

README, Capture: T0, frame, σs and σe, C = H(σe) sent anonymously to a proxy that publishes it (T1), DNG file.

| File | Contents |
|---|---|
| `__main__.py` | The capture flow |
| `ohttp.py` | Oblivious HTTP (RFC 9458) with Binary HTTP (RFC 9292) and HPKE (RFC 9180); the relay |
| `blind_tokens.py` | RSA blind signatures (RFC 9474, RSABSSA-SHA384-PSS-Deterministic) for prepaid tokens |
| `proxy.py` | Sells tokens against an on-chain payment; as OHTTP gateway, redeems a token and publishes C |
| `tokens.py` | The user's token wallet; command line to buy tokens |
| `dng.py` | DNG files: pixels as a CFA image, dev_params as standard tags, secure-negative data in DNGPrivateData |

```bash
python -m decima.capture.tokens buy 5
python -m decima.capture [--device ID] [--image photo.jpg]
```

C must land in a ledger M with 0 < M − N ≤ x (`X_LEDGERS` in `core/config.py`). The secure negative is written to `out/captures/<id>/capture.dng` and never leaves the device.
