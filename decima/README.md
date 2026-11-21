# decima

The DECIMA simulation, one sub-package per phase of the protocol in the [repository README](../README.md). See [ARCHITECTURE.md](../ARCHITECTURE.md) for how the sectors fit together.

| Sector | Phase | Entry point |
|---|---|---|
| [core](core/) | shared | `python -m decima.core.wallets` |
| [device](device/) | Capture (the camera) | — |
| [setup](setup/) | Setup | `python -m decima.setup` |
| [capture](capture/) | Capture | `python -m decima.capture`, `python -m decima.capture.tokens` |
| [attestation](attestation/) | Attestation | `python -m decima.attestation` |
| [pipeline](pipeline/) | Verification (development) | — |
| [verification](verification/) | Verification | `python -m decima.verification` |

`python -m decima.demo [--attacks] [--image photo.jpg]` runs every phase in order and prints a summary.
