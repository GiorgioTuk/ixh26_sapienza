# IXH26 – Universal Photo-Origin Validation Protocol

Project for the **IXH26 Italian XRPL Hackathon** (Bari, 20–21 November 2026), **Track 1 – Advanced Cryptography for Blockchain**.

> Challenge: design a secure protocol that generalises to any device and guarantees authentic photo origin via decentralised blockchain technology (XRP Ledger).

## Problem

_TBD_

## Solution

_TBD_

## Architecture

_TBD_

## Getting started

Requires Python 3.12. Everything runs on the **XRPL Testnet**.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m sim.setup_wallets
python -m sim.check_setup --anchor
```

- `sim.setup_wallets` creates (or reuses) one funded Testnet wallet per on-chain role and stores the seeds in `.env`, which is git-ignored. Never commit it.
- `sim.check_setup` prints library versions, Testnet status and wallet balances; `--anchor` also sends a test memo transaction and reads it back from a validated ledger.

### On-chain roles

| Role | Replaces (Apple) | Purpose |
|---|---|---|
| `manufacturer` | Factory CAs | Issues and revokes device credentials |
| `device` | Device + timestamp service | Camera identity; anchors capture commitments |
| `verifier` | Private Cloud Compute | Open attestation service; publishes reference-image records |

### Phase 1 simulation (capture)

No public Apple Reference Image samples exist, so capture is simulated with ECDSA P-256 keys, as in Apple's design.

```bash
python -m sim.factory                      # 3 CAs (once) + provision a new device
python -m sim.capture                      # synthetic scene, T0 + T1 from the XRPL Testnet
python -m sim.capture --image photo.jpg    # use any photo as the scene
python -m sim.capture --no-anchor          # offline capture: no T1
```

| Step | What happens |
|---|---|
| T0 | Latest validated ledger (index, hash, close time): lower bound, the capture cannot predate it |
| Embedded digest | SHA-256 over T0, device manifest and secure boot manifest; the only input the sensor accepts |
| σs | Sensor signs the 12-bit RGGB raw frame + frame metadata (incl. embedded digest) |
| σe | Secure Enclave signs SHA-256(σs) + OS metadata (lens, zoom, exposure, ISO) |
| T1 | Device wallet anchors SHA-256(σe) in a memo; the validated ledger close time is the upper bound |

Each capture is written to `out/captures/<id>/`: `capture.json` (metadata, manifests, signatures, T0/T1), `raw.npy` (raw frame) and `debug_scene.png` (simulation-only ground truth). `out/` holds private keys and is git-ignored.

### Project layout

```
sim/
  config.py         network URL, roles, seeds from .env
  ledger.py         XRPL client, ledger/T0 lookup, memo anchoring, transaction lookup
  setup_wallets.py  create/fund role wallets
  check_setup.py    environment and Testnet check
  crypto.py         ECDSA P-256 keys, signatures, X.509 certificates, canonical JSON
  protocol.py       exact bytes each entity signs or commits to
  factory.py        simulated factory: CAs, device provisioning, manifests
  scene.py          synthetic scene or photo as linear light
  device.py         Phase 1 entities: Sensor, SecureEnclave, Device
  capture.py        Phase 1 capture flow and secure-negative bundle
```

## Team

| Name | Role |
|---|---|
| Giorgio | Implementation & pitch |
| _TBD_ | _TBD_ |

## Third-party libraries & pre-existing work

_TBD_

## AI usage disclosure

As required by the hackathon rules, we declare every AI tool used, how and where.

| Tool | Used for | Where |
|---|---|---|
| Claude (Anthropic) | Repository setup, planning | This repository |
| Claude (Anthropic) | Simulation environment setup code (Testnet wallets, memo anchoring, checks) | `sim/`, `requirements.txt` |
| Claude (Anthropic) | Phase 1 capture simulator (factory, sensor/enclave signatures, T0/T1 on XRPL) | `sim/crypto.py`, `protocol.py`, `factory.py`, `scene.py`, `device.py`, `capture.py` |
