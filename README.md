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

### Phase 2a: open verification

Replaces Apple's Private Cloud Compute checks: anyone with the CA root certificates and access to an XRPL node can run it. It trusts the ledger, not the bundle's own T0/T1 claims.

```bash
python -m sim.verify                 # latest capture; writes verification.json next to it
python -m sim.verify <capture-id>
python -m sim.verify --offline       # skip the on-chain time checks
python -m sim.tamper all             # build tampered copies and verify each one
```

Checks: bundle format, raw frame vs metadata and hash, manifest signed by CA 3, sensor cert by CA 1, enclave cert by CA 2, same-device binding, embedded digest, σs, σe, T0 ledger on-chain, T1 anchor = commitment(σe), T1 claims vs chain, T0 before T1. Verdict: `VERIFIED`, `VERIFIED WITH WARNINGS` (e.g. offline capture without T1) or `REJECTED`.

| Attack (`sim.tamper`) | Caught by |
|---|---|
| `raw-bit`: flip one bit of the raw frame | Raw SHA-256, σs |
| `os-meta`: change zoom after signing | σe |
| `backdate`: claim a real but older T0 ledger | Embedded digest |
| `fake-sensor`: edited image signed with an uncertified key | Manifest (CA 3), sensor cert (CA 1), embedded digest, σe |
| `replay-t1`: reuse another capture's anchor | T1 anchor = commitment(σe) |

The timestamp scheme lives in `sim/timestamps.py` (`acquire_t0`, `anchor_t1`, `verify_window`), so it can be replaced without touching capture or verification. Revocation is not implemented yet.

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
  timestamps.py     T0/T1 scheme: acquire, anchor, verify on XRPL
  report.py         check results and verdict
  verifier.py       Phase 2a checks (certificates, signatures, digest, time window)
  verify.py         verification CLI, writes verification.json
  tamper.py         attack simulations against a capture
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
| Claude (Anthropic) | Phase 2a verifier and attack simulations | `sim/timestamps.py`, `report.py`, `verifier.py`, `verify.py`, `tamper.py` |
