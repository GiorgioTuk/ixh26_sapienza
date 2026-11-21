# IXH26 – DECIMA: DECentralized IMage Authentication

Project for the **IXH26 Italian XRPL Hackathon** (Bari, 20–21 November 2026), **Track 1 – Advanced Cryptography for Blockchain**.

> Challenge: design a secure protocol that generalises to any device and guarantees authentic photo origin via decentralised blockchain technology (XRP Ledger).

## Solution

#### Setup
We keep the photo sensor and the Secure Enclave. The sensor and Secure Enclave keys and the device manifest are certified by the hardware manufacturers and assemblers: they are the only ones able to do so and, since this is hardware production, this phase cannot be decentralized. The roots of trust for verification (admitted manufacturers and key registries) are instead published on-chain, where they remain publicly verifiable and immutable: they are therefore decentralized, censorship-resistant and cannot be modified by any authority.

#### Capture
T0 is the hash of ledger N: it is necessarily subsequent to the publication of N, which provides a temporal lower bound, as in Apple. As in Apple, we keep the creation of the frame, σs and σe. The sensor hardware signs the frame exactly as it streams it, pixels first and metadata after: σs = ECDSA(sk_s, e) with e = SHA256(raw_pix ‖ metadata). We then send on-chain the commitment C = H(σe) anonymously (over OHTTP), paying the fee with a prepaid blind token, to a proxy that publishes them. The ledger M that includes it, within x ledgers of N, constitutes our T1. Finally, we generate the DNG file.

#### Attestation
The user generates a zero-knowledge proof with Longfellow (based on Ligero), optimized for SHA-256 and ECDSA signatures.
Public inputs: S, tail, dev_params, T0, C, pk_man, R_s, R_e, R_rev_s, R_rev_e.
Private (never revealed): metadata, keys, manifests, σs, σe, σ_man, Merkle paths.
Claim:
- e = SHA-256 resumed from state S over tail ‖ metadata, i.e. e = SHA256(raw_pix ‖ metadata);
- metadata[dev_fields] = dev_params;
- metadata[digest_slot] = H(T0 ‖ dev_manifest ‖ boot_manifest);
- σs is valid on e under the sensor key contained in the manifest;
- σe is valid under the Secure Enclave key contained in the same manifest;
- the manifest signature is valid: ECDSA.verify(pk_man, H(manifest), σ_man);
- C = H(σe);
- sensor and Secure Enclave are registered by their respective manufacturers: H(pk_s) ∈ R_s, H(pk_e) ∈ R_e (Merkle tree);
- the keys are not revoked: H(pk_s) ∉ R_rev_s, H(pk_e) ∉ R_rev_e (indexed Merkle tree).

raw_pix are the pixels captured by the sensor; raw_pix ‖ metadata is the raw frame signed by the sensor. The metadata cannot be revealed because it would link the user (it contains the device-bound digest), so it stays private. dev_params are the only metadata fields revealed: model-level values (resolution, CFA pattern, bit depth, black and white levels) needed to develop the JPEG from the pixels. Per-unit calibration data is excluded, since it would identify the device. The metadata layout is fixed, so dev_fields and digest_slot are fixed offsets.

The circuit never hashes the megabytes of pixels. SHA-256 reads its input in 64-byte blocks and keeps a 32-byte running state: S is the state right after the last full block of pixels, tail the remaining pixel bytes (fewer than 64). S and tail depend only on the pixels, so the verifier computes them itself from raw_pix; the circuit only continues the hash over tail ‖ metadata (a few blocks) and checks that the result is the e signed by the sensor. Together the two parts are exactly SHA256(raw_pix ‖ metadata): different pixels give a different S, from which no signed e can be reached. This requires the sensor to stream pixels before metadata, and raw_pix to be sent in the exact byte format the sensor hashed.

#### Verification
The user sends the JPEG photo, the raw pixels, dev_params, T1 (the transaction containing C) and the proof; the metadata never leaves the device. The verifier runs SHA-256 over the pixels up to state S and checks that:
- the proof is valid for the public inputs, with S and tail computed by the verifier itself;
- the circuit hash, pk_man and roots R_s, R_e, R_rev_s, R_rev_e are the valid ones on-chain;
- T0 is the hash of ledger N, C is in a transaction of ledger M (T1) and 0 < M − N ≤ x;
- dev_params and the declared pipeline are among the admitted ones, and developing the pixels with them yields exactly the JPEG photo.

## Getting started

Requires Python 3.12. Everything runs on the **XRPL Testnet**.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m decima.core.wallets        # one funded Testnet wallet per role, seeds in .env (git-ignored)
python -m decima.setup trust-root    # bootstrap the pre-existing trust root (once)
python -m decima.demo --attacks      # the whole protocol phase by phase, plus attacks
```

The code is organised by protocol phase in `decima/` (`core`, `device`, `setup`, `capture`, `attestation`, `pipeline`, `verification`); each folder has its own README. See [ARCHITECTURE.md](ARCHITECTURE.md) for the design and the data formats, and [LICENSE.md](LICENSE.md) (Apache-2.0).

```bash
python -m decima.setup device                  # Setup: provision a device, manufacturers register its keys on-chain
python -m decima.capture.tokens buy 5          # Capture: buy prepaid blind tokens from the proxy
python -m decima.capture                       # Capture: T0, frame, σs, σe, C over OHTTP, T1, DNG
python -m decima.attestation                   # Attestation: proof + photo.jpg, raw.dng (pixels only), package.json
python -m decima.verification                  # Verification
python -m decima.setup revoke <device> sensor  # a manufacturer revokes a key
```

**The zero-knowledge proof is simulated** (`decima/attestation/proof_system.py`): the statement is implemented exactly (`statement.py`), but the proof is an HMAC under a simulator key, not a Longfellow/Ligero proof. A real backend replaces only `proof_system.py`.

## Team

| Name |
|---|
| Giorgio Tuccinardi|
| Leonardo Vona |
| Leonardo Rufini |

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
| Claude (Anthropic) | Phase 2b development pipeline, composite signature, reference JPEG checks; algorithm and patent research | `sim/develop.py`, `service.py`, `jpeg_container.py`, `attest.py`, `check_reference.py` |
| Claude (Anthropic) | Review of the solution design against Apple's core requirements and the track slides | Solution design, pitch |
| Claude (Anthropic) | Implementation of the solution README, code organisation and documentation | `decima/`, `ARCHITECTURE.md`, sector READMEs |
