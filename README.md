# IXH26 – DECIMA: DECentralized IMage Authentication

Project for the **IXH26 Italian XRPL Hackathon** (Bari, 20–21 November 2026), **Track 1 – Advanced Cryptography for Blockchain**.

> Challenge: design a secure protocol that generalises to any device and guarantees authentic photo origin via decentralised blockchain technology (XRP Ledger).

## Solution

#### Setup
We keep the photo sensor and the Secure Enclave. The sensor and Secure Enclave keys and the device manifest are certified by the hardware manufacturers and assemblers: they are the only ones able to do so and, since this is hardware production, this phase cannot be decentralized. The roots of trust for verification (admitted manufacturers and key registries) are instead published on-chain, where they remain publicly verifiable and immutable: they are therefore decentralized, censorship-resistant and cannot be modified by any authority. If, at the time of purchase, the device is not registered on-chain, the user returns it.

#### Capture
T0 is the hash of ledger N: it is necessarily subsequent to the publication of N, which provides a temporal lower bound, as in Apple. As in Apple, we keep the creation of the frame, σs and σe. We then send on-chain the commitment C = H(σe) anonymously (over OHTTP), paying the fee with a prepaid blind token, to a proxy that publishes them. The ledger M that includes it, within x ledgers of N, constitutes our T1. Finally, we generate the DNG file.

#### Attestation
The user generates a zero-knowledge proof with Longfellow (based on Ligero), optimized for SHA-256 and ECDSA signatures.
Public inputs: SHA256(raw_pix), dev_params, T0, C, pk_man, R_s, R_e, R_rev_s, R_rev_e.
Claim:
- e = H(raw_frame);
- e = H(raw_pix||metadata);
- metadata[corresponding_fields] = dev_params;
- H(T0 ‖ dev_manifest ‖ boot_manifest) = raw_frame[slot];
- σs is valid under the sensor key contained in the manifest;
- σe is valid under the Secure Enclave key contained in the same manifest;
- the manifest signature is valid: ECDSA.verify(pk_man, H(manifest), σ_man);
- C = H(σe);
- sensor and Secure Enclave are registered by their respective manufacturers: H(pk_s) ∈ R_s, H(pk_e) ∈ R_e (Merkle tree);
- the keys are not revoked: H(pk_s) ∉ R_rev_s, H(pk_e) ∉ R_rev_e (indexed Merkle tree).

Raw pix are the pixel captured by the camera wich are hashed without metadata. raw_pix||metadata compose the raw_frame, but metadata cannot be revealed because they would link the user. dev_params are the only metadata revealed which does not link the user and are needed in order to reconstruct the JPEG image from the raw pixels collected by the camera.

#### Verification
The user sends the photo, the raw pixel captured by the camera, the metadata needed for reconstructing JPEG from pixels and the proof. The verifier computes the hash of the pixels and checks that:
- the proof is valid and its public input matches the computed hash;
- the circuit hash, pk_man and roots R_s, R_e, R_rev_s, R_rev_e are the valid ones on-chain;
- T0 is the hash of ledger N, T1 is included in ledger M and M − N ≤ x;
- processing the raw with the declared pipeline, among the admitted ones, yields exactly the JPEG photo.

A verifier without these means can rely on a smart contract. To publish anonymously, the user can remove the metadata from the raw.

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
python -m sim.capture                      # Full HD 1920x1080 synthetic scene, T0 + T1 from the XRPL Testnet
python -m sim.capture --image photo.jpg    # use any photo as the scene (cropped to the frame size)
python -m sim.capture --size 5664x4248     # ~24 MP 4:3 frame (Apple supports 12, 24 and 48 MP)
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

### Phase 2b: development and reference signature

```bash
python -m sim.attest                        # verify, develop, sign -> reference.jpg + reference.json
python -m sim.check_reference <capture-id>  # client-side check of reference.jpg (or pass a JPEG path)
```

Follows the parameters of Apple's white paper (*Apple Reference Image*, September 2026):

| Step | Apple | This simulation |
|---|---|---|
| Gate | Develop only if digest, σs, σe, CA chains and same-device binding verify | Same; integrity failures stop development |
| Time bounds | Bad lower bound → March 31, 2026; missing/bad upper bound → development time | Same fallbacks, bounds taken from the XRPL ledgers |
| Development | Demosaicing, tone mapping, related corrections (closed, inside PCC) | Open, integer-only `ixh26-develop/1`: black level, gray-world WB (Q12), Hamilton-Adams demosaicing, sRGB LUT |
| Commitment | JPEG hashed; the hash is signed and gives the photo GUID | SHA-256 of the JPEG (with its reference metadata); GUID = first 128 bits |
| Final signature | Composite MLDSA87-RSA-3072-PSS-SHA512, embedded in the JPEG | Same scheme (both must verify), embedded in an APP11 segment |
| Confidence score | Neural network with hidden weights | Not implemented |
| Client check | Verify the final signature, check GUID not revoked | Commitment, GUID, composite signature, bit-identical re-development; revocation not implemented |

The development is deterministic: re-running it on the same raw gives bit-identical pixels, so anyone holding the secure negative can check that the reference JPEG really comes from it. The reference metadata carries no device identifier. Hamilton-Adams was chosen over Malvar-He-Cutler because the latter's patent (US 7,502,505) is active until 2027-01-25, while Hamilton-Adams' (US 5,629,734) has expired. Not stated by Apple and assumed here: 12-bit RGGB raw, JPEG quality 92.

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
  develop.py        Phase 2b open, deterministic raw development
  service.py        composite ML-DSA-87 + RSA-3072-PSS-SHA512 signing service
  jpeg_container.py embed/strip the signature segment in a JPEG
  attest.py         Phase 2 attestation CLI: verify, develop, sign the reference JPEG
  check_reference.py client-side check of a reference JPEG
```

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
