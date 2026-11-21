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
- the circuit hash, pk_man and roots R_s, R_e are the valid ones on-chain, and R_rev_s, R_rev_e are the revocation roots required by the chosen verification mode;
- T0 is the hash of ledger N, C is in a transaction of ledger M (T1) and 0 < M − N ≤ x;
- dev_params and the declared pipeline are among the admitted ones, and developing the pixels with them yields exactly the JPEG photo.

The verifier chooses one of two verification modes, which differ only in the revocation roots they accept:
- **capture-time verification**: R_rev_s, R_rev_e must be the roots valid at ledger M, so the keys were not revoked when the photo was anchored. A proof generated against these roots never expires: it can be generated once and reused.
- **current-status verification**: R_rev_s, R_rev_e must be the current roots, so revocations made after capture also apply, retroactively. The proof must be generated on demand, since every new revocation changes the current roots.

The circuit is the same in both modes. Revocations are only ever added, so a proof generated against the current roots satisfies both modes. The mode is chosen by the verifier, not by the prover.

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
python -m decima.verification                  # Verification, current-status mode
python -m decima.verification --mode capture-time  # Verification, capture-time mode
python -m decima.setup revoke <device> sensor  # a manufacturer revokes a key
```

**The zero-knowledge proof is simulated** (`decima/attestation/proof_system.py`): the statement is implemented exactly (`statement.py`), but the proof is an HMAC under a simulator key, not a Longfellow/Ligero proof. A real backend replaces only `proof_system.py`.

## Implementation scope, assumptions and design choices

### Not implemented, and why

| Item | Why |
|---|---|
| Real Longfellow proof | Longfellow has no ready circuit for this statement and writing one in C++ did not fit the hackathon. `decima/attestation/proof_system.py` simulates it: it checks the exact statement (`statement.py`) and emits an HMAC under a simulator key, so it is not zero-knowledge in the cryptographic sense and not publicly verifiable. A real backend replaces only that file. |
| Smart-contract verifier | The XRPL Testnet has no smart-contract amendment (no WASM or Hooks), so verification runs off-chain with `decima.verification`. |
| Check at purchase | The device being registered on-chain at purchase is left to the buyer and not simulated; registration itself is (`decima.setup device`). |
| Real hardware | The photo sensor and the Secure Enclave are Python objects with keys in files. |
| Real network for OHTTP | Messages follow RFC 9458 / 9292 / 9180 byte for byte, but relay and gateway run in the same process and the client address is a placeholder. |

### Assumed true

- **Trust root**: it is pre-existing and out of scope. One account publishes the admitted manufacturers, circuit hashes, pipelines and dev_params once; who governs it is not modelled.
- **Hardware and manufacturers**: the sensor signs only what it captures, sensor and Secure Enclave keys cannot be extracted, and manufacturers register only genuine keys.
- **Anonymity of the channel**: the OHTTP relay and the proxy do not collude.
- **Ledger history**: the history stays available to verifiers. The Testnet is reset from time to time, which erases demo data.
- **JPEG encoder**: verifiers use the same JPEG encoder build (Pillow pinned in `requirements.txt`), because the photo is compared byte for byte.

### Design choices

- **x = 20 ledgers**, about one minute: enough for OHTTP and the proxy to publish C.
- **Raw frame**: `raw_pix` as little-endian uint16, then a fixed 59-byte metadata block. dev_params are width, height, CFA, bit depth, black level and white level; frame counter, exposure, gain and the digest slot stay private.
- **S and tail**: computed with a resumable SHA-256 in pure Python, because `hashlib` does not expose its state (about 6 s for Full HD). With S and tail the circuit needs 192 SHA-256 blocks instead of about 65,000.
- **Registries**: fixed-depth (20) SHA-256 Merkle trees for R_s and R_e and indexed Merkle trees for R_rev_s and R_rev_e, with domain-separated leaves and nodes.
  - The roots go in the makers' DIDs. DID Data is capped at 128 bytes, hence a binary layout.
  - The added leaves go in memos of the same transaction, so anyone can rebuild the trees.
- **Valid roots**: a verifier accepts any R_s / R_e an admitted maker ever published (registries only grow). For R_rev_s / R_rev_e it follows the verification mode (`--mode`):
  - **current-status**: only the current roots. Any new revocation by a maker invalidates the earlier proofs of all its devices, which must be regenerated.
  - **capture-time**: the roots valid at ledger M or any later ones. A key absent from a later set was also absent at M, which is why a proof made against the current roots passes both modes.
  - `decima.attestation --roots capture-time` builds a proof against the roots at M, which never expires.
- **Prepaid tokens**: RSA blind signatures (RFC 9474, RSABSSA-SHA384-PSS-Deterministic), bought with an on-chain payment of 0.01 XRP each. The proxy keeps the list of spent tokens.
- **HPKE**: written out for OHTTP, because the response needs the HPKE secret export. It is tested against the `cryptography` implementation.
- **Publication of C**: the proxy publishes each C right away in a memo of its own transaction. The user sends that transaction as T1, and the verifier accepts any validated transaction containing C.
- **DNG**: written with `tifffile`. The secure-negative data sits in the DNGPrivateData tag and never leaves the device; the published `raw.dng` holds only the pixels and the dev_params tags.
- **Pipeline**: integer-only and deterministic (Hamilton-Adams demosaicing; Malvar-He-Cutler avoided because its patent is active until 2027).
- **Identifiers**: the pipeline ID and the circuit ID are hashes of the code, so after changing `develop.py` or the statement the trust root must be published again.

## Team

| Name |
|---|
| Giorgio Tuccinardi|
| Leonardo Vona |
| Leonardo Rufini |

## AI usage disclosure

As required by the hackathon rules, we declare every AI tool used, how and where. The protocol design in the *Solution* section is the team's own.

| Tool | Category | How it was used | Where |
|---|---|---|---|
| Claude (Anthropic), in Claude Code | Code generation | Implementation of the protocol described in *Solution*: XRPL interaction (DIDs, memos, payments), key and revocation registries (Merkle and indexed Merkle trees), sensor and Secure Enclave simulation, Oblivious HTTP, prepaid blind tokens, the proxy, DNG files, resumable SHA-256, the statement and the simulated proof system, the development pipeline, the verifier and the end-to-end demo | `decima/`, `requirements.txt`, `.env.example` |
| Claude (Anthropic), in Claude Code | Repository and file-system structure | Organisation of the code into one package per protocol phase plus shared building blocks, module boundaries and dependency direction, git-ignore rules for secrets and simulation output | `decima/` layout, `.gitignore` |
| Claude (Anthropic), in Claude Code | Tests | End-to-end demo that runs the whole protocol on the XRPL Testnet step by step and checks each outcome, including attack scenarios (tampered photo, revoked key) | `decima/demo.py` |
| Claude (Anthropic), in Claude Code | Documentation | Architecture document, one README per code sector, the *Getting started* and *Implementation scope* sections of this README, the license header | `ARCHITECTURE.md`, `decima/README.md`, `decima/*/README.md`, `README.md`, `LICENSE.md` |

An earlier prototype of the simulation, also written with Claude, was replaced by the current code and is no longer in the repository.
