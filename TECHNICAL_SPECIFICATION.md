# DECIMA – Technical description

DECIMA proves that a photo comes from a genuine camera sensor, within a known time window, without a central authority and without revealing which device took it. It keeps the hardware root of trust of Apple's Reference Image (a signing sensor and a Secure Enclave) and replaces the vendor's servers with the **XRP Ledger** (registries, revocation, timestamps) and a **zero-knowledge proof** (Longfellow, based on Ligero) that anyone can verify. The full specification is in the [README](README.md) (Solution); the code layout is in [ARCHITECTURE.md](ARCHITECTURE.md).

## 1. Trust assumptions

- **Hardware and manufacturers:** the sensor signs only what it captures, sensor and Secure Enclave keys cannot be extracted, and manufacturers register only genuine keys.
- **Trust root:** pre-existing and out of scope. One account publishes the admitted manufacturers, circuit hashes, pipelines and dev_params; who governs it is not modelled.
- **Anonymity of the channel:** the OHTTP relay and the proxy do not collude.
- **Ledger:** validated ledgers are final, their hashes are unpredictable before they close, and the history stays available to verifiers.
- **JPEG encoder:** verifiers use the same encoder build as the prover, because the photo is compared byte for byte.
- **Cryptography:** SHA-256 and ECDSA P-256 are secure, and the proof system is sound and zero-knowledge.

## 2. Actors and on-chain state

Every actor writes only its own XRPL account. Roots and keys live in the account's native **DID** object; the history lives in transaction **memos**, so anyone can rebuild every tree and compare it with the roots in the DID.

| Actor | DID Data | Memos |
|---|---|---|
| Trust root | `IXT2` ‖ SHA-256 of the trust-root document | The document: admitted makers, circuit IDs, pipeline IDs, dev_params |
| Sensor maker | `IXR2` ‖ kind ‖ size ‖ R_s ‖ revoked count ‖ R_rev_s (77 B) | Added leaves H(pk_s); revoked H(pk_s) |
| Enclave maker | Same layout with R_e, R_rev_e | Added leaves H(pk_e); revoked H(pk_e) |
| Assembler | `IXA2` ‖ pk_man, compressed P-256 point (37 B) | – |
| Proxy | – | One commitment C per memo |

Registries are fixed-depth (20, about 1M keys each) SHA-256 Merkle trees with domain-separated leaves and nodes. Revocation registries are **indexed Merkle trees**: the leaves (value, next_value) form a sorted linked list, so the non-membership of x is one membership proof of the "low leaf" with low < x < next (or low < x when there is no larger value).

## 3. Protocol

### Setup
Certification stays with the hardware manufacturers and assemblers, because hardware production cannot be decentralized. Only the roots of trust go on-chain, where they are publicly verifiable and censorship-resistant, and no authority can alter them (each maker can only append to its own registries). At the factory, the sensor and Secure Enclave each get a P-256 key. The assembler signs a device manifest binding both public keys: σ_man = ECDSA(sk_man, H(dev_manifest)). The sensor and enclave makers append H(pk_s) and H(pk_e) to their registries on-chain.

### Capture
1. **T0**: the OS reads the hash of the latest validated ledger N and computes the embedded digest D = H(T0 ‖ dev_manifest ‖ boot_manifest).
2. **σs**: the sensor writes D into the metadata digest slot and signs the frame exactly as it streams it, pixels first: σs = ECDSA(sk_s, SHA256(raw_pix ‖ metadata)).
3. **σe**: the Secure Enclave signs H(σs) ‖ OS metadata (lens, zoom, exposure, ISO).
4. **T1**: the device sends C = H(σe) to the proxy over **Oblivious HTTP** (RFC 9458) and pays with a prepaid **blind-signature token** (RFC 9474). The proxy publishes C in a memo from its own account. The ledger M that contains it is T1, and it must satisfy 0 < M − N ≤ x, with x = 20 ledgers (about one minute).
5. Everything is stored in a DNG file, the secure negative, which never leaves the device.

Frame format: raw_pix is 12-bit RGGB as little-endian uint16, row-major. The metadata is 59 bytes with a fixed layout: dev_fields (width, height, CFA, bit depth, black level, white level), private fields (frame counter, exposure, gain) and the 32-byte digest slot.

### Attestation
The user proves the following statement in zero knowledge.

- **Public inputs:** S, tail, dev_params, T0, C, pk_man, R_s, R_e, R_rev_s, R_rev_e.
- **Private witness:** metadata, dev_manifest (holds pk_s and pk_e), boot_manifest, OS metadata, σs, σe, σ_man, four Merkle paths.

The metadata stays private because it would link the user (it contains the device-bound digest). dev_params are the only metadata fields revealed: model-level values needed to develop the JPEG. Per-unit calibration data is excluded, since it would identify the device.

| # | Claim |
|---|---|
| 1 | e = SHA-256 resumed from state S over tail ‖ metadata, i.e. e = SHA256(raw_pix ‖ metadata) |
| 2 | metadata[dev_fields] = dev_params |
| 3 | metadata[digest_slot] = H(T0 ‖ dev_manifest ‖ boot_manifest) |
| 4 | ECDSA.verify(pk_s, e, σs), with pk_s from the manifest |
| 5 | ECDSA.verify(pk_e, H(H(σs) ‖ os_meta), σe), with pk_e from the same manifest |
| 6 | ECDSA.verify(pk_man, H(manifest), σ_man): the manifest signature is valid |
| 7 | C = H(σe) |
| 8 | H(pk_s) ∈ R_s and H(pk_e) ∈ R_e (Merkle membership) |
| 9 | H(pk_s) ∉ R_rev_s and H(pk_e) ∉ R_rev_e (indexed Merkle non-membership) |

The user then sends the JPEG photo, the raw pixels, dev_params, T1 (the transaction containing C) and the proof: `photo.jpg`, `raw.dng` (pixels and dev_params only), `proof.json` and `package.json`. The metadata never leaves the device.

### Verification
The verifier trusts only the ledger and its own computations:

1. It computes S and tail from the received pixels and checks the proof against them.
2. The circuit ID is listed in the trust root, pk_man is in an admitted assembler's DID, and R_s and R_e were published by admitted makers. Registries are append-only, so any past root is valid.
3. R_rev_s and R_rev_e are accepted according to the revocation mode (see the table below).
4. T0 is the hash of a validated ledger N, C is in the memo of transaction T1 validated in ledger M, and 0 < M − N ≤ x.
5. dev_params and the pipeline are admitted, and developing the pixels gives a **byte-identical** JPEG.

| Revocation mode | R_rev accepted | Effect |
|---|---|---|
| capture-time | The roots valid at ledger M, or any later ones | The keys were not revoked when the photo was anchored. The proof never expires: generated once, then reused |
| current-status | Only the current roots | Revocations made after capture also apply, retroactively. Every new revocation changes the roots, so the proof is generated on demand |

The circuit is the same in both modes, and the verifier chooses the mode, not the prover. Revocations are only ever added, so a proof against the current roots satisfies both modes.

The development pipeline is open, integer-only and deterministic: black level, gray-world white balance (Q12), Hamilton-Adams demosaicing, sRGB lookup table, baseline JPEG q92 with no metadata. Its ID is the SHA-256 of its source.

## 4. Keeping the circuit small: split SHA-256

Hashing megabytes of pixels inside a ZK circuit is infeasible, and the sensor hardware signs SHA256(raw_pix ‖ metadata) and cannot be changed. SHA-256 reads its input in 64-byte blocks and keeps a 32-byte running state, so the computation is split in two:

- **Verifier, in the clear:** runs SHA-256 over the pixels up to S, the state after the last full block. tail is the remaining pixel bytes (fewer than 64; zero for every common resolution).
- **Circuit:** resumes from the public S over tail ‖ metadata and checks that the result is the e signed by the sensor.

Different pixels give a different S, from which no signed e can be reached. The requirements are that the sensor streams pixels before metadata, and that raw_pix is sent in the exact byte format the sensor hashed.

| | Blocks hashed by the verifier | Blocks in the circuit (pixel part) |
|---|---|---|
| 1920×1080 | 64,800 | 2 |
| 4032×3024 (12 MP) | 381,024 | 2 |

With S and tail the whole circuit needs 192 SHA-256 blocks instead of about 65,000 for Full HD (most of them for the four 20-level Merkle paths), plus 3 ECDSA P-256 verifications, **whatever the resolution**. Longfellow is optimised for exactly these primitives.

## 5. Security

| Attack | Defense |
|---|---|
| AI-generated or synthetic image | No σs from a registered sensor key (claims 4, 8) |
| Pixels changed after capture | The verifier's S changes, so the signed e can't be reached (claim 1) |
| JPEG edited | Re-development is not byte-identical |
| False dev_params | Bound to the signed metadata (claim 2) |
| Backdating (claim an older T0) | T0 is inside the signed digest slot (claim 3), and a ledger hash can't be known before the ledger closes |
| Post-dating or holding a photo | C must be on-chain within x ledgers of N |
| Replaying another photo's T1 | C = H(σe) is proven (claim 7) and checked in transaction T1 |
| Sensor of one device, enclave of another | Both keys come from one manifest signed by pk_man (claims 4–6) |
| Uncertified manufacturer or forged roots | pk_man and roots must come from admitted makers' DIDs; trees are rebuilt from the memos |
| Stolen key | Revocation registry (claim 9), in either revocation mode |
| Unapproved circuit or pipeline | IDs must be listed in the trust root |
| Proxy links or censors users | OHTTP: the relay sees the IP but not the content, the proxy the content but not the IP (assuming they don't collude). Blind tokens: redemption unlinkable to purchase. The verifier accepts C from any validated transaction, so anyone can run a proxy |

## 6. Privacy

- **Revealed:** the pixels, dev_params (camera model), pk_man (assembler brand), the registries used (sensor and enclave makers), and T0, C, T1 (capture window).
- **Hidden:** device serial, pk_s, pk_e, every signature, the frame metadata (frame counter, exposure, gain, digest), OS metadata and the manifests.
- **On-chain:** every C is a hash posted by the shared proxy account. Buying tokens is linkable to the user's account; spending them is not.
- **Limitation:** the raw pixels carry the sensor's noise fingerprint (PRNU). Two raws from the same sensor can be linked with image forensics, outside the protocol.

## 7. Implementation status

A working prototype on the XRPL Testnet (Python 3.12, xrpl-py):

```bash
python -m decima.core.wallets        # one funded Testnet wallet per role
python -m decima.setup trust-root    # bootstrap the pre-existing trust root (once)
python -m decima.demo --attacks      # the whole protocol phase by phase, plus attacks
```

| Component | Status |
|---|---|
| XRPL: DID registries, memos, token payments, T0/T1 | Real, on Testnet |
| Merkle and indexed Merkle trees | Implemented |
| Resumable SHA-256 (FIPS 180-4), for S and tail | Implemented in pure Python, because `hashlib` does not expose its state (about 6 s for Full HD) |
| OHTTP (RFC 9458 / 9292 / 9180) and blind tokens (RFC 9474) | Messages byte for byte; relay and gateway run in the same process, and the client address is a placeholder |
| ZK statement (`attestation/statement.py`) | Implemented exactly: 11 checks (the 9 claims, split per key) |
| Longfellow proof (`attestation/proof_system.py`) | **Simulated**: Longfellow has no ready circuit for this statement, and writing one in C++ did not fit the hackathon. The simulation issues an HMAC only if the statement holds, so it is neither zero-knowledge nor publicly verifiable; a real backend replaces only this file |
| Sensor and Secure Enclave | Simulated (Python objects, keys in files); signatures are real ECDSA P-256 |
| Development pipeline and verifier | Implemented, deterministic |
| Trust root | Assumed pre-existing; bootstrapped by a script |
| Smart-contract verifier | Not implemented: the XRPL Testnet has no smart-contract amendment (no WASM or Hooks) |
| Check at purchase | Not simulated: checking that a device is registered on-chain is left to the buyer |

The demo checks the honest flow, a tampered photo (refused) and a full revocation sequence. A revoked key's earlier photo is refused in current-status mode and accepted in capture-time mode, and new proofs against the current roots are refused.

## 8. Limitations and future work

- **Real Longfellow circuit (C++).** The manifests would need a fixed binary layout instead of the prototype's JSON.
- **Throughput.** One XRPL transaction per photo doesn't scale to every photo taken worldwide. The proxy can batch commitments into one Merkle root per ledger, at the cost of one more inclusion claim.
- **Re-capture.** Photographing a screen with a real camera is not detected (Apple uses a confidence score).
- **Not covered yet:** offline capture, decentralized governance of the trust root, and light verifiers through on-chain attestations or XRPL smart contracts.
