# device

The camera, kept as in Apple's design (README, Capture: "we keep the creation of the frame, σs and σe").

| File | Contents |
|---|---|
| `frame.py` | Raw frame layout: `raw_pix ‖ metadata`, fixed `dev_fields` and `digest_slot` offsets, the model's dev_params |
| `hardware.py` | `Device`: the OS computes D = H(T0 ‖ dev_manifest ‖ boot_manifest); the sensor signs σs = ECDSA(sk_s, SHA256(raw_pix ‖ metadata)); the Secure Enclave signs σe over H(σs) ‖ OS metadata |
| `scene.py` | Scenes in linear light: a synthetic landscape or any photo |

Devices are provisioned by [setup](../setup/) and stored in `out/devices/<id>/` (private keys, manifests, σ_man).
