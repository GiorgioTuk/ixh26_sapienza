# pipeline

The admitted development pipeline (README, Verification: "developing the pixels with them yields exactly the JPEG photo").

| File | Contents |
|---|---|
| `develop.py` | `develop(raw_pix, dev_params) -> JPEG bytes`. Integer-only and deterministic: black level, gray-world white balance (Q12), Hamilton-Adams demosaicing (Kodak US 5,629,734, expired), sRGB lookup table, baseline JPEG q92 with no metadata |

`PIPELINE_ID` is the hash of `develop.py`: the trust root lists the admitted IDs, and a verifier runs the pipeline only if its own copy has the declared ID. Malvar-He-Cutler demosaicing was avoided because its patent (US 7,502,505) is active until 2027-01-25.
