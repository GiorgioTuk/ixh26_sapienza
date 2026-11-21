"""DNG files (README, Capture: "Finally, we generate the DNG file").

The secure negative is a standard DNG: the raw pixels as a CFA image, the dev_params as the standard DNG tags
(size, CFA pattern, black and white level), and everything else (raw frame metadata, σs, σe, OS metadata,
manifests, σ_man, T0, C, T1) in the DNGPrivateData tag. Removing that tag gives the anonymous raw that the
user publishes (README: "To publish anonymously, the user can remove the metadata from the raw")."""

import json
from pathlib import Path

import numpy as np
import tifffile

DNG_PRIVATE_DATA, PRIVATE_PREFIX = 50740, b"IXH26\x00"
CFA_CODES = {"R": 0, "G": 1, "B": 2}


def _tags(dev_params: dict, private: dict | None) -> list[tuple]:
    tags = [
        (271, "s", 0, "SimCam", True), (272, "s", 0, "SimCam-1", True),   # Make, Model
        (33421, "H", 2, (2, 2), True),                                       # CFARepeatPatternDim
        (33422, "B", 4, tuple(CFA_CODES[c] for c in dev_params["cfa"]), True),  # CFAPattern
        (50706, "B", 4, (1, 4, 0, 0), True),                                 # DNGVersion
        (50707, "B", 4, (1, 1, 0, 0), True),                                 # DNGBackwardVersion
        (50708, "s", 0, "SimCam-1", True),                                   # UniqueCameraModel
        (50714, "H", 1, dev_params["black_level"], True),                    # BlackLevel
        (50717, "H", 1, dev_params["white_level"], True),                    # WhiteLevel
        (50721, "2i", 9, (1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 0, 1, 0, 1, 0, 1, 1, 1), True),  # ColorMatrix1
        (50778, "H", 1, 21, True),                                           # CalibrationIlluminant1 = D65
    ]
    if private is not None:
        payload = PRIVATE_PREFIX + json.dumps(private, sort_keys=True).encode()
        tags.append((DNG_PRIVATE_DATA, "B", len(payload), payload, True))
    return tags


def write(path: Path, raw_pix: np.ndarray, dev_params: dict, private: dict | None) -> None:
    tifffile.imwrite(path, raw_pix.astype("<u2"), photometric=32803, compression=None, planarconfig=None,
                     subfiletype=0, metadata=None, extratags=_tags(dev_params, private))


def read(path: Path) -> tuple[np.ndarray, dict, dict | None]:
    """Raw pixels, dev_params read from the standard DNG tags, private data (None if stripped)."""
    with tifffile.TiffFile(path) as tif:
        page = tif.pages[0]
        raw_pix = page.asarray().astype("<u2")
        t = page.tags
        dev_params = {"width": int(page.imagewidth), "height": int(page.imagelength),
                      "cfa": "".join("RGB"[c] for c in t[33422].value), "bit_depth": 12,
                      "black_level": int(np.ravel(t[50714].value)[0]), "white_level": int(np.ravel(t[50717].value)[0])}
        private = None
        if DNG_PRIVATE_DATA in t:
            data = bytes(t[DNG_PRIVATE_DATA].value)
            private = json.loads(data[len(PRIVATE_PREFIX):]) if data.startswith(PRIVATE_PREFIX) else None
    return raw_pix, dev_params, private
