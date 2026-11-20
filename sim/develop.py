"""Phase 2b: open, integer-only development of the raw frame. Same input gives bit-identical pixels on any machine.

Black level -> gray-world white balance (Q12 fixed point) -> Hamilton-Adams demosaicing (Kodak US 5,629,734,
expired) with color-difference chroma -> sRGB tone curve as a 12-to-8-bit lookup table.
"""

import numpy as np

from sim.crypto import sha256_hex

PROFILE = "ixh26-develop/1"
STEPS = ["black-level", "gray-world-wb-q12", "hamilton-adams-1997", "srgb-lut-12to8"]
MAX_GAIN_Q12 = 8 * 4096

SRGB_LUT = np.array([round(255 * (12.92 * v if v <= 0.0031308 else 1.055 * v ** (1 / 2.4) - 0.055))
                     for v in (i / 4095 for i in range(4096))], dtype=np.uint8)
LUT_SHA256 = sha256_hex(SRGB_LUT.tobytes())


def _masks(h: int, w: int) -> tuple[np.ndarray, ...]:
    r = np.zeros((h, w), bool); r[0::2, 0::2] = True
    g_rrow = np.zeros((h, w), bool); g_rrow[0::2, 1::2] = True
    g_brow = np.zeros((h, w), bool); g_brow[1::2, 0::2] = True
    b = np.zeros((h, w), bool); b[1::2, 1::2] = True
    return r, g_rrow, g_brow, b


def _shifter(a: np.ndarray, pad: int):
    # Reflect padding mirrors without repeating the edge, so the Bayer parity is preserved.
    p = np.pad(a, pad, mode="reflect")
    h, w = a.shape
    return lambda dy, dx: p[pad + dy:pad + dy + h, pad + dx:pad + dx + w]


def _hamilton_adams(m: np.ndarray, maxv: int, masks: tuple[np.ndarray, ...]) -> np.ndarray:
    r_m, gr_m, gb_m, b_m = masks
    s = _shifter(m, 2)
    c = s(0, 0)
    lap_h, lap_v = 2 * c - s(0, -2) - s(0, 2), 2 * c - s(-2, 0) - s(2, 0)
    grad_h = np.abs(s(0, -1) - s(0, 1)) + np.abs(lap_h)
    grad_v = np.abs(s(-1, 0) - s(1, 0)) + np.abs(lap_v)
    est_h4 = 2 * (s(0, -1) + s(0, 1)) + lap_h
    est_v4 = 2 * (s(-1, 0) + s(1, 0)) + lap_v
    est = np.where(grad_h < grad_v, (est_h4 + 2) >> 2,
                   np.where(grad_v < grad_h, (est_v4 + 2) >> 2, (est_h4 + est_v4 + 4) >> 3))
    g = np.clip(np.where(r_m | b_m, est, m), 0, maxv)

    planes = []
    for known, same_row, same_col in ((r_m, gr_m, gb_m), (b_m, gb_m, gr_m)):
        d = _shifter(np.where(known, m - g, 0), 1)
        horiz = d(0, -1) + d(0, 1)
        vert = d(-1, 0) + d(1, 0)
        diag = d(-1, -1) + d(-1, 1) + d(1, -1) + d(1, 1)
        plane = np.where(known, m, np.where(same_row, g + ((horiz + 1) >> 1),
                         np.where(same_col, g + ((vert + 1) >> 1), g + ((diag + 2) >> 2))))
        planes.append(np.clip(plane, 0, maxv))
    return np.stack([planes[0], g, planes[1]], axis=-1)


def develop(raw: np.ndarray, frame: dict) -> tuple[np.ndarray, dict]:
    if frame["cfa"] != "RGGB":
        raise ValueError(f"unsupported CFA {frame['cfa']}")
    black, maxv = frame["black_level"], frame["white_level"] - frame["black_level"]
    m = np.clip(raw.astype(np.int32) - black, 0, maxv)
    masks = _masks(*m.shape)
    r_m, gr_m, gb_m, b_m = masks
    channels = (r_m, gr_m | gb_m, b_m)
    sums = [int(m[x].sum(dtype=np.int64)) for x in channels]
    counts = [int(x.sum()) for x in channels]
    gains = [min((sums[1] * counts[i] * 4096) // max(sums[i] * counts[1], 1), MAX_GAIN_Q12) for i in range(3)]
    m = np.clip((m * np.where(r_m, gains[0], np.where(b_m, gains[2], gains[1])) + 2048) >> 12, 0, maxv)
    rgb = _hamilton_adams(m, maxv, masks)
    pixels = SRGB_LUT[(rgb * 4095 + maxv // 2) // maxv]
    return pixels, {"profile": PROFILE, "steps": STEPS, "wb_gains_q12": gains, "lut_sha256": LUT_SHA256}
