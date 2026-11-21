"""Test scenes in linear light: a synthetic landscape, or any photo cropped to the frame size."""

import numpy as np
from PIL import Image, ImageOps


def _srgb_to_linear(c: np.ndarray) -> np.ndarray:
    return np.where(c <= 0.04045, c / 12.92, ((c + 0.055) / 1.055) ** 2.4)


def synthetic_scene(width: int, height: int) -> np.ndarray:
    y, x = np.mgrid[0:height, 0:width] / np.array([height, width])[:, None, None]
    sky = np.stack([0.35 + 0.2 * x, 0.55 + 0.2 * x, 0.85 - 0.1 * y], axis=-1) * (1 - y[..., None] * 0.5)
    ground = np.stack([0.25 + 0.1 * x, 0.45 - 0.1 * y, 0.15 + 0.05 * x], axis=-1)
    scene = np.where((y > 0.6 + 0.08 * np.sin(x * 9))[..., None], ground, sky)
    sun = ((x - 0.75) ** 2 * (width / height) ** 2 + (y - 0.25) ** 2) < 0.006
    scene[sun] = [1.0, 0.95, 0.7]
    for i, color in enumerate([[0.8, 0.1, 0.1], [0.1, 0.7, 0.2], [0.1, 0.2, 0.8], [0.9, 0.8, 0.1]]):
        scene[(np.abs(x - 0.1 - 0.08 * i) < 0.03) & (np.abs(y - 0.8) < 0.05)] = color
    return _srgb_to_linear(np.clip(scene, 0, 1))


def load_scene(path: str, width: int, height: int) -> np.ndarray:
    img = ImageOps.fit(Image.open(path).convert("RGB"), (width, height), Image.LANCZOS)
    return _srgb_to_linear(np.asarray(img, dtype=np.float64) / 255.0)
