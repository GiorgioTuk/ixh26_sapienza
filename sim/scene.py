"""Light reaching the sensor, as linear RGB in [0, 1]: a synthetic landscape or any photo."""

from pathlib import Path

import numpy as np
from PIL import Image, ImageOps


def synthetic_scene(height: int = 1080, width: int = 1920) -> np.ndarray:
    y, x = np.mgrid[0:height, 0:width] / np.array([height, width])[:, None, None]
    scene = np.stack([0.35 + 0.2 * y, 0.55 + 0.15 * y, 0.9 - 0.3 * y], axis=-1)
    scene[(x - 0.75) ** 2 + (y - 0.2) ** 2 < 0.004] = [1.0, 0.95, 0.6]
    scene[y > 0.55 + 0.25 * np.abs(np.sin(x * 6))] = [0.25, 0.45, 0.2]
    return scene


def load_image(path: Path, width: int = 1920, height: int = 1080) -> np.ndarray:
    img = ImageOps.fit(Image.open(path).convert("RGB"), (width, height), Image.Resampling.LANCZOS)
    srgb = np.asarray(img, dtype=np.float64) / 255
    return np.where(srgb <= 0.04045, srgb / 12.92, ((srgb + 0.055) / 1.055) ** 2.4)


def save_srgb(linear: np.ndarray, path: Path) -> None:
    rgb = np.clip(linear, 0, 1)
    srgb = np.where(rgb <= 0.0031308, 12.92 * rgb, 1.055 * rgb ** (1 / 2.4) - 0.055)
    Image.fromarray((srgb * 255 + 0.5).astype(np.uint8)).save(path)
