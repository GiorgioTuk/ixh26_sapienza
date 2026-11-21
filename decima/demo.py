"""Runs the whole protocol of the README end to end on the XRPL Testnet and prints each phase.

  python -m decima.demo              Setup -> Capture -> Attestation -> Verification
  python -m decima.demo --attacks    also: tampered photo, revoked key
  python -m decima.demo --image photo.jpg   use a real photo as the scene

Every step is the same command a user would type; the demo only chains them, passes the IDs along and checks
that each one ends as expected."""

import argparse
import os
import re
import shutil
import subprocess
import sys
import time
from queue import Empty, Queue
from threading import Thread

from decima.core.config import OUT_DIR, PUBLISHED_DIR

BOLD, DIM, GREEN, RED, RESET = ("\033[1m", "\033[2m", "\033[32m", "\033[31m", "\033[0m") if sys.stdout.isatty() \
    else ("",) * 5
results = []


def phase(title: str, subtitle: str) -> None:
    print(f"\n{BOLD}{'=' * 78}\n  {title}\n{'=' * 78}{RESET}\n{DIM}  {subtitle}{RESET}")


SPINNER = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
SHOW_SPINNER = sys.stdout.isatty()  # no animation when the output goes to a file or a pipe


def _read_lines(stream, queue: Queue) -> None:
    for line in stream:
        queue.put(line)
    queue.put(None)


def step(label: str, args: list[str], expect_ok: bool = True) -> str:
    """Run `python -m decima.<args>`, stream its output, record whether it ended as expected.
    While the command prints nothing (waiting for the Testnet, developing the image...), a spinner with the
    elapsed time is shown on the current line and cleared as soon as the next line arrives."""
    print(f"\n{BOLD}> {label}{RESET}  {DIM}python -m decima.{' '.join(args)}{RESET}")
    proc = subprocess.Popen([sys.executable, "-m", f"decima.{args[0]}", *args[1:]], stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True, env={**os.environ, "PYTHONUNBUFFERED": "1"})
    queue: Queue = Queue()
    Thread(target=_read_lines, args=(proc.stdout, queue), daemon=True).start()
    lines, start, frame, spinning = [], time.time(), 0, False
    while True:
        try:
            line = queue.get(timeout=0.1)
        except Empty:
            if SHOW_SPINNER:
                print(f"\r    {DIM}{SPINNER[frame % len(SPINNER)]} working... {time.time() - start:4.1f} s{RESET}",
                      end="", flush=True)
                frame, spinning = frame + 1, True
            continue
        if spinning:
            print("\r\033[K", end="")
            spinning = False
        if line is None:
            break
        lines.append(line)
        print("    " + line, end="", flush=True)
    ok = (proc.wait() == 0) == expect_ok
    results.append((label, "succeeds" if expect_ok else "is refused", ok))
    print(f"  {GREEN + 'as expected' if ok else RED + 'NOT as expected'}{RESET}")
    return "".join(lines)


def grab(pattern: str, text: str) -> str:
    match = re.search(pattern, text)
    if not match:
        raise SystemExit(f"could not find {pattern!r} in the output above")
    return match.group(1)


def unspent_tokens() -> int:
    out = subprocess.run([sys.executable, "-m", "decima.capture.tokens", "list"], capture_output=True, text=True).stdout
    return int(grab(r"(\d+) unspent", out))


def capture_and_attest(device: str, image: str | None, banner: bool = True) -> str:
    out = step("Capture", ["capture", "--device", device] + (["--image", image] if image else []))
    capture_id = grab(r"Capture (\w+) with device", out)
    if banner:
        phase("ATTESTATION", "The user proves the README statement in zero knowledge (simulated Longfellow) "
                             "and prepares photo, raw without metadata, proof.")
    step("Generate the proof and the package to publish", ["attestation", capture_id])
    return capture_id


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--attacks", action="store_true", help="also run the negative scenarios")
    parser.add_argument("--image", help="photo to use as the scene")
    args = parser.parse_args()
    start = time.time()

    phase("SETUP", "Manufacturers certify the keys at the factory; the roots of trust are on-chain.")
    step("Wallets on the XRPL Testnet", ["core.wallets"])
    step("Trust root (assumed pre-existing)", ["setup", "trust-root"])
    out = step("Factory: provision a device, manufacturers register its keys on-chain", ["setup", "device"])
    device = grab(r"Provisioned device (\w+)", out)
    step("Roots of trust read from the ledger", ["setup", "status"])

    phase("CAPTURE", "T0 = hash of ledger N; σs = ECDSA(sk_s, SHA256(raw_pix || metadata)), σe; C = H(σe) over OHTTP "
                     "with a prepaid blind token to the proxy; T1 = ledger M; DNG file.")
    needed = 2 if args.attacks else 1
    if unspent_tokens() < needed:
        step("Buy prepaid blind tokens from the proxy", ["capture.tokens", "buy", "3"])
    capture_id = capture_and_attest(device, args.image)

    phase("VERIFICATION", "S and tail from the pixels, proof, roots on-chain, T0 and T1 with 0 < M - N <= x, admitted "
                          "dev_params and pipeline, re-development into exactly the same JPEG.")
    step("Verify the published package", ["verification", capture_id])

    if args.attacks:
        phase("ATTACKS", "Each of these must be refused.")
        tampered = OUT_DIR / "demo_tampered" / capture_id
        shutil.rmtree(tampered, ignore_errors=True)
        shutil.copytree(PUBLISHED_DIR / capture_id, tampered)
        photo = bytearray((tampered / "photo.jpg").read_bytes())
        photo[len(photo) // 2] ^= 1
        (tampered / "photo.jpg").write_bytes(photo)
        print(f"\n{DIM}  one byte of a copy of the published photo flipped: {tampered}{RESET}")
        step("Verify a tampered photo", ["verification", str(tampered)], expect_ok=False)

        out = step("Factory: a device whose key will be revoked", ["setup", "device"])
        victim = grab(r"Provisioned device (\w+)", out)
        victim_capture = capture_and_attest(victim, args.image, banner=False)
        step("Verify before the revocation", ["verification", victim_capture])
        step("The sensor maker revokes the sensor key", ["setup", "revoke", victim, "sensor"])
        step("Verify the already-published package", ["verification", victim_capture], expect_ok=False)
        step("Try to prove again with the revoked key", ["attestation", victim_capture], expect_ok=False)

    phase("SUMMARY", f"{len(results)} steps in {time.time() - start:.0f} s")
    for label, expected, ok in results:
        print(f"  {GREEN + 'OK  ' if ok else RED + 'FAIL'}{RESET}  {label} ({expected})")
    if not all(ok for *_, ok in results):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
