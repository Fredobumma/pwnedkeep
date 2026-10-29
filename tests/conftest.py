from __future__ import annotations

import hashlib
import random
from collections.abc import Iterator
from pathlib import Path

import pytest

from pwnedkeep.server import ntlm
from pwnedkeep.store import Mode, Writer

# passwords with the counts the real data has for them, and a few hundred random hashes around them
KNOWN = {'password': 52372427, '123456': 209972844, 'correct horse battery staple': 437}


def digests(mode: Mode) -> dict[bytes, int]:
    rng = random.Random(7)
    hashed = {
        (hashlib.sha1(p.encode()).digest() if mode is Mode.SHA1 else ntlm(p)): count for p, count in KNOWN.items()
    }
    for _ in range(500):
        hashed[rng.randbytes(mode.hash_bytes)] = rng.randint(1, 1000)
    # several hashes in one range, to check ordering within it
    base = hashlib.sha1(b'password').digest()[:3] if mode is Mode.SHA1 else ntlm('password')[:3]
    for _ in range(20):
        digest = bytes([base[0], base[1], (base[2] & 0xF0) | rng.randint(0, 15)]) + rng.randbytes(mode.hash_bytes - 3)
        hashed[digest] = rng.randint(1, 50)
    return hashed


def lines(mode: Mode) -> list[str]:
    """The data as the official downloader writes it: every hash in full, sorted."""
    return [f'{d.hex().upper()}:{c}' for d, c in sorted(digests(mode).items())]


def build(path: Path, mode: Mode) -> Path:
    by_prefix: dict[int, list[tuple[bytes, int]]] = {}
    for digest, count in sorted(digests(mode).items()):
        by_prefix.setdefault(int.from_bytes(digest[:3], 'big') >> 4, []).append((digest[2:], count))
    with Writer(path, mode, 1_800_000_000) as writer:
        for prefix in sorted(by_prefix):
            writer.write_prefix(prefix, by_prefix[prefix])
    return path


@pytest.fixture
def sha1_store(tmp_path: Path) -> Iterator[Path]:
    yield build(tmp_path / 'sha1.pwnd', Mode.SHA1)


@pytest.fixture
def ntlm_store(tmp_path: Path) -> Iterator[Path]:
    yield build(tmp_path / 'ntlm.pwnd', Mode.NTLM)
