"""The store: the Pwned Passwords data in one file, laid out for lookups.

A header, then an index with one entry for each of the 2^20 five-character prefixes, then every hash in order, each
as a fixed-size record. A range is one slice of the file, and a single hash is a binary search inside it. The file is
memory-mapped, so the operating system keeps the busy parts in memory and the rest on disk.

    header   64 bytes: magic, version, mode, record size, record count, build time
    index    (2^20 + 1) x uint64: the number of the first record of each prefix, and the total at the end
    records  the hash without its first two bytes, then the count as a uint32, little-endian
"""

from __future__ import annotations

import mmap
import os
import struct
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import BinaryIO

MAGIC = b'PWNDKEEP'
VERSION = 1
HEADER = struct.Struct('<8sHBBIQQ32x')
PREFIXES = 1 << 20
INDEX = struct.Struct(f'<{PREFIXES + 1}Q')
COUNT = struct.Struct('<I')


class Mode(Enum):
    SHA1 = 'sha1'
    NTLM = 'ntlm'

    @property
    def hash_bytes(self) -> int:
        return 20 if self is Mode.SHA1 else 16

    @property
    def suffix_chars(self) -> int:
        """Hex characters after the five of the prefix: 35 for SHA-1, 27 for NTLM."""
        return self.hash_bytes * 2 - 5

    @property
    def record_size(self) -> int:
        return self.hash_bytes - 2 + COUNT.size


class StoreError(Exception):
    pass


def parse_prefix(prefix: str) -> int:
    if len(prefix) != 5:
        raise ValueError('The hash prefix was not in a valid format')
    try:
        return int(prefix, 16)
    except ValueError:
        raise ValueError('The hash prefix was not valid hexadecimal') from None


@dataclass(frozen=True)
class Info:
    mode: Mode
    records: int
    built_at: int


class Store:
    """A store opened for reading. Cheap to open; safe to share between threads."""

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self.path = Path(path)
        with open(self.path, 'rb') as f:
            self._map = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        try:
            magic, version, mode, record_size, _, records, built_at = HEADER.unpack_from(self._map, 0)
        except struct.error:
            raise StoreError(f'{self.path} is not a pwnedkeep store') from None
        if magic != MAGIC:
            raise StoreError(f'{self.path} is not a pwnedkeep store')
        if version != VERSION:
            raise StoreError(f'{self.path} is a version {version} store; this pwnedkeep reads version {VERSION}')
        self.mode = Mode.SHA1 if mode == 0 else Mode.NTLM
        if record_size != self.mode.record_size:
            raise StoreError(f'{self.path} has records of {record_size} bytes, not {self.mode.record_size}')
        self._records_at = HEADER.size + INDEX.size
        if len(self._map) != self._records_at + records * record_size:
            raise StoreError(f'{self.path} is incomplete')
        self.info = Info(self.mode, records, built_at)
        self._index = memoryview(self._map)[HEADER.size : HEADER.size + INDEX.size].cast('Q')
        self._size = record_size
        stat = os.stat(self.path)
        self.identity = (stat.st_ino, stat.st_mtime_ns)

    def close(self) -> None:
        self._index.release()
        self._map.close()

    def _bounds(self, prefix: int) -> tuple[int, int]:
        return self._index[prefix], self._index[prefix + 1]

    def range_records(self, prefix: int) -> Iterator[tuple[bytes, int]]:
        """The suffixes of a prefix, as bytes, with their counts, in order."""
        start, end = self._bounds(prefix)
        data = self._map[self._records_at + start * self._size : self._records_at + end * self._size]
        cut = self._size - COUNT.size
        for at in range(0, len(data), self._size):
            yield data[at : at + cut], COUNT.unpack_from(data, at + cut)[0]

    def range_text(self, prefix: int) -> list[str]:
        """The lines `/range/{prefix}` answers with: the suffix in upper-case hex, a colon, the count."""
        return [f'{suffix.hex().upper()[1:]}:{count}' for suffix, count in self.range_records(prefix)]

    def count(self, digest: bytes) -> int:
        """How many times a hash appears in breaches; 0 for none."""
        if len(digest) != self.mode.hash_bytes:
            raise ValueError(f'a {self.mode.value} hash is {self.mode.hash_bytes} bytes')
        prefix = int.from_bytes(digest[:3], 'big') >> 4
        start, end = self._bounds(prefix)
        key = digest[2:]
        low, high = start, end
        while low < high:
            middle = (low + high) // 2
            at = self._records_at + middle * self._size
            found = self._map[at : at + len(key)]
            if found == key:
                return int(COUNT.unpack_from(self._map, at + len(key))[0])
            if found < key:
                low = middle + 1
            else:
                high = middle
        return 0


def suffix_bytes(prefix: int, suffix: str, mode: Mode) -> bytes:
    """The record key for a prefix and the hex suffix that follows it: the hash without its first two bytes."""
    if len(suffix) != mode.suffix_chars:
        raise ValueError(f'a {mode.value} suffix is {mode.suffix_chars} characters: {suffix!r}')
    digest = bytes.fromhex(f'{prefix:05X}{suffix}')
    return digest[2:]


class Writer:
    """Writes a store, a prefix at a time and in order, to a temporary file that takes its place when complete."""

    def __init__(self, path: str | os.PathLike[str], mode: Mode, built_at: int) -> None:
        self.path = Path(path)
        self.mode = mode
        self.built_at = built_at
        self._tmp = self.path.with_name(self.path.name + '.partial')
        self._file: BinaryIO = open(self._tmp, 'wb')  # noqa: SIM115
        self._file.write(b'\0' * (HEADER.size + INDEX.size))
        self._index = [0] * (PREFIXES + 1)
        self._next = 0
        self._records = 0

    def __enter__(self) -> Writer:
        return self

    def __exit__(self, *exc: object) -> None:
        if exc[0] is None:
            self.finish()
        else:
            self.abort()

    def write_prefix(self, prefix: int, records: Iterable[tuple[bytes, int]]) -> None:
        """Writes the records of one prefix. Prefixes must come in order; ones never written are empty."""
        if prefix < self._next:
            raise StoreError(f'prefixes out of order: {prefix:05X} after {self._next - 1:05X}')
        for skipped in range(self._next, prefix + 1):
            self._index[skipped] = self._records
        size = self.mode.hash_bytes - 2
        previous = b''
        chunk = bytearray()
        for key, count in records:
            if len(key) != size:
                raise StoreError(f'a record of {len(key)} bytes in prefix {prefix:05X}')
            if key <= previous:
                raise StoreError(f'suffixes out of order, or repeated, in prefix {prefix:05X}')
            if (int.from_bytes(key[:1], 'big') >> 4) != (prefix & 0xF):
                raise StoreError(f'a hash that does not belong to prefix {prefix:05X}')
            previous = key
            chunk += key
            chunk += COUNT.pack(min(count, 0xFFFFFFFF))
            self._records += 1
        self._file.write(chunk)
        self._next = prefix + 1

    def finish(self) -> None:
        for prefix in range(self._next, PREFIXES + 1):
            self._index[prefix] = self._records
        self._file.seek(0)
        mode = 0 if self.mode is Mode.SHA1 else 1
        self._file.write(HEADER.pack(MAGIC, VERSION, mode, self.mode.record_size, 0, self._records, self.built_at))
        self._file.write(INDEX.pack(*self._index))
        self._file.flush()
        os.fsync(self._file.fileno())
        self._file.close()
        os.replace(self._tmp, self.path)

    def abort(self) -> None:
        self._file.close()
        self._tmp.unlink(missing_ok=True)
