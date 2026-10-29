"""Filling a store: from the Pwned Passwords API directly, or from what the official downloader saved."""

from __future__ import annotations

import asyncio
import os
import time
from collections.abc import Callable, Iterator
from pathlib import Path

import httpx

from .store import PREFIXES, Mode, Store, StoreError, Writer, suffix_bytes

API = 'https://api.pwnedpasswords.com'
USER_AGENT = 'pwnedkeep (+https://github.com/fredobumma/pwnedkeep)'


def parse_range(prefix: int, text: str, mode: Mode) -> list[tuple[bytes, int]]:
    """The records in a `/range` response body, in order. Padding, with a count of 0, is dropped."""
    records = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        suffix, _, count = line.partition(':')
        if int(count) > 0:
            records.append((suffix_bytes(prefix, suffix.upper(), mode), int(count)))
    records.sort()
    return records


# ---- the official downloader's files -------------------------------------------------------------------------


def _from_single_file(path: Path, mode: Mode) -> Iterator[tuple[int, list[tuple[bytes, int]]]]:
    """`pwnedpasswords.txt`: every hash in full, `HASH:COUNT`, one per line, sorted."""
    chars = mode.hash_bytes * 2
    current = -1
    records: list[tuple[bytes, int]] = []
    with open(path, encoding='ascii') as f:
        for number, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            digest, _, count = line.partition(':')
            if len(digest) != chars:
                raise StoreError(f'line {number}: not a {mode.value} hash: {digest[:50]!r}')
            prefix = int(digest[:5], 16)
            if prefix != current:
                if prefix < current:
                    raise StoreError(f'line {number}: the file is not sorted')
                if current >= 0:
                    yield current, records
                current, records = prefix, []
            records.append((bytes.fromhex(digest)[2:], int(count)))
    if current >= 0:
        yield current, records


def _from_directory(path: Path, mode: Mode) -> Iterator[tuple[int, list[tuple[bytes, int]]]]:
    """A folder of `XXXXX.txt` files, one for each prefix, each a `/range` response."""
    names = {name.upper() for name in os.listdir(path) if name.lower().endswith('.txt')}
    for prefix in range(PREFIXES):
        name = f'{prefix:05X}.TXT'
        if name in names:
            file = path / f'{prefix:05X}.txt'
            if not file.exists():
                file = path / f'{prefix:05x}.txt'
            yield prefix, parse_range(prefix, file.read_text(encoding='ascii'), mode)


def import_files(source: str | os.PathLike[str], out: str | os.PathLike[str], mode: Mode) -> int:
    """Builds a store from the official downloader's output, a single file or a folder. Returns the hash count."""
    path = Path(source)
    ranges = _from_directory(path, mode) if path.is_dir() else _from_single_file(path, mode)
    with Writer(out, mode, int(time.time())) as writer:
        for prefix, records in ranges:
            writer.write_prefix(prefix, records)
    return Store(out).info.records


# ---- the API -------------------------------------------------------------------------------------------------


def etags_path(store: str | os.PathLike[str]) -> Path:
    return Path(f'{store}.etags')


def read_etags(store: str | os.PathLike[str]) -> dict[int, str]:
    path = etags_path(store)
    if not path.exists():
        return {}
    etags = {}
    for line in path.read_text(encoding='ascii').splitlines():
        prefix, _, etag = line.partition(' ')
        if etag:
            etags[int(prefix, 16)] = etag
    return etags


def write_etags(store: str | os.PathLike[str], etags: dict[int, str]) -> None:
    path = etags_path(store)
    tmp = path.with_name(path.name + '.partial')
    tmp.write_text(''.join(f'{p:05X} {etags[p]}\n' for p in sorted(etags)), encoding='ascii')
    os.replace(tmp, path)


class Progress:
    def __init__(self) -> None:
        self.done = 0
        self.changed = 0
        self.unchanged = 0


async def download(
    out: str | os.PathLike[str],
    mode: Mode,
    *,
    concurrency: int = 64,
    prefixes: list[int] | None = None,
    base_url: str = API,
    transport: httpx.AsyncBaseTransport | None = None,
    on_progress: Callable[[Progress], None] | None = None,
) -> Progress:
    """
    Downloads every range into a store, or brings an existing store up to date. Each range is asked for with the ETag
    it had last time, so ranges that have not changed come back as 304 and are copied from the old store, and an
    update fetches only what is new. The new store replaces the old one when it is complete.
    """
    out = Path(out)
    old = Store(out) if out.exists() else None
    if old and old.mode is not mode:
        raise StoreError(f'{out} holds {old.mode.value} hashes, not {mode.value}')
    etags = read_etags(out) if old else {}
    wanted = sorted(set(prefixes)) if prefixes is not None else list(range(PREFIXES))
    progress = Progress()
    query = '?mode=ntlm' if mode is Mode.NTLM else ''

    async with httpx.AsyncClient(
        base_url=base_url,
        http2=transport is None,
        transport=transport,
        timeout=httpx.Timeout(30),
        headers={'User-Agent': USER_AGENT},
        limits=httpx.Limits(max_connections=concurrency),
    ) as client:
        semaphore = asyncio.Semaphore(concurrency)

        async def fetch(prefix: int) -> list[tuple[bytes, int]] | None:
            """The range's records, or None when it has not changed since the old store."""
            headers = {'If-None-Match': etags[prefix]} if old and prefix in etags else {}
            async with semaphore:
                for attempt in range(5):
                    try:
                        response = await client.get(f'/range/{prefix:05X}{query}', headers=headers)
                        if response.status_code == 304:
                            return None
                        response.raise_for_status()
                        break
                    except (httpx.TransportError, httpx.HTTPStatusError):
                        if attempt == 4:
                            raise
                        await asyncio.sleep(2**attempt)
            if etag := response.headers.get('etag'):
                etags[prefix] = etag
            return parse_range(prefix, response.text, mode)

        # an update of only some ranges keeps the others as they were
        order = list(range(PREFIXES)) if old else wanted
        chosen = set(wanted)

        with Writer(out, mode, int(time.time())) as writer:
            # fetched a window at a time, written in order, so memory stays small however big the store
            window = concurrency * 16
            for start in range(0, len(order), window):
                batch = order[start : start + window]
                fetched = await asyncio.gather(*(fetch(p) for p in batch if p in chosen))
                by_prefix = dict(zip([p for p in batch if p in chosen], fetched, strict=True))
                for prefix in batch:
                    records = by_prefix.get(prefix)
                    if records is None:
                        assert old is not None
                        writer.write_prefix(prefix, old.range_records(prefix))
                        if prefix in chosen:
                            progress.unchanged += 1
                    else:
                        writer.write_prefix(prefix, records)
                        progress.changed += 1
                    progress.done += prefix in chosen
                if on_progress:
                    on_progress(progress)
            if old:
                old.close()
    write_etags(out, etags)
    return progress
