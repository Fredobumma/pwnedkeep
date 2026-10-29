from __future__ import annotations

import asyncio
import hashlib
from pathlib import Path

import httpx
import pytest

from pwnedkeep.sources import download, import_files, read_etags
from pwnedkeep.store import Mode, Store, StoreError

from .conftest import KNOWN, lines

PASSWORD = hashlib.sha1(b'password').hexdigest().upper()
PREFIX = PASSWORD[:5]


def test_import_the_single_file(tmp_path: Path) -> None:
    source = tmp_path / 'pwnedpasswords.txt'
    source.write_text('\r\n'.join(lines(Mode.SHA1)) + '\r\n', encoding='ascii')
    count = import_files(source, tmp_path / 'sha1.pwnd', Mode.SHA1)
    assert count == len(lines(Mode.SHA1))
    assert Store(tmp_path / 'sha1.pwnd').count(bytes.fromhex(PASSWORD)) == KNOWN['password']


def test_import_a_folder_of_ranges(tmp_path: Path) -> None:
    folder = tmp_path / 'ranges'
    folder.mkdir()
    by_prefix: dict[str, list[str]] = {}
    for line in lines(Mode.SHA1):
        by_prefix.setdefault(line[:5], []).append(line[5:])
    for prefix, rows in by_prefix.items():
        # with padding mixed in, as a padded download would have it
        (folder / f'{prefix}.txt').write_text('\r\n'.join([*rows, f'{"0" * 35}:0']), encoding='ascii')
    assert import_files(folder, tmp_path / 'sha1.pwnd', Mode.SHA1) == len(lines(Mode.SHA1))


def test_import_refuses_an_unsorted_file(tmp_path: Path) -> None:
    source = tmp_path / 'pwnedpasswords.txt'
    source.write_text('\n'.join(reversed(lines(Mode.SHA1))), encoding='ascii')
    with pytest.raises(StoreError, match='not sorted'):
        import_files(source, tmp_path / 'sha1.pwnd', Mode.SHA1)
    assert not (tmp_path / 'sha1.pwnd').exists()


class FakeApi:
    """api.pwnedpasswords.com for a few ranges, with ETags, 304s, padding and the odd failure."""

    def __init__(self) -> None:
        self.ranges = {PREFIX: [f'{PASSWORD[5:]}:52372427', f'{"F" * 35}:3'], '00000': [f'{"A" * 35}:9']}
        self.version = 1
        self.requests: list[httpx.Request] = []
        self.fail_next = 0

    def etag(self, prefix: str) -> str:
        return f'"{prefix}-{self.version}"'

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.fail_next:
            self.fail_next -= 1
            return httpx.Response(500)
        prefix = request.url.path.rsplit('/', 1)[1]
        rows = self.ranges.get(prefix, [])
        if request.headers.get('if-none-match') == self.etag(prefix):
            return httpx.Response(304)
        body = '\r\n'.join(sorted([*rows, f'{"1" * 35}:0']))
        return httpx.Response(200, text=body, headers={'ETag': self.etag(prefix)})


def run(store: Path, api: FakeApi, prefixes: list[int]) -> tuple[int, int]:
    progress = asyncio.run(
        download(store, Mode.SHA1, prefixes=prefixes, transport=httpx.MockTransport(api.handler), concurrency=4)
    )
    return progress.changed, progress.unchanged


def test_download_then_update_only_what_changed(tmp_path: Path) -> None:
    api = FakeApi()
    store = tmp_path / 'sha1.pwnd'
    wanted = [int(PREFIX, 16), 0, 0xFFFFF]

    assert run(store, api, wanted) == (3, 0)
    s = Store(store)
    assert s.count(bytes.fromhex(PASSWORD)) == 52372427
    assert s.info.records == 3  # padding dropped
    assert read_etags(store) == {p: api.etag(f'{p:05X}') for p in wanted}

    # nothing changed: every range is a 304, and the store keeps its data
    assert run(store, api, wanted) == (0, 3)
    assert Store(store).count(bytes.fromhex(PASSWORD)) == 52372427

    # one range changed
    api.version = 2
    api.ranges[PREFIX] = [f'{PASSWORD[5:]}:52372500']
    assert run(store, api, wanted) == (3, 0)
    assert Store(store).count(bytes.fromhex(PASSWORD)) == 52372500


def test_updating_some_ranges_keeps_the_others(tmp_path: Path) -> None:
    api = FakeApi()
    store = tmp_path / 'sha1.pwnd'
    run(store, api, [int(PREFIX, 16), 0])
    api.version = 2
    api.ranges['00000'] = [f'{"B" * 35}:4']
    assert run(store, api, [0]) == (1, 0)
    s = Store(store)
    assert s.count(bytes.fromhex(PASSWORD)) == 52372427
    assert s.range_text(0) == [f'{"B" * 35}:4']


def test_download_retries_failures(tmp_path: Path) -> None:
    api = FakeApi()
    api.fail_next = 2
    assert run(tmp_path / 'sha1.pwnd', api, [int(PREFIX, 16)]) == (1, 0)
    assert len(api.requests) == 3


def test_ntlm_ranges_are_asked_for_in_ntlm_mode(tmp_path: Path) -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(200, text=f'{"C" * 27}:2')

    asyncio.run(download(tmp_path / 'ntlm.pwnd', Mode.NTLM, prefixes=[0x8846F], transport=httpx.MockTransport(handler)))
    assert seen == ['https://api.pwnedpasswords.com/range/8846F?mode=ntlm']
    assert Store(tmp_path / 'ntlm.pwnd').range_text(0x8846F) == [f'{"C" * 27}:2']


def test_an_update_keeps_the_mode(tmp_path: Path, sha1_store: Path) -> None:
    with pytest.raises(StoreError, match='sha1 hashes, not ntlm'):
        asyncio.run(
            download(
                sha1_store,
                Mode.NTLM,
                prefixes=[0],
                transport=httpx.MockTransport(lambda r: httpx.Response(500)),
            )
        )
