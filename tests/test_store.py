from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from pwnedkeep.server import md4, ntlm
from pwnedkeep.store import Mode, Store, StoreError, Writer, parse_prefix, suffix_bytes

from .conftest import KNOWN, digests


def test_ranges_hold_every_hash_in_order(sha1_store: Path) -> None:
    store = Store(sha1_store)
    expected = digests(Mode.SHA1)
    assert store.info.records == len(expected)
    seen = 0
    for digest, count in expected.items():
        prefix = int.from_bytes(digest[:3], 'big') >> 4
        line = f'{digest.hex().upper()[5:]}:{count}'
        text = store.range_text(prefix)
        assert line in text
        assert text == sorted(text)
        seen += 1
    assert seen == len(expected)


def test_counts(sha1_store: Path, ntlm_store: Path) -> None:
    sha1, nt = Store(sha1_store), Store(ntlm_store)
    for password, count in KNOWN.items():
        assert sha1.count(hashlib.sha1(password.encode()).digest()) == count
        assert nt.count(ntlm(password)) == count
    assert sha1.count(hashlib.sha1(b'not in the data').digest()) == 0
    assert nt.count(ntlm('not in the data')) == 0
    with pytest.raises(ValueError):
        sha1.count(b'short')


def test_suffix_lengths(sha1_store: Path, ntlm_store: Path) -> None:
    prefix = int(hashlib.sha1(b'password').hexdigest()[:5], 16)
    assert all(len(line.split(':')[0]) == 35 for line in Store(sha1_store).range_text(prefix))
    nt_prefix = int(ntlm('password').hex()[:5], 16)
    assert all(len(line.split(':')[0]) == 27 for line in Store(ntlm_store).range_text(nt_prefix))


def test_empty_ranges(sha1_store: Path) -> None:
    store = Store(sha1_store)
    empty = next(p for p in range(1 << 20) if not store.range_text(p))
    assert store.range_text(empty) == []


def test_writer_refuses_disorder(tmp_path: Path) -> None:
    with Writer(tmp_path / 'a.pwnd', Mode.SHA1, 0) as writer:
        writer.write_prefix(5, [])
        with pytest.raises(StoreError, match='out of order'):
            writer.write_prefix(4, [])
        writer.write_prefix(6, [])

    key = suffix_bytes(7, '0' * 35, Mode.SHA1)
    later = suffix_bytes(7, '1' * 35, Mode.SHA1)
    with pytest.raises(StoreError, match='out of order'), Writer(tmp_path / 'b.pwnd', Mode.SHA1, 0) as writer:
        writer.write_prefix(7, [(later, 1), (key, 1)])
    assert not (tmp_path / 'b.pwnd').exists()
    assert not (tmp_path / 'b.pwnd.partial').exists()

    with (
        pytest.raises(StoreError, match='does not belong'),
        Writer(tmp_path / 'c.pwnd', Mode.SHA1, 0) as writer,
    ):
        writer.write_prefix(8, [(key, 1)])


def test_refuses_what_is_not_a_store(tmp_path: Path, sha1_store: Path) -> None:
    junk = tmp_path / 'junk'
    junk.write_bytes(b'hello' * 100)
    with pytest.raises(StoreError, match='not a pwnedkeep store'):
        Store(junk)
    truncated = tmp_path / 'truncated'
    truncated.write_bytes(sha1_store.read_bytes()[:-5])
    with pytest.raises(StoreError, match='incomplete'):
        Store(truncated)


def test_prefixes() -> None:
    assert parse_prefix('5baa6') == 0x5BAA6
    for bad, message in (('5BAA', 'format'), ('5BAA61', 'format'), ('XYZ12', 'hexadecimal')):
        with pytest.raises(ValueError, match=message):
            parse_prefix(bad)


def test_md4_and_ntlm() -> None:
    # RFC 1320's test suite, and the NT hashes everyone knows
    assert md4(b'').hex() == '31d6cfe0d16ae931b73c59d7e0c089c0'
    assert md4(b'abc').hex() == 'a448017aaf21d8525fc10ae87aa6729d'
    assert md4(b'message digest').hex() == 'd9130a8164549fe818874806e1c7014b'
    assert md4(b'1234567890' * 8).hex() == 'e33b4ddc9c38f2199c3e7b164fcc0536'
    assert ntlm('password').hex().upper() == '8846F7EAEE8FB117AD06BDD830B7586C'
    assert ntlm('').hex().upper() == '31D6CFE0D16AE931B73C59D7E0C089C0'
