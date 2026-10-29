from __future__ import annotations

from pathlib import Path

import pytest

from pwnedkeep.cli import main
from pwnedkeep.server import ntlm
from pwnedkeep.store import Mode, Store

from .conftest import KNOWN, lines


def test_lookup(sha1_store: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(['lookup', str(sha1_store), '--password', 'password']) == 1
    assert '52,372,427' in capsys.readouterr().out
    assert main(['lookup', str(sha1_store), '--password', 'not in the data, surely']) == 0
    assert 'not found' in capsys.readouterr().out


def test_audit_reads_secretsdump_and_plain_dumps(
    ntlm_store: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    dump = tmp_path / 'ntds.txt'
    dump.write_text(
        '\n'.join(
            [
                f'CORP\\alice:1104:aad3b435b51404eeaad3b435b51404ee:{ntlm("password").hex()}:::',
                f'CORP\\bob:1105:aad3b435b51404eeaad3b435b51404ee:{ntlm("a strong one nobody has").hex()}:::',
                f'carol:{ntlm("123456").hex().upper()}',
                'not a line of a dump',
            ]
        ),
        encoding='utf-8',
    )
    assert main(['audit', str(ntlm_store), str(dump)]) == 1
    captured = capsys.readouterr()
    assert captured.out.splitlines() == [f'CORP\\alice\t{KNOWN["password"]:,}', f'carol\t{KNOWN["123456"]:,}']
    assert '2 of 3 accounts' in captured.err


def test_audit_needs_an_ntlm_store(sha1_store: Path, tmp_path: Path) -> None:
    dump = tmp_path / 'dump.txt'
    dump.write_text('x:' + '0' * 32, encoding='utf-8')
    assert main(['audit', str(sha1_store), str(dump)]) == 2


def test_import(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    source = tmp_path / 'pwnedpasswords.txt'
    source.write_text('\n'.join(lines(Mode.SHA1)), encoding='ascii')
    assert main(['import', str(source), str(tmp_path / 'sha1.pwnd')]) == 0
    assert Store(tmp_path / 'sha1.pwnd').info.records == len(lines(Mode.SHA1))


def test_errors_are_short(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    (tmp_path / 'junk').write_bytes(b'junk')
    assert main(['lookup', str(tmp_path / 'junk'), '--password', 'x']) == 2
    assert capsys.readouterr().err.startswith('pwnedkeep: ')


def test_ntlm_lookup(ntlm_store: Path) -> None:
    assert main(['lookup', str(ntlm_store), '--hash', ntlm('password').hex()]) == 1
