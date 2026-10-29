from __future__ import annotations

import hashlib
import json
import os
import shutil
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from pwnedkeep.server import Settings, create_app, ntlm
from pwnedkeep.store import Mode, Store

from .conftest import KNOWN, build

PASSWORD = hashlib.sha1(b'password').hexdigest().upper()
NT = ntlm('password').hex().upper()


@pytest.fixture
def client(sha1_store: Path, ntlm_store: Path) -> TestClient:
    return TestClient(create_app(Settings(sha1=sha1_store, ntlm=ntlm_store)))


def test_range_answers_as_the_public_api(client: TestClient, sha1_store: Path) -> None:
    response = client.get(f'/range/{PASSWORD[:5]}')
    assert response.status_code == 200
    assert response.headers['content-type'] == 'text/plain; charset=utf-8'
    assert response.headers['cache-control'] == 'public, max-age=2678400'
    assert response.headers['access-control-allow-origin'] == '*'
    assert response.headers['vary'] == 'Add-Padding'
    body = response.text
    assert f'{PASSWORD[5:]}:{KNOWN["password"]}' in body.split('\r\n')
    assert not body.endswith('\r\n')
    assert body == '\r\n'.join(Store(sha1_store).range_text(int(PASSWORD[:5], 16)))
    # prefixes in lower case are the same range
    assert client.get(f'/range/{PASSWORD[:5].lower()}').text == body


def test_ntlm_mode(client: TestClient) -> None:
    lines = client.get(f'/range/{NT[:5]}?mode=ntlm').text.split('\r\n')
    assert f'{NT[5:]}:{KNOWN["password"]}' in lines
    assert all(len(line.split(':')[0]) == 27 for line in lines)


def test_padding(client: TestClient) -> None:
    plain = client.get(f'/range/{PASSWORD[:5]}').text.split('\r\n')
    padded = client.get(f'/range/{PASSWORD[:5]}', headers={'Add-Padding': 'true'}).text.split('\r\n')
    assert 800 <= len(padded) <= 1000
    real = [line for line in padded if not line.endswith(':0')]
    assert real == plain
    assert padded == sorted(padded)
    assert all(len(line.split(':')[0]) == 35 for line in padded)


def test_bad_prefixes(client: TestClient) -> None:
    for prefix, message in (
        ('XYZ12', 'The hash prefix was not valid hexadecimal'),
        ('5BAA', 'The hash prefix was not in a valid format'),
    ):
        response = client.get(f'/range/{prefix}')
        assert response.status_code == 400
        assert response.text == message


def test_check(client: TestClient) -> None:
    assert client.post('/check', json={'password': 'password'}).json() == {
        'pwned': True,
        'count': KNOWN['password'],
    }
    assert client.post('/check', json={'sha1': PASSWORD.lower()}).json() == {
        'pwned': True,
        'count': KNOWN['password'],
    }
    assert client.post('/check', json={'ntlm': NT}).json() == {'pwned': True, 'count': KNOWN['password']}
    assert client.post('/check', json={'password': 'not in the data, surely'}).json() == {
        'pwned': False,
        'count': 0,
    }


def test_check_refuses_bad_input(client: TestClient) -> None:
    for body in ({'sha1': 'abc'}, {'ntlm': PASSWORD}, {'sha1': 'Z' * 40}, {'password': 5}, {}, [1]):
        assert client.post('/check', content=json.dumps(body)).status_code == 400, body
    assert client.post('/check', content='not json').status_code == 400


def test_bulk(client: TestClient) -> None:
    other = hashlib.sha1(b'not in the data, surely').hexdigest()
    response = client.post('/check/bulk', json={'sha1': [PASSWORD, other]}).json()
    assert response == {
        'results': [{'hash': PASSWORD, 'count': KNOWN['password']}, {'hash': other.upper(), 'count': 0}],
        'pwned': 1,
    }
    assert client.post('/check/bulk', json={'ntlm': [NT]}).json()['pwned'] == 1
    assert client.post('/check/bulk', json={'sha1': []}).status_code == 400
    assert client.post('/check/bulk', json={'sha1': [PASSWORD] * 10_001}).status_code == 400
    assert client.post('/check/bulk', json={'sha1': [PASSWORD], 'ntlm': [NT]}).status_code == 400


def test_a_missing_store(sha1_store: Path) -> None:
    client = TestClient(create_app(Settings(sha1=sha1_store)))
    assert client.get(f'/range/{NT[:5]}?mode=ntlm').status_code == 404
    assert client.post('/check', json={'ntlm': NT}).status_code == 404
    # with only a SHA-1 store, a password is checked by its SHA-1
    assert client.post('/check', json={'password': 'password'}).json()['count'] == KNOWN['password']


def test_api_keys(sha1_store: Path) -> None:
    client = TestClient(create_app(Settings(sha1=sha1_store, api_keys=['key-one', 'key-two'])))
    assert client.get('/range/00000').status_code == 401
    assert client.get('/range/00000', headers={'Authorization': 'Bearer wrong'}).status_code == 401
    assert client.get('/range/00000', headers={'Authorization': 'Bearer key-two'}).status_code == 200
    assert client.get('/range/00000', headers={'X-Api-Key': 'key-one'}).status_code == 200
    assert client.get('/health').status_code == 200


def test_health_metrics_and_spec(client: TestClient) -> None:
    health = client.get('/health').json()
    assert health['ok'] is True
    assert set(health['stores']) == {'sha1', 'ntlm'}
    client.get('/range/00000')
    client.post('/check', json={'password': 'password'})
    metrics = client.get('/metrics').text
    assert 'pwnedkeep_ranges_total 1' in metrics
    assert 'pwnedkeep_found_total 1' in metrics
    assert client.get('/openapi.json').json()['openapi'] == '3.1.0'


def test_a_new_store_is_picked_up_without_a_restart(tmp_path: Path) -> None:
    path = build(tmp_path / 'sha1.pwnd', Mode.SHA1)
    client = TestClient(create_app(Settings(sha1=path, reload_seconds=0)))
    assert client.post('/check', json={'sha1': PASSWORD}).json()['count'] == KNOWN['password']

    # an update writes a new file and moves it into place, as `pwnedkeep download` does
    from pwnedkeep.store import Writer, suffix_bytes

    with Writer(tmp_path / 'next.pwnd', Mode.SHA1, 1_900_000_000) as writer:
        writer.write_prefix(int(PASSWORD[:5], 16), [(suffix_bytes(int(PASSWORD[:5], 16), PASSWORD[5:], Mode.SHA1), 99)])
    shutil.move(tmp_path / 'next.pwnd', path)
    os.utime(path)
    assert client.post('/check', json={'sha1': PASSWORD}).json()['count'] == 99


def test_a_store_that_arrives_later_is_loaded(tmp_path: Path, sha1_store: Path) -> None:
    later = tmp_path / 'ntlm.pwnd'
    client = TestClient(create_app(Settings(sha1=sha1_store, ntlm=later, reload_seconds=0)))
    assert client.post('/check', json={'ntlm': NT}).status_code == 404
    build(later, Mode.NTLM)
    assert client.post('/check', json={'ntlm': NT}).json()['count'] == KNOWN['password']


def test_no_store_at_all_is_an_error(tmp_path: Path) -> None:
    from pwnedkeep.store import StoreError

    with pytest.raises(StoreError, match='pwnedkeep download'):
        create_app(Settings(sha1=tmp_path / 'missing.pwnd'))
