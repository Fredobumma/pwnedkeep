"""The HTTP API: `/range` as api.pwnedpasswords.com has it, plus direct and bulk checks for your own apps."""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import threading
import time
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse, Response
from starlette.routing import Route

from .store import Mode, Store, StoreError, parse_prefix

MAX_BULK = 10_000
CACHE_SECONDS = 2678400  # as api.pwnedpasswords.com: 31 days
_random = secrets.SystemRandom()


def ntlm(password: str) -> bytes:
    """The NT hash of a password: MD4 of its UTF-16LE encoding."""
    return md4(password.encode('utf-16-le'))


def md4(data: bytes) -> bytes:
    """MD4, written out, since OpenSSL 3 no longer provides it to hashlib."""

    def rotate(x: int, n: int) -> int:
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

    def f(x: int, y: int, z: int) -> int:
        return (x & y) | (~x & z)

    def g(x: int, y: int, z: int) -> int:
        return (x & y) | (x & z) | (y & z)

    def h(x: int, y: int, z: int) -> int:
        return x ^ y ^ z

    length = len(data) * 8
    data += b'\x80' + b'\0' * ((55 - len(data)) % 64) + length.to_bytes(8, 'little')
    a, b, c, d = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476
    for offset in range(0, len(data), 64):
        x = [int.from_bytes(data[offset + i : offset + i + 4], 'little') for i in range(0, 64, 4)]
        aa, bb, cc, dd = a, b, c, d
        for i in range(16):
            s = (3, 7, 11, 19)[i % 4]
            a, b, c, d = d, rotate((a + f(b, c, d) + x[i]) & 0xFFFFFFFF, s), b, c
        for i in range(16):
            k = (i % 4) * 4 + i // 4
            s = (3, 5, 9, 13)[i % 4]
            a, b, c, d = d, rotate((a + g(b, c, d) + x[k] + 0x5A827999) & 0xFFFFFFFF, s), b, c
        for i in range(16):
            k = (0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15)[i]
            s = (3, 9, 11, 15)[i % 4]
            a, b, c, d = d, rotate((a + h(b, c, d) + x[k] + 0x6ED9EBA1) & 0xFFFFFFFF, s), b, c
        a, b, c, d = (
            (a + aa) & 0xFFFFFFFF,
            (b + bb) & 0xFFFFFFFF,
            (c + cc) & 0xFFFFFFFF,
            (d + dd) & 0xFFFFFFFF,
        )
    return b''.join(v.to_bytes(4, 'little') for v in (a, b, c, d))


@dataclass
class Settings:
    sha1: Path | None = None
    ntlm: Path | None = None
    api_keys: list[str] = field(default_factory=list)
    reload_seconds: float = 30.0

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> Settings:
        env = dict(os.environ if env is None else env)
        return cls(
            sha1=Path(env['PWNEDKEEP_SHA1']) if env.get('PWNEDKEEP_SHA1') else None,
            ntlm=Path(env['PWNEDKEEP_NTLM']) if env.get('PWNEDKEEP_NTLM') else None,
            api_keys=[k.strip() for k in env.get('PWNEDKEEP_API_KEYS', '').split(',') if k.strip()],
            reload_seconds=float(env.get('PWNEDKEEP_RELOAD_SECONDS', '30')),
        )


class Stores:
    """The open stores, swapped for new ones when an update replaces their files."""

    def __init__(self, settings: Settings) -> None:
        self._paths = {Mode.SHA1: settings.sha1, Mode.NTLM: settings.ntlm}
        self._stores: dict[Mode, Store] = {}
        self._lock = threading.Lock()
        self._reload_seconds = settings.reload_seconds
        self._checked = 0.0
        if not any(self._paths.values()):
            raise StoreError('no store: set PWNEDKEEP_SHA1, PWNEDKEEP_NTLM or both')
        # a store still being downloaded is loaded once it is there
        for mode, path in self._paths.items():
            if path and path.exists():
                self._stores[mode] = Store(path)
        if not self._stores:
            missing = ', '.join(str(p) for p in self._paths.values() if p)
            raise StoreError(f'no store found at {missing}: run `pwnedkeep download` first')

    def get(self, mode: Mode) -> Store | None:
        now = time.monotonic()
        if now - self._checked >= self._reload_seconds:
            self._checked = now
            self.reload()
        return self._stores.get(mode)

    def reload(self) -> None:
        with self._lock:
            for mode, path in self._paths.items():
                store = self._stores.get(mode)
                if not path:
                    continue
                try:
                    stat = path.stat()
                except FileNotFoundError:
                    continue
                if store is None or (stat.st_ino, stat.st_mtime_ns) != store.identity:
                    # the old map stays readable for requests already using it; it is closed when they let it go
                    self._stores[mode] = Store(path)

    def info(self) -> dict[str, Any]:
        return {
            mode.value: {'hashes': store.info.records, 'builtAt': store.info.built_at}
            for mode, store in self._stores.items()
        }


class Metrics:
    def __init__(self) -> None:
        self.ranges = 0
        self.checks = 0
        self.found = 0
        self._lock = threading.Lock()

    def add(self, *, ranges: int = 0, checks: int = 0, found: int = 0) -> None:
        with self._lock:
            self.ranges += ranges
            self.checks += checks
            self.found += found


def _error(status: int, message: str) -> JSONResponse:
    return JSONResponse({'error': message}, status_code=status)


def _mode(request: Request) -> Mode:
    return Mode.NTLM if request.query_params.get('mode', '').lower() == 'ntlm' else Mode.SHA1


def _padding(lines: list[str], mode: Mode) -> list[str]:
    """Fake suffixes with a count of 0, as api.pwnedpasswords.com adds, so a response's size gives nothing away."""
    target = max(len(lines) + _random.randint(100, 200), _random.randint(800, 1000))
    fake = {f'{_random.getrandbits(mode.suffix_chars * 4):0{mode.suffix_chars}X}:0' for _ in range(target - len(lines))}
    return sorted(lines + list(fake))


def create_app(settings: Settings) -> Starlette:
    stores = Stores(settings)
    metrics = Metrics()
    spec = resources.files('pwnedkeep').joinpath('openapi.json').read_text(encoding='utf-8')
    keys = [k.encode() for k in settings.api_keys]

    def store_for(mode: Mode) -> Store:
        store = stores.get(mode)
        if store is None:
            raise LookupError(f'this server has no {mode.value} store')
        return store

    async def range_(request: Request) -> Response:
        mode = _mode(request)
        try:
            prefix = parse_prefix(request.path_params['prefix'])
            store = store_for(mode)
        except ValueError as e:
            return PlainTextResponse(str(e), status_code=400)
        except LookupError as e:
            return PlainTextResponse(str(e), status_code=404)
        lines = store.range_text(prefix)
        if request.headers.get('add-padding', '').lower() == 'true':
            lines = _padding(lines, mode)
        metrics.add(ranges=1)
        return PlainTextResponse(
            '\r\n'.join(lines),
            headers={
                'Cache-Control': f'public, max-age={CACHE_SECONDS}',
                'Access-Control-Allow-Origin': '*',
                'Vary': 'Add-Padding',
                'ETag': f'"{store.info.built_at:x}-{prefix:05X}"',
            },
            media_type='text/plain; charset=utf-8',
        )

    async def body(request: Request) -> dict[str, Any]:
        try:
            data = json.loads(await request.body())
        except ValueError:
            raise ValueError('the body must be JSON') from None
        if not isinstance(data, dict):
            raise ValueError('the body must be a JSON object')
        return data

    def digest_of(value: Any, mode: Mode) -> bytes:
        if not isinstance(value, str) or len(value) != mode.hash_bytes * 2:
            raise ValueError(f'a {mode.value} hash is {mode.hash_bytes * 2} hex characters')
        try:
            return bytes.fromhex(value)
        except ValueError:
            raise ValueError(f'not hexadecimal: {value!r}') from None

    async def check(request: Request) -> Response:
        try:
            data = await body(request)
            if 'password' in data:
                if not isinstance(data['password'], str):
                    raise ValueError('password must be a string')
                mode = Mode.SHA1 if stores.get(Mode.SHA1) else Mode.NTLM
                password = data['password']
                digest = hashlib.sha1(password.encode()).digest() if mode is Mode.SHA1 else ntlm(password)
            elif 'sha1' in data:
                mode, digest = Mode.SHA1, digest_of(data['sha1'], Mode.SHA1)
            elif 'ntlm' in data:
                mode, digest = Mode.NTLM, digest_of(data['ntlm'], Mode.NTLM)
            else:
                raise ValueError('send one of password, sha1 or ntlm')
            count = store_for(mode).count(digest)
        except ValueError as e:
            return _error(400, str(e))
        except LookupError as e:
            return _error(404, str(e))
        metrics.add(checks=1, found=int(count > 0))
        return JSONResponse({'pwned': count > 0, 'count': count})

    async def check_bulk(request: Request) -> Response:
        try:
            data = await body(request)
            modes = [m for m in Mode if m.value in data]
            if len(modes) != 1:
                raise ValueError('send a list of hashes as sha1 or as ntlm')
            mode = modes[0]
            hashes = data[mode.value]
            if not isinstance(hashes, list) or not hashes or len(hashes) > MAX_BULK:
                raise ValueError(f'{mode.value} must be a list of 1 to {MAX_BULK} hashes')
            store = store_for(mode)
            results = [{'hash': h.upper(), 'count': store.count(digest_of(h, mode))} for h in hashes]
        except ValueError as e:
            return _error(400, str(e))
        except LookupError as e:
            return _error(404, str(e))
        found = sum(1 for r in results if r['count'])
        metrics.add(checks=len(results), found=found)
        return JSONResponse({'results': results, 'pwned': found})

    async def health(request: Request) -> Response:
        return JSONResponse({'ok': True, 'stores': stores.info()})

    async def openapi(request: Request) -> Response:
        return Response(spec, media_type='application/json')

    async def metrics_(request: Request) -> Response:
        info = stores.info()
        lines = [
            '# HELP pwnedkeep_ranges_total Range requests answered.',
            '# TYPE pwnedkeep_ranges_total counter',
            f'pwnedkeep_ranges_total {metrics.ranges}',
            '# HELP pwnedkeep_checks_total Hashes checked with /check and /check/bulk.',
            '# TYPE pwnedkeep_checks_total counter',
            f'pwnedkeep_checks_total {metrics.checks}',
            '# HELP pwnedkeep_found_total Checked hashes that were in breaches.',
            '# TYPE pwnedkeep_found_total counter',
            f'pwnedkeep_found_total {metrics.found}',
            '# HELP pwnedkeep_hashes Hashes in each store.',
            '# TYPE pwnedkeep_hashes gauge',
            *(f'pwnedkeep_hashes{{mode="{mode}"}} {s["hashes"]}' for mode, s in info.items()),
            '# HELP pwnedkeep_built_timestamp_seconds When each store was built.',
            '# TYPE pwnedkeep_built_timestamp_seconds gauge',
            *(f'pwnedkeep_built_timestamp_seconds{{mode="{mode}"}} {s["builtAt"]}' for mode, s in info.items()),
        ]
        return PlainTextResponse('\n'.join(lines) + '\n', media_type='text/plain; version=0.0.4')

    class KeyCheck(BaseHTTPMiddleware):
        async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
            if keys and request.url.path != '/health':
                given = request.headers.get('authorization', '').removeprefix('Bearer ').strip()
                given = given or request.headers.get('x-api-key', '')
                # compared with every key, every time, so timing says nothing about which part was right
                matched = False
                for key in keys:
                    matched |= secrets.compare_digest(given.encode(), key)
                if not matched:
                    return _error(401, 'an API key is required: Authorization: Bearer <key>, or X-Api-Key')
            return await call_next(request)

    return Starlette(
        routes=[
            Route('/range/{prefix}', range_, methods=['GET']),
            Route('/check', check, methods=['POST']),
            Route('/check/bulk', check_bulk, methods=['POST']),
            Route('/health', health, methods=['GET']),
            Route('/metrics', metrics_, methods=['GET']),
            Route('/openapi.json', openapi, methods=['GET']),
        ],
        middleware=[Middleware(KeyCheck)],
    )
