"""The command line: download or import the data, serve it, and check passwords and hash dumps against it."""

from __future__ import annotations

import argparse
import asyncio
import getpass
import hashlib
import os
import re
import sys
import time
from collections.abc import Callable
from pathlib import Path

from . import __version__
from .server import Settings, ntlm
from .sources import Progress, download, import_files
from .store import Mode, Store, StoreError


def _progress(started: float) -> Callable[[Progress], None]:
    def show(progress: Progress) -> None:
        elapsed = time.monotonic() - started
        rate = progress.done / elapsed if elapsed else 0
        print(
            f'\r{progress.done:>9,} ranges  {progress.changed:,} new or changed  {progress.unchanged:,} unchanged  '
            f'{rate:,.0f}/s',
            end='',
            file=sys.stderr,
            flush=True,
        )

    return show


def cmd_download(args: argparse.Namespace) -> int:
    mode = Mode(args.mode)
    prefixes = [int(p, 16) for p in args.prefixes.split(',')] if args.prefixes else None
    existed = Path(args.store).exists()
    started = time.monotonic()
    progress = asyncio.run(
        download(args.store, mode, concurrency=args.concurrency, prefixes=prefixes, on_progress=_progress(started))
    )
    print(file=sys.stderr)
    store = Store(args.store)
    verb = 'updated' if existed else 'downloaded'
    print(
        f'{verb} {args.store}: {store.info.records:,} {mode.value} hashes; '
        f'{progress.changed:,} ranges fetched, {progress.unchanged:,} unchanged, in {time.monotonic() - started:,.0f}s'
    )
    return 0


def cmd_import(args: argparse.Namespace) -> int:
    count = import_files(args.source, args.store, Mode(args.mode))
    print(f'imported {count:,} {args.mode} hashes into {args.store}')
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    from .server import create_app

    settings = Settings.from_env()
    if args.sha1:
        settings.sha1 = Path(args.sha1)
    if args.ntlm:
        settings.ntlm = Path(args.ntlm)
    elif settings.ntlm is None and settings.sha1 and (settings.sha1.parent / 'ntlm.pwnd').exists():
        settings.ntlm = settings.sha1.parent / 'ntlm.pwnd'
    uvicorn.run(create_app(settings), host=args.host, port=args.port, access_log=False, proxy_headers=True)
    return 0


def cmd_lookup(args: argparse.Namespace) -> int:
    store = Store(args.store)
    if args.hash:
        digest = bytes.fromhex(args.hash)
    else:
        password = args.password if args.password is not None else getpass.getpass('Password: ')
        digest = hashlib.sha1(password.encode()).digest() if store.mode is Mode.SHA1 else ntlm(password)
    count = store.count(digest)
    print(f'found in breaches {count:,} times' if count else 'not found in any breach')
    return 1 if count else 0


# `user:hash`, or the `user:rid:lm:nt:::` of secretsdump and similar tools
_DUMP_LINE = re.compile(r'^(?P<user>[^:]+):(?:\d+:[0-9a-fA-F]{32}:)?(?P<nt>[0-9a-fA-F]{32})(?::.*)?$')


def cmd_audit(args: argparse.Namespace) -> int:
    store = Store(args.store)
    if store.mode is not Mode.NTLM:
        print('audit needs an NTLM store: download one with --mode ntlm', file=sys.stderr)
        return 2
    checked = found = 0
    with open(args.dump, encoding='utf-8', errors='replace') as f:
        for line in f:
            match = _DUMP_LINE.match(line.strip())
            if not match:
                continue
            checked += 1
            count = store.count(bytes.fromhex(match['nt']))
            if count:
                found += 1
                print(f'{match["user"]}\t{count:,}')
    print(f'{found:,} of {checked:,} accounts use a password found in breaches', file=sys.stderr)
    return 1 if found else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog='pwnedkeep', description='Your own Pwned Passwords API.')
    parser.add_argument('--version', action='version', version=f'pwnedkeep {__version__}')
    commands = parser.add_subparsers(dest='command', required=True)

    p = commands.add_parser('download', help='download the data from api.pwnedpasswords.com, or update it')
    p.add_argument('store', help='the store file, such as sha1.pwnd; an existing one is updated')
    p.add_argument('--mode', choices=[m.value for m in Mode], default='sha1')
    p.add_argument('--concurrency', type=int, default=64)
    p.add_argument('--prefixes', help='only these ranges, comma-separated, such as 5BAA6,21BD1 (for testing)')
    p.set_defaults(run=cmd_download)

    p = commands.add_parser('import', help="build a store from the official downloader's files")
    p.add_argument('source', help='pwnedpasswords.txt, or a folder of XXXXX.txt range files')
    p.add_argument('store')
    p.add_argument('--mode', choices=[m.value for m in Mode], default='sha1')
    p.set_defaults(run=cmd_import)

    p = commands.add_parser('serve', help='serve the API')
    p.add_argument('--sha1', help='a SHA-1 store (or PWNEDKEEP_SHA1)')
    p.add_argument('--ntlm', help='an NTLM store (or PWNEDKEEP_NTLM)')
    p.add_argument('--host', default=os.environ.get('HOST', '0.0.0.0'))
    p.add_argument('--port', type=int, default=int(os.environ.get('PORT', '8000')))
    p.set_defaults(run=cmd_serve)

    p = commands.add_parser('lookup', help='check one password or hash; exits 1 if it was found')
    p.add_argument('store')
    group = p.add_mutually_exclusive_group()
    group.add_argument('--password', help='prompted for if neither this nor --hash is given')
    group.add_argument('--hash', help='a SHA-1 or NTLM hash, in hex')
    p.set_defaults(run=cmd_lookup)

    p = commands.add_parser('audit', help='check a dump of NT hashes; prints the accounts whose password was found')
    p.add_argument('store', help='an NTLM store')
    p.add_argument('dump', help='lines of user:nthash, or the user:rid:lm:nt::: of secretsdump')
    p.set_defaults(run=cmd_audit)

    args = parser.parse_args(argv)
    try:
        return int(args.run(args))
    except (StoreError, ValueError, OSError) as e:
        print(f'pwnedkeep: {e}', file=sys.stderr)
        return 2
