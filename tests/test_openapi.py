from __future__ import annotations

import json
import re
from importlib import resources
from pathlib import Path

from starlette.routing import Route

import pwnedkeep
from pwnedkeep.server import Settings, create_app


def test_the_spec_documents_every_route(sha1_store: Path) -> None:
    spec = json.loads(resources.files('pwnedkeep').joinpath('openapi.json').read_text(encoding='utf-8'))
    app = create_app(Settings(sha1=sha1_store))
    routes = {
        (method.lower(), route.path)
        for route in app.routes
        if isinstance(route, Route)
        for method in (route.methods or set())
        if method != 'HEAD'
    }
    documented = {(method, path) for path, operations in spec['paths'].items() for method in operations}
    assert routes == documented
    assert spec['info']['version'] == pwnedkeep.__version__
    assert all(re.match(r'^/[a-z/{}.]*$', path) for _, path in documented)
