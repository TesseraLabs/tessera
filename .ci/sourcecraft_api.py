"""Bounded SourceCraft API calls; credentials never leave the fixed API host."""
import json
import os
import urllib.error
import urllib.request


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise ValueError('HTTP redirects are forbidden')


def call(path, body=None):
    if not path.startswith('/repos/tessera-labs/') or '\\' in path:
        raise ValueError('unexpected API path')
    token = os.environ.get('SOURCECRAFT_TOKEN')
    if not token:
        raise ValueError('SourceCraft token is required')
    request = urllib.request.Request(
        'https://api.sourcecraft.tech' + path,
        data=None if body is None else json.dumps(body).encode(),
        headers={'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'},
        method='GET' if body is None else 'POST',
    )
    try:
        with urllib.request.build_opener(NoRedirect).open(request, timeout=30) as response:
            data = response.read(2 * 1024 * 1024 + 1)
    except urllib.error.HTTPError as error:
        raise ValueError(f'SourceCraft API HTTP {error.code}') from None
    except urllib.error.URLError:
        raise ValueError('SourceCraft API request failed') from None
    if len(data) > 2 * 1024 * 1024:
        raise ValueError('SourceCraft API response exceeds limit')
    return json.loads(data)
