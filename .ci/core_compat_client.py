"""Require a minimal exact-SHA result from protected private SourceCraft CI."""
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import tarfile
import time
import urllib.error
import urllib.parse
import urllib.request

from sourcecraft_api import call, NoRedirect

CORE = 'tessera-labs/tessera'
PRIVATE = '/repos/tessera-labs/tessera-enterprise/cicd/'
FIELDS = {'schema_version', 'core_repo', 'core_pr', 'core_sha', 'core_base_sha',
          'enterprise_sha', 'scope', 'status', 'signature_inputs_verified'}


def validate_receipt(record, head, base, slug):
    if set(record) != FIELDS:
        raise ValueError('unexpected receipt fields')
    expected = {'schema_version': 1, 'core_repo': CORE, 'core_pr': slug,
                'core_sha': head, 'core_base_sha': base,
                'scope': 'api-and-contract-smoke-not-native-package', 'status': 'success'}
    if any(record.get(key) != value for key, value in expected.items()):
        raise ValueError('compatibility receipt is for another revision')
    if record['signature_inputs_verified'] is not True:
        raise ValueError('source signatures were not verified')
    if not re.fullmatch('[0-9a-f]{40}', record['enterprise_sha']):
        raise ValueError('invalid private commit SHA')
    return record


def read_receipt(url):
    parsed = urllib.parse.urlsplit(url)
    if (parsed.scheme != 'https' or parsed.username or parsed.password or parsed.fragment or
            parsed.port not in (None, 443) or not parsed.hostname or
            not (parsed.hostname == 'storage.yandexcloud.net' or
                 parsed.hostname.endswith('.storage.yandexcloud.net'))):
        raise ValueError('unexpected artifact destination')
    # The SourceCraft bearer credential is never attached to artifact downloads.
    try:
        with urllib.request.build_opener(NoRedirect).open(url, timeout=60) as response:
            archive = response.read(4 * 1024 * 1024 + 1)
    except urllib.error.HTTPError as error:
        raise ValueError(f'artifact download HTTP {error.code}') from None
    if len(archive) > 4 * 1024 * 1024:
        raise ValueError('receipt archive exceeds limit')
    result = None
    with tarfile.open(fileobj=io.BytesIO(archive), mode='r:*') as bundle:
        for index, member in enumerate(bundle):
            if index >= 100:
                raise ValueError('too many receipt archive entries')
            path = PurePosixPath(member.name)
            if path.is_absolute() or '..' in path.parts:
                raise ValueError('unsafe receipt archive path')
            if member.isdir():
                continue
            if (not member.isfile() or path.name != 'receipt.json' or
                    member.size > 65536 or result is not None):
                raise ValueError('unexpected receipt archive member')
            stream = bundle.extractfile(member)
            if stream is None:
                raise ValueError('receipt file missing')
            result = json.loads(stream.read(65537))
    if not isinstance(result, dict):
        raise ValueError('receipt missing or invalid')
    return result


def current_pr(head, base, slug):
    pr = call('/repos/' + CORE + '/pulls/' + slug)
    repo = pr.get('repository', {})
    source = pr.get('source', {})
    if (pr.get('status') != 'open' or pr.get('target_branch') != 'main' or
            repo.get('slug') != 'tessera' or
            repo.get('organization', {}).get('slug') != 'tessera-labs' or
            source.get('sha') != head or pr.get('target', {}).get('sha') != base or
            not source.get('label', '').startswith(CORE + ':')):
        raise ValueError('authoritative public PR revisions differ')


def main():
    head = subprocess.check_output(['git', 'rev-parse', 'HEAD^{commit}'], text=True).strip()
    base = os.environ.get('SOURCECRAFT_BASE_SHA') or os.environ.get('VALIDATION_BASE', '')
    slug = os.environ.get('SOURCECRAFT_PR_SLUG') or os.environ.get('VALIDATION_PR', '')
    if not all(re.fullmatch('[0-9a-f]{40}', value) for value in (head, base)):
        raise ValueError('invalid public source or target SHA')
    if not re.fullmatch('[1-9][0-9]{0,18}', slug):
        raise ValueError('invalid public PR slug')
    current_pr(head, base, slug)
    response = call(PRIVATE + 'runs', {'shared': True, 'workflows': [
        {'name': 'core-compatibility', 'values': [
            {'name': 'CORE_SHA', 'value': head}, {'name': 'CORE_PR', 'value': slug}]}]})
    run = response.get('slug', '')
    if not re.fullmatch('[1-9][0-9]{0,18}', run):
        raise ValueError('invalid private run identifier')
    deadline = time.monotonic() + 3300
    print('Waiting for protected private exact-SHA compatibility.', flush=True)
    while time.monotonic() < deadline:
        status = call(PRIVATE + 'runs/' + run).get('status')
        if status == 'success':
            break
        if status in {'failed', 'canceled', 'cancelled', 'error', 'timeout'}:
            # Never copy private logs or error messages into the public job.
            raise ValueError('private compatibility workflow did not pass')
        time.sleep(10)
    else:
        raise ValueError('private compatibility timed out')
    artifacts = call(PRIVATE + 'artifacts/' + run +
                     '/core-compatibility/exact-source-consumers/public-receipt')
    matches = [item for item in artifacts.get('artifacts', [])
               if item.get('local_path') == 'compat-public' and item.get('status') == 'success']
    if len(matches) != 1:
        raise ValueError('minimal private receipt not found')
    record = validate_receipt(read_receipt(matches[0]['download_url']), head, base, slug)
    current_pr(head, base, slug)
    output = Path('ci-compatibility'); output.mkdir(exist_ok=True)
    with (output / 'receipt.json').open('x', encoding='utf-8') as stream:
        json.dump({**record, 'private_run': run}, stream, indent=2)
    print('Enterprise exact-SHA compatibility passed.', flush=True)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError, tarfile.TarError) as error:
        raise SystemExit('Compatibility refused: ' + str(error)) from None
