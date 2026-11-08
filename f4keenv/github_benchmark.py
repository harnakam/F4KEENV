"""Read hosted scanner results only from an eligible private repository.

Never uploads fixtures, enables validity checks, or reads secret values into reports.
"""
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
from urllib.parse import quote

from .benchmark import metrics
from .corpus import validate_corpus
from .store import now


def gh(endpoint, projection, paginate=False):
    command = ['gh', 'api', endpoint, '--jq', projection]
    if paginate:
        command.append('--paginate')
    result = subprocess.run(command, capture_output=True, text=True, encoding='utf-8', timeout=120)
    if result.returncode:
        raise ValueError('GitHub API access failed: ' + result.stderr.strip())
    if paginate:
        return [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
    return json.loads(result.stdout)


def run_github_benchmark(repository, corpus_directory, output, path_prefix, scan_complete=False):
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository):
        raise ValueError('Repository must be owner/name')
    root = 'repos/' + repository
    info = gh(root, '{private: .private, branch: .default_branch, security: .security_and_analysis}')
    if info['private'] is not True:
        raise ValueError('Hosted experiments require a private repository; refusing a public repository')
    security = info.get('security') or {}
    if security.get('secret_scanning', {}).get('status') != 'enabled':
        raise ValueError('Private repository needs an eligible Secret Protection setup with secret scanning enabled')
    if security.get('secret_scanning_validity_checks', {}).get('status') != 'disabled':
        raise ValueError('Validity checks must explicitly be disabled before a hosted benchmark')
    validate_corpus(corpus_directory)
    corpus_directory = Path(corpus_directory).resolve()
    manifest = json.loads((corpus_directory / 'manifest.json').read_text(encoding='utf-8'))
    prefix = PurePosixPath(path_prefix.replace('\\', '/'))
    if prefix.is_absolute() or '..' in prefix.parts:
        raise ValueError('Repository corpus prefix must be a relative path without parent traversal')
    ref_endpoint = root + '/git/ref/heads/' + quote(info['branch'], safe='/')
    revision = gh(ref_endpoint, '.object.sha')
    tree = gh(root + '/git/trees/' + revision + '?recursive=1',
              '{truncated: .truncated, files: [.tree[] | select(.type=="blob") | {path, sha}]}')
    if tree['truncated']:
        raise ValueError('GitHub tree is truncated; split the hosted corpus into smaller benchmark repositories')
    remote_files = {row['path']: row['sha'] for row in tree['files']}
    fixture_paths = {}
    expected_files = {}
    for row in manifest['fixtures']:
        remote_path = (prefix / row['path']).as_posix()
        content = (corpus_directory / 'corpus' / row['path']).read_bytes()
        expected = hashlib.sha1(b'blob ' + str(len(content)).encode() + b'\0' + content).hexdigest()
        if remote_files.get(remote_path) != expected:
            raise ValueError('Hosted corpus differs from the local manifest: ' + remote_path)
        fixture_paths[remote_path] = row['fixture_id']
        expected_files[remote_path] = expected
    alerts = gh(root + '/secret-scanning/alerts?per_page=100',
                '.[] | {number, secret_type, validity, state}', paginate=True)
    hits = {}
    commit_files = {revision: remote_files}
    for alert in alerts:
        locations = gh(root + f'/secret-scanning/alerts/{alert["number"]}/locations?per_page=100',
                       '.[] | {type, path: .details.path, commit_sha: .details.commit_sha}', paginate=True)
        for location in locations:
            fixture_id = fixture_paths.get(location.get('path'))
            if not fixture_id or location.get('type') != 'commit':
                continue
            origin = location.get('commit_sha')
            if not origin:
                raise ValueError('Matched alert location has no source commit')
            if origin not in commit_files:
                original = gh(root + '/git/trees/' + origin + '?recursive=1',
                              '{truncated: .truncated, files: [.tree[] | select(.type=="blob") | {path, sha}]}')
                if original['truncated']:
                    raise ValueError('Alert source tree is truncated; cannot verify fixture identity')
                commit_files[origin] = {item['path']: item['sha'] for item in original['files']}
            if commit_files[origin].get(location['path']) == expected_files[location['path']]:
                hits.setdefault(fixture_id, set()).add(alert['secret_type'])
    if gh(ref_endpoint, '.object.sha') != revision:
        raise ValueError('Hosted branch changed during benchmark; repeat against a stable snapshot')
    output = Path(output)
    if output.exists():
        raise ValueError('Hosted benchmark output already exists')
    output.mkdir(parents=True)
    rows = []
    for fixture in manifest['fixtures']:
        detected = fixture['fixture_id'] in hits
        rows.append({key: fixture[key] for key in ('fixture_id', 'provider_id', 'credential_type', 'variant', 'context', 'kind', 'generator_id', 'expected', 'label_basis')}
                    | {'detector': 'github-secret-scanning', 'detector_version': 'hosted-unversioned',
                       'detected': detected if detected or scan_complete else None,
                       'rule_ids': sorted(hits.get(fixture['fixture_id'], [])),
                       'scan_status': 'user_confirmed_complete' if scan_complete else 'completion_unconfirmed'})
    summary = {'created_at': now(), 'repository': repository, 'revision': revision,
               'validity_checks': 'disabled', 'fixture_count': len(rows), 'scan_complete_user_confirmed': scan_complete,
               'metrics': metrics(rows) if scan_complete else None,
               'note': 'Metrics remain unknown until hosted scanning completion is explicitly confirmed.'}
    (output / 'results.jsonl').write_text(''.join(json.dumps(row) + '\n' for row in rows), encoding='utf-8', newline='\n')
    (output / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n', encoding='utf-8', newline='\n')
    return summary
