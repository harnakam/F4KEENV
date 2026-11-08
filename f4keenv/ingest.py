"""Seed collection never equates detector counts with validated providers."""
import json
import tomllib
import urllib.parse
from jsonschema import ValidationError

from .openapi import canonical, extract
from .store import identity

APISGURU = 'https://api.apis.guru/v2/list.json'
GITLEAKS_REF = '5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c'


def provider(registry, domain, product, name, evidence_id, source_key, observed=False):
    key, domain, product = canonical(domain, product)
    old = registry.get('providers', key)
    sources = set(old['source_keys'] if old else []) | {source_key}
    evidence = set(old['evidence_ids'] if old else []) | {evidence_id}
    row = {**(old or {}), 'id': key, 'provider_domain': domain, 'product': product, 'name': name or source_key,
           'category': old['category'] if old else 'unknown', 'source_keys': sorted(sources),
           'evidence_ids': sorted(evidence), 'validation_status': old['validation_status'] if old else 'candidate',
           'auth_observed': observed or bool(old and old['auth_observed']),
           'official_identity_verified': old['official_identity_verified'] if old else False}
    registry.put('providers', row)
    return key


def queue_research(registry, row, evidence_id):
    registry.put('tasks', {'id': identity('task', row['id'], 'official-auth-research'),
        'provider_id': row['id'], 'status': 'pending', 'priority': 0.7,
        'queries': [
            {'kind': 'concrete', 'query': f'{row["name"]} official API authentication credentials'},
            {'kind': 'abstract', 'query': f'{row["product"]} API authentication developer portal'},
            {'kind': 'related', 'query': f'{row["provider_domain"]} API SDK authentication migration'}],
        'evidence_ids': [evidence_id], 'reason': 'Official identity, serialization and issuance remain unverified'})


def ingest_openapi(registry, spec, url, body, domain, product, source_key, retrieved_at=None):
    if not isinstance(spec, dict) or not isinstance(spec.get('info', {}), dict):
        raise ValueError('OpenAPI document and info must be objects')
    evidence_id = registry.evidence(url, body, 'aggregated_openapi', retrieved_at=retrieved_at)
    key = provider(registry, domain, product, spec.get('info', {}).get('title') or product, evidence_id, source_key)
    rows, coverage = extract(spec, key, evidence_id)
    # Replace facts from this scheme namespace; removed schemes must not linger after refresh.
    for old in registry.rows('credentials'):
        if old['provider_id'] == key and old['evidence_kind'] == 'aggregated_openapi':
            registry.db.execute('DELETE FROM records WHERE kind=? AND id=?', ('credentials', old['id']))
    for row in rows:
        registry.put('credentials', row)
    row = registry.get('providers', key)
    row['auth_observed'] = bool(rows)
    row['openapi_coverage'] = coverage
    row['origin_urls'] = [item.get('url') for item in spec.get('info', {}).get('x-origin', []) if isinstance(item, dict) and item.get('url')]
    registry.put('providers', row)
    return len(rows)


def ingest_apisguru(registry, fetcher, limit):
    body, meta = fetcher.fetch(APISGURU)
    listing = json.loads(body)
    evidence_id = registry.evidence(APISGURU, body, 'directory', retrieved_at=meta['retrieved_at'])
    candidates = []
    for source_key, entry in sorted(listing.items()):
        domain, _, product = source_key.partition(':')
        product = product or 'default'
        preferred = entry.get('preferred')
        if preferred not in entry.get('versions', {}):
            continue
        version = entry['versions'][preferred]
        key = provider(registry, domain, product, version.get('info', {}).get('title') or source_key, evidence_id, source_key)
        queue_research(registry, registry.get('providers', key), evidence_id)
        if version.get('swaggerUrl'):
            candidates.append((domain, product, source_key, version['swaggerUrl']))
    # Interleave provider groups to avoid spending the entire budget on one vendor.
    groups = {}
    for candidate in candidates:
        groups.setdefault(candidate[0], []).append(candidate)
    ordered = []
    while groups:
        for domain in list(groups):
            ordered.append(groups[domain].pop(0))
            if not groups[domain]:
                del groups[domain]
    results = {'listed_services': len(candidates), 'specs_attempted': 0, 'specs_loaded': 0, 'errors': []}
    registry.db.commit()
    for domain, product, source_key, url in ordered[:limit]:
        results['specs_attempted'] += 1
        try:
            payload, info = fetcher.fetch(url)
            with registry.db:
                ingest_openapi(registry, json.loads(payload), url, payload, domain, product, source_key, info['retrieved_at'])
            results['specs_loaded'] += 1
        except (OSError, ValueError, ValidationError) as error:
            results['errors'].append({'source_key': source_key, 'url': url, 'error': str(error)})
    return results


def ingest_gitleaks(registry, fetcher, revision=GITLEAKS_REF):
    url = f'https://raw.githubusercontent.com/gitleaks/gitleaks/{revision}/config/gitleaks.toml'
    body, meta = fetcher.fetch(url)
    config = tomllib.loads(body.decode('utf-8-sig'))
    evidence_id = registry.evidence(url, body, 'detector_implementation', revision, meta['retrieved_at'])
    rules = [{key: rule[key] for key in ('id', 'description', 'regex', 'entropy', 'keywords',
              'secretGroup', 'allowlist', 'allowlists', 'path', 'stopwords', 'required') if key in rule}
             for rule in config.get('rules', [])]
    registry.put('detectors', {'id': identity('detector', 'gitleaks', revision), 'name': 'gitleaks',
        'revision': revision, 'evidence_ids': [evidence_id], 'rules': rules,
        'global_allowlists': config.get('allowlists', config.get('allowlist', {})),
        'index_kind': 'rules', 'provider_mapping': 'unresolved'})
    return len(rules)


def ingest_detector_index(registry, fetcher, owner, repository, path_prefix, branch):
    base = f'https://api.github.com/repos/{owner}/{repository}'
    commit_body, commit_meta = fetcher.fetch(base + '/commits/' + branch)
    revision = json.loads(commit_body)['sha']
    url = base + '/git/trees/' + revision + '?recursive=1'
    body, meta = fetcher.fetch(url)
    tree = json.loads(body)
    if tree.get('truncated'):
        raise ValueError(f'Truncated detector source tree: {repository}')
    evidence_id = registry.evidence(url, body, 'detector_source_index', revision, meta['retrieved_at'])
    registry.evidence(base + '/commits/' + branch, commit_body, 'revision_resolution', revision, commit_meta['retrieved_at'])
    names = {}
    for item in tree['tree']:
        path = item['path']
        if not path.startswith(path_prefix) or item['type'] != 'blob':
            continue
        rest = path[len(path_prefix):]
        if repository == 'trufflehog':
            name = rest.split('/')[0] if '/' in rest else None
        else:
            name = rest[:-3] if rest.endswith('.py') and '/' not in rest and not rest.startswith('_') else None
        if name:
            names.setdefault(name, []).append(path)
    registry.put('detectors', {'id': identity('detector', repository, revision), 'name': repository,
        'revision': revision, 'evidence_ids': [evidence_id],
        'rules': [{'id': name, 'source_paths': sorted(paths)} for name, paths in sorted(names.items())],
        'global_allowlists': {}, 'index_kind': 'source_index', 'provider_mapping': 'unresolved'})
    return len(names)


def ingest_catalog(registry, catalog, body, url):
    evidence_id = registry.evidence(url, body, 'legacy_catalog')
    for spec in catalog:
        service = spec['service']
        key = provider(registry, 'catalog:' + service, 'default', service, evidence_id, 'catalog:' + service)
        registry.put('credentials', {'id': identity('cred', 'catalog', spec['id']), 'provider_id': key,
            'credential_type': 'unknown', 'variant': 'unverified',
            'auth': {'type': 'unknown', 'location': 'unknown'},
            'serialization': {'status': 'approximate' if spec['id'] == 'hypixel-uuid' else 'detector_observed',
                              'pattern': spec['pattern'], 'generator_rule': spec},
            'issuance': {'method': 'unknown', 'algorithm': 'unknown'}, 'confidence': 0.4,
            'evidence_kind': 'legacy_catalog', 'evidence_ids': [evidence_id],
            'synthetic_capability': 'local_only',
            'detector_refs': [spec['rule_id']] if spec.get('rule_id') else [], 'operations': []})
