"""Prioritize evidence gaps; exported tasks can be consumed by a research agent."""
from collections import Counter, defaultdict
import json
from pathlib import Path
import random

from .store import identity


def schedule(registry, output, limit=100):
    output = Path(output)
    if output.exists():
        raise ValueError('Task output already exists')
    providers = registry.rows('providers')
    credentials = defaultdict(list)
    for row in registry.rows('credentials'):
        credentials[row['provider_id']].append(row)
    categories = Counter(p['category'] for p in providers)
    domains = Counter(p['provider_domain'] for p in providers)
    tasks = []
    for provider in providers:
        facts = credentials[provider['id']]
        if provider['validation_status'] == 'validated' and facts and all(
                c['serialization']['status'] == 'officially_documented' for c in facts):
            continue
        novelty = 1 / domains[provider['provider_domain']]
        gap = 1 / categories[provider['category']]
        uncertainty = 1.0 if not facts or any(c['serialization']['status'] in {'unknown', 'approximate'} for c in facts) else 0.6
        relevance = 1.0 if any(c['detector_refs'] for c in facts) else 0.5
        quality = max((c['confidence'] for c in facts), default=0.3)
        components = {'novelty': novelty, 'coverage_gap': gap, 'uncertainty': uncertainty,
                      'detector_relevance': relevance, 'evidence_quality': quality, 'cost': 0.0}
        score = 0.30 * novelty + 0.25 * gap + 0.20 * uncertainty + 0.15 * relevance + 0.10 * quality
        task = {'id': identity('task', provider['id'], 'official-auth-research'),
            'provider_id': provider['id'], 'status': 'pending', 'priority': score,
            'score_components': components, 'evidence_ids': provider['evidence_ids'],
            'queries': [
                {'kind': 'concrete', 'query': f'{provider["name"]} official API authentication token format issuance'},
                {'kind': 'abstract', 'query': f'{provider["category"]} {provider["product"]} API credential authentication developer documentation'},
                {'kind': 'related', 'query': f'{provider["provider_domain"]} SDK API token migration legacy developer portal'}],
            'candidate_origins': provider.get('origin_urls', []),
            'reason': 'Resolve official identity, credential serialization and issuance from primary sources; do not use search snippets as evidence'}
        tasks.append(task)
    tasks.sort(key=lambda task: (-task['priority'], task['provider_id']))
    with registry.db:
        for task in tasks:
            existing = registry.get('tasks', task['id'])
            if existing and existing['status'] in {'running', 'complete'}:
                continue
            registry.put('tasks', task)
    selected = [t for t in tasks if registry.get('tasks', t['id'])['status'] not in {'running', 'complete'}][:limit]
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(''.join(json.dumps(t, ensure_ascii=False) + '\n' for t in selected), encoding='utf-8', newline='\n')
    return {'pending_gaps': len(tasks), 'exported_tasks': len(selected), 'search_requests_sent': 0}


def audit_sample(registry, output, per_stratum=5, seed='f4keenv-audit-v1'):
    groups = defaultdict(list)
    for row in registry.rows('credentials'):
        groups[(row['evidence_kind'], row['serialization']['status'], str(row['confidence']))].append(row)
    rng = random.Random(seed)
    samples = []
    for stratum, rows in sorted(groups.items()):
        for row in rng.sample(sorted(rows, key=lambda r: r['id']), min(per_stratum, len(rows))):
            samples.append({'credential_id': row['id'], 'provider_id': row['provider_id'],
                            'stratum': list(stratum), 'evidence_ids': row['evidence_ids'],
                            'review_status': 'pending', 'review_notes': None})
    output = Path(output)
    if output.exists():
        raise ValueError('Audit output already exists')
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(''.join(json.dumps(row) + '\n' for row in samples), encoding='utf-8', newline='\n')
    return {'strata': len(groups), 'samples': len(samples), 'seed_id': seed}
