"""Create a reproducible local shape benchmark and a separate symbolic public tier."""
import hashlib
import json
import random
import re
import secrets
import uuid
from pathlib import Path

from jsonschema import Draft202012Validator

from .store import BASE, identity, now
from .tokens import value_for, near_miss

CONTEXTS = ('env', 'json', 'yaml', 'python')


def rng_for(seed, *parts):
    if seed is None:
        return secrets.SystemRandom()
    digest = hashlib.sha256(json.dumps([seed, *parts]).encode()).digest()
    return random.Random(int.from_bytes(digest, 'big'))


def render(variable, value, context):
    if context == 'json':
        return json.dumps({variable: value}) + '\n'
    if context == 'yaml':
        return variable + ': ' + json.dumps(value) + '\n'
    if context == 'python':
        return variable + ' = ' + repr(value) + '\n'
    return variable + '=' + value + '\n'


def generate_corpus(registry, output, positives=50, negatives=50, seed='f4keenv-v1'):
    output = Path(output)
    if output.exists():
        raise ValueError('Corpus output already exists; select a fresh directory')
    catalog = json.loads((BASE / 'catalog/services.json').read_text(encoding='utf-8'))
    credentials = registry.rows('credentials')
    known = {row['serialization']['generator_rule']['id']: row for row in credentials
             if row['evidence_kind'] == 'legacy_catalog'}
    missing = set(s['id'] for s in catalog) - known.keys()
    if missing:
        raise ValueError('Run collect before generation; missing catalog provenance: ' + ', '.join(sorted(missing)))
    validator = Draft202012Validator(json.loads((BASE / 'schemas/fixture.schema.json').read_text()))
    corpus = output / 'corpus'
    corpus.mkdir(parents=True)
    seed_id = seed if seed is not None else 'os-random:' + secrets.token_hex(16)
    records = []
    all_values = set()
    for spec in catalog:
        credential = known[spec['id']]
        if credential['serialization']['generator_rule'] != spec:
            raise ValueError('Catalog changed since provenance import; run collect again before generation')
        for kind, count in (('positive', positives), ('near_miss', negatives // 2), ('natural_negative', negatives - negatives // 2)):
            for index in range(count):
                rng = rng_for(seed, spec['id'], kind, index)
                value = value_for(spec, rng)
                variable = spec['variable']
                expected = kind == 'positive'
                if kind == 'near_miss':
                    # A non-word separator breaks every supported catalog prefix/charset.
                    value = near_miss(spec, value)
                    if re.fullmatch(spec['pattern'], value):
                        raise ValueError('Near-miss mutation did not break the source pattern')
                elif kind == 'natural_negative':
                    variable = 'REQUEST_ID' if index % 2 else 'COMMIT_HASH'
                    value = str(uuid.UUID(int=rng.getrandbits(128), version=4)) if index % 2 else ''.join(rng.choice('0123456789abcdef') for _ in range(40))
                elif not re.fullmatch(spec['pattern'], value):
                    raise ValueError('Positive generation failed source shape validation')
                if value in all_values:
                    raise ValueError('Duplicate fixture value')
                all_values.add(value)
                context = CONTEXTS[index % len(CONTEXTS)]
                fixture_id = identity('f4k', spec['id'], kind, index, seed_id)
                relative = Path(spec['id']) / kind / (fixture_id + '.' + ('py' if context == 'python' else context))
                path = corpus / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                data = render(variable, value, context).encode('utf-8')
                path.write_bytes(data)
                approximate = credential['serialization']['status'] == 'approximate'
                record = {'fixture_id': fixture_id, 'provider_id': credential['provider_id'],
                    'credential_type': credential['credential_type'], 'variant': credential['variant'],
                    'synthetic': True, 'never_issued': True, 'generator_id': spec['id'],
                    'generator_version': '1.0.0', 'seed_id': seed_id,
                    'source_evidence_ids': credential['evidence_ids'], 'public_release': False,
                    'kind': kind, 'context': context, 'path': relative.as_posix(),
                    'sha256': hashlib.sha256(data).hexdigest(),
                    'expected': None if approximate else expected,
                    'label_basis': 'unverified_approximation' if approximate else 'synthetic_shape_and_context',
                    'source_rule_id': spec.get('rule_id')}
                validator.validate(record)
                records.append(record)
    manifest = {'schema_version': 1, 'synthetic': True, 'public_release': False,
        'generated_at': now(), 'seed_id': seed_id, 'fixture_count': len(records),
        'provider_count': len({r['provider_id'] for r in records}),
        'format_count': len(catalog), 'labels_describe': 'synthetic shape detection, not active credentials',
        'sampling_bias': 'Catalog formats mostly originate from Gitleaks rules; this is not a representative scanner ranking.',
        'unknown_serialization_skipped': sum(r['serialization']['status'] == 'unknown' for r in credentials),
        'fixtures': records}
    (output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8', newline='\n')
    return validate_corpus(output)


def validate_corpus(output):
    output = Path(output)
    manifest = json.loads((output / 'manifest.json').read_text(encoding='utf-8'))
    if not isinstance(manifest, dict) or manifest.get('synthetic') is not True or manifest.get('public_release') is not False:
        raise ValueError('Benchmark manifest must explicitly identify a local synthetic corpus')
    if not isinstance(manifest.get('fixtures'), list) or not manifest['fixtures']:
        raise ValueError('Benchmark manifest must contain fixtures')
    for field in ('fixture_count', 'format_count', 'provider_count'):
        if not isinstance(manifest.get(field), int) or isinstance(manifest[field], bool) or manifest[field] < 1:
            raise ValueError('Invalid corpus count: ' + field)
    if not isinstance(manifest.get('labels_describe'), str):
        raise ValueError('Missing corpus label scope')
    validator = Draft202012Validator(json.loads((BASE / 'schemas/fixture.schema.json').read_text()))
    root = (output / 'corpus').resolve()
    paths, ids = set(), set()
    for record in manifest['fixtures']:
        validator.validate(record)
        path = (root / record['path']).resolve()
        if not path.is_relative_to(root) or record['path'] in paths or record['fixture_id'] in ids:
            raise ValueError('Duplicate or unsafe fixture identity/path')
        if hashlib.sha256(path.read_bytes()).hexdigest() != record['sha256']:
            raise ValueError('Fixture checksum mismatch: ' + record['fixture_id'])
        paths.add(record['path'])
        ids.add(record['fixture_id'])
    actual = {p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file()}
    if paths != actual or manifest['fixture_count'] != len(ids):
        raise ValueError('Incomplete corpus or unexpected files')
    if manifest['format_count'] != len({r['generator_id'] for r in manifest['fixtures']}) or manifest['provider_count'] != len({r['provider_id'] for r in manifest['fixtures']}):
        raise ValueError('Corpus format/provider count mismatch')
    return {'fixtures': len(ids), 'formats': manifest['format_count'], 'providers': manifest['provider_count'],
            'unscored': sum(r['expected'] is None for r in manifest['fixtures'])}


def public_templates(output, registry=None):
    output = Path(output)
    if output.exists():
        raise ValueError('Template output already exists')
    catalog = json.loads((BASE / 'catalog/services.json').read_text(encoding='utf-8'))
    rows = []
    for spec in catalog:
        if spec['format'] == 'uuid4':
            template = '<uuid-v4>'
        elif spec['format'] == 'regex':
            template = '<matches:' + spec['id'] + '>'
        else:
            template = ''.join(part if isinstance(part, str) else f'<random:{part["length"]}>' for part in spec['parts'])
        rows.append({'format': spec['id'], 'service': spec['service'], 'variable': spec['variable'],
                     'template': template, 'synthetic': True, 'public_release': True,
                     'source': spec['source'], 'evidence': spec['evidence'], 'pattern': spec['pattern']})
    if registry is not None:
        for credential in registry.rows('credentials'):
            if credential['evidence_kind'] != 'aggregated_openapi':
                continue
            rows.append({'credential_id': credential['id'], 'provider_id': credential['provider_id'],
                'auth': credential['auth'], 'serialization': credential['serialization'],
                'template': '<credential:format-undocumented>', 'issuance': credential['issuance'],
                'synthetic': True, 'public_release': True, 'evidence_ids': credential['evidence_ids']})
    output.mkdir(parents=True)
    (output / 'templates.json').write_text(json.dumps(rows, indent=2) + '\n', encoding='utf-8', newline='\n')
    return {'templates': len(rows), 'credential_values_generated': 0}
