"""Offline synthetic credentials; never reads credentials or calls providers."""
import argparse
import hashlib
import json
import re
import secrets
import uuid
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def make_value(spec):
    if spec['format'] == 'regex':
        from f4keenv.tokens import value_for
        return value_for(spec, secrets.SystemRandom())
    if spec['format'] == 'uuid4':
        return str(uuid.uuid4())
    return ''.join(part if isinstance(part, str) else ''.join(
        secrets.choice(part['alphabet']) for _ in range(part['length']))
        for part in spec['parts'])


def validate(root, catalog):
    manifest = json.loads((root / 'manifest.json').read_text(encoding='utf-8'))
    snapshot = manifest.get('formats')
    specs = {s['id']: s for s in (snapshot if snapshot is not None else catalog)}
    active_ids = {item.get('format_id', item['service']) for item in manifest['samples']}
    if not active_ids or not active_ids.issubset(specs):
        raise ValueError('Manifest references unknown formats')
    if snapshot is not None and len(specs) != len(snapshot):
        raise ValueError('Duplicate format definitions in manifest')
    seen, paths = set(), set()
    counts = {key: 0 for key in active_ids}
    for item in manifest['samples']:
        format_id = item.get('format_id', item['service'])
        spec = specs[format_id]
        if manifest.get('schema_version', 1) >= 3 and item['service'] != spec['service']:
            raise ValueError('Sample service does not match its format definition')
        relative = Path(item['path'])
        path = (root / relative).resolve()
        if not path.is_relative_to(root.resolve()) or item['path'] in paths:
            raise ValueError('Unsafe or duplicate sample path')
        paths.add(item['path'])
        data = path.read_bytes()
        text = data.decode('utf-8')
        key, value = text.rstrip('\n').split('=', 1)
        if key != spec['variable'] or not re.fullmatch(spec['pattern'], value):
            raise ValueError(f'Format mismatch: {relative}')
        if hashlib.sha256(data).hexdigest() != item['sha256']:
            raise ValueError(f'Integrity mismatch: {relative}')
        if value in seen:
            raise ValueError('Duplicate value')
        seen.add(value)
        counts[format_id] += 1
    actual = {p.relative_to(root).as_posix() for p in root.rglob('.env')}
    per_format = manifest.get('samples_per_format', manifest.get('samples_per_service'))
    if actual != paths or any(n != per_format for n in counts.values()):
        raise ValueError('Incomplete or unexpected dataset')
    expected_count = len({specs[key]['service'] for key in active_ids}) if manifest.get('schema_version', 1) >= 2 else len(active_ids)
    if manifest['synthetic'] is not True or manifest['service_count'] != expected_count:
        raise ValueError('Incorrect dataset metadata')
    if snapshot is not None and (active_ids != set(specs) or manifest['format_count'] != len(specs)):
        raise ValueError('Incomplete format coverage')
    return len(seen)


def generate(root, catalog, count):
    if root.exists():
        raise ValueError('Output already exists; choose a fresh --output directory')
    root.mkdir(parents=True)
    records = []
    for spec in catalog:
        for index in range(count):
            relative = Path(spec['id']) / f'{index:05d}' / '.env'
            path = root / relative
            path.parent.mkdir(parents=True)
            data = f"{spec['variable']}={make_value(spec)}\n".encode('utf-8')
            path.write_bytes(data)
            records.append({'path': relative.as_posix(), 'format_id': spec['id'], 'service': spec['service'],
                            'sha256': hashlib.sha256(data).hexdigest(),
                            'rule_id': spec.get('rule_id'), 'synthetic': True})
    manifest = {'schema_version': 3, 'synthetic': True,
                'generation': 'OS randomness; no provider issuance or validation',
                'service_count': len({s['service'] for s in catalog}), 'format_count': len(catalog),
                'formats': catalog, 'samples_per_format': count,
                'samples': records}
    (root / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8', newline='\n')
    return validate(root, catalog)


def main():
    base = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=base / 'dataset')
    parser.add_argument('--samples', type=int, default=400)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    if not 1 <= args.samples <= 10000:
        parser.error('--samples must be between 1 and 10000 per service')
    catalog = json.loads((base / 'catalog' / 'services.json').read_text(encoding='utf-8'))
    try:
        count = validate(args.output, catalog) if args.check else generate(args.output, catalog, args.samples)
    except (ValueError, OSError, KeyError) as error:
        parser.exit(1, f'{error}\n')
    print(f'Validated {count} synthetic samples.')


if __name__ == '__main__':
    main()
