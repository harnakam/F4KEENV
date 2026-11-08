"""Expand the generator catalog from a pinned, licensed detector source.

Requires research dependencies and Go for independent source-regex verification.
Does not collect sample keys from source code or contact credential issuers.
"""
import io
import json
import random
import re
from pathlib import Path, PurePosixPath
import subprocess
import sys
import zipfile

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from f4keenv.ingest import GITLEAKS_REF
from f4keenv.sources import Fetcher, HOSTS
from f4keenv.tokens import value_for, near_miss
from f4keenv.corpus import render

EXCLUDE = {'age', 'curl', 'generic', 'jwt', 'kubernetes', 'privatekey', 'stopwords'}
ALIASES = {'artifactory': 'jfrog', 'gcp': 'google-cloud'}


def python_regex(expression):
    expression = expression.replace('[[:alnum:]]', '[A-Za-z0-9]').replace('[[:xdigit:]]', '[A-Fa-f0-9]')
    insensitive = '(?i)' in expression
    expression = expression.replace('(?i)', '')
    if '(?m)' in expression or '(?s)' in expression:
        raise ValueError('Multiline or dotall source requires a dedicated generator')
    return '(?a:' + ('(?i:' + expression + ')' if insensitive else expression) + ')'


def capture_body(expression, wanted):
    if not wanted:
        return expression
    stack, captures, in_class = [], 0, False
    i = 0
    while i < len(expression):
        char = expression[i]
        if char == '\\':
            i += 2
            continue
        if char == '[':
            in_class = True
        elif char == ']':
            in_class = False
        elif not in_class and char == '(':
            if expression.startswith('(?i)', i):
                i += 4
                continue
            captured = not expression.startswith('(?', i)
            if captured:
                captures += 1
            stack.append((captures if captured else None, i + 1))
        elif not in_class and char == ')':
            group, start = stack.pop()
            if group == wanted:
                return expression[start:i]
        i += 1
    raise ValueError('Could not isolate source secret capture group')


def main():
    catalog_path = BASE / 'catalog/services.json'
    catalog = json.loads(catalog_path.read_text(encoding='utf-8'))
    existing = {row['id'] for row in catalog}
    # Only the pinned public archive is added to the downloader's approved hosts.
    HOSTS.add('codeload.github.com')
    archive_url = f'https://codeload.github.com/gitleaks/gitleaks/zip/{GITLEAKS_REF}'
    fetcher = Fetcher(BASE / 'work/catalog-expansion')
    archive_bytes, archive_meta = fetcher.fetch(archive_url)
    config_url = f'https://raw.githubusercontent.com/gitleaks/gitleaks/{GITLEAKS_REF}/config/gitleaks.toml'
    config_bytes, config_meta = fetcher.fetch(config_url)
    import tomllib
    rules = tomllib.loads(config_bytes.decode('utf-8-sig'))['rules']
    mappings = {}
    with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
        for name in archive.namelist():
            if '/cmd/generate/config/rules/' not in name or not name.endswith('.go'):
                continue
            service = PurePosixPath(name).stem
            if service in EXCLUDE:
                continue
            service = ALIASES.get(service, service).replace('_', '-')
            source = archive.read(name).decode('utf-8')
            for rule_id in re.findall(r'RuleID:\s*"([^"\n]+)"', source):
                mappings[rule_id] = (service, name.split('/', 1)[1])
    proposals, probes, ranges, skipped = [], [], [], []
    for rule in rules:
        if rule['id'] in existing:
            continue
        if rule['id'] not in mappings:
            skipped.append({'id': rule['id'], 'reason': 'Generic/non-service rule or no explicit source-file mapping'})
            continue
        try:
            normalized = python_regex(rule['regex'])
            compiled = re.compile(normalized)
            group = rule.get('secretGroup', 1 if compiled.groups else 0)
            body = capture_body(rule['regex'], group)
            if '[^' in body or '\\W' in body or '\\D' in body:
                raise ValueError('Unstable negated alphabets require a dedicated generator')
            pattern = python_regex(body)
            re.compile(pattern)
            service, source_path = mappings[rule['id']]
            keyword = next((k for k in rule.get('keywords', []) if re.fullmatch(r'[A-Za-z][A-Za-z0-9_-]{1,30}', k)), service)
            variable = re.sub(r'[^A-Z0-9_]', '_', keyword.upper()) + '_KEY'
            if variable[0].isdigit():
                variable = 'API_' + variable
            spec = {'id': rule['id'], 'service': service, 'variable': variable, 'format': 'regex',
                    'pattern': pattern, 'rule_id': rule['id'], 'detector_regex': normalized,
                    'source_regex': rule['regex'],
                    'source': f'https://github.com/gitleaks/gitleaks/blob/{GITLEAKS_REF}/{source_path}',
                    'source_revision': GITLEAKS_REF,
                    'evidence': 'detector-pattern; source-file service grouping; not official issuer specification'}
            values = [value_for(spec, random.Random(f'{rule["id"]}:{i}')) for i in range(10)]
            if len(set(values)) < 8:
                raise ValueError('Insufficient distinct synthesized values')
            start = len(probes)
            for value in values:
                near_miss(spec, value)
                for context in ('env', 'json', 'yaml', 'python'):
                    text = render(variable, value, context)
                    if not compiled.search(text):
                        raise ValueError('Source context does not match the generated assignment')
                    probes.append({'id': rule['id'], 'regex': rule['regex'], 'text': text})
            ranges.append((start, len(probes)))
            proposals.append(spec)
        except (ValueError, re.error, KeyError, IndexError) as error:
            skipped.append({'id': rule['id'], 'reason': str(error)})
            # Failed proposals may have appended probes, which must not shift later ranges.
    checked = subprocess.run(['go', 'run', str(BASE / 'scripts/regex_oracle.go')],
                             input=json.dumps(probes), capture_output=True, text=True, encoding='utf-8', timeout=120)
    if checked.returncode:
        raise ValueError('Independent Go regex verification failed: ' + checked.stderr)
    results = json.loads(checked.stdout)
    assert len(results) == len(probes)
    added = []
    for spec, (start, end) in zip(proposals, ranges):
        if not all(results[start:end]):
            skipped.append({'id': spec['id'], 'reason': 'Independent Go source regex rejected one or more probes'})
            continue
        added.append(spec)
    catalog.extend(added)
    catalog.sort(key=lambda row: (row['service'], row['id']))
    report = {'source_revision': GITLEAKS_REF, 'source_archive': archive_meta,
              'source_config': config_meta, 'existing_formats': len(existing), 'added_formats': len(added),
              'format_count': len(catalog), 'service_count': len({r['service'] for r in catalog}),
              'source_service_mapping': 'explicit RuleID to source-file group; aliases are declared in the builder',
              'verification': '10 distinct-seeded values x 4 contexts per added format; original Go regexp oracle',
              'oracle_probe_count': len(probes), 'skipped': skipped}
    temporary = catalog_path.with_suffix('.json.tmp')
    temporary.write_text(json.dumps(catalog, indent=2) + '\n', encoding='utf-8', newline='\n')
    temporary.replace(catalog_path)
    (BASE / 'research/catalog-expansion.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8', newline='\n')
    print(json.dumps({k: v for k, v in report.items() if k not in {'skipped', 'source_archive', 'source_config'}}, indent=2))
    print(f'Skipped with reasons: {len(skipped)}')


if __name__ == '__main__':
    main()
