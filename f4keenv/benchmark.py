"""Run real scanners with verification disabled and score fixture-level findings."""
import json
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import time
import platform

from .corpus import validate_corpus
from .store import now


def rate(numerator, denominator):
    return numerator / denominator if denominator else None


def metrics(rows):
    scored = [r for r in rows if r['expected'] is not None and r['detected'] is not None]
    tp = sum(r['expected'] and r['detected'] for r in scored)
    fp = sum(not r['expected'] and r['detected'] for r in scored)
    fn = sum(r['expected'] and not r['detected'] for r in scored)
    tn = sum(not r['expected'] and not r['detected'] for r in scored)
    return {'tp': tp, 'fp': fp, 'fn': fn, 'tn': tn, 'scored': len(scored),
            'unscored': len(rows) - len(scored), 'recall': rate(tp, tp + fn),
            'precision': rate(tp, tp + fp), 'false_positive_rate': rate(fp, fp + tn)}


def executable(value):
    result = shutil.which(str(value))
    if not result:
        path = Path(value).resolve()
        if path.is_file():
            result = str(path)
    if not result:
        raise ValueError('Scanner executable not found: ' + str(value))
    return str(Path(result).resolve())


def normalize_path(raw, corpus):
    normalized = str(raw).replace('\\', '/')
    path = Path(normalized)
    path = path.resolve() if path.is_absolute() else (corpus / path).resolve()
    if not path.is_relative_to(corpus):
        raise ValueError('Finding points outside corpus: ' + str(raw))
    return path.relative_to(corpus).as_posix()


def parse_findings(detector, stdout, report, corpus):
    hits = {}
    def add(path, rule):
        key = normalize_path(path, corpus)
        hits.setdefault(key, set()).add(str(rule))
    if detector == 'gitleaks':
        if not report.exists():
            raise ValueError('Gitleaks did not write its report')
        for row in json.loads(report.read_text(encoding='utf-8')) or []:
            add(row['File'], row['RuleID'])
    elif detector == 'trufflehog':
        for line in stdout.splitlines():
            if not line.strip():
                continue
            row = json.loads(line)
            if 'DetectorName' not in row:
                raise ValueError('Unexpected TruffleHog stdout record')
            source = row['SourceMetadata']['Data']['Filesystem']
            add(source['file'], row['DetectorName'])
    else:
        data = json.loads(stdout)
        for path, rows in data['results'].items():
            for row in rows:
                add(path, row['type'])
    return hits


def run_benchmark(corpus_directory, output, tools, config=None, timeout=300):
    corpus_directory = Path(corpus_directory).resolve()
    validate_corpus(corpus_directory)
    manifest = json.loads((corpus_directory / 'manifest.json').read_text(encoding='utf-8'))
    corpus = corpus_directory / 'corpus'
    output = Path(output).resolve()
    if output.exists():
        raise ValueError('Benchmark output already exists; choose a fresh directory')
    if output.is_relative_to(corpus):
        raise ValueError('Benchmark output must be outside the scanned corpus')
    resolved = {name: executable(value) for name, value in tools.items()}
    output.mkdir(parents=True)
    raw = output / 'raw'
    raw.mkdir()
    summary = {'created_at': now(), 'external_verification': False,
               'corpus_manifest_sha256': hashlib.sha256((corpus_directory / 'manifest.json').read_bytes()).hexdigest(),
               'label_scope': manifest['labels_describe'], 'detectors': {}, 'errors': []}
    summary['sampling_bias'] = manifest.get('sampling_bias', 'Catalog formats mostly originate from Gitleaks rules.')
    summary['platform'] = {'system': platform.system(), 'release': platform.release(),
                           'machine': platform.machine(), 'python': platform.python_version()}
    total_bytes = sum((corpus / row['path']).stat().st_size for row in manifest['fixtures'])
    records = []
    for name, tool in resolved.items():
        report_path = raw / (name + '.json')
        if name == 'gitleaks':
            command = [tool, 'dir', '.', '--report-format', 'json', '--report-path', str(report_path),
                       '--exit-code', '0', '--redact=100', '--no-banner']
            if config:
                command += ['--config', str(Path(config).resolve())]
            version_args = [tool, 'version']
        elif name == 'trufflehog':
            command = [tool, 'filesystem', '.', '--json', '--no-verification', '--no-update',
                       '--results=verified,unknown,unverified', '--concurrency=1', '--no-filter-unverified', '--fail-on-scan-errors']
            version_args = [tool, '--version']
        elif name == 'detect-secrets':
            command = [tool, 'scan', '--no-verify', '--all-files', '.']
            version_args = [tool, '--version']
        else:
            raise ValueError('Unsupported scanner: ' + name)
        version_run = subprocess.run(version_args, capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=30)
        if version_run.returncode:
            raise ValueError('Cannot determine scanner version: ' + name)
        tool_version = (version_run.stdout + version_run.stderr).strip()
        env = dict(os.environ)
        env.pop('GITLEAKS_CONFIG', None)
        env.pop('GITLEAKS_CONFIG_TOML', None)
        started = time.perf_counter()
        hits, failure = {}, None
        try:
            result = subprocess.run(command, cwd=corpus, capture_output=True, text=True,
                                    encoding='utf-8', errors='replace', timeout=timeout, env=env)
            (raw / (name + '.stderr.log')).write_text(result.stderr, encoding='utf-8', newline='\n')
            if name != 'gitleaks':
                report_path.write_text(result.stdout, encoding='utf-8', newline='\n')
            if result.returncode:
                raise ValueError(f'Scanner exited {result.returncode}; see {name}.stderr.log')
            hits = parse_findings(name, result.stdout, report_path, corpus)
            unknown = set(hits) - {r['path'] for r in manifest['fixtures']}
            if unknown:
                raise ValueError(f'{len(unknown)} findings could not be mapped to fixtures')
        except (OSError, ValueError, KeyError, subprocess.TimeoutExpired) as error:
            failure = str(error)
            summary['errors'].append({'detector': name, 'error': failure})
        elapsed = time.perf_counter() - started
        detector_rows = []
        for fixture in manifest['fixtures']:
            row = {key: fixture[key] for key in ('fixture_id', 'provider_id', 'credential_type',
                   'variant', 'context', 'kind', 'generator_id', 'expected', 'label_basis')}
            row.update(detector=name, detector_version=tool_version,
                       detected=None if failure else fixture['path'] in hits,
                       rule_ids=sorted(hits.get(fixture['path'], [])),
                       source_rule_id=fixture.get('source_rule_id'),
                       source_rule_detected=(fixture.get('source_rule_id') in hits.get(fixture['path'], set()))
                           if name == 'gitleaks' and not failure and fixture.get('source_rule_id') else None,
                       scan_status='error' if failure else 'complete')
            detector_rows.append(row)
        summary['detectors'][name] = {'version': tool_version, 'command': command,
            'wall_seconds': elapsed, 'bytes_scanned': total_bytes, 'mb_per_second': total_bytes / 1e6 / elapsed,
            'timing_includes_startup': True, 'cpu_seconds': None, 'peak_memory_bytes': None,
            'resource_measurement': 'wall-clock only', 'metrics': metrics(detector_rows),
            'metric_scope': 'any finding in the fixture; not provider classification accuracy',
            'provider_coverage': {
                'detected': len({r['provider_id'] for r in detector_rows if r['expected'] is True and r['detected'] is True}),
                'eligible': len({r['provider_id'] for r in detector_rows if r['expected'] is True})},
            'source_rule_metrics': metrics([{**r, 'detected': r['source_rule_detected']} for r in detector_rows])
                if name == 'gitleaks' else None,
            'by_format': {format_id: metrics([r for r in detector_rows if r['generator_id'] == format_id])
                          for format_id in sorted({r['generator_id'] for r in detector_rows})}}
        for field in ('provider_id', 'credential_type', 'variant', 'context'):
            summary['detectors'][name]['by_' + field] = {
                value: metrics([r for r in detector_rows if r[field] == value])
                for value in sorted({r[field] for r in detector_rows})}
        records.extend(detector_rows)
        print(f'{name}: {"failed" if failure else "complete"}, {elapsed:.2f}s', flush=True)
    (output / 'results.jsonl').write_text(''.join(json.dumps(r) + '\n' for r in records), encoding='utf-8', newline='\n')
    (output / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n', encoding='utf-8', newline='\n')
    table = ['# F4KEENV local shape benchmark', '',
             'Fixed synthetic inputs; external credential verification disabled.', '',
             '**Scope:** ' + summary['label_scope'], '',
             '**Sampling bias:** ' + summary['sampling_bias'], '',
             '| Scanner | Version | TP | FP | FN | TN | Unscored | Recall | Precision | FPR | Seconds |',
             '|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|']
    def percent(value):
        return 'n/a' if value is None else f'{value:.2%}'
    for name, result in summary['detectors'].items():
        m = result['metrics']
        table.append(f'| {name} | {result["version"]} | {m["tp"]} | {m["fp"]} | {m["fn"]} | {m["tn"]} | {m["unscored"]} | {percent(m["recall"])} | {percent(m["precision"])} | {percent(m["false_positive_rate"])} | {result["wall_seconds"]:.3f} |')
    table += ['', 'Metrics count any finding in a fixture; provider classification is separate. Exact source-rule scores are available for Gitleaks only.',
              'Approximate Hypixel samples are unscored. Single-field inputs do not model all paired-credential requirements.',
              'This is not a general scanner ranking. CPU time and peak RSS were not measured.',
              'GitHub hosted results require a separate eligible private repository and are not inferred from these local runs.', '']
    (output / 'report.md').write_text('\n'.join(table), encoding='utf-8', newline='\n')
    return summary
