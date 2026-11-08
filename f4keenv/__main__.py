"""Run with python -m f4keenv --help (Python 3.11+)."""
import argparse
import json
import sys
import shutil
import subprocess
from pathlib import Path

from jsonschema import ValidationError
from . import __version__

from .ingest import (ingest_apisguru, ingest_catalog, ingest_detector_index,
                     ingest_gitleaks, ingest_openapi)
from .sources import Fetcher
from .github_patterns import ingest_github_patterns
from .store import BASE, Registry, now
from .corpus import generate_corpus, public_templates, validate_corpus
from .benchmark import run_benchmark
from .scheduler import schedule, audit_sample
from .github_benchmark import run_github_benchmark


def main():
    parser = argparse.ArgumentParser(description='F4KEENV public-source research registry; never authenticates synthetic credentials.')
    parser.add_argument('--version', action='version', version=__version__)
    parser.add_argument('--workspace', type=Path, default=BASE / 'work/research')
    commands = parser.add_subparsers(dest='command', required=True)
    collect = commands.add_parser('collect', help='Ingest APIs.guru, pinned Gitleaks and detector source indexes')
    collect.add_argument('--spec-limit', type=int, default=20, help='OpenAPI downloads, 0..10000; directory metadata is always ingested')
    collect.add_argument('--refresh', action='store_true', help='Refresh remote caches (source SHA and timestamp are retained)')
    collect.add_argument('--skip-source-indexes', action='store_true')
    collect.add_argument('--workers', type=int, default=4, help='Concurrent downloads, 1..16; shared per-host rate limit remains in effect')
    local = commands.add_parser('import-openapi', help='Import a user-provided OpenAPI JSON file; does not follow external refs')
    local.add_argument('file', type=Path)
    local.add_argument('--domain', required=True)
    local.add_argument('--product', default='default')
    local.add_argument('--source-url', required=True)
    commands.add_parser('validate', help='Validate all schemas, evidence and provider references')
    export = commands.add_parser('export', help='Create immutable JSONL snapshot and atomically update latest.json')
    export.add_argument('--output', type=Path, help='Copy the snapshot to a new distributable directory; never overwrite')
    generate = commands.add_parser('generate-corpus', help='Generate a local positive/negative benchmark with independent synthetic provenance')
    generate.add_argument('--output', type=Path, default=BASE / 'benchmark-local/corpus-v1')
    generate.add_argument('--positives', type=int, default=50)
    generate.add_argument('--negatives', type=int, default=50)
    generate.add_argument('--seed', default='f4keenv-v1')
    generate.add_argument('--os-random', action='store_true')
    templates = commands.add_parser('public-templates', help='Export symbolic templates without credential values')
    templates.add_argument('--output', type=Path, default=BASE / 'corpus-public')
    corpus_check = commands.add_parser('validate-corpus', help='Check corpus metadata, identity, checksums and file completeness')
    corpus_check.add_argument('corpus', type=Path)
    benchmark = commands.add_parser('benchmark', help='Run installed scanners with external verification disabled')
    benchmark.add_argument('corpus', type=Path)
    benchmark.add_argument('--output', type=Path, required=True)
    benchmark.add_argument('--gitleaks', default='gitleaks')
    benchmark.add_argument('--trufflehog', default='trufflehog')
    benchmark.add_argument('--detect-secrets', default='detect-secrets')
    benchmark.add_argument('--gitleaks-config', type=Path)
    benchmark.add_argument('--timeout', type=int, default=300)
    scheduler = commands.add_parser('schedule', help='Rank evidence gaps and export concrete/abstract/related research tasks (does not submit searches)')
    scheduler.add_argument('--output', type=Path, required=True)
    scheduler.add_argument('--limit', type=int, default=100)
    audit = commands.add_parser('audit-sample', help='Create a reproducible confidence-stratified manual review sample')
    audit.add_argument('--output', type=Path, required=True)
    audit.add_argument('--per-stratum', type=int, default=5)
    hosted = commands.add_parser('github-benchmark', help='Read alerts for an identical corpus in an eligible private repository; never uploads data')
    hosted.add_argument('repository')
    hosted.add_argument('corpus', type=Path)
    hosted.add_argument('--output', type=Path, required=True)
    hosted.add_argument('--path-prefix', required=True, help='Repository-relative path to the scanned corpus files')
    hosted.add_argument('--scan-complete', action='store_true', help='Explicitly confirm hosted scanning has finished; otherwise scores remain unknown')
    args = parser.parse_args()
    if args.command == 'collect' and not 0 <= args.spec_limit <= 10000:
        parser.error('--spec-limit must be between 0 and 10000')
    if args.command == 'collect' and not 1 <= args.workers <= 16:
        parser.error('--workers must be between 1 and 16')
    if args.command == 'generate-corpus' and not (1 <= args.positives <= 10000 and 0 <= args.negatives <= 10000):
        parser.error('positives must be 1..10000 and negatives 0..10000 per format')
    registry = Registry(args.workspace)
    report = {'command': args.command, 'started_at': now(), 'sources': {}, 'errors': []}
    try:
        if args.command == 'github-benchmark':
            print(json.dumps(run_github_benchmark(args.repository, args.corpus, args.output,
                                                 args.path_prefix, args.scan_complete), indent=2))
            return 0
        if args.command == 'schedule':
            if args.limit < 1:
                raise ValueError('Task limit must be positive')
            print(json.dumps(schedule(registry, args.output, args.limit), indent=2))
            return 0
        if args.command == 'audit-sample':
            if args.per_stratum < 1:
                raise ValueError('Audit sample size must be positive')
            print(json.dumps(audit_sample(registry, args.output, args.per_stratum), indent=2))
            return 0
        if args.command == 'generate-corpus':
            print(json.dumps(generate_corpus(registry, args.output, args.positives, args.negatives,
                                            None if args.os_random else args.seed), indent=2))
            return 0
        if args.command == 'public-templates':
            print(json.dumps(public_templates(args.output, registry), indent=2))
            return 0
        if args.command == 'validate-corpus':
            print(json.dumps(validate_corpus(args.corpus), indent=2))
            return 0
        if args.command == 'benchmark':
            if args.timeout < 1:
                raise ValueError('Scanner timeout must be positive')
            result = run_benchmark(args.corpus, args.output,
                {'gitleaks': args.gitleaks, 'trufflehog': args.trufflehog, 'detect-secrets': args.detect_secrets},
                args.gitleaks_config, args.timeout)
            print(json.dumps(result, indent=2))
            return 1 if result['errors'] else 0
        if args.command == 'export' and args.output is not None and args.output.exists():
            raise ValueError('Export output already exists; choose a new directory')
        if args.command == 'collect':
            fetcher = Fetcher(args.workspace, args.refresh)
            jobs = [
                ('apisguru', lambda: ingest_apisguru(registry, fetcher, args.spec_limit, args.workers)),
                ('gitleaks', lambda: ingest_gitleaks(registry, fetcher)),
                ('github-patterns', lambda: ingest_github_patterns(registry, fetcher)),
            ]
            if not args.skip_source_indexes:
                jobs += [
                    ('trufflehog', lambda: ingest_detector_index(registry, fetcher, 'trufflesecurity', 'trufflehog', 'pkg/detectors/', 'main')),
                    ('detect-secrets', lambda: ingest_detector_index(registry, fetcher, 'Yelp', 'detect-secrets', 'detect_secrets/plugins/', 'master')),
                ]
            for name, job in jobs:
                print(f'Collecting {name}...', flush=True)
                try:
                    with registry.db:
                        report['sources'][name] = job()
                    if isinstance(report['sources'][name], dict):
                        report['errors'].extend(report['sources'][name].get('errors', []))
                except (OSError, ValueError, ValidationError) as error:
                    report['errors'].append({'source': name, 'error': str(error)})
            catalog_path = BASE / 'catalog/services.json'
            payload = catalog_path.read_bytes()
            with registry.db:
                ingest_catalog(registry, json.loads(payload), payload, 'repo:catalog/services.json')
        elif args.command == 'import-openapi':
            payload = args.file.read_bytes()
            with registry.db:
                count = ingest_openapi(registry, json.loads(payload), args.source_url, payload,
                                       args.domain, args.product, 'local:' + args.source_url)
            report['sources']['openapi_credentials'] = count
        elif args.command == 'validate':
            registry.validate()
        summary = registry.export()
        report['summary'] = summary
        report['completed_at'] = now()
        destination = args.workspace / 'snapshots' / summary['snapshot'] / 'collection-report.json'
        destination.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8', newline='\n')
        if args.command == 'export' and args.output is not None:
            shutil.copytree(destination.parent, args.output)
            report['exported_snapshot'] = str(args.output)
        print(json.dumps(report, indent=2))
        return 1 if report['errors'] else 0
    except (OSError, ValueError, ValidationError, subprocess.SubprocessError) as error:
        print(f'Research failed: {error}', file=sys.stderr)
        return 1
    finally:
        registry.close()


if __name__ == '__main__':
    sys.exit(main())
