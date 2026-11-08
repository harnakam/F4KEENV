"""Run with python -m f4keenv --help (Python 3.11+)."""
import argparse
import json
import sys
import shutil
from pathlib import Path

from jsonschema import ValidationError

from .ingest import (ingest_apisguru, ingest_catalog, ingest_detector_index,
                     ingest_gitleaks, ingest_openapi)
from .sources import Fetcher
from .github_patterns import ingest_github_patterns
from .store import BASE, Registry, now


def main():
    parser = argparse.ArgumentParser(description='F4KEENV public-source research registry; never authenticates synthetic credentials.')
    parser.add_argument('--workspace', type=Path, default=BASE / 'work/research')
    commands = parser.add_subparsers(dest='command', required=True)
    collect = commands.add_parser('collect', help='Ingest APIs.guru, pinned Gitleaks and detector source indexes')
    collect.add_argument('--spec-limit', type=int, default=20, help='OpenAPI downloads, 0..10000; directory metadata is always ingested')
    collect.add_argument('--refresh', action='store_true', help='Refresh remote caches (source SHA and timestamp are retained)')
    collect.add_argument('--skip-source-indexes', action='store_true')
    local = commands.add_parser('import-openapi', help='Import a user-provided OpenAPI JSON file; does not follow external refs')
    local.add_argument('file', type=Path)
    local.add_argument('--domain', required=True)
    local.add_argument('--product', default='default')
    local.add_argument('--source-url', required=True)
    commands.add_parser('validate', help='Validate all schemas, evidence and provider references')
    export = commands.add_parser('export', help='Create immutable JSONL snapshot and atomically update latest.json')
    export.add_argument('--output', type=Path, help='Copy the snapshot to a new distributable directory; never overwrite')
    args = parser.parse_args()
    if args.command == 'collect' and not 0 <= args.spec_limit <= 10000:
        parser.error('--spec-limit must be between 0 and 10000')
    registry = Registry(args.workspace)
    report = {'command': args.command, 'started_at': now(), 'sources': {}, 'errors': []}
    try:
        if args.command == 'export' and args.output is not None and args.output.exists():
            raise ValueError('Export output already exists; choose a new directory')
        if args.command == 'collect':
            fetcher = Fetcher(args.workspace, args.refresh)
            jobs = [
                ('apisguru', lambda: ingest_apisguru(registry, fetcher, args.spec_limit)),
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
    except (OSError, ValueError, ValidationError) as error:
        print(f'Research failed: {error}', file=sys.stderr)
        return 1
    finally:
        registry.close()


if __name__ == '__main__':
    sys.exit(main())
