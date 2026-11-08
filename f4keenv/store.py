"""Transactional, idempotent research registry with immutable JSONL exports."""
import hashlib
import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4
import platform
from importlib.metadata import version

from jsonschema import Draft202012Validator

BASE = Path(__file__).resolve().parent.parent
KINDS = ('providers', 'credentials', 'evidence', 'detectors', 'tasks')


def now():
    return datetime.now(timezone.utc).isoformat()


def identity(kind, *parts):
    value = json.dumps(parts, ensure_ascii=True, separators=(',', ':'))
    return kind + '_' + hashlib.sha256(value.encode()).hexdigest()[:24]


class Registry:
    def __init__(self, root):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.root / 'registry.sqlite3')
        self.db.execute('CREATE TABLE IF NOT EXISTS records (kind TEXT, id TEXT, payload TEXT, PRIMARY KEY(kind,id))')
        self.validators = {}
        for kind in KINDS:
            schema = json.loads((BASE / 'schemas' / (kind + '.schema.json')).read_text())
            Draft202012Validator.check_schema(schema)
            self.validators[kind] = Draft202012Validator(schema)

    def put(self, kind, record):
        self.validators[kind].validate(record)
        self.db.execute('INSERT INTO records VALUES (?,?,?) ON CONFLICT(kind,id) DO UPDATE SET payload=excluded.payload',
                        (kind, record['id'], json.dumps(record, ensure_ascii=False, sort_keys=True)))

    def get(self, kind, key):
        row = self.db.execute('SELECT payload FROM records WHERE kind=? AND id=?', (kind, key)).fetchone()
        return json.loads(row[0]) if row else None

    def rows(self, kind):
        return [json.loads(row[0]) for row in self.db.execute('SELECT payload FROM records WHERE kind=? ORDER BY id', (kind,))]

    def evidence(self, url, body, source_kind, revision=None, retrieved_at=None):
        digest = hashlib.sha256(body).hexdigest()
        key = identity('ev', url, digest)
        existing = self.get('evidence', key)
        record = {'id': key, 'url': url, 'sha256': digest, 'retrieved_at': retrieved_at or now(),
                  'first_seen_at': existing['first_seen_at'] if existing else now(),
                  'source_kind': source_kind, 'revision': revision,
                  'license': 'unknown', 'redistributed_body': False}
        self.put('evidence', record)
        return key

    def validate(self):
        data = {kind: self.rows(kind) for kind in KINDS}
        for kind, rows in data.items():
            for row in rows:
                self.validators[kind].validate(row)
        providers = {r['id'] for r in data['providers']}
        evidence = {r['id'] for r in data['evidence']}
        for kind in ('providers', 'credentials', 'detectors', 'tasks'):
            for row in data[kind]:
                if not set(row['evidence_ids']).issubset(evidence):
                    raise ValueError(f'Missing evidence: {kind}/{row["id"]}')
                if kind in {'credentials', 'tasks'} and row['provider_id'] not in providers:
                    raise ValueError(f'Missing provider: {row["id"]}')
        return data

    def export(self):
        data = self.validate()
        run_id = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + uuid4().hex[:8]
        destination = self.root / 'snapshots' / run_id
        destination.mkdir(parents=True)
        files = {}
        for kind, rows in data.items():
            content = ''.join(json.dumps(row, ensure_ascii=False, sort_keys=True) + '\n' for row in rows)
            path = destination / (kind + '.jsonl')
            path.write_text(content, encoding='utf-8', newline='\n')
            files[path.name] = {'rows': len(rows), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
        summary = {'schema_version': 1, 'collector_version': '0.1.0',
                   'runtime': {'python': platform.python_version(), 'jsonschema': version('jsonschema')},
                   'created_at': now(), 'snapshot': run_id, 'files': files,
                   'candidate_services': len(data['providers']),
                   'auth_observed_services': sum(r['auth_observed'] for r in data['providers']),
                   'officially_validated_services': sum(r['validation_status'] == 'validated' for r in data['providers']),
                   'credential_records': len(data['credentials']),
                   'detector_rules': sum(len(r['rules']) for r in data['detectors'] if r['index_kind'] == 'rules'),
                   'detector_source_units': sum(len(r['rules']) for r in data['detectors'] if r['index_kind'] == 'source_index'),
                   'hosted_supported_patterns': sum(len(r['rules']) for r in data['detectors'] if r['index_kind'] == 'supported_patterns'),
                   'service_goal': 10000,
                   'goal_reached': sum(r['validation_status'] == 'validated' for r in data['providers']) >= 10000}
        # This collector never promotes aggregator/detector evidence to official validation.
        (destination / 'manifest.json').write_text(json.dumps(summary, indent=2) + '\n', encoding='utf-8', newline='\n')
        pointer = self.root / ('latest-' + uuid4().hex + '.tmp')
        pointer.write_text(json.dumps({'snapshot': run_id}) + '\n', encoding='utf-8')
        os.replace(pointer, self.root / 'latest.json')
        return summary

    def close(self):
        self.db.close()
