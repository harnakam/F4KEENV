#!/usr/bin/env python3
"""Generate synthetic credential fixtures. No provider is contacted.

Usage: python scripts/generate_envs.py [--force] [--check]
Values resemble credentials but are randomly generated and never provisioned.
"""

import argparse
import re
import secrets
import string
from pathlib import Path

SERVICES = (
    'auth', 'billing', 'payments', 'users', 'notifications', 'mail',
    'search', 'catalog', 'orders', 'inventory', 'shipping', 'analytics',
    'reporting', 'media', 'uploads', 'webhooks', 'scheduler', 'worker',
    'gateway', 'audit',
)
APPS = ('web', 'admin', 'dashboard', 'portal', 'api', 'console',
        'backoffice', 'docs', 'status', 'checkout')
INFRA = ('postgres', 'redis', 'rabbitmq', 'minio', 'grafana',
         'prometheus', 'elasticsearch', 'vault', 'keycloak', 'backup')
STAGES = ('development', 'staging', 'production')


def token(length, alphabet=string.ascii_letters + string.digits):
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def targets():
    yield Path('.env'), 'platform', 'development'
    for group, names in (('services', SERVICES), ('apps', APPS), ('infra', INFRA)):
        for name in names:
            for stage in STAGES:
                yield Path(group) / name / 'config' / stage / '.env', name, stage


def render(name, stage):
    slug = name.replace('-', '_')
    values = {
        'APP_NAME': name,
        'NODE_ENV': stage,
        'PORT': '3000',
        'LOG_LEVEL': 'debug' if stage == 'development' else 'info',
        'APP_URL': f'https://{name}.{stage}.example.invalid',
        'DATABASE_URL': f'postgresql://{slug}:{token(32)}@localhost:5432/{slug}_{stage}',
        'REDIS_URL': f'redis://:{token(32)}@localhost:6379/0',
        'JWT_SECRET': secrets.token_hex(32),
        'SESSION_SECRET': secrets.token_hex(32),
        'ENCRYPTION_KEY': secrets.token_hex(32),
    }
    if name in ('platform', 'payments', 'billing', 'orders', 'checkout'):
        values.update(STRIPE_SECRET_KEY='sk_live_' + token(48),
                      STRIPE_WEBHOOK_SECRET='whsec_' + token(32))
    if name in ('platform', 'media', 'uploads', 'backup', 'minio'):
        values.update(AWS_ACCESS_KEY_ID='AKIA' + token(16, string.ascii_uppercase + '234567'),
                      AWS_SECRET_ACCESS_KEY=token(40), AWS_REGION='ap-northeast-1',
                      S3_BUCKET=f'{name}-{stage}-assets',
                      S3_ENDPOINT='http://localhost:9000')
    if name in ('platform', 'mail', 'notifications', 'users', 'auth'):
        values.update(SMTP_HOST='smtp.example.invalid', SMTP_PORT='587',
                      SMTP_USER=f'{name}@example.invalid', SMTP_PASSWORD=token(32),
                      MAIL_FROM=f'noreply@{name}.example.invalid')
    if name in ('platform', 'analytics', 'search', 'reporting', 'worker'):
        values['OPENAI_API_KEY'] = 'sk-proj-' + token(74) + 'T3BlbkFJ' + token(74)
    if name in ('platform', 'webhooks', 'scheduler', 'audit', 'console'):
        values['GITHUB_TOKEN'] = 'ghp_' + token(36)
    return ''.join(f'{key}={value}\n' for key, value in values.items())


def check(root):
    for relative, name, stage in targets():
        path = root / relative
        lines = path.read_text(encoding='utf-8').splitlines()
        if not lines or any(not re.fullmatch(r'[A-Z][A-Z0-9_]*=.+', line) for line in lines):
            raise ValueError(f'Invalid environment syntax: {relative}')
        values = dict(line.split('=', 1) for line in lines)
        expected = set(line.split('=', 1)[0] for line in render(name, stage).splitlines())
        if len(values) != len(lines) or set(values) != expected:
            raise ValueError(f'Duplicate or unexpected variables: {relative}')
        if values['APP_NAME'] != name or values['NODE_ENV'] != stage:
            raise ValueError(f'Incorrect service or stage: {relative}')
        if not values['APP_URL'].endswith('.example.invalid'):
            raise ValueError(f'Unexpected application host: {relative}')
        if '@localhost:' not in values['DATABASE_URL'] or '@localhost:' not in values['REDIS_URL']:
            raise ValueError(f'Unexpected database host: {relative}')
    print('Validated 121 environment files (root + 120 nested fixtures).')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--force', action='store_true', help='Replace existing fixture files.')
    parser.add_argument('--check', action='store_true', help='Validate existing files without writing.')
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    if args.check:
        check(root)
        return
    paths = list(targets())
    existing = [str(path) for path, _, _ in paths if (root / path).exists()]
    if existing and not args.force:
        parser.error('Existing files found; use --force to regenerate: ' + ', '.join(existing[:5]))
    for relative, name, stage in paths:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(render(name, stage), encoding='utf-8', newline='\n')
    check(root)


if __name__ == '__main__':
    main()
