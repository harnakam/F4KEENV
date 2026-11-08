"""Read the public documentation's embedded pattern table, not private API state."""
import json
from html.parser import HTMLParser

from .store import identity

URL = 'https://docs.github.com/en/code-security/secret-scanning/introduction/supported-secret-scanning-patterns'


class PageData(HTMLParser):
    def __init__(self):
        super().__init__()
        self.capture = False
        self.chunks = []

    def handle_starttag(self, tag, attrs):
        if tag == 'script' and dict(attrs).get('id') == '__NEXT_DATA__':
            self.capture = True

    def handle_endtag(self, tag):
        if tag == 'script':
            self.capture = False

    def handle_data(self, text):
        if self.capture:
            self.chunks.append(text)


def ingest_github_patterns(registry, fetcher):
    body, meta = fetcher.fetch(URL)
    parser = PageData()
    parser.feed(body.decode('utf-8'))
    try:
        patterns = json.loads(''.join(parser.chunks))['props']['pageProps']['patterns']
    except (ValueError, KeyError, TypeError) as error:
        raise ValueError('GitHub supported-patterns document changed; refusing partial table import') from error
    if not isinstance(patterns, list) or not patterns:
        raise ValueError('Missing GitHub supported-patterns table')
    rules = []
    for pattern in patterns:
        if not isinstance(pattern, dict) or not pattern.get('provider') or not pattern.get('secretType'):
            raise ValueError('Invalid GitHub pattern record')
        rules.append({'id': identity('pattern', pattern['provider'], pattern['secretType']), **pattern})
    evidence_id = registry.evidence(URL, body, 'official_detector_documentation',
                                    meta['sha256'], meta['retrieved_at'])
    registry.put('detectors', {'id': identity('detector', 'github', meta['sha256']),
        'name': 'github-secret-scanning', 'revision': meta['sha256'],
        'evidence_ids': [evidence_id], 'rules': rules, 'global_allowlists': {},
        'index_kind': 'supported_patterns', 'provider_mapping': 'unresolved'})
    return len(rules)
