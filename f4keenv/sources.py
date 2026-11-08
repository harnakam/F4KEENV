"""Bounded public-source downloads, robots compliance, caching and provenance."""
import hashlib
import json
import time
import urllib.error
import urllib.parse
import urllib.request
import urllib.robotparser
from pathlib import Path

from .store import now

AGENT = 'F4KEENVResearch/0.1'
HOSTS = {'api.apis.guru', 'apis.guru', 'raw.githubusercontent.com', 'api.github.com', 'docs.github.com'}
MAX_BYTES = 32 * 1024 * 1024


def check_url(url):
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != 'https' or parsed.hostname not in HOSTS or parsed.username or parsed.password or parsed.port not in {None, 443}:
        raise ValueError(f'Not an approved public research host: {url}')


class Redirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, newurl):
        check_url(newurl)
        return super().redirect_request(request, fp, code, message, headers, newurl)


class Fetcher:
    def __init__(self, root, refresh=False):
        self.root = Path(root) / 'cache'
        self.root.mkdir(parents=True, exist_ok=True)
        self.refresh = refresh
        self.robots = {}
        self.last = {}
        self.opener = urllib.request.build_opener(Redirects())

    def download(self, url):
        check_url(url)
        host = urllib.parse.urlsplit(url).hostname
        delay = max(0, 0.25 - (time.monotonic() - self.last.get(host, 0)))
        if delay:
            time.sleep(delay)
        request = urllib.request.Request(url, headers={'User-Agent': AGENT, 'Accept': 'application/json, text/plain, */*'})
        try:
            with self.opener.open(request, timeout=30) as response:
                data = response.read(MAX_BYTES + 1)
                if len(data) > MAX_BYTES:
                    raise ValueError(f'Response exceeds {MAX_BYTES} bytes: {url}')
                return data, response.geturl()
        finally:
            self.last[host] = time.monotonic()

    def allowed(self, url):
        parsed = urllib.parse.urlsplit(url)
        origin = f'{parsed.scheme}://{parsed.netloc}'
        if origin not in self.robots:
            robot = urllib.robotparser.RobotFileParser()
            try:
                data, _ = self.download(origin + '/robots.txt')
                robot.parse(data.decode('utf-8', errors='replace').splitlines())
            except urllib.error.HTTPError as error:
                if 400 <= error.code < 500 and error.code not in {401, 403, 429}:
                    robot.parse([])
                else:
                    robot.disallow_all = True
            except (OSError, ValueError):
                robot.disallow_all = True
            self.robots[origin] = robot
        return self.robots[origin].can_fetch(AGENT, url)

    def fetch(self, url):
        check_url(url)
        key = hashlib.sha256(url.encode()).hexdigest()
        meta_path = self.root / (key + '.json')
        if not self.refresh and meta_path.exists():
            meta = json.loads(meta_path.read_text())
            body = (self.root / (meta['sha256'] + '.body')).read_bytes()
            if hashlib.sha256(body).hexdigest() != meta['sha256']:
                raise ValueError(f'Corrupted source cache: {url}')
            return body, meta
        if not self.allowed(url):
            raise ValueError(f'robots.txt denies or could not authorize retrieval: {url}')
        body, final = self.download(url)
        digest = hashlib.sha256(body).hexdigest()
        meta = {'url': url, 'final_url': final, 'sha256': digest, 'retrieved_at': now()}
        (self.root / (digest + '.body')).write_bytes(body)
        meta_path.write_text(json.dumps(meta), encoding='utf-8')
        return body, meta
