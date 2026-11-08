"""Bounded public-source downloads, robots compliance, caching and provenance."""
import hashlib
import json
import time
import os
import threading
from uuid import uuid4
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
        self.throttle_lock = threading.Lock()
        self.robots_lock = threading.Lock()

    def download(self, url):
        check_url(url)
        parsed = urllib.parse.urlsplit(url)
        host = parsed.hostname
        # Public directory URLs can contain literal spaces in version names.
        normalized = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc,
            urllib.parse.quote(parsed.path, safe="/%:@!$&'()*+,;=-._~"),
            urllib.parse.quote(parsed.query, safe="=&%:/?@!$'()*+,;_-~"), ''))
        with self.throttle_lock:
            scheduled = max(time.monotonic(), self.last.get(host, 0))
            self.last[host] = scheduled + 0.25
        delay = max(0, scheduled - time.monotonic())
        if delay:
            time.sleep(delay)
        request = urllib.request.Request(normalized, headers={'User-Agent': AGENT, 'Accept': 'application/json, text/plain, */*'})
        with urllib.request.build_opener(Redirects()).open(request, timeout=30) as response:
            data = response.read(MAX_BYTES + 1)
            if len(data) > MAX_BYTES:
                raise ValueError(f'Response exceeds {MAX_BYTES} bytes: {url}')
            return data, response.geturl()

    def allowed(self, url):
        with self.robots_lock:
            return self._allowed(url)

    def _allowed(self, url):
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
        body_temp = self.root / (uuid4().hex + '.tmp')
        meta_temp = self.root / (uuid4().hex + '.tmp')
        try:
            body_temp.write_bytes(body)
            os.replace(body_temp, self.root / (digest + '.body'))
            meta_temp.write_text(json.dumps(meta), encoding='utf-8')
            os.replace(meta_temp, meta_path)
        finally:
            body_temp.unlink(missing_ok=True)
            meta_temp.unlink(missing_ok=True)
        return body, meta
