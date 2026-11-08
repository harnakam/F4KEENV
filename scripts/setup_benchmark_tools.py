"""Download pinned Windows x64 scanner releases and verify publisher checksums.

Run with Python 3.11+; does not alter PATH or install system-wide software.
"""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import platform
import tarfile
import urllib.request
import zipfile

RELEASES = (
    ('gitleaks', 'gitleaks/gitleaks', '8.30.1', 'windows_x64.zip'),
    ('trufflehog', 'trufflesecurity/trufflehog', '3.99.8', 'windows_amd64.tar.gz'),
)


def download(url, target):
    if target.exists():
        return
    request = urllib.request.Request(url, headers={'User-Agent': 'F4KEENVBenchmarkSetup/1.0'})
    temporary = target.with_suffix(target.suffix + '.partial')
    total = 0
    try:
        with urllib.request.urlopen(request, timeout=60) as response, temporary.open('wb') as out:
            while chunk := response.read(1024 * 1024):
                total += len(chunk)
                if total > 300 * 1024 * 1024:
                    raise ValueError('Release asset exceeds 300 MiB limit')
                out.write(chunk)
        temporary.replace(target)
    finally:
        temporary.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=Path(__file__).resolve().parent.parent / 'work/tools')
    args = parser.parse_args()
    if platform.system() != 'Windows' or platform.machine().lower() not in {'amd64', 'x86_64'}:
        parser.error('This installer supports Windows x64. Install official platform binaries and pass their paths to benchmark on other systems.')
    args.output.mkdir(parents=True, exist_ok=True)
    records = []
    for tool, repository, version, suffix in RELEASES:
        base = f'https://github.com/{repository}/releases/download/v{version}/'
        name = f'{tool}_{version}_{suffix}'
        checksums = f'{tool}_{version}_checksums.txt'
        asset = args.output / name
        download(base + name, asset)
        download(base + checksums, args.output / checksums)
        entries = [line.split() for line in (args.output / checksums).read_text(encoding='utf-8').splitlines() if line.strip()]
        expected = next(row[0] for row in entries if row[-1].lstrip('*') == name)
        actual = hashlib.sha256(asset.read_bytes()).hexdigest()
        if expected != actual:
            raise ValueError('Checksum mismatch; remove the cached asset before retrying: ' + name)
        destination = args.output / tool
        destination.mkdir(exist_ok=True)
        if suffix.endswith('.zip'):
            with zipfile.ZipFile(asset) as archive:
                selected = [member for member in archive.infolist() if PurePosixPath(member.filename).name == tool + '.exe']
                if len(selected) != 1:
                    raise ValueError('Release does not contain exactly one scanner executable')
                data = archive.read(selected[0])
        else:
            with tarfile.open(asset) as archive:
                selected = [member for member in archive.getmembers() if member.isfile() and PurePosixPath(member.name).name == tool + '.exe']
                if len(selected) != 1:
                    raise ValueError('Release does not contain exactly one scanner executable')
                with archive.extractfile(selected[0]) as stream:
                    data = stream.read()
        executable = destination / (tool + '.exe')
        executable.write_bytes(data)
        records.append({'tool': tool, 'version': version, 'release_url': base + name,
                        'archive_sha256': actual, 'binary_sha256': hashlib.sha256(data).hexdigest()})
        print(f'{tool} {version}: checksum verified')
    (args.output / 'tools.lock.json').write_text(json.dumps(records, indent=2) + '\n', encoding='utf-8', newline='\n')


if __name__ == '__main__':
    main()
