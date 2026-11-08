"""Compare samples to pinned detector regexes, without network access.

This is a Python regex comparison, not a full Gitleaks execution (entropy,
allowlists and keyword prefilters are not evaluated).
"""
import json
import re
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
catalog = json.loads((BASE / 'catalog/services.json').read_text())
manifest = json.loads((BASE / 'dataset/manifest.json').read_text())
results = []
for spec in catalog:
    samples = [s for s in manifest['samples'] if s['service'] == spec['id']]
    regex = spec.get('detector_regex')
    matched = None
    if regex:
        flags = re.I if '(?i)' in regex else 0
        pattern = re.compile(regex.replace('(?i)', ''), flags)
        matched = sum(bool(pattern.search((BASE / 'dataset' / s['path']).read_text())) for s in samples)
        if matched != len(samples):
            raise ValueError(f"Pattern mismatch: {spec['id']}: {matched}/{len(samples)}")
    results.append({'format': spec['id'], 'samples': len(samples), 'regex_matches': matched})
report = {'method': __doc__, 'results': results}
(BASE / 'research/pattern-results.json').write_text(json.dumps(report, indent=2)+'\n', encoding='utf-8', newline='\n')
print(f'Checked {len(results)} formats; Hypixel has no mapped detector rule.')
