"""Compare samples to pinned detector regexes, without network access.

This is a Python regex comparison, not a full Gitleaks execution (entropy,
allowlists and keyword prefilters are not evaluated).
"""
import json
import re
import argparse
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--dataset', type=Path, default=BASE / 'dataset')
parser.add_argument('--output', type=Path, default=BASE / 'research/pattern-results.json')
args = parser.parse_args()
catalog = json.loads((BASE / 'catalog/services.json').read_text(encoding='utf-8'))
manifest = json.loads((args.dataset / 'manifest.json').read_text(encoding='utf-8'))
active_ids = {sample.get('format_id', sample['service']) for sample in manifest['samples']}
snapshot = manifest.get('formats', catalog)
active_catalog = [spec for spec in snapshot if spec['id'] in active_ids]
if not active_ids or len(active_catalog) != len(active_ids):
    raise ValueError('Incomplete dataset format definitions')
results = []
for spec in active_catalog:
    samples = [s for s in manifest['samples'] if s.get('format_id', s['service']) == spec['id']]
    regex = spec.get('detector_regex')
    matched = None
    if regex:
        flags = re.I if '(?i)' in regex else 0
        pattern = re.compile(regex.replace('(?i)', ''), flags)
        matched = sum(bool(pattern.search((args.dataset / s['path']).read_text(encoding='utf-8'))) for s in samples)
        if matched != len(samples):
            raise ValueError(f"Pattern mismatch: {spec['id']}: {matched}/{len(samples)}")
    results.append({'format': spec['id'], 'samples': len(samples), 'regex_matches': matched})
report = {'method': __doc__, 'results': results, 'dataset_formats': len(active_catalog),
          'current_catalog_formats': len(catalog), 'catalog_formats_not_in_dataset': len(set(s['id'] for s in catalog) - active_ids)}
args.output.parent.mkdir(parents=True, exist_ok=True)
args.output.write_text(json.dumps(report, indent=2)+'\n', encoding='utf-8', newline='\n')
print(f'Checked {len(results)} populated formats; {report["catalog_formats_not_in_dataset"]} current catalog formats are not in this dataset.')
