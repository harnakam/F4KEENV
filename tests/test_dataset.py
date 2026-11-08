import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
module_spec = importlib.util.spec_from_file_location('dataset', BASE / 'scripts/generate_dataset.py')
dataset = importlib.util.module_from_spec(module_spec)
module_spec.loader.exec_module(dataset)
CATALOG = json.loads((BASE / 'catalog/services.json').read_text())


class DatasetTests(unittest.TestCase):
    def test_generation_integrity_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / 'samples'
            self.assertEqual(dataset.generate(root, CATALOG, 2), 2 * len(CATALOG))
            before = (root / 'manifest.json').read_bytes()
            with self.assertRaises(ValueError):
                dataset.generate(root, CATALOG, 2)
            self.assertEqual(before, (root / 'manifest.json').read_bytes())
            manifest = json.loads(before)
            self.assertEqual(manifest['service_count'], len({s['service'] for s in CATALOG}))
            self.assertEqual(manifest['format_count'], len(CATALOG))
            by_id = {spec['id']: spec for spec in CATALOG}
            self.assertTrue(all(sample['service'] == by_id[sample['format_id']]['service'] for sample in manifest['samples']))
            sample = root / manifest['samples'][0]['path']
            sample.write_text('GITHUB_PAT=broken\n')
            with self.assertRaises(ValueError):
                dataset.validate(root, CATALOG)

    def test_manifest_path_cannot_escape(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / 'samples'
            dataset.generate(root, CATALOG, 1)
            path = root / 'manifest.json'
            data = json.loads(path.read_text())
            data['samples'][0]['path'] = '../outside.env'
            path.write_text(json.dumps(data))
            with self.assertRaises(ValueError):
                dataset.validate(root, CATALOG)

    def test_extra_files_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / 'samples'
            dataset.generate(root, CATALOG, 1)
            (root / '.env').write_text('EXTRA=value\n')
            with self.assertRaises(ValueError):
                dataset.validate(root, CATALOG)


if __name__ == '__main__':
    unittest.main()
