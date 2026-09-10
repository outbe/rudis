"""Behavioral tests for per-node configuration creation and preservation."""
import importlib.util
from pathlib import Path
import tempfile
import tomllib
import unittest

SPEC = importlib.util.spec_from_file_location("offchain_storage", Path(__file__).parents[1] / "offchain_storage.py")
STORAGE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(STORAGE)


class StorageConfigTests(unittest.TestCase):
    def test_new_node_defaults_to_local_rocksdb(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "validator-0/offchain-storage.toml"
            document = STORAGE.settings({}, database="db", mongo_uri="mongodb://localhost")
            STORAGE.ensure(path, document)
            self.assertEqual(STORAGE.load(path), document)
            self.assertEqual(document["backend"], "rocksdb")
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertFalse(Path(document["rocksdb"]["path"]).is_absolute())

    def test_restart_keeps_exact_operator_file_and_backend(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "offchain-storage.toml"
            original = '# operator settings\nversion = 1\nbackend = "mongodb"\n[mongodb]\nuri = "mongodb://operator:secret@localhost"\ndatabase = "existing"\n'
            path.write_text(original)
            chosen = STORAGE.ensure(path, STORAGE.settings({}, database="new", mongo_uri="new"))
            self.assertEqual(chosen["backend"], "mongodb")
            self.assertEqual(path.read_text(), original)

    def test_invalid_existing_file_fails_without_replacement_or_secret_diagnostic(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "offchain-storage.toml"
            for source in [
                'version=1\nbackend="mongodb"\n[mongodb]\nuri="mongodb://secret"\n',
                'version=true\nbackend="rocksdb"\n[rocksdb]\npath="a"\nsecondary_path="b"\n',
                'version=1\nbackend="rocksdb"\nunknown="secret"\n[rocksdb]\npath="a"\nsecondary_path="b"\n',
                'version=1\nbackend="mongodb"\n[mongodb]\nuri=secret\n',
            ]:
                with self.subTest(source=source):
                    path.write_text(source)
                    with self.assertRaises(ValueError) as error:
                        STORAGE.ensure(path, STORAGE.settings({}, database="new", mongo_uri="new"))
                    self.assertNotIn("secret", str(error.exception))
                    self.assertEqual(path.read_text(), source)

    def test_config_roundtrips_unicode_and_quotes(self):
        document = STORAGE.settings({"offchain_storage": {"rocksdb": {"path": 'данные/"rocks"', "secondary_path": "читатель/😀"}}}, database="db", mongo_uri="uri")
        self.assertEqual(tomllib.loads(STORAGE.render(document)), document)

    def test_backends_cannot_be_mixed(self):
        with self.assertRaises(ValueError):
            STORAGE.settings({"offchain_storage": {"backend": "mongodb", "rocksdb": {}}}, database="db", mongo_uri="uri")
