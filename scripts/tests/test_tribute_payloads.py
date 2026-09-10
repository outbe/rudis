import argparse
import ast
import json
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
PRODUCERS = (
    REPO_ROOT / "scripts" / "tribute_offer.py",
    REPO_ROOT / "scripts" / "tributefactory" / "offer_tribute.py",
)
CASES = json.loads(
    (REPO_ROOT / "testdata" / "tribute" / "canonical-amounts-v1.json").read_text()
)


def load_pure_function(path: Path, name: str):
    tree = ast.parse(path.read_text(), filename=str(path))
    function = next(
        (node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == name),
        None,
    )
    if function is None:
        raise AssertionError(f"{path.relative_to(REPO_ROOT)} does not define {name}")
    module = ast.Module(body=[function], type_ignores=[])
    namespace = {"argparse": argparse}
    exec(compile(module, str(path), "exec"), namespace)
    return namespace[name], tree, function


class TributePayloadProducerTests(unittest.TestCase):
    def test_every_operational_producer_enforces_the_canonical_u64_base(self) -> None:
        for path in PRODUCERS:
            with self.subTest(path=path.relative_to(REPO_ROOT)):
                canonical, tree, definition = load_pure_function(path, "canonical_amount_base")
                for value in CASES["accepted_base"]:
                    self.assertEqual(canonical(value), value)
                for value in CASES["rejected_base"]:
                    with self.assertRaises((ValueError, argparse.ArgumentTypeError)):
                        canonical(value)

                calls = [
                    node
                    for node in ast.walk(tree)
                    if isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name)
                    and node.func.id == "canonical_amount_base"
                    and not (definition.lineno <= node.lineno <= definition.end_lineno)
                ]
                self.assertTrue(calls, "payload producer defines canonicalization but never uses it")


if __name__ == "__main__":
    unittest.main()
