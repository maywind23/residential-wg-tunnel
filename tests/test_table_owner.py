import importlib.util
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location(
    "residential_wg_tunnel", Path(__file__).resolve().parents[1] / "residential-wg-tunnel.py"
)
tunnel = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tunnel)


class TableOwnerTests(unittest.TestCase):
    name = "rwg_64656661756c74"
    owner = "residential-wg-tunnel:default"

    def listing(self, **keys):
        table = {"family": "inet", "name": self.name, **keys}
        return subprocess.CompletedProcess([], 0, json.dumps({"nftables": [{"table": table}]}))

    def test_uses_comment_in_modern_json(self):
        with patch.object(tunnel, "cmd", return_value=self.listing(comment=self.owner)) as run:
            self.assertEqual(tunnel.table_owner(self.name), self.owner)
        run.assert_called_once()

    def test_recovers_legacy_comment_from_text(self):
        text = f'table inet {self.name} {{\n\tcomment "{self.owner}"\n\tchain input {{\n\t}}\n}}\n'
        with patch.object(tunnel, "cmd", side_effect=[self.listing(), subprocess.CompletedProcess([], 0, text)]):
            self.assertEqual(tunnel.table_owner(self.name), self.owner)

    def test_ignores_a_chain_comment(self):
        text = f'table inet {self.name} {{\n\tchain input {{\n\t\tcomment "{self.owner}"\n\t}}\n}}\n'
        with patch.object(tunnel, "cmd", side_effect=[self.listing(), subprocess.CompletedProcess([], 0, text)]):
            self.assertEqual(tunnel.table_owner(self.name), "")

    def test_missing_table(self):
        with patch.object(tunnel, "cmd", return_value=subprocess.CompletedProcess([], 1, "")):
            self.assertIsNone(tunnel.table_owner(self.name))
