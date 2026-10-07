#!/usr/bin/env python3
"""Reject cache evidence that could hide local reuse or changed outputs."""

import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import verify_cache as proof


def record(hit=False, runner="local"):
    return {"mnemonic": "SonicKernelBuild", "exitCode": 0, "status": "", "cacheable": True,
            "remoteCacheable": True, "cacheHit": hit, "runner": runner,
            "inputs": [{"path": "config", "digest": {"hash": "same"}}]}


class CacheProofTest(unittest.TestCase):
    def test_reads_concatenated_bazel_json_records(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "execution.json"
            path.write_text(json.dumps({"mnemonic": "Other"}) + "\n" + json.dumps(record()))
            self.assertEqual(proof.kernel_record(path.parent), record())

    def test_rejects_ambiguous_or_failed_kernel_actions(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "execution.json"
            for entries in ([], [record(), record()], [dict(record(), exitCode=1)]):
                path.write_text("\n".join(json.dumps(entry) for entry in entries))
                with self.assertRaises(ValueError):
                    proof.kernel_record(path.parent)

    def test_rejects_local_hits_and_changed_action_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cold, hit = root / "cold", root / "hit"
            for second in (record(True, "disk cache hit"), record(False),
                           dict(record(True, "remote cache hit"), inputs=[{"path": "changed"}])):
                with patch.object(proof, "kernel_record", side_effect=[record(), second]):
                    with self.assertRaises(ValueError):
                        proof.verify(cold, hit, root / "evidence")

    def test_rejects_reusing_one_output_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaisesRegex(ValueError, "distinct"):
                proof.verify(root, root, root / "evidence")

    def test_rejects_output_paths_outside_owned_work_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for output in ("/outside/package.deb", "/work/../escape.deb"):
                (root / "output-paths.txt").write_text(output + "\n")
                with self.assertRaises(ValueError):
                    proof.outputs(root)


    def test_cli_omits_arbitrary_execution_fields(self):
        sentinel = "SENSITIVE_FIXTURE_DO_NOT_PUBLISH"
        receipt = {"result": "passed", "cold_compiled": True, "consumer_kernel_cache_hit": True,
                   "kernel_compilation_skipped": True, "outputs_sha256": {sentinel: "digest"},
                   "cold_metrics": {"environment": sentinel}, "hit_metrics": {"diagnostic": sentinel}}
        output = io.StringIO()
        with patch.object(proof, "verify", return_value=receipt), \
                patch.object(sys, "argv", ["verify", "--cold", "/tmp/cold", "--hit", "/tmp/hit", "--artifacts", "/tmp/artifacts"]), \
                contextlib.redirect_stdout(output):
            proof.main()
        self.assertNotIn(sentinel, output.getvalue())
        self.assertEqual(json.loads(output.getvalue()), {
            "result": "passed", "cold_compiled": True, "consumer_kernel_cache_hit": True,
            "kernel_compilation_skipped": True, "verified_output_count": 1,
        })


if __name__ == "__main__":
    unittest.main()
