"""Runs the SIMULATED extension unit tests (tests/extension/*.test.js) with Node's built-in test runner.

They load the real extension/background.js with a fake chrome API (tests/extension/harness.js), so they
check the worker's logic, not Chrome itself; the real-browser tests are in tests/browser/. Skipped when
Node.js is not installed.
"""
import re
import shutil
import subprocess
from pathlib import Path

import pytest

TESTS = Path(__file__).resolve().parent / "extension"
NODE = shutil.which("node")


@pytest.mark.skipif(NODE is None, reason="Node.js not installed")
def test_background_worker_logic_simulated():
    proc = subprocess.run([NODE, "--test", *sorted(str(p) for p in TESTS.glob("*.test.js"))],
                          capture_output=True, text=True, timeout=120)
    output = proc.stdout + proc.stderr
    summary = dict(re.findall(r"^ℹ (tests|pass|fail|skipped) (\d+)$", output, re.M))
    assert proc.returncode == 0, output[-4000:]
    assert int(summary.get("tests", 0)) >= 40 and summary.get("fail") == "0", output[-2000:]
    assert summary.get("skipped", "0") == "0"
