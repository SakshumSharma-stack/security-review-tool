"""
Run every snippet in GOLDEN_TEST_SET against the live /scan endpoint and
report PASS / FAIL based on whether the expected_rule_id appears in the
returned vulnerabilities.

Usage (from the project root):
    python examples/run_golden_tests.py

Requirements:
    - API_KEY set in the project .env file
    - requests  (pip install requests)
    - python-dotenv  (pip install python-dotenv)
"""

import os
import sys
import time

import requests
from dotenv import load_dotenv

# ── Path setup ────────────────────────────────────────────────────────────────
# Allow `from golden_test_set import ...` regardless of cwd
sys.path.insert(0, os.path.dirname(__file__))
from golden_test_set import GOLDEN_TEST_SET  # noqa: E402

# ── Config ────────────────────────────────────────────────────────────────────
load_dotenv()

API_URL = "https://security-review-sakshum.lemonriver-d0f61589.eastus.azurecontainerapps.io"
API_KEY = os.environ.get("API_KEY", "")
TIMEOUT = 180  # seconds — each scan can take up to 2 min for the full pipeline

# ── Helpers ───────────────────────────────────────────────────────────────────

def _rule_ids(vulnerabilities: list) -> list[str]:
    return [v.get("rule_id", "") for v in vulnerabilities]


def _scan(code: str) -> tuple[list, str | None]:
    """POST code to /scan. Returns (vulnerabilities, error_message)."""
    try:
        resp = requests.post(
            f"{API_URL}/scan",
            json={"code": code, "language": "python"},
            headers={"X-API-Key": API_KEY, "Content-Type": "application/json"},
            timeout=TIMEOUT,
        )
    except requests.exceptions.Timeout:
        return [], "Request timed out"
    except requests.exceptions.RequestException as e:
        return [], f"Network error: {e}"

    if resp.status_code == 401:
        return [], "401 Unauthorized — check API_KEY in .env"
    if resp.status_code == 429:
        return [], "429 Rate limited — wait before retrying"
    if not resp.ok:
        return [], f"HTTP {resp.status_code}: {resp.text[:120]}"

    try:
        data = resp.json()
    except Exception as e:
        return [], f"Invalid JSON response: {e}"

    return data.get("vulnerabilities", []), None


# ── Runner ────────────────────────────────────────────────────────────────────

def run_all() -> None:
    if not API_KEY:
        print("ERROR: API_KEY not set in .env — cannot authenticate.")
        sys.exit(1)

    total   = len(GOLDEN_TEST_SET)
    passed  = 0
    failed  = 0
    errored = 0

    print("=" * 70)
    print(f"  SecureGuard Golden Test Suite  —  {total} tests")
    print(f"  Endpoint: {API_URL}")
    print("=" * 70)

    for i, (name, entry) in enumerate(GOLDEN_TEST_SET.items(), start=1):
        expected = entry["expected_rule_id"]
        severity = entry["expected_severity"]

        print(f"\n[{i:02d}/{total}] {name}")
        print(f"       expect  rule={expected}  severity={severity}")

        start = time.time()
        vulns, error = _scan(entry["code"])
        elapsed = time.time() - start

        if error:
            errored += 1
            print(f"       ERROR   {error}")
            print(f"       RESULT  ✗ ERROR  ({elapsed:.1f}s)")
            continue

        actual_ids = _rule_ids(vulns)
        hit = expected in actual_ids

        if hit:
            passed += 1
            status = "✓ PASS"
        else:
            failed += 1
            status = "✗ FAIL"

        actual_display = ", ".join(actual_ids) if actual_ids else "(none)"
        print(f"       actual  rule_ids returned: {actual_display}")
        print(f"       RESULT  {status}  ({elapsed:.1f}s)")

        if not hit:
            print(f"       NOTE    expected '{expected}' not found in results")

    # ── Summary ───────────────────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print(f"  SUMMARY:  {passed}/{total} passed  |  {failed} failed  |  {errored} errors")

    if failed == 0 and errored == 0:
        print("  All tests passed.")
    else:
        if failed:
            print(f"  {failed} test(s) did not return the expected rule_id.")
        if errored:
            print(f"  {errored} test(s) could not be executed (network / auth errors).")
    print("=" * 70)

    sys.exit(0 if (failed == 0 and errored == 0) else 1)


if __name__ == "__main__":
    run_all()
