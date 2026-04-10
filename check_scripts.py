#!/usr/bin/env python3
"""
check_scripts.py — Run syntax checks and tests on all Python scripts in labs/.

Checks performed:
  1. py_compile on every .py file (catches syntax errors)
  2. pytest on every test_*.py file

Exit code 0 = all good, 1 = something failed.
"""

import os
import py_compile
import subprocess
import sys

LABS_DIR = os.path.dirname(os.path.abspath(__file__))


def find_py_files():
    return sorted(
        f for f in os.listdir(LABS_DIR)
        if f.endswith(".py") and not f.startswith("__")
    )


def check_syntax(files):
    print("=== Syntax check ===")
    failed = []
    for f in files:
        path = os.path.join(LABS_DIR, f)
        try:
            py_compile.compile(path, doraise=True)
            print(f"  OK  {f}")
        except py_compile.PyCompileError as e:
            print(f"  FAIL {f}: {e}")
            failed.append(f)
    return failed


def run_tests():
    test_files = [f for f in find_py_files() if f.startswith("test_")]
    if not test_files:
        print("\n=== No test files found, skipping ===")
        return []

    print(f"\n=== Running pytest ({len(test_files)} test file(s)) ===")
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "-v", "--tb=short"] + test_files,
        cwd=LABS_DIR,
    )
    return [] if result.returncode == 0 else ["pytest"]


def main():
    files = find_py_files()
    print(f"Found {len(files)} Python files in {LABS_DIR}\n")

    problems = []
    problems.extend(check_syntax(files))
    problems.extend(run_tests())

    print()
    if problems:
        print(f"FAILED — issues: {', '.join(problems)}")
        sys.exit(1)
    else:
        print("ALL CHECKS PASSED")


if __name__ == "__main__":
    main()
