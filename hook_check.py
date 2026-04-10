#!/usr/bin/env python3
"""Hook wrapper: reads Claude Code PostToolUse JSON from stdin,
checks if the edited file is a .py in labs/, and runs check_scripts.py if so."""

import json
import os
import subprocess
import sys

LABS_DIR = os.path.dirname(os.path.abspath(__file__))

def main():
    try:
        data = json.load(sys.stdin)
    except Exception:
        sys.exit(0)

    file_path = data.get("tool_input", {}).get("file_path", "")
    # Normalise to forward slashes for comparison
    file_path = file_path.replace("\\", "/")

    labs_marker = "/labs/"
    if labs_marker not in file_path or not file_path.endswith(".py"):
        sys.exit(0)

    result = subprocess.run(
        [sys.executable, os.path.join(LABS_DIR, "check_scripts.py")],
        cwd=LABS_DIR,
    )
    sys.exit(result.returncode)

if __name__ == "__main__":
    main()
