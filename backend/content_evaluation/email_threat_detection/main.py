"""Package entry point for email_threat_detection.

Delegates execution to the main runner.
"""

from pathlib import Path
import sys

# Ensure parent directory is in path
parent_dir = Path(__file__).resolve().parent.parent
if str(parent_dir) not in sys.path:
    sys.path.insert(0, str(parent_dir))

from main import run_single_sample, run_smoke_tests

if __name__ == "__main__":
    run_single_sample()
    if "--smoke-tests" in sys.argv or "--all" in sys.argv:
        run_smoke_tests()
