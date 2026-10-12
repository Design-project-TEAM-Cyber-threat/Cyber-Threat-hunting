"""
Runs every framework-free test (Steps 1-7 core). Works from any folder, e.g.:  python run_all_tests.py
The Django API tests are separate:  cd backend  &&  python manage.py test
"""
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONPATH=str(ROOT))
failed = []
for test in sorted((ROOT / "tests").glob("test_*.py")):
    r = subprocess.run([sys.executable, str(test)], cwd=ROOT, env=env, capture_output=True, text=True)
    ok = r.returncode == 0
    last = (r.stdout.strip().splitlines() or [""])[-1]
    print(f"{'PASS' if ok else 'FAIL'}  {test.name:26s} {last if ok else ''}")
    if not ok:
        failed.append(test.name)
        print(r.stdout[-1500:], r.stderr[-1500:])
print("\nAll framework-free tests passed." if not failed else f"\nFAILED: {failed}")
print("Next: cd backend  &&  python manage.py test")
sys.exit(1 if failed else 0)
