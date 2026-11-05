#!/usr/bin/env python3
"""Check dispatch/run matching without GitHub access or repository mutations."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parent.parent / "gitcompile.sh"


class GitcompileTests(unittest.TestCase):
    def run_compile(self, never_register=False):
        with tempfile.TemporaryDirectory(prefix="traffic-masq gitcompile ") as directory:
            root = Path(directory)
            shutil.copy2(SCRIPT, root / "gitcompile.sh")
            commands = root / "commands"
            commands.mkdir()
            log = root / "calls.jsonl"
            fake = commands / "fake"
            fake.write_text('''#!/usr/bin/env python3
import json, os, pathlib, sys
command = pathlib.Path(sys.argv[0]).name
args = sys.argv[1:]
root = pathlib.Path(os.environ["COMPILE_TEST_ROOT"])
with (root / "calls.jsonl").open("a") as log:
    log.write(json.dumps([command, *args]) + "\\n")
if command == "git":
    if args[:2] == ["symbolic-ref", "--short"]:
        print("main")
    elif args == ["rev-parse", "HEAD"]:
        print("a" * 40)
elif command == "gh":
    if args[:2] == ["run", "list"]:
        if "--branch" not in args:
            print("200")
        else:
            count_path = root / "polls"
            count = int(count_path.read_text()) if count_path.exists() else 0
            count_path.write_text(str(count + 1))
            print("100" if count == 0 or os.environ["COMPILE_TEST_NEVER"] == "1" else "201")
    elif args[:2] == ["run", "view"]:
        print("https://example.invalid/runs/201")
''')
            fake.chmod(0o755)
            for name in ("git", "gh", "sleep"):
                (commands / name).symlink_to(fake)
            result = subprocess.run(
                ["bash", str(root / "gitcompile.sh"), "-n", "--test-only"],
                env={
                    **os.environ,
                    "PATH": f"{commands}:{os.environ['PATH']}",
                    "COMPILE_TEST_ROOT": str(root),
                    "COMPILE_TEST_NEVER": "1" if never_register else "0",
                },
                capture_output=True,
                text=True,
                timeout=30,
            )
            return result, [json.loads(line) for line in log.read_text().splitlines()]

    def test_waits_for_new_run_on_the_expected_commit(self):
        result, calls = self.run_compile()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        polls = [call for call in calls if call[:3] == ["gh", "run", "list"] and "--branch" in call]
        self.assertEqual(len(polls), 2)
        for call in polls:
            self.assertEqual(call[call.index("--commit") + 1], "a" * 40)
            self.assertEqual(call[call.index("--event") + 1], "workflow_dispatch")
        watches = [call for call in calls if call[:3] == ["gh", "run", "watch"]]
        self.assertEqual(watches, [["gh", "run", "watch", "201", "--exit-status"]])

    def test_does_not_accept_old_success_when_registration_times_out(self):
        result, calls = self.run_compile(never_register=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Failed to detect newly queued workflow run", result.stdout + result.stderr)
        self.assertFalse(any(call[:3] == ["gh", "run", "watch"] for call in calls))
        self.assertIn(["git", "push", "origin", "--delete", "ci-temp-main"], calls)


if __name__ == "__main__":
    unittest.main()
