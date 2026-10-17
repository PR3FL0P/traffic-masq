#!/usr/bin/env python3
"""Exercise the update wrapper with isolated binaries; never touch host services."""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parent.parent / "update.sh"


class UpdateTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="traffic-masq update ")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.build = self.root / "new binaries"
        self.prefix = self.root / "installed prefix"
        self.config = self.root / "saved config.toml"
        self.config.write_text("saved configuration sentinel\n")
        self.log = self.root / "calls.jsonl"
        self.fake_commands = self.root / "commands"
        self.fake_commands.mkdir()
        identity = self.fake_commands / "id"
        identity.write_text("#!/bin/sh\nprintf '0\\n'\n")
        identity.chmod(0o755)
        self.make_binary(self.build / "traffic-masqd", "new")
        self.make_binary(self.build / "traffic-masq", "tui")
        self.make_binary(self.prefix / "sbin/traffic-masqd", "old")
        self.environment = {
            **os.environ,
            "PATH": f"{self.fake_commands}:{os.environ['PATH']}",
            "UPDATE_TEST_LOG": str(self.log),
        }
        for name in ("DESTDIR", "BINARY_DIR", "PREFIX", "TRAFFIC_MASQ_CONFIG", "UPDATE_TEST_FAIL"):
            self.environment.pop(name, None)

    def make_binary(self, path, role):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            "#!/usr/bin/env python3\n"
            "import json, os, sys\n"
            f"role = {role!r}\n"
            "with open(os.environ['UPDATE_TEST_LOG'], 'a') as log:\n"
            "    log.write(json.dumps([role, *sys.argv[1:]]) + '\\n')\n"
            "operation = sys.argv[-1] if sys.argv[-1] in ('validate', 'stop') else "
            "('install' if 'install' in sys.argv else 'help')\n"
            "sys.exit(17 if os.environ.get('UPDATE_TEST_FAIL') == role + ':' + operation else 0)\n"
        )
        path.chmod(0o755)

    def run_update(self, *options, defaults=False):
        arguments = [] if defaults else [
            "--binary-dir", str(self.build),
            "--prefix", str(self.prefix),
            "--config", str(self.config),
        ]
        return subprocess.run(
            ["sh", str(SCRIPT), *arguments, *options],
            env=self.environment, text=True, capture_output=True, check=False,
            cwd=self.root,
        )

    def calls(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []

    def test_update_validates_before_stop_and_preserves_installer_options(self):
        result = self.run_update()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.calls(), [
            ["new", "--help"],
            ["tui", "--help"],
            ["new", "--config", str(self.config), "config", "validate"],
            ["old", "--config", str(self.config), "stop"],
            ["new", "--config", str(self.config), "install", "--non-interactive",
             "--skip-user-access", "--defer-password", "--prefix", str(self.prefix),
             "--init-system", "auto", "--start"],
        ])
        self.assertEqual(self.config.read_text(), "saved configuration sentinel\n")

    def test_dry_run_never_stops_or_installs(self):
        result = self.run_update("--dry-run")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(self.calls()), 3)
        self.assertIn("Dry run", result.stdout)

    def test_no_start(self):
        result = self.run_update("--no-start")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("--start", self.calls()[-1])

    def test_environment_defaults(self):
        self.environment.update(BINARY_DIR=str(self.build), PREFIX=str(self.prefix),
                                TRAFFIC_MASQ_CONFIG=str(self.config))
        result = self.run_update(defaults=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.calls()[-1][-5:], ["--prefix", str(self.prefix), "--init-system", "auto", "--start"])

    def test_preflight_failures_do_not_stop_the_daemon(self):
        for failure in ("new:help", "tui:help", "new:validate"):
            with self.subTest(failure=failure):
                self.environment["UPDATE_TEST_FAIL"] = failure
                self.log.unlink(missing_ok=True)
                result = self.run_update()
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(any(call[0] == "old" or "install" in call for call in self.calls()))

    def test_invalid_arguments_do_not_execute_binaries(self):
        for options in (("--unknown",), ("--config",), ("--prefix", "relative"),
                        ("--prefix", "/opt/../usr"), ("--config", str(self.root / "missing"))):
            with self.subTest(options=options):
                result = self.run_update(*options)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.calls(), [])

    def test_missing_or_symlinked_binary_does_not_stop_daemon(self):
        tui = self.build / "traffic-masq"
        tui.unlink()
        for symlink in (False, True):
            with self.subTest(symlink=symlink):
                if symlink:
                    tui.symlink_to(self.build / "traffic-masqd")
                result = self.run_update()
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(any(call[0] == "old" for call in self.calls()))

    def test_stop_failure_prevents_installation(self):
        self.environment["UPDATE_TEST_FAIL"] = "old:stop"
        result = self.run_update()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any("install" in call for call in self.calls()))

    def test_install_failure_reports_partial_update(self):
        self.environment["UPDATE_TEST_FAIL"] = "new:install"
        result = self.run_update()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Installation may be partial", result.stderr)
        self.assertEqual(len(self.calls()), 5)


if __name__ == "__main__":
    unittest.main()
