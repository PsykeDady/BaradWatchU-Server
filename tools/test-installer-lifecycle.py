#!/usr/bin/env python3
"""Linux process lifecycle tests; temporary prefixes only, no installation/sudo."""
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import unittest

INSTALLER = Path(__file__).resolve().parents[1] / "install.sh"
SOURCE = INSTALLER.read_text()
HELPERS = SOURCE[SOURCE.index("STOP_TIMEOUT=${"):SOURCE.index("print_options()")]


class Lifecycle(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="bwu-installer-lifecycle-")
        self.prefix = Path(self.tmp.name) / "prefix with spaces"
        self.other = Path(self.tmp.name) / "other"
        self.processes = []
        for directory in (self.prefix, self.other):
            (directory / "bin").mkdir(parents=True)
            shutil.copy2("/usr/bin/sleep", directory / "bin/baradwatchu-server")

    def tearDown(self):
        for process in self.processes:
            if process.poll() is None:
                process.kill()
            process.wait()
        self.tmp.cleanup()

    def launch(self, prefix, ignore=False):
        process = subprocess.Popen(
            [str(prefix / "bin/baradwatchu-server"), "30"],
            preexec_fn=(lambda: signal.signal(signal.SIGTERM, signal.SIG_IGN)) if ignore else None,
        )
        self.processes.append(process)
        return process

    def shell(self, operation):
        env = dict(os.environ, BARADWATCHU_STOP_TIMEOUT="1")
        env.pop("SUDO_USER", None)
        return subprocess.run(
            ["bash", "-c", 'set -Eeuo pipefail\nBIN=baradwatchu-server\nPREFIX=$1\nDRY=1\n'
             'fail() { echo "$*" >&2; exit 1; }\n'
             'option() { printf "%s %s\\n" "$1" "$2"; }\n'
             + HELPERS + "\n" + operation, "test", str(self.prefix)],
            env=env, capture_output=True, text=True, timeout=5,
        )

    def test_exact_prefix_only(self):
        ours = self.launch(self.prefix)
        other = self.launch(self.other)
        result = self.shell("stop_running_instances")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(ours.wait(timeout=2), -signal.SIGTERM)
        self.assertIsNone(other.poll())

    def test_timeout_does_not_kill_or_continue(self):
        ours = self.launch(self.prefix, ignore=True)
        result = self.shell('stop_running_instances; echo FILE_WRITES_ALLOWED')
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("did not exit", result.stderr)
        self.assertNotIn("FILE_WRITES_ALLOWED", result.stdout)
        self.assertIsNone(ours.poll())

    def test_plan_is_read_only(self):
        ours = self.launch(self.prefix)
        result = self.shell("describe_instances")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("would be closed", result.stdout)
        self.assertIsNone(ours.poll())

    def test_foreign_owner_is_preserved(self):
        ours = self.launch(self.prefix)
        result = self.shell('REAL_UID=999999; stop_running_instances')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("other users", result.stderr)
        self.assertIsNone(ours.poll())

    def test_no_instances(self):
        self.assertEqual(self.shell("stop_running_instances").returncode, 0)

    def test_install_and_uninstall_stop_after_preflight(self):
        install = SOURCE[SOURCE.index("install_source() {"):SOURCE.index("while (($#))")]
        self.assertLess(install.index('echo "Staged'), install.index("stop_running_instances"))
        self.assertLess(install.index("stop_running_instances"), install.index('for i in "${!files[@]}"'))
        uninstall = SOURCE[SOURCE.index("uninstall() {"):SOURCE.index("install_source() {")]
        self.assertIn('done < <(tail -n +5 "$manifest")\n    ((DRY)) || stop_running_instances', uninstall)


if __name__ == "__main__":
    unittest.main(verbosity=2)
