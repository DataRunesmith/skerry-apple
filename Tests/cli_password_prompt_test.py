"""Run after `swift build`: python3 Tests/cli_password_prompt_test.py."""

import fcntl
import os
from pathlib import Path
import pty
import select
import signal
import subprocess
import tempfile
import termios
import time
import unittest

CLI = Path(__file__).resolve().parents[1] / ".build/debug/skerry-cli"


class PasswordPromptTests(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.TemporaryDirectory()
        self.addCleanup(self.home.cleanup)
        self.env = os.environ.copy()
        for name in ("SKERRY_PASSWORD", "SKERRY_KEY_FILE", "SKERRY_ED25519_HEX"):
            self.env.pop(name, None)
        self.env["HOME"] = self.home.name
        self.args = [str(CLI), "test@127.0.0.1:1", "true"]

    def start_terminal(self, echo=True):
        master, slave = pty.openpty()
        self.addCleanup(os.close, master)
        self.addCleanup(os.close, slave)
        settings = termios.tcgetattr(slave)
        if echo:
            settings[3] |= termios.ECHO | termios.ECHONL
        else:
            settings[3] &= ~(termios.ECHO | termios.ECHONL)
        termios.tcsetattr(slave, termios.TCSANOW, settings)
        original = termios.tcgetattr(slave)
        flags = fcntl.fcntl(slave, fcntl.F_GETFL)
        # Own process group under this process, so job-control stops are not
        # discarded as they would be in an orphaned group (e.g. under PID 1).
        proc = subprocess.Popen(self.args, stdin=slave, stdout=slave, stderr=slave, env=self.env,
                                process_group=0)
        self.addCleanup(self.stop, proc)
        output = self.read_until(master, b"127.0.0.1: ")
        self.assertEqual(termios.tcgetattr(slave)[3] & (termios.ECHO | termios.ECHONL), 0)
        return proc, master, slave, original, flags, output

    @staticmethod
    def stop(proc):
        if proc.poll() is None:
            proc.kill()
            proc.wait()

    def read_until(self, fd, marker):
        output = b""
        deadline = time.monotonic() + 10
        while marker not in output and time.monotonic() < deadline:
            if select.select([fd], [], [], 0.1)[0]:
                output += os.read(fd, 4096)
        self.assertIn(marker, output)
        return output

    def check_restored(self, slave, original, flags):
        self.assertEqual(termios.tcgetattr(slave), original)
        self.assertEqual(fcntl.fcntl(slave, fcntl.F_GETFL), flags)

    def test_terminal_input_is_hidden_and_settings_restored(self):
        for echo in (True, False):
            with self.subTest(echo=echo):
                proc, master, slave, original, flags, output = self.start_terminal(echo)
                sample = b"fixture-input-123"
                os.write(master, sample + b"\n")
                output += self.read_until(master, b"\n")
                proc.wait(timeout=10)
                self.assertNotIn(sample, output)
                self.check_restored(slave, original, flags)

    def test_eof_restores_settings(self):
        proc, master, slave, original, flags, _ = self.start_terminal()
        os.write(master, b"\x04")
        self.assertEqual(proc.wait(timeout=10), 2)
        self.check_restored(slave, original, flags)

    def test_interrupt_restores_settings(self):
        for sig in (signal.SIGINT, signal.SIGTERM):
            with self.subTest(signal=sig):
                proc, master, slave, original, flags, _ = self.start_terminal()
                os.write(master, b"fixture-input")
                proc.send_signal(sig)
                self.assertEqual(proc.wait(timeout=10), -sig)
                self.check_restored(slave, original, flags)

    def test_stop_and_resume_keeps_reading(self):
        proc, master, slave, original, flags, _ = self.start_terminal()
        proc.send_signal(signal.SIGTSTP)
        deadline = time.monotonic() + 10
        status = 0
        while time.monotonic() < deadline:
            pid, status = os.waitpid(proc.pid, os.WUNTRACED | os.WNOHANG)
            if pid:
                break
            time.sleep(0.05)
        self.assertTrue(os.WIFSTOPPED(status))
        # The terminal shows input again while the job is stopped.
        self.assertEqual(termios.tcgetattr(slave)[3], original[3])
        proc.send_signal(signal.SIGCONT)
        output = self.read_until(master, b"127.0.0.1: ")
        self.assertEqual(termios.tcgetattr(slave)[3] & (termios.ECHO | termios.ECHONL), 0)
        sample = b"fixture-input-456"
        os.write(master, sample + b"\n")
        proc.wait(timeout=10)
        output += self.read_until(master, b"Fel:")
        self.assertNotIn(sample, output)
        self.assertNotIn("Kunde inte läsa lösenordet".encode(), output)
        self.check_restored(slave, original, flags)

    def test_empty_pipe_input_is_rejected(self):
        proc = subprocess.run(self.args, input=b"", stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, env=self.env, timeout=10)
        self.assertIn("Kunde inte läsa lösenordet".encode(), proc.stderr)
        self.assertEqual(proc.returncode, 2)

    def test_pipe_input_still_reaches_connection(self):
        proc = subprocess.run(self.args, input=b"fixture-input\n", stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, env=self.env, timeout=10)
        self.assertNotIn(b"fixture-input", proc.stdout + proc.stderr)
        self.assertIn(b"Fel:", proc.stderr)
        self.assertNotIn("Kunde inte läsa lösenordet".encode(), proc.stderr)
        self.assertNotEqual(proc.returncode, 0)


if __name__ == "__main__":
    unittest.main()
