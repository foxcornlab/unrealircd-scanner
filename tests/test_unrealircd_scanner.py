#!/usr/bin/env python3
"""Tests for unrealircd_scanner.py (CVE-2026-114713 triage).

Covers version parsing and grading, the fixed/hot-patch traps, module
evidence, exposure flags, local detection via a fake unrealircd script,
live probes against a mock IRC server (including the PING handshake and
the non-UnrealIRCd case), CLI exit codes, JSON output and inventory
grading.
"""

import io
import json
import os
import socket
import stat
import sys
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import unrealircd_scanner as scanner


class FakeIRCServer(threading.Thread):
    """Minimal IRC server: sends canned lines, answers nothing."""

    def __init__(self, lines, ping_first=False):
        super().__init__(daemon=True)
        self.lines = lines
        self.ping_first = ping_first
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.received = []
        self.pong_seen = False

    def run(self):
        self.sock.listen(1)
        conn, _ = self.sock.accept()
        conn.settimeout(5)
        try:
            if self.ping_first:
                conn.sendall(b"PING :abc123\r\n")
                data = conn.recv(4096)
                self.received.append(data)
                if b"PONG" in data:
                    self.pong_seen = True
            for line in self.lines:
                conn.sendall((line + "\r\n").encode())
            # Drain what the client sends (NICK/USER/QUIT) so the socket
            # does not RST before the client reads.
            try:
                while True:
                    data = conn.recv(4096)
                    if not data:
                        break
                    self.received.append(data)
            except socket.timeout:
                pass
        except OSError:
            pass
        finally:
            conn.close()
            self.sock.close()


def start_server(lines, ping_first=False):
    server = FakeIRCServer(lines, ping_first=ping_first)
    server.start()
    return server


class TestParseVersion(unittest.TestCase):
    def test_plain_release(self):
        version, kind, _ = scanner.parse_version("6.2.7")
        self.assertEqual((version, kind), ((6, 2, 7), "release"))

    def test_four_part_release(self):
        version, kind, _ = scanner.parse_version("6.2.7.1")
        self.assertEqual((version, kind), ((6, 2, 7, 1), "release"))

    def test_banner_token(self):
        version, kind, _ = scanner.parse_version("UnrealIRCd-6.2.7")
        self.assertEqual((version, kind), ((6, 2, 7), "release"))

    def test_bare_line_is_not_a_grade(self):
        version, kind, note = scanner.parse_version("6.2")
        self.assertEqual(kind, "line")
        self.assertIn("patch level", note)

    def test_prerelease(self):
        version, kind, _ = scanner.parse_version("6.2.7.1-rc1")
        self.assertEqual(kind, "prerelease")

    def test_garbage(self):
        version, kind, _ = scanner.parse_version("not a version")
        self.assertIsNone(version)
        self.assertIsNone(kind)


class TestGrade(unittest.TestCase):
    def check(self, raw):
        version, kind, _ = scanner.parse_version(raw)
        return scanner.grade(version, kind)

    def test_fixed_release(self):
        self.assertEqual(self.check("6.2.7.1")[0], "PATCHED")

    def test_later_release(self):
        self.assertEqual(self.check("6.2.8")[0], "PATCHED")
        self.assertEqual(self.check("6.3.0")[0], "PATCHED")

    def test_boundary_vulnerable(self):
        verdict, detail = self.check("6.2.7")
        self.assertEqual(verdict, "VULNERABLE")
        self.assertIn("6.2.7.1", detail)

    def test_oldest_affected(self):
        self.assertEqual(self.check("6.0.0")[0], "VULNERABLE")

    def test_five_x_no_fix(self):
        verdict, detail = self.check("5.2.1")
        self.assertEqual(verdict, "VULNERABLE")
        self.assertIn("no fix", detail)
        self.assertIn("2023-07-01", detail)

    def test_four_x_unknown_not_clean(self):
        verdict, detail = self.check("4.2.4")
        self.assertEqual(verdict, "UNKNOWN")
        self.assertIn("not checked", detail)

    def test_three_two_unknown_not_clean(self):
        self.assertEqual(self.check("3.2.10")[0], "UNKNOWN")

    def test_below_three_two_unknown(self):
        self.assertEqual(self.check("2.9.9")[0], "UNKNOWN")

    def test_bare_line_unknown(self):
        self.assertEqual(self.check("6.2")[0], "UNKNOWN")

    def test_prerelease_unknown(self):
        self.assertEqual(self.check("6.2.7.1-rc1")[0], "UNKNOWN")


class TestModuleStatus(unittest.TestCase):
    def test_hotpatch_is_patched(self):
        verdict, detail = scanner.grade_module_status(
            "5.0-hot-patch-bundle-20261107")
        self.assertEqual(verdict, "PATCHED")
        self.assertIn("hot-patch", detail)

    def test_fixed_module_version(self):
        self.assertEqual(
            scanner.grade_module_status("6.2.7.1")[0], "PATCHED")

    def test_plain_five_zero_is_unpatched(self):
        verdict, detail = scanner.grade_module_status("5.0")
        self.assertEqual(verdict, "VULNERABLE")
        self.assertIn("NOT applied", detail)

    def test_garbage_module_version(self):
        self.assertIsNone(scanner.grade_module_status("nonsense"))

    def test_module_absent_means_not_exposed(self):
        # module-status ran, labeled-response not listed: not loaded.
        result = scanner.scan_version(
            "6.2.7", "local", module_version=None, module_checked=True)
        self.assertEqual(result["verdict"], "NOT-EXPOSED")
        self.assertIn("not loaded", result["detail"])


class TestExposureFlags(unittest.TestCase):
    def test_single_server(self):
        result = scanner.scan_version("6.2.7", "x", single_server=True)
        self.assertEqual(result["verdict"], "NOT-EXPOSED")
        self.assertIn("no links", result["detail"])

    def test_no_labeled_response(self):
        result = scanner.scan_version("6.2.7", "x",
                                      no_labeled_response=True)
        self.assertEqual(result["verdict"], "NOT-EXPOSED")

    def test_flags_do_not_clear_patched(self):
        result = scanner.scan_version("6.2.7.1", "x", single_server=True)
        self.assertEqual(result["verdict"], "PATCHED")

    def test_flags_do_not_clear_unknown(self):
        result = scanner.scan_version("4.2.4", "x", single_server=True)
        self.assertEqual(result["verdict"], "UNKNOWN")


class TestProbeServer(unittest.TestCase):
    def test_vulnerable_banner(self):
        server = start_server([
            ":irc.test 001 nick :Welcome",
            ":irc.test 002 nick :Your host is irc.test",
            ":irc.test 004 nick irc.test UnrealIRCd-6.2.7 iow... :x",
        ])
        result = scanner.scan_server("127.0.0.1", server.port, False,
                                     "mock")
        server.join(timeout=5)
        self.assertEqual(result["verdict"], "VULNERABLE")
        self.assertEqual(result["version"], "6.2.7")

    def test_patched_banner(self):
        server = start_server([
            ":irc.test 001 nick :Welcome",
            ":irc.test 004 nick irc.test UnrealIRCd-6.2.7.1 iow... :x",
        ])
        result = scanner.scan_server("127.0.0.1", server.port, False,
                                     "mock")
        server.join(timeout=5)
        self.assertEqual(result["verdict"], "PATCHED")

    def test_ping_answered_before_welcome(self):
        server = start_server([
            ":irc.test 001 nick :Welcome",
            ":irc.test 004 nick irc.test UnrealIRCd-6.2.7 iow... :x",
        ], ping_first=True)
        result = scanner.scan_server("127.0.0.1", server.port, False,
                                     "mock")
        server.join(timeout=5)
        self.assertEqual(result["verdict"], "VULNERABLE")
        # The PONG may arrive after the server's first recv, so check
        # everything the server received, not just the first chunk.
        self.assertIn(b"PONG", b"".join(server.received))

    def test_non_unrealircd_is_unknown(self):
        server = start_server([
            ":irc.test 001 nick :Welcome",
            ":irc.test 004 nick irc.test InspIRCd-4.2.0 iow... :x",
        ])
        result = scanner.scan_server("127.0.0.1", server.port, False,
                                     "mock")
        server.join(timeout=5)
        self.assertEqual(result["verdict"], "UNKNOWN")
        self.assertIn("does not identify as UnrealIRCd", result["detail"])

    def test_version_reply_fallback(self):
        # No 004 at all; VERSION is asked and the 351 reply carries it.
        server = start_server([
            ":irc.test 001 nick :Welcome",
            ":irc.test 351 nick UnrealIRCd-6.2.7.1 irc.test :x",
        ])
        result = scanner.scan_server("127.0.0.1", server.port, False,
                                     "mock")
        server.join(timeout=5)
        self.assertEqual(result["verdict"], "PATCHED")
        self.assertEqual(result["version"], "6.2.7.1")

    def test_connection_refused_is_unknown(self):
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.close()
        result = scanner.scan_server("127.0.0.1", port, False, "mock")
        self.assertEqual(result["verdict"], "UNKNOWN")
        self.assertIn("could not connect", result["detail"])


class TestLocalDetection(unittest.TestCase):
    def make_install(self, version_out, module_out):
        tmp = tempfile.mkdtemp()
        script = Path(tmp) / "unrealircd"
        script.write_text(
            "#!/bin/sh\n"
            "if [ \"$1\" = version ]; then echo \"%s\"; fi\n"
            "if [ \"$1\" = module-status ]; then printf '%%s\\n' \"%s\"; fi\n"
            % (version_out, module_out))
        script.chmod(script.stat().st_mode | stat.S_IEXEC)
        return tmp

    def test_hotpatched_install(self):
        root = self.make_install(
            "UnrealIRCd 6.2.7 (abc123)",
            "labeled-response 5.0-hot-patch-bundle-20261107")
        raw, module, checked, method, _ = scanner.detect_local(root)
        self.assertEqual(raw, "6.2.7")
        self.assertEqual(module, "5.0-hot-patch-bundle-20261107")
        result = scanner.scan_version(
            raw, "local", module_version=module, module_checked=checked)
        self.assertEqual(result["verdict"], "PATCHED")

    def test_unpatched_install(self):
        root = self.make_install(
            "UnrealIRCd 6.2.7 (abc123)", "labeled-response 5.0")
        raw, module, checked, method, _ = scanner.detect_local(root)
        result = scanner.scan_version(
            raw, "local", module_version=module, module_checked=checked)
        self.assertEqual(result["verdict"], "VULNERABLE")
        self.assertIn("NOT applied", result["detail"])

    def test_fixed_release_install(self):
        root = self.make_install(
            "UnrealIRCd 6.2.7.1 (abc123)", "labeled-response 6.2.7.1")
        raw, module, checked, method, _ = scanner.detect_local(root)
        result = scanner.scan_version(
            raw, "local", module_version=module, module_checked=checked)
        self.assertEqual(result["verdict"], "PATCHED")

    def test_directory_name_fallback(self):
        tmp = tempfile.mkdtemp()
        root = os.path.join(tmp, "unrealircd-6.2.7.1")
        os.mkdir(root)
        raw, module, checked, method, _ = scanner.detect_local(root)
        self.assertEqual(raw, "6.2.7.1")
        self.assertIn("directory name", method)

    def test_missing_directory(self):
        with self.assertRaises(ValueError):
            scanner.detect_local("/nonexistent/dir/xyz")


class TestCLI(unittest.TestCase):
    def run_main(self, argv):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = scanner.main(argv)
        return code, buf.getvalue()

    def test_version_vulnerable_exit_2(self):
        code, out = self.run_main(["--version", "6.2.7"])
        self.assertEqual(code, 2)
        self.assertIn("[VULNERABLE]", out)

    def test_version_patched_exit_0(self):
        code, out = self.run_main(["--version", "6.2.7.1"])
        self.assertEqual(code, 0)
        self.assertIn("[PATCHED]", out)

    def test_version_unknown_exit_0(self):
        code, out = self.run_main(["--version", "4.2.4"])
        self.assertEqual(code, 0)
        self.assertIn("[UNKNOWN]", out)

    def test_no_args_exit_1(self):
        code, out = self.run_main([])
        self.assertEqual(code, 1)

    def test_list(self):
        code, out = self.run_main(["--list"])
        self.assertEqual(code, 0)
        self.assertIn("CVE-2026-114713", out)
        self.assertIn("6.2.7.1", out)

    def test_json_output(self):
        code, out = self.run_main(["--version", "6.2.7", "--json"])
        self.assertEqual(code, 2)
        data = json.loads(out)
        self.assertEqual(data[0]["verdict"], "VULNERABLE")

    def test_server_flag_end_to_end(self):
        server = start_server([
            ":irc.test 001 nick :Welcome",
            ":irc.test 004 nick irc.test UnrealIRCd-5.2.1 iow... :x",
        ])
        code, out = self.run_main(
            ["--server", "127.0.0.1:%d" % server.port])
        server.join(timeout=5)
        self.assertEqual(code, 2)
        self.assertIn("[VULNERABLE]", out)
        self.assertIn("no fix", out)

    def test_inventory_mixed(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json",
                                        delete=False) as fh:
            json.dump([
                {"label": "hub", "version": "6.2.7"},
                {"label": "leaf", "version": "6.2.7.1"},
                {"label": "old", "version": "5.2.1",
                 "single_server": True},
            ], fh)
            path = fh.name
        try:
            code, out = self.run_main(["--inventory-json", path])
        finally:
            os.unlink(path)
        self.assertEqual(code, 2)
        self.assertIn("[VULNERABLE]", out)
        self.assertIn("[PATCHED]", out)
        self.assertIn("[NOT-EXPOSED]", out)

    def test_version_file_module_status(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt",
                                        delete=False) as fh:
            fh.write("UnrealIRCd 6.2.7\n"
                     "labeled-response 5.0-hot-patch-bundle-20261107\n")
            path = fh.name
        try:
            code, out = self.run_main(["--version-file", path])
        finally:
            os.unlink(path)
        self.assertEqual(code, 0)
        self.assertIn("[PATCHED]", out)


if __name__ == "__main__":
    unittest.main()
