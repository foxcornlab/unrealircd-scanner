#!/usr/bin/env python3
"""Detection-only local triage for CVE-2026-114713 in UnrealIRCd.

The flaw is an improper neutralization of delimiters (CWE-140, CVSS 3.1
8.6, AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:H/A:N) in the ``labeled-response``
module. The module echoes the client-supplied IRCv3 ``@label=`` message
tag into server replies without escaping ``\\r``, ``\\n``, ``;``, ``\\``
or spaces, so any ordinary, unprivileged user can inject raw lines into
server-to-server traffic. On a network with two or more linked servers
those lines are executed with server authority: an ordinary user can
KILL, GLINE and do many more bad things. The maintainer calls it the
most critical issue found in UnrealIRCd in fifteen years, and reported
active exploitation on 8 November 2026. CISA added it to the Known
Exploited Vulnerabilities catalog on 13 November 2026, with a federal
remediation deadline of 16 November 2026.

The fix is UnrealIRCd 6.2.7.1, released 7 November 2026, or the
no-restart hot-patch ``bundle-20261107`` on 6.0.0 through 6.2.7
(``./unrealircd hot-patch bundle-20261107``). The same bundle fixes
eight other issues: two ways for an ordinary user to reveal another
user's IP address, a blacklist-recheck hang, a crash on CHGIDENT from
Services, a "server is full" counting error, an unbounded Services ban
count, a TLS renegotiation flood, and a possible whowasdb crash. This
tool grades only CVE-2026-114713, but a server that needs the hot-patch
needs it for all nine. UnrealIRCd 5 is affected too and has no fix at
all: it has been end of life since 1 July 2023, and the only mitigation
is blacklisting the module and restarting. 3.2.x and 4 were not checked
by the advisory, which says it is likely several of the nine bugs go
all the way back; they are graded UNKNOWN, never clean.

This tool sends no payloads, no crafted labels, and no exploit traffic.
The only network it ever touches is a plain IRC connection to a server
you name with --server: it registers with a throwaway nick, reads the
version the server prints in its own 004 welcome numeric (and the 351
VERSION reply as a fallback), answers PINGs, and disconnects. It never
joins a channel, never sends a PRIVMSG, never sets a label. A VULNERABLE
grade means the version is below the fixed release; it does not mean the
server was compromised, and a PATCHED grade does not prove the server
was never attacked. If compromise is suspected, preserve evidence and
review server-to-server command logs before upgrading, because an
upgrade alone does not undo what an attacker already did with server
authority.

Usage:
    python3 unrealircd_scanner.py --version 6.2.7
    python3 unrealircd_scanner.py --version 6.2.7.1
    python3 unrealircd_scanner.py --version-file version.txt
    python3 unrealircd_scanner.py --local /home/irc/unrealircd
    python3 unrealircd_scanner.py --server irc.example.com
    python3 unrealircd_scanner.py --server irc.example.com:6697 --tls
    python3 unrealircd_scanner.py --inventory-json servers.json
    python3 unrealircd_scanner.py --list

Exit codes: 0 = nothing vulnerable found, 2 = vulnerable finding,
1 = scan error (missing argument, bad input, no version found).
UNKNOWN does not change the exit code, but it is not clean: an
unparseable, pre-release, or unmapped version has not been cleared, it
has simply not been graded.
"""

import argparse
import json
import random
import re
import socket
import ssl
import subprocess
import sys
from pathlib import Path

CVE_ID = "CVE-2026-114713"
# Fixed release, per the UnrealIRCd advisory of 7 November 2026
# (forums.unrealircd.org, topic 9487). Hot-patch bundle-20261107 covers
# 6.0.0 through 6.2.7 on *NIX; there is no hot-patch for 5.x or older.
FIXED = (6, 2, 7, 1)
FIXED_STR = "6.2.7.1"
HOTPATCH_BUNDLE = "hot-patch-bundle-20261107"

VERSION_RE = re.compile(r"(\d+)\.(\d+)(?:\.(\d+))?(?:\.(\d+))?")
# The version token in the 004 numeric and the VERSION (351) reply,
# e.g. ":irc.example.org 004 nick irc.example.org UnrealIRCd-6.2.7 ..."
BANNER_VERSION_RE = re.compile(r"UnrealIRCd-(\d+(?:\.\d+){1,3})")
# ./unrealircd version prints e.g. "UnrealIRCd 6.2.7.1 ..."
LOCAL_VERSION_RE = re.compile(r"UnrealIRCd[- ](\d+(?:\.\d+){1,3})")
# ./unrealircd module-status lines look like:
#   labeled-response 5.0-hot-patch-bundle-20261107
#   labeled-response 6.2.7.1
#   labeled-response 5.0
MODULE_LINE_RE = re.compile(r"^labeled-response\s+(\S+)", re.MULTILINE)


def pad(version):
    """Pad a version tuple to four components for comparison."""
    return tuple(list(version) + [0] * (4 - len(version)))


def parse_version(raw):
    """Parse an UnrealIRCd version string.

    Returns (tuple, kind, note) where kind is one of "release",
    "prerelease", "line" (bare major.minor, no patch level), or None
    when nothing parseable is found. Versions are compared as four-part
    tuples, so 6.2.7.1 is one step above 6.2.7.
    """
    if raw is None:
        return None, None, "no version string supplied"
    text = str(raw).strip()
    if not text:
        return None, None, "empty version string"
    match = VERSION_RE.search(text)
    if not match:
        return None, None, "no x.y.z version in %r" % text
    parts = [int(g) for g in match.groups() if g is not None]
    rest = text[match.end():]
    if len(parts) < 3:
        return tuple(parts), "line", (
            "bare %s: no patch level, and the patch level is the whole "
            "story here (6.2.7 is vulnerable, 6.2.7.1 is fixed)"
            % ".".join(str(p) for p in parts))
    if rest.startswith("-") and re.match(r"-(rc|alpha|beta|dev|git|snapshot)",
                                         rest, re.I):
        return (tuple(parts), "prerelease",
                "pre-release build %r: the fix landed in the 6.2.7.1 "
                "release, so whether this build has it depends on its "
                "build date. Treat it as unpatched until confirmed."
                % text)
    return tuple(parts), "release", ""


def grade(version, kind):
    """Grade a parsed version against the 6.2.7.1 fix.

    Returns (verdict, detail). Verdict is PATCHED, VULNERABLE, or UNKNOWN.
    """
    if version is None:
        return "UNKNOWN", "no version to grade"
    if kind in ("prerelease", "line"):
        return "UNKNOWN", parse_version_note(version, kind)
    full = pad(version)
    if full >= FIXED:
        return "PATCHED", "at or above the 6.2.7.1 fix"
    if full >= (6, 0, 0, 0):
        return ("VULNERABLE",
                "6.0.0 through 6.2.7: fix is 6.2.7.1, or hot-patch "
                "bundle-20261107. A remote version string cannot show "
                "whether the hot-patch is applied; verify locally with "
                "./unrealircd module-status")
    if version[0] == 5:
        return ("VULNERABLE",
                "UnrealIRCd 5 is affected and has no fix: end of life "
                "since 2023-07-01, no hot-patch. Mitigation is "
                'blacklist-module "labeled-response"; in the config on '
                "every server, then restart (not rehash). Upgrade to "
                "6.2.7.1.")
    if version[0] in (3, 4):
        return ("UNKNOWN",
                "end-of-life %d.x, not checked by the advisory, which "
                "says it is likely several of the nine bugs go all the "
                "way back to 3.2.x. No fix exists on this line. Do not "
                "treat it as clean; upgrade to 6.2.7.1."
                % version[0])
    return ("UNKNOWN",
            "version below 3.2, outside anything the advisory covers. "
            "No fix exists on this line; upgrade to 6.2.7.1.")


def parse_version_note(version, kind):
    if kind == "line":
        return ("bare %s: no patch level, and the patch level is the whole "
                "story here (6.2.7 is vulnerable, 6.2.7.1 is fixed)"
                % ".".join(str(p) for p in version))
    return ("pre-release build: the fix landed in the 6.2.7.1 release, so "
            "whether this build has it depends on its build date. Treat "
            "it as unpatched until confirmed.")


def grade_module_status(module_version):
    """Grade the labeled-response module version from module-status.

    Returns (verdict, detail) or None when the module version string
    cannot be interpreted. The module version is the only evidence of
    the hot-patch: the server version string stays 6.2.7 after a
    hot-patch, so a remote banner can never prove it.
    """
    if module_version is None:
        return None
    if HOTPATCH_BUNDLE in module_version:
        return ("PATCHED",
                "labeled-response %s: hot-patch bundle-20261107 is "
                "installed, server is safe" % module_version)
    version, kind, _ = parse_version(module_version)
    if version is None:
        return None
    if kind == "release" and pad(version) >= FIXED:
        return ("PATCHED",
                "labeled-response %s: running the fixed release, server "
                "is safe" % module_version)
    if version == (5, 0):
        # "5.0" parses as kind "line" (two components), so check the
        # tuple, not the kind: it is the unpatched module version.
        return ("VULNERABLE",
                "labeled-response 5.0 with no patch bundle: the hot-patch "
                "was NOT applied")
    return None


def apply_exposure(verdict, detail, single_server, no_labeled_response):
    """Fold the operator's deployment facts into the verdict.

    The flaw needs two linked servers and the labeled-response module.
    A standalone server with no links, or a server with the module
    blacklisted, cannot be exploited this way, so a vulnerable version
    grades NOT-EXPOSED instead of VULNERABLE. The version grade is
    still shown; only the final verdict changes.
    """
    if verdict != "VULNERABLE":
        return verdict, detail
    detail = detail.rstrip(".")
    if no_labeled_response:
        return ("NOT-EXPOSED",
                detail + ". The labeled-response module is not loaded, so "
                "the injection has nowhere to land. The version is still "
                "behind the fix, and the other eight issues in bundle "
                "20261107 are still open: upgrade to 6.2.7.1 on your "
                "normal cycle.")
    if single_server:
        return ("NOT-EXPOSED",
                detail + ". This server has no links, and the injection "
                "needs two or more linked servers to reach server "
                "authority. Linking a second server later re-exposes it, "
                "so upgrade to 6.2.7.1 before linking.")
    return verdict, detail + (". Confirm the network has two or more "
                              "linked servers and the labeled-response "
                              "module loaded; a standalone server or a "
                              "blacklisted module is not exposed.")


def extract_banner_version(line):
    """Pull the UnrealIRCd version out of a 004 or 351 numeric line."""
    match = BANNER_VERSION_RE.search(line or "")
    return match.group(1) if match else None


def probe_server(host, port, use_tls, timeout=10):
    """Read the version off a live UnrealIRCd over plain IRC.

    Connects, registers with a throwaway nick, answers PINGs, and reads
    the version the server prints in its own 004 welcome numeric (the
    351 VERSION reply as a fallback). No channel join, no PRIVMSG, no
    label, no payload of any kind.
    Returns (version_raw, method, warnings, banner_line). Raises
    ValueError on failure.
    """
    nick = "unrealircd-triage-%04x" % random.randint(0, 0xFFFF)
    warnings = []
    banner = None
    sock = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        if use_tls:
            context = ssl.create_default_context()
            sock = context.wrap_socket(sock, server_hostname=host)
        sock.settimeout(timeout)
        stream = sock.makefile("r", encoding="utf-8", errors="replace",
                               newline="\r\n")
        sock.sendall(("NICK %s\r\n" % nick).encode())
        sock.sendall(("USER %s 0 * :triage\r\n" % nick).encode())
        registered = False
        version_raw = None
        method = None
        deadline_lines = 0
        for line in stream:
            deadline_lines += 1
            if deadline_lines > 200:
                break
            line = line.rstrip("\r\n")
            if not line:
                continue
            upper = line.upper()
            if upper.startswith("PING"):
                token = line[5:].strip()
                sock.sendall(("PONG %s\r\n" % token).encode())
                continue
            parts = line.split()
            if len(parts) >= 2 and parts[1] == "001":
                registered = True
            if len(parts) >= 2 and parts[1] == "004":
                banner = line
                version_raw = extract_banner_version(line)
                method = "004 welcome numeric"
                break
            if registered and version_raw is None and method is None:
                # Ask once for VERSION after registration; the 351 reply
                # carries the same version string.
                try:
                    sock.sendall(b"VERSION\r\n")
                except OSError:
                    pass
                method = "VERSION requested"
            if len(parts) >= 2 and parts[1] == "351":
                banner = line
                version_raw = extract_banner_version(line)
                method = "351 VERSION reply"
                break
        if banner is None and not registered:
            raise ValueError(
                "no welcome numeric received from %s:%d within %ds: the "
                "server may require SASL, be closed to new connections, "
                "or not be an IRC server" % (host, port, timeout))
        if banner is None:
            raise ValueError(
                "registered with %s:%d but the server sent no 004 or 351 "
                "numeric carrying a version" % (host, port))
        return version_raw, method, warnings, banner
    except socket.timeout:
        raise ValueError("timed out waiting for a welcome numeric from "
                         "%s:%d" % (host, port))
    except OSError as exc:
        raise ValueError("could not connect to %s:%d: %s" % (host, port, exc))
    finally:
        if sock is not None:
            try:
                sock.sendall(b"QUIT :triage done\r\n")
            except OSError:
                pass
            try:
                sock.close()
            except OSError:
                pass


def detect_local(path):
    """Detect the UnrealIRCd version of a local install directory.

    Tries, in order: ./unrealircd version, ./unrealircd module-status
    (which also proves or disproves the hot-patch), the directory name.
    Collects every version found; if they disagree the result is
    UNKNOWN with the conflict listed, never a silent pick.
    Returns (version_raw, module_version_or_None, method, warnings).
    """
    root = Path(path)
    if not root.is_dir():
        raise ValueError("not a directory: %s" % path)
    found = {}  # raw version string -> method
    warnings = []
    module_version = None
    module_checked = False

    script = root / "unrealircd"
    if script.is_file():
        try:
            out = subprocess.run(
                [str(script), "version"], capture_output=True, text=True,
                timeout=30, cwd=str(root)).stdout
            match = LOCAL_VERSION_RE.search(out or "")
            if match:
                found[match.group(1)] = "./unrealircd version"
        except (OSError, subprocess.SubprocessError) as exc:
            warnings.append("./unrealircd version failed: %s" % exc)
        try:
            out = subprocess.run(
                [str(script), "module-status"], capture_output=True,
                text=True, timeout=30, cwd=str(root)).stdout
            module_checked = True
            match = MODULE_LINE_RE.search(out or "")
            if match:
                module_version = match.group(1)
        except (OSError, subprocess.SubprocessError) as exc:
            warnings.append("./unrealircd module-status failed: %s" % exc)

    if not found:
        match = VERSION_RE.search(root.name)
        if match and len([g for g in match.groups() if g]) >= 3:
            found[".".join(g for g in match.groups() if g)] = (
                "directory name %s" % root.name)

    if not found:
        raise ValueError("no UnrealIRCd version found under %s: no "
                         "./unrealircd script, no version in the directory "
                         "name" % path)
    if len(found) > 1:
        raise ValueError("version sources disagree under %s: %s"
                         % (path, "; ".join("%s (%s)" % (v, m)
                                            for v, m in found.items())))
    raw, method = next(iter(found.items()))
    return raw, module_version, module_checked, method, warnings


def scan_version(raw, label, single_server=False,
                 no_labeled_response=False, module_version=None,
                 module_checked=False, banner=None):
    """Grade one version string. Returns a result dict."""
    version, kind, note = parse_version(raw)
    if version is None:
        detail = note
        if banner:
            detail += ". Server banner: %r" % banner
        return {"label": label, "version": raw, "verdict": "UNKNOWN",
                "detail": detail, "kind": kind}
    verdict, detail = grade(version, kind)
    if module_version is not None:
        module_grade = grade_module_status(module_version)
        if module_grade is not None:
            verdict, detail = module_grade
    elif module_checked and verdict == "VULNERABLE":
        # module-status ran and labeled-response is not listed at all:
        # the module is not loaded, so the injection has nowhere to land.
        verdict, detail = apply_exposure(verdict, detail, False, True)
        return {"label": label, "version": raw,
                "parsed": ".".join(str(x) for x in version),
                "kind": kind, "verdict": verdict, "detail": detail}
    verdict, detail = apply_exposure(verdict, detail, single_server,
                                     no_labeled_response)
    return {"label": label, "version": raw,
            "parsed": ".".join(str(x) for x in version),
            "kind": kind, "verdict": verdict, "detail": detail}


def scan_server(host, port, use_tls, label, single_server=False,
                no_labeled_response=False):
    """Probe one IRC server and grade it. Returns a result dict."""
    try:
        raw, method, warnings, banner = probe_server(host, port, use_tls)
    except ValueError as exc:
        return {"label": label, "version": None, "verdict": "UNKNOWN",
                "detail": str(exc)}
    if raw is None:
        return {"label": label, "version": None, "verdict": "UNKNOWN",
                "detail": ("server at %s:%d does not identify as "
                           "UnrealIRCd in its welcome numeric, so it "
                           "cannot be graded for this flaw. Banner: %r"
                           % (host, port, banner)),
                "warnings": warnings}
    result = scan_version(raw, "%s (%s)" % (label, method), single_server,
                          no_labeled_response, banner=banner)
    result["warnings"] = warnings
    return result


def print_result(result, as_json=False):
    if as_json:
        print(json.dumps(result, indent=2))
        return
    print("[%s] %s" % (result["verdict"], result["label"]))
    print("  version: %s" % result["version"])
    if result.get("parsed"):
        print("  parsed:  %s (%s)" % (result["parsed"], result["kind"]))
    print("  detail:  %s" % result["detail"])
    for warning in result.get("warnings", []):
        print("  warning: %s" % warning)


def parse_server_arg(arg):
    """Split host[:port] into (host, port_or_None)."""
    if arg.startswith("["):
        host, _, rest = arg[1:].partition("]")
        port = int(rest.lstrip(":")) if rest.startswith(":") else None
        return host, port
    if ":" in arg:
        host, _, port = arg.rpartition(":")
        return host, int(port)
    return arg, None


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Detection-only triage for CVE-2026-114713 (UnrealIRCd "
                    "IRCv3 label newline injection, fixed in 6.2.7.1 / "
                    "hot-patch bundle-20261107).")
    parser.add_argument("--version", help="UnrealIRCd version, e.g. 6.2.7")
    parser.add_argument("--version-file",
                        help="file holding a version string, or "
                             "./unrealircd module-status output")
    parser.add_argument("--local", nargs="?", const=".",
                        help="local UnrealIRCd install directory "
                             "(default: current directory)")
    parser.add_argument("--server",
                        help="IRC server you own, host[:port], e.g. "
                             "irc.example.com or irc.example.com:6697")
    parser.add_argument("--tls", action="store_true",
                        help="use TLS for --server (default port 6697)")
    parser.add_argument("--port", type=int, default=None,
                        help="port for --server (default 6667, or 6697 "
                             "with --tls)")
    parser.add_argument("--single-server", action="store_true",
                        help="the network has only one server, no links")
    parser.add_argument("--no-labeled-response", action="store_true",
                        help="the labeled-response module is blacklisted "
                             "or not loaded")
    parser.add_argument("--inventory-json",
                        help="JSON list of {label, version}, {label, host, "
                             "port, tls} or {label, path} entries for a "
                             "fleet")
    parser.add_argument("--json", action="store_true",
                        help="machine-readable output")
    parser.add_argument("--list", action="store_true",
                        help="show the CVE summary and exit")
    args = parser.parse_args(argv)

    if args.list:
        print("%s: UnrealIRCd labeled-response IRCv3 label newline injection"
              % CVE_ID)
        print("  CVSS 8.6 (AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:H/A:N), CWE-140")
        print("  Advisory 7 November 2026, CVE published 8 November 2026,")
        print("  CISA KEV added 13 November 2026, due 16 November 2026.")
        print("  The @label= tag is echoed unescaped into server replies,")
        print("  so any ordinary user injects server-to-server commands")
        print("  that run with server authority on linked networks.")
        print("  Affected: 6.0.0 through 6.2.7, and EOL 5.x (no fix).")
        print("  Fixed in 6.2.7.1, or hot-patch bundle-20261107 on 6.0.0-6.2.7.")
        print("  The same bundle fixes eight other issues, including two")
        print("  IP-address leaks and a TLS renegotiation flood.")
        return 0

    results = []
    if args.version:
        results.append(scan_version(args.version, "version %s" % args.version,
                                    args.single_server,
                                    args.no_labeled_response))
    if args.version_file:
        try:
            text = Path(args.version_file).read_text().strip()
        except OSError as exc:
            print("error: cannot read %s: %s" % (args.version_file, exc),
                  file=sys.stderr)
            return 1
        module_match = MODULE_LINE_RE.search(text)
        if module_match:
            raw = None
            for line in text.splitlines():
                match = LOCAL_VERSION_RE.search(line)
                if match:
                    raw = match.group(1)
                    break
            if raw is None:
                print("error: %s looks like module-status output but "
                      "carries no server version; add --version too"
                      % args.version_file, file=sys.stderr)
                return 1
            results.append(scan_version(
                raw, "file %s" % args.version_file, args.single_server,
                args.no_labeled_response,
                module_version=module_match.group(1), module_checked=True))
        else:
            raw = text.splitlines()[0].strip() if text.splitlines() else ""
            results.append(scan_version(raw, "file %s" % args.version_file,
                                        args.single_server,
                                        args.no_labeled_response))
    if args.local is not None:
        try:
            raw, module_version, module_checked, method, warnings = \
                detect_local(args.local)
        except ValueError as exc:
            print("error: %s" % exc, file=sys.stderr)
            return 1
        for warning in warnings:
            print("warning: %s" % warning, file=sys.stderr)
        results.append(scan_version(
            raw, "local install %s (%s)" % (args.local, method),
            args.single_server, args.no_labeled_response,
            module_version=module_version, module_checked=module_checked))
    if args.server:
        host, arg_port = parse_server_arg(args.server)
        port = args.port or arg_port or (6697 if args.tls else 6667)
        results.append(scan_server(
            host, port, args.tls, "server %s:%d" % (host, port),
            args.single_server, args.no_labeled_response))
    if args.inventory_json:
        try:
            entries = json.loads(Path(args.inventory_json).read_text())
        except (OSError, ValueError) as exc:
            print("error: cannot read inventory %s: %s"
                  % (args.inventory_json, exc), file=sys.stderr)
            return 1
        if not isinstance(entries, list):
            print("error: inventory must be a JSON list", file=sys.stderr)
            return 1
        for entry in entries:
            label = entry.get("label", entry.get("host", "?"))
            single = entry.get("single_server", entry.get(
                "single", args.single_server))
            no_lr = entry.get("no_labeled_response", entry.get(
                "no_label", args.no_labeled_response))
            if "version" in entry:
                results.append(scan_version(entry["version"], label, single,
                                            no_lr))
            elif "host" in entry:
                port = (entry.get("port")
                        or (6697 if entry.get("tls") else 6667))
                results.append(scan_server(entry["host"], port,
                                           bool(entry.get("tls")),
                                           "%s:%d" % (label, port),
                                           single, no_lr))
            elif "path" in entry:
                try:
                    raw, module_version, module_checked, method, _ = \
                        detect_local(entry["path"])
                except ValueError as exc:
                    results.append({"label": label, "version": None,
                                    "verdict": "UNKNOWN", "detail": str(exc)})
                    continue
                results.append(scan_version(
                    raw, "%s (%s)" % (label, method), single, no_lr,
                    module_version=module_version,
                    module_checked=module_checked))
            else:
                results.append({"label": label, "version": None,
                                "verdict": "UNKNOWN",
                                "detail": "entry has neither version, host "
                                          "nor path"})

    if not results:
        parser.print_usage(sys.stderr)
        print("error: give one of --version, --version-file, --local, "
              "--server, --inventory-json, or --list", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        for result in results:
            print_result(result)
    vulnerable = any(r["verdict"] == "VULNERABLE" for r in results)
    return 2 if vulnerable else 0


if __name__ == "__main__":
    sys.exit(main())
