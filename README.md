# `unrealircd-scanner`

Local triage for `CVE-2026-114713`, the `UnrealIRCd` `IRCv3` label injection that lets any ordinary user run commands with server authority on a linked `IRC` network. Give it a version you own, a server you run, or a local install, and it tells you whether that server is still open. It never sends a label, never joins a channel, never touches the network beyond reading the version the server prints about itself.

## `The flaw`

The bug is an improper neutralization of delimiters, `CWE-140`, in the `labeled-response` module, which handles the `IRCv3` `label` message tag. The validation in `labeled_response_mtag_is_ok()` checked only the length of the client-supplied `@label=` value (`<= 64` characters) and never rejected `\r`, `\n`, `;`, `\` or spaces. The module echoes the tag into server replies, so an ordinary user injects raw newlines into server-to-server traffic, and on a network with two or more linked servers those lines are executed with server authority. Any user can `KILL`, `GLINE`, and do many more bad things, with no login beyond a normal `IRC` account and no `IRCOp` privileges of their own.

The maintainer, `Bram Matthys` (`Syzop`), found it during an internal `AI`-assisted audit of the codebase, about a hundred hours of audit work since `February 2026`, and calls it the most critical issue found in `UnrealIRCd` in fifteen years. He reported active exploitation on `8 November 2026`, and `CISA` added the flaw to its `Known Exploited Vulnerabilities` catalog on `13 November 2026`, with a federal remediation deadline of `16 November 2026` and a forensic-triage flag.

`CVE-2026-114713` scores `CVSS 3.1 8.6 High` (`AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:H/A:N`). The project calls the issue `CRITICAL` in its advisory while the score says `High`; this tool follows the `8.6` score and notes the wording gap rather than picking a winner. The score is below `9`, but the `KEV` listing is the trigger: confirmed exploitation in the wild, six days from disclosure to this check, and a three-day federal deadline.

## `The traps`

| `Signal` | `Grade` | `Why` |
| --- | --- | --- |
| `6.2.7` | `VULNERABLE` | **The 6.2.7 trap.** `6.2.7` is the newest release before the fix. The fix is `6.2.7.1`, one patch level up, not `6.2.7`. A check on the first three numbers clears this server by mistake. |
| `6.2.7` with the hot-patch, seen over the network | `VULNERABLE` (with a note) | **The hot-patch trap.** A hot-patched server still prints `UnrealIRCd-6.2.7` in its banner, so a remote version string can never prove the patch. Verify locally with `./unrealircd module-status` before believing a remote `VULNERABLE`. |
| `6.2.7` with the hot-patch, seen locally | `PATCHED` | `module-status` shows `labeled-response 5.0-hot-patch-bundle-20261107`. That is the proof. |
| `labeled-response 5.0` in `module-status` | `VULNERABLE` | **The patch was not applied.** A bare `5.0` with no bundle suffix means the hot-patch never landed. |
| `5.x`, for example `5.2.1` | `VULNERABLE` | **No fix exists.** `UnrealIRCd 5` is affected and has been end of life since `2023-07-01`. There is no hot-patch for it. The only mitigation is `blacklist-module "labeled-response";` in the config on every server, then restart, not rehash. Upgrade to `6.2.7.1`. |
| `4.x` or `3.2.x` | `UNKNOWN` | The advisory did not check them and says it is likely several of the nine bugs go all the way back to `3.2.x`. No fix exists on those lines. Do not treat them as cleared. |
| A bare `6.2` with no patch level | `UNKNOWN` | The patch level is the whole story here. Without it the server has not been cleared, only left ungraded. |
| A vulnerable build on a single server, or with the module blacklisted | `NOT-EXPOSED` | The injection needs two or more linked servers and the `labeled-response` module. Still upgrade: the code is vulnerable, and linking a second server later re-exposes it. |
| The `SPAMFILTER` workaround applied | `VULNERABLE` | The workaround blocks bad labels, but only if every server on the network is on `6.0.4` or newer, and it does not fix the other eight issues in the bundle. It is a mitigation, not a fix. |

## `What it checks`

- `One version` (`--version 6.2.7`): graded against the `6.2.7.1` fix
- `A local install` (`--local /home/irc/unrealircd`): runs `./unrealircd version` and `./unrealircd module-status`, so the hot-patch is actually proven instead of guessed
- `A server you run` (`--server irc.example.com`): connects, registers with a throwaway nick, reads the version from the `004` welcome numeric (the `351 VERSION` reply as a fallback), answers `PING`s, and disconnects. Plain `6667` by default, `--tls` for `6697`
- `A version file or module-status dump` (`--version-file version.txt`): a version string, or `module-status` output carrying a `labeled-response` line
- `A fleet, offline` (`--inventory-json servers.json`): a `JSON` list of `{label, version}`, `{label, host, port, tls}` or `{label, path}` entries
- `Exposure flags` (`--single-server`, `--no-labeled-response`): a vulnerable build grades `NOT-EXPOSED` instead of `VULNERABLE` where the flaw cannot reach
- `The full table` (`--list`): the `CVE` summary and the fix
- `Machine output` (`--json`): the same grades as `JSON`

```sh
python3 unrealircd_scanner.py --version 6.2.7
python3 unrealircd_scanner.py --version 6.2.7.1
python3 unrealircd_scanner.py --local /home/irc/unrealircd
python3 unrealircd_scanner.py --server irc.example.com
python3 unrealircd_scanner.py --server irc.example.com:6697 --tls
python3 unrealircd_scanner.py --version 6.2.7 --single-server
python3 unrealircd_scanner.py --inventory-json servers.json
```

```json
[
  {"label": "hub", "version": "6.2.7"},
  {"label": "leaf", "host": "irc.example.com", "port": 6697, "tls": true},
  {"label": "old", "path": "/home/irc/unrealircd-old"}
]
```

Exit codes: `0` nothing vulnerable found, `2` vulnerable finding, `1` scan error. `UNKNOWN` does not change the exit code, but it is not clean.

## `The table`

| `Line` | `Affected` | `Fixed in` |
| --- | --- | --- |
| `UnrealIRCd 6` | `6.0.0` through `6.2.7` | `6.2.7.1`, or hot-patch `bundle-20261107` on `6.0.0`-`6.2.7` (`*NIX`, no restart) |
| `UnrealIRCd 5` | all `5.x` | no fix, end of life since `2023-07-01`. Mitigation: blacklist the `labeled-response` module and restart |
| `UnrealIRCd 3.2.x` / `4` | likely affected, not checked | no fix. Upgrade to `6.2.7.1` |

The same `6.2.7.1` release and hot-patch bundle fix eight other issues alongside the critical one: two ways for an ordinary user to reveal another user's `IP` address, a blacklist-recheck hang, a crash on `CHGIDENT` from `Services` that a normal user can trigger, a counting error that tells every new connect the server is full, an unbounded `Services` ban count, a `TLS` renegotiation flood, and a possible `whowasdb` crash. This tool grades only `CVE-2026-114713`, but a server that needs the hot-patch needs it for all nine.

Find the version in the `004` numeric when you connect, in `./unrealircd version` on the server, or in `./unrealircd module-status` for the hot-patch proof. As an `IRCOp` you can check a remote server's module the same way with `MODULE -all`, including `MODULE -all remote.server.name` for a linked server.

## `What this tool does not do`

It does not test the injection. Testing it would mean sending a crafted `@label=` tag that injects server-to-server commands, which is an attack, not a version check. It does not scan the network for `IRC` servers, and it does not grade a server from a port scan or a web page: the version comes from the `IRC` banner the server prints itself, or from files you supply. A `VULNERABLE` grade means the version is below the fix; it does not mean the server was compromised.

## `Tests`

```sh
python3 -m unittest discover -s tests -v
```

`45` tests, all passing: version parsing, the `6.2.7` / `6.2.7.1` boundary, later releases, the `5.x` no-fix line, `UNKNOWN` grades for `4.x`, `3.2.x`, bare lines and pre-releases, the hot-patch module evidence (patched, unpatched, fixed release, module absent), the exposure flags, local detection against a fake `unrealircd` script (hot-patched, unpatched, fixed release, directory-name fallback), live probes against a mock `IRC` server (vulnerable and patched banners, the `PING` handshake, the `VERSION` fallback, a non-`UnrealIRCd` server, connection refused), `CLI` exit codes, `JSON` output, and inventory grading.

## `Sources`

- `UnrealIRCd` advisory, forums topic `9487`, `7 November 2026`: the flaw, the affected and fixed versions, the hot-patch bundle, the `SPAMFILTER` workaround, the `module-status` verification strings, the `5.x` end-of-life note, and the nine-issue list. Exploitation update added `8 November 2026`
- `CVE-2026-114713`, published `8 November 2026`, `CVSS 3.1 8.6` (`AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:H/A:N`), `CWE-140`, alias `GHSA-237f-p9h6-wq4r`. `NVD` status still `Undergoing Analysis` as of `13 November`
- `CISA Known Exploited Vulnerabilities` catalog, `CVE-2026-114713`, added `13 November 2026`, due `16 November 2026`, forensic-triage flag, exploitation active
- `Rapid7` vulnerability database, `CVE-2026-114713`: `6.0.0 before 6.2.7.1`, same vector and score, corroborating the range
- `Garrett Stimpson`, `8 November 2026`: analysis of the advisory and the fix, the `labeled_response_mtag_is_ok()` length-only check, the three-step fix order, and the `module-status` verification

Two disagreements to note. First, the wording: the project calls the issue `CRITICAL` in its advisory while the `CVSS` score is `8.6 High`. This tool follows the `8.6` score and uses the project's wording only as the project's own assessment. Second, the timing: the advisory and fix shipped `7 November`, the `CVE` record `8 November`, and the `KEV` addition `13 November`. The `72`-hour window for this check runs from the `KEV` addition, which is the fresh trigger: `CISA` confirming exploitation in the wild, not the original disclosure.

No public detection-only scanner for this `CVE` was found at publication time: no `nuclei` template exists for `CVE-2026-114713`, and no `foxcornlab` repo covered `UnrealIRCd` or `IRC` before this one. Write-ups and analysis exist, but none of them grades a server.

## `Disclaimer`

Defensive triage only, for systems you own or are authorized to assess. This tool grades exposure from version strings you supply, from a local install, or from the version an `IRC` server publishes about itself in its own welcome numeric. It does not exploit anything, and it is not a substitute for the vendor update.

## `Thanks to`

- `Bram Matthys` (`Syzop`) and the `UnrealIRCd` project for the advisory, the fix, and the hot-patch
- `CISA` for the `KEV` listing that confirmed exploitation
- `Garrett Stimpson` for the clear public analysis of the advisory

> Research by `Vineeth Kumar` (`foxcornlab`). Found a bug or want a feature, open an `issue`.
