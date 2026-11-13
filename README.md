# BaradWatchU Server

*One Server to rule them all, One Server to find them, One Server to bring them all and in security bind them.*

[Leggi in italiano](LEGGIMI.md)

BaradWatchU Server coordinates consent-based workstation audits through the independent Client.

## Status and architecture

The MVP uses the existing Rust/Axum backend and Angular 18 dashboard. Authentication is
configurable: loopback-only LOCAL for development or Google OIDC Authorization Code + PKCE
with backend cookie sessions and an explicit multi-admin allowlist. Both use the same manual
Ed25519 pairing, trusted Client inventory, remote requests/status/results and JSON download.
Client audit execution, consent and local history remain in the Client.

- `crates/server/src/auth.rs`: Google discovery, code exchange and signed token validation;
  tokens stay in the backend and are discarded. LOCAL issues a random, eight-hour loopback session with a
  descriptive operator label only to a browser presenting the launch token (Client model, see below); logout revokes it and the next session receives fresh tokens. Cookies are Secure, HttpOnly, SameSite=Lax, host-only; mutations
  require session CSRF token and exact Origin.
- `storage.rs`: SQLite identity seed, trusted Client public keys, administrators
  keyed by Google issuer + subject (with latest verified display name/email). Owner-only
  data directory (0700) and database (0600); no automatic identity generation.
- `tunnel.rs`, `tls.rs`: outbound Client tunnel listener, TLS 1.3/raw Ed25519 keys,
  reciprocal trust checks and live connection registry. No TOFU or automatic trust.
- `http.rs`: protected fleet APIs and built Angular assets on the same origin. OIDC checks the
  allowlist on each request; LOCAL relies on its enforced loopback listener. OIDC admin
  revocation affects already-open sessions.
- Sessions (8 hours) and routing records (24 hours; up to 4096 requests) are in memory and
  lost on Server restart. Received reports are retained in the existing SQLite database after retrieval from the Client,
  which retains completed results for one hour in memory and keeps local history separately.
  Each operator can retrieve their own requests. One Server process per data directory.

Policy distribution, scheduling, remediation,
complex roles, multi-tenancy, native packages and Server service packaging remain
outside this MVP. The source installer still does not create a system service.

## Version and CLI

Server and Client have independent release lifecycles. The Server's authoritative product version is `[workspace.package].version` in this repository's root `Cargo.toml`; Rust packages inherit it. Angular `package.json` and the displayed dashboard version are generated/synchronized from that source by `node web/sync-version.mjs` (also run automatically by `npm run build`). Change the workspace version using SemVer, then run the sync command. Product version is independent of API/protocol/schema versions; the remote protocol remains v1.

```sh
cargo run -p baradwatchu-server -- --version
cargo run -p baradwatchu-server -- --help
```

The release executable supports the same flags without starting the HTTP server.

## Prerequisites

- Rust stable toolchain with Cargo and rustfmt (workspace baseline: Rust 1.88+).
- Node.js 20.11.1 or later within Node 20 and npm 8+; `web/.nvmrc` selects Node 20. Commands reject incompatible Node versions with an actionable message.
- Network access on first dependency resolution unless dependencies are already cached.
- GNU/Linux with glibc 2.17+ to build; a cache records the actual build host glibc and conservatively requires the same or a newer version.
- For the full source build: C/C++ compilers, make, Python 3 and tar (including native npm dependency fallbacks).

The installer follows `web/.nvmrc`: when the active Node is not a supported Node 20, it loads
the user's nvm installation and selects the pinned runtime before checking or invoking npm.
This uses the npm paired with that Node and does not require a system Node/npm package when
nvm already provides Node 20.

## Commands

From the repository root:

```sh
cargo fmt --all -- --check
cargo test --workspace --locked
cargo build --workspace --locked
cargo build --release --workspace --locked
cargo run -p baradwatchu-server
cargo run -p baradwatchu-server -- --version
cargo run -p baradwatchu-server -- --help
```

The service listens on `127.0.0.1:3000` by default; set `BARADWATCHU_SERVER_ADDR` to an IP address and port to override (IPv6: `[::1]:3000`). Configuration/bind errors return exit 1, invalid CLI arguments return 2; Ctrl-C/SIGTERM initiates graceful shutdown. Check `http://127.0.0.1:3000/health` for JSON health status.

Build the dashboard separately:

```sh
cd web
npm ci
npm start       # local development
npm test        # version tooling tests
npm run build   # production
```

Use `nvm use` in `web/`. For the complete workflow, build Angular and open the Rust-served
`http://localhost:3000`. Configuration is selected from `BARADWATCHU_SERVER_CONFIG` when
set; otherwise the Server checks `/etc/baradwatchu/server.json`, then
`$XDG_CONFIG_HOME/baradwatchu/server.json` (normally `~/.config/baradwatchu/server.json`).
If no file exists, the full dashboard starts in loopback-only LOCAL mode. An explicitly selected or discovered file that
exists but cannot be read causes startup to fail; the Server does not silently choose a
different authentication mode.
For Angular live development, `npm start` stays in the foreground on port 4300 and proxies
`/api` and `/auth` to `127.0.0.1:3000`; use `http://localhost:4300` as `publicUrl`. OIDC also
uses its matching Google callback; LOCAL needs no callback. Angular never starts Rust.

## Authentication mode and local development

Authentication mode is selected by `authMode` in `server.json`. Missing configuration or
an omitted `authMode` selects `LOCAL`; `OIDC` must be explicit and still requires Google
configuration and administrator authorization. Run `baradwatchu-server dashboard
[--no-browser]` and keep it running (plain `baradwatchu-server` starts without a browser).

LOCAL launch follows the Client dashboard: at startup the Server generates a random 64-hex launch
token and writes `{schemaVersion, pid, origin, port, token}` to
`$XDG_RUNTIME_DIR/baradwatchu-server/dashboard.json` (fallback `<data dir>/run`; directory 0700,
file 0600), prints the `http://localhost:3000/?k=TOKEN` link and opens it through the private
`open-dashboard.html` launcher, so the token is never on a command line. The browser keeps the
token per tab (sessionStorage), removes it from the address bar, and exchanges it once via the
`X-BaradWatchU-Token` header on `/api/session` for the HttpOnly cookie/CSRF session. Without the
token `/api/session` answers 401 `LOCAL_TOKEN_REQUIRED`. Running `dashboard` again as the same
user reuses the live session (port reachable and PID running the same executable), like the
Client; the record is removed at shutdown. Only the user who started the Server can read the
token. The Client uses `$XDG_RUNTIME_DIR/baradwatchu/` and an ephemeral port, so both coexist.
The source installer defaults to `/usr/local`, builds as your user, then requests sudo
for file installation. LOCAL describes runtime authentication, not installation permissions.
An old `~/.local/bin/baradwatchu-server` may shadow the system binary: use the absolute
`/usr/local/bin/baradwatchu-server` until you remove the older installation explicitly.

For development without OAuth credentials, create a private `server.local.json`:

```json
{
  "authMode": "LOCAL",
  "publicUrl": "http://localhost:3000",
  "localOperatorName": "Mario Rossi"
}
```

```sh
chmod 600 server.local.json
export BARADWATCHU_SERVER_CONFIG="$PWD/server.local.json"
export BARADWATCHU_SERVER_ADDR=127.0.0.1:3000
export BARADWATCHU_SERVER_DATA_DIR="$HOME/.local/state/baradwatchu-server"
cargo run -p baradwatchu-server
```

Build the Angular dashboard with `(cd web && npm run build)` and open
`http://localhost:3000`. Without `localOperatorName`, the Server uses `USER`, then
`LOGNAME`/`USERNAME`, then the generic `Operatore locale` label. This is a descriptive label only:
loopback access does not authenticate the browser user, and a system service may resolve
its own service account. LOCAL requires `127.0.0.1` or `::1`, HTTP localhost public URL,
and any port; startup fails on wildcard/non-loopback bindings. Browser `Host` headers other than the
configured origin or `127.0.0.1`/`[::1]`/`localhost` with the listen port are refused (421
`INVALID_HOST`, DNS-rebinding guard); forwarded headers are never trusted. Use it only on a trusted development/local machine; do not put it behind
a public reverse proxy. Server identity pairing, Client mTLS, explicit consent and the
Client's 120-second consent window are unchanged.

To switch back, set `"authMode": "OIDC"` (omitting it selects LOCAL) and restore the `google` block from
`server.example.json` with real local credentials. Restart the Server. `/api/auth-mode`
reports `OIDC`, `/api/session` returns 401 before Google login, and `/auth/login` starts the
existing OIDC flow; the LOCAL session endpoint does not issue a session cookie in OIDC mode. LOCAL logout ends the current browser session; it does not identify or sign out the OS user. A new session again requires the launch token (kept by the same tab or reopened with `baradwatchu-server dashboard`).

## Google OAuth setup

1. In Google Cloud Console, select/create a project. Open **Google Auth Platform → Branding**
   and configure the application name, support email and contact email.
2. Under **Audience**, choose **Internal** for your Workspace organization, where available;
   otherwise use **External / Testing** and add both operators as test users.
3. Under **Data Access**, configure only `openid`, `email`, `profile` (the console may show
   the email/profile scopes as `userinfo.email` and `userinfo.profile`). No Workspace data
   APIs or service accounts are required by this MVP.
4. Under **Clients → Create client**, choose **Web application**. Add the exact authorized
   redirect URI **`http://localhost:3000/auth/callback`**. This backend flow needs no JavaScript
   origin registration. For a deployed instance, add `https://YOUR-SERVER/auth/callback`.
5. Copy the client ID and secret into a private local configuration, never into Git. If your
   organization restricts OAuth apps, its Workspace administrator must permit this client.

Google permits HTTP localhost web-app redirects for development; a public domain is not
required. See [Google's web-server flow](https://developers.google.com/identity/protocols/oauth2/web-server)
and [consent configuration](https://developers.google.com/workspace/guides/configure-oauth-consent).

```sh
cp server.example.json server.local.json
chmod 600 server.local.json
# Edit the placeholders; set workspaceDomain to your Workspace domain or omit it.
export BARADWATCHU_SERVER_CONFIG="$PWD/server.local.json"
export BARADWATCHU_SERVER_DATA_DIR="$HOME/.local/state/baradwatchu-server"
cargo build --workspace --locked
(cd web && npm run build)
cargo run -p baradwatchu-server
```

`server.local.json` is ignored by Git. In OIDC mode, `publicUrl` must be an HTTPS origin,
except exact HTTP `localhost` with a loopback backend bind. `google.redirectUri` must equal
`publicUrl/auth/callback`. Optional `webDir` overrides the built dashboard directory; by
default the installed `share/baradwatchu-server/web` or checkout build is used. Google
configuration is read at startup; restart after changes. `workspaceDomain` checks the signed
`hd` claim, not an email suffix; it never grants administrator authorization.

Secure cookies are retained on localhost (verified with Chrome); browsers that do not
support this localhost exception need local HTTPS. Outside local development, place a TLS
reverse proxy in front of the loopback backend and expose only the configured HTTPS origin.
Proxy all routes without changing paths. Do not expose the backend HTTP listener directly.
The Server does not trust forwarded headers to determine its public origin.

## First administrator and additional administrators

Sign in through the dashboard. A valid Google user not on the allowlist sees only their
verified issuer/subject and an authorization-required screen. There is no registration API.
As the local OS account that owns the Server data directory, run:

```sh
# Keep BARADWATCHU_SERVER_DATA_DIR identical to the running Server's value.
./target/debug/baradwatchu-server setup admin allow GOOGLE_SUBJECT_ONE
./target/debug/baradwatchu-server setup admin allow GOOGLE_SUBJECT_TWO
# Revocation takes effect on the next API request, without restarting.
./target/debug/baradwatchu-server setup admin revoke GOOGLE_SUBJECT_ONE
```

The issuer is fixed to `https://accounts.google.com`; copy each `sub` from its authenticated
screen. Names/emails are informational and refreshed after login. Both allowlisted operators
may request audits; sign out ends only the BaradWatchU session, not the Google account session.
After granting access, use **Check authorization again** (or sign in again). These small local
provisioning commands also work with the installed `baradwatchu-server` binary.

## Manual pairing and audit workflow

Generate the Server identity through the authorized dashboard, or explicitly:

```sh
./target/debug/baradwatchu-server setup identity generate "Company Server"
./target/debug/baradwatchu-server setup identity export > server-public.json
```

Generation refuses to replace an existing identity. Import `server-public.json` on the Client
with `baradwatchu-agent trust import server-public.json`, after independently checking the
fingerprint. Export the Client identity (`baradwatchu-agent identity export --output client-public.json`)
and select that JSON file in the Server dashboard. Its name and fingerprint appear from the file;
no fingerprint transcription is needed. Check the displayed fingerprint independently before confirming. The imported public key remains the trust anchor. No Client address is stored. On success, the form clears and shows the registered Client. The local CLI equivalent is:

```sh
./target/debug/baradwatchu-server setup client import client-public.json "Workstation"
```

The Client needs its system service running, `remote enable`, and its **Active connections** tab configured with this Server's DNS or IP and tunnel port (default 7445). The Client opens the authenticated channel; the Server fleet shows **Connected** only while it is live. The Server tunnel listens on `0.0.0.0:7445` by default (override with `BARADWATCHU_SERVER_TUNNEL_ADDR`); expose only that mTLS port, while LOCAL dashboard HTTP stays on loopback. A linked user session/tray is required for consent. Configure firewall/routing for the Server port. Use the updated Client service **and**
user agent: earlier strict v1 readers reject the optional requester metadata. No automatic
fallback drops attribution. Select **Request audit** in the Server dashboard; the Client asks
for consent naming the Google operator and the Server. Only local acceptance within **120
seconds** starts execution. BUSY has no queue; UNAVAILABLE, REJECTED, EXPIRED and FAILED are
shown explicitly. After a connection error, **Retry same request** retains the request ID;
never automatically create a second request. Status polling stops on errors and can be resumed.

The completed report is displayed/downloadable as JSON. It records `LOCAL`/`REMOTE` and, for
remote audits, operator display name and Server reference. The Client's own history and PDF
contain the same attribution. The trusted Server key authenticates the request; the name
never does. Older reports remain readable with unknown origin. Google email/sub are not sent
to the Client. The one-hour result lifetime is separate from the 120-second consent timeout;
Client service restart loses in-memory results, Server restart loses routing records/sessions,
and neither erases Client history. The dashboard lists every request still held by the Server
for the requesting operator (up to 24 hours), rather than retaining only the last ID in the tab.

The dashboard follows the Client's Ash & Ember palette and offers Italian/English selection
(shared with the Client through language.json). Its Requirements tab lists the paired Client
catalog, with localized descriptions, priority, platform-specific behavior, paths and SHA-256
values. Expand an item to read its bundled Client tool/configuration source. The Server does
not execute these files or show Client execution results in this catalog.

The result view also opens a printable PDF using the Client renderer (template 1.3.0),
including original Client version, observations and requester attribution. It renders the
received JSON without running checks or changing the report. The Client must still hold the
result; its one-hour retention applies to both JSON and PDF retrieval. Settings exposes the
same theme selection as the Client: `$XDG_CONFIG_HOME/baradwatchu/report-theme.json` and
`themes/*.json` (normally under `~/.config/baradwatchu`). This sharing is intentional.

The Server parses the Client audit model, rejects invalid schemas/duplicate requirement IDs,
and reports inconsistent digest syntax, VERIFIED claims, file states, folder gates and
installation counters. Historical reports without provenance remain readable with unknown
evidence. Reported manifest digests are observations; they cannot be recomputed from a list
of file hashes alone. Independently configured expectations remain separate from Client claims.

The Settings language selector persists `system`, `italian` or `english` in the Client-compatible `baradwatchu/language.json` under the Server account configuration directory. Dashboard labels come from JSON message catalogs through `/api/messages`; PDF rendering reads the same preference. Changing it requires an authorized session and CSRF protection. It is shared with a Client running under the same account, not a per-browser OIDC preference.

### Client catalog, Server expectations and custom checks

The Server binary bundles the paired Client release's `catalog/builtin-tools.sha256`,
configurations and tool sources for Linux, Windows and macOS (manifest platforms `linux`,
`windows`, `macos`, folders `checks`, `checks-windows`, `checks-macos`). This is the default expected catalog
and is shown on the Requirements page with the paired Client version. The bundled manifest
digest is `45918aceff1549dfb53c1634fc0ff48c3b9e8ef8f81d83697f6b67f7a0d6bb92`. Administrators can replace it
with the exact manifest from a newer verified Client package; that fleet-wide override is
stored in SQLite and takes effect without reinstalling the Server. In the Requirements page,
the active `builtin-tools.sha256` is shown read-only; replacing it requires selecting a file
with that exact name and confirming the fleet-wide change. Reset restores the manifest
bundled with the installed Server. A Server upgrade without an override adopts the new
bundled baseline. This manifest section appears after the custom-check list and editor.

The Requirements page also creates Server custom checks using the Client fields: ID, name,
description, priority, tool file, arguments and timeout. The Server stores the tool and
metadata but never executes it. Export produces a portable JSON package. On a Client, choose
**Import Server package** in Custom Checks, review the prefilled values and confirm; the
Client calculates and pins the tool SHA-256 during import. A Client runs it only after the
normal local user import flow and later audit/check action.

For a received audit, the Server compares every installed catalog file's reported digest and
the Client-declared expected digest with the active expected manifest. Missing, extra,
duplicate and unverified files are distinguished. Missing installation evidence or an
absent platform is unknown. A complete match requires the exact manifest digest and every
expected file with consistent reported identity/state/digests and no extra files. This
compares mTLS-authenticated observations; it does not prove checks ran or sign the report.

The extended real-Client tests also verify Server history after Client shutdown, operator isolation/revocation, deletion, and byte-for-byte PDF equality with the Client under the same default theme and English language. Run with isolated Server preferences:

```sh
python3 tools/test-remote-history.py --client /absolute/path/to/baradwatchu-agent
# Optional: --artifacts /tmp/baradwatchu-pdf-review
```

The fixture disables the nine built-in checks for a fast transport/consent/report test and accepts consent through the Client CLI. It does not validate privileged checks, human consent windows or real Google login.

The Client PDF header labels remote and local origin separately; legacy reports without attribution use an unknown-origin label.

### Received report history

The Remote audits tab lists requests and saved reports as compact rows with Client identity, date and state. Open a row to see request details or a received report; only the opened report renders its findings, PDF and JSON actions. Active requests are refreshed while the dashboard is open, and completed reports are retrieved and saved. Request routing and statuses remain in Server memory for up to 24 hours; saved reports persist across restarts. Deleting or clearing removes only saved copies. An opened report, like the Client view, sorts findings by severity (ERROR, FAIL, WARN, …) and offers status counter filters plus search by ID or name. JSON is retained in the existing private Server SQLite database, including original fields unknown to this Server version. No audit is generated. Unlike the Client's single-account file cache, the Server uses its database to scope copies by operator and request ID (timestamps can collide across Clients). PDFs are rendered on demand from saved JSON using the Client renderer and shared theme; no additional PDF file is retained.

Reports survive Server restarts and the Client's one-hour remote cache expiration, until explicitly deleted. Only the requesting operator may access them, and OIDC still checks current admin authorization. Removing Client trust prevents new remote retrieval but leaves already received history available. Repeated retrieval is idempotent; changed content under the same request ID is rejected. Deletion is local to the Server; retrieving the remote result again can save a new copy. Comparisons use current Server expectations. Usage counts JSON payload bytes, not SQLite disk allocation; deletion releases logical records without guaranteeing an immediate database-file shrink. No automatic retention policy is configured.

## Linux source installation


Before installation/update or removal changes files, the installer stops running processes of the selected installation owned by the invoking user (also when invoked through sudo). It matches the exact executable path, sends SIGTERM and waits up to 10 seconds; set `BARADWATCHU_STOP_TIMEOUT=1..99` to change this. A timeout aborts before installed files change; no SIGKILL is used. Other users' processes and other installation prefixes are left running and reported. Restart manually with the installed `baradwatchu-server dashboard`. `--dry-run` reports the effective plan without stopping processes. Lifecycle checks: `python3 tools/test-installer-lifecycle.py` (temporary prefixes, no root or actual installation).

Supported installer detection: Arch Linux, Fedora, Debian and Ubuntu, including `ID_LIKE`. `--missing-deps` only inspects dependencies, reports missing local Angular packages and prints package-manager/project commands; it never installs system packages. Required source-build tools are Rust/Cargo 1.88+, Node.js 20 >=20.11.1, npm 8+, C/C++, make, Python 3 and tar; glibc 2.17+ is the minimum checked on the build host. A validated prebuilt cache does not require Node/Angular tooling, but this source installer builds those assets when building from source.

```sh
./install.sh --help
./install.sh --missing-deps
./install.sh --dry-run --prefix=/tmp/baradwatchu-preview
./install.sh                                  # build as user, install in /usr/local via sudo
./install.sh --build-only --build-dir="$HOME/.cache/baradwatchu/baradwatchu-server-0.0.1"
sudo ./install.sh --no-build --build-dir="$HOME/.cache/baradwatchu/baradwatchu-server-0.0.1" --prefix=/usr/local
./install.sh --uninstall --prefix=/usr/local
```

`--no-build` requires a complete cache created from this exact source tree, version and host platform. Plain `./install.sh` builds as the current unprivileged user, then uses sudo to install under `/usr/local`. For a system prefix, build as an unprivileged user first, then run the install with `sudo` and `--no-build --prefix=/usr/local`; never build as root. Neither mode creates a service or production configuration. Uninstall removes only unchanged payload files listed in the source manifest; it refuses package-manager-owned or modified files and preserves configuration/data. Updates use the same ownership manifest. No service is restarted.

`--build-only` uses Cargo `--locked` and a temporary Angular workspace inside the cache: `npm ci` does not replace checkout `node_modules`. Dependencies, npm logs and node-gyp headers stay in the cache. Sources must remain unchanged during the build. `-h` aliases `--help`, `-U` aliases `--uninstall`, and `--build-dir=DIR` selects the marked build cache. Exit codes are 0 for success, 1 for execution/validation failures, and 2 for invalid or conflicting options.

Source installation builds from this checkout. Arch `pacman`, Debian/Ubuntu `.deb`, and Fedora `.rpm` are planned in [`packaging/README.md`](packaging/README.md); none has a package recipe/artifact yet. The source installer refuses to mix with package-manager ownership.

## Verification and limits

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
# Build Client in its own repository first; opt-in isolated cross-repository test:
BWU_CLIENT_BIN=/absolute/path/to/BaradWatchU-Client/target/debug/baradwatchu-agent \
  cargo test --lib two_oidc_admins --locked -- --ignored --nocapture
(cd web && npm test && npm run build)
# Requires Chrome and Node 20 experimental WebSocket:
(cd web && node --experimental-websocket dashboard.smoke.mjs)
```

Automated verification covers the signed RSA OIDC mock/code/PKCE exchange, invalid claims,
replay, allowlist/CSRF/session checks, manual trust and HTTP framing. The opt-in test exercises
two independently allowlisted mock-Google operators through the real Server router/mTLS and
real isolated Client service/link/audit processes; local consent is supplied through the Client
CLI. Both names are checked in consent, returned JSON, cached history and PDF. It does not
use Google credentials, a privileged installed service or a human-operated consent window.
Browser smoke covers the built dashboard against a fixture API, including Secure/HttpOnly
cookies on HTTP localhost. The bundled RSA key is test-only, never an operational credential.

**Not verified:** live Google login with real OAuth credentials, two real Workspace users,
production TLS proxy and real privileged service deployment. Follow the setup above, allow
both real subjects, pair a real Client, request/accept one audit per operator and check both
names in the consent prompt and result. No successful real-Google end-to-end run is claimed.
Server MSRV is now 1.88 because the OIDC dependencies require it; validation used the local
newer toolchain. Full source reinstall/service deployment was not performed for this MVP.

Build cache v2 still checks artifact hashes/glibc before reuse, without executing binaries in
`--no-build`. Old caches need rebuilding. User data/configuration are preserved. Audit findings
are observations from the trusted Client, not independent Server certification or remediation.

## Requirements and roadmap

The canonical requirements and milestone gates are in the parent workspace's local `REQUIREMENTS.md` (§§ 2, 4.1, 8–14). That file is a local development document and is not a dependency or public file in this repository.

## Repository map

```text
Cargo.toml                 Rust workspace
crates/server/              Axum service and storage boundary
web/                        Independent Angular dashboard
install.sh                  Linux source installer (service setup deferred)
packaging/README.md         Linux package ownership and release plan
packaging/product.toml      Package paths and ownership metadata (plan only)
```
