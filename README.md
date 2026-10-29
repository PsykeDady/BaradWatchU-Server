# BaradWatchU Server

*One Server to rule them all, One Server to find them, One Server to bring them all and in security bind them.*

[Leggi in italiano](LEGGIMI.md)

BaradWatchU is an endpoint security compliance auditing platform. The server will manage device enrollment, desired policies, audit evidence, fleet inventory and reports; the independent client agent will collect local observations and later send them to this server.

## Status

**Implemented in L0.1:** Rust/Axum HTTP service source with `GET /health`; Angular 18 dashboard scaffold that clearly reports that fleet data is unavailable.

**Validated in L0.1.1:** version `0.0.1`, Rust CLI, debug/release builds and Angular production build. Regression tests cover startup and version metadata. The installer was checked with isolated caches and prefixes for install/update/uninstall; its complete build reaches the Rust stage, while npm installation in a fresh cache is blocked in the offline environment. System services and native packages remain planned.

**Planned:** authenticated enrollment, policy assignment, audit ingestion and history, device inventory, reporting, and SQLite persistence behind a storage boundary that can later support PostgreSQL. None of these features are implemented yet.

## Architecture

- `crates/server`: Rust service binary; `src/main.rs` owns process/runtime/signal handling; `src/config.rs` validates startup configuration; `src/http.rs` defines the testable router; `src/storage.rs` marks the persistence boundary without an implementation.
- `web`: Angular dashboard, built separately and not yet served by the Rust process.
- Future API areas: enrollment, policies, audit ingestion, inventory and reporting. No placeholder business endpoints are exposed.
- SQLite is the planned initial database; schema and adapter work is deferred until persistence is in scope.

## Version and CLI

Server and Client have independent release lifecycles. The Server's authoritative product version is `[workspace.package].version` in this repository's root `Cargo.toml`; Rust packages inherit it. Angular `package.json` and the displayed dashboard version are generated/synchronized from that source by `node web/sync-version.mjs` (also run automatically by `npm run build`). Change the workspace version using SemVer, then run the sync command. Product version is independent of future API/protocol/schema versions; those contracts are not defined yet.

```sh
cargo run -p baradwatchu-server -- --version
cargo run -p baradwatchu-server -- --help
```

The release executable supports the same flags without starting the HTTP server.

## Prerequisites

- Rust stable toolchain with Cargo and rustfmt (workspace baseline: Rust 1.80+).
- Node.js 20.11.1 or later within Node 20 and npm 8+; `web/.nvmrc` selects Node 20. Commands reject incompatible Node versions with an actionable message.
- Network access on first dependency resolution unless dependencies are already cached.
- GNU/Linux with glibc 2.17+ to build; a cache records the actual build host glibc and conservatively requires the same or a newer version.
- For the full source build: C/C++ compilers, make, Python 3 and tar (including native npm dependency fallbacks).

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

If using nvm, run `nvm use` in `web/` before npm commands. The development UI listens at `http://127.0.0.1:4200` and remains independent of the Rust process. `npm start` stays in the foreground; stop it with Ctrl-C before running other commands in that terminal.

## Linux source installation

Supported installer detection: Arch Linux, Fedora, Debian and Ubuntu, including `ID_LIKE`. `--missing-deps` only inspects dependencies, reports missing local Angular packages and prints package-manager/project commands; it never installs system packages. Required source-build tools are Rust/Cargo 1.80+, Node.js 20 >=20.11.1, npm 8+, C/C++, make, Python 3 and tar; glibc 2.17+ is the minimum checked on the build host. A validated prebuilt cache does not require Node/Angular tooling, but this source installer builds those assets when building from source.

```sh
./install.sh --help
./install.sh --missing-deps
./install.sh --dry-run --prefix=/tmp/baradwatchu-preview
./install.sh --local                         # limited user development copy
./install.sh --build-only --build-dir="$HOME/.cache/baradwatchu/baradwatchu-server-0.0.1"
sudo ./install.sh --no-build --build-dir="$HOME/.cache/baradwatchu/baradwatchu-server-0.0.1" --prefix=/usr/local
./install.sh --uninstall --prefix=/usr/local
```

`--no-build` requires a complete cache created from this exact source tree, version and host platform. For a system prefix, build as an unprivileged user first, then run the install with `sudo` and `--no-build`; never build as root. `--local` installs under `~/.local` for manual development use. Neither mode creates a service or production configuration. Uninstall removes only unchanged payload files listed in the source manifest; it refuses package-manager-owned or modified files and preserves configuration/data. Updates use the same ownership manifest. No service is restarted.

`--build-only` uses Cargo `--locked` and a temporary Angular workspace inside the cache: `npm ci` does not replace checkout `node_modules`. Dependencies, npm logs and node-gyp headers stay in the cache. Sources must remain unchanged during the build. `-h` aliases `--help`, `-U` aliases `--uninstall`, and `--build-dir=DIR` selects the marked build cache. Exit codes are 0 for success, 1 for execution/validation failures, and 2 for invalid or conflicting options.

Source installation builds from this checkout. Arch `pacman`, Debian/Ubuntu `.deb`, and Fedora `.rpm` are planned in [`packaging/README.md`](packaging/README.md); none has a package recipe/artifact yet. The source installer refuses to mix with package-manager ownership.

`cargo test --workspace --locked` runs 8 Rust tests; `npm test` runs 4 version tooling cases. No Angular UI test runner is configured. Formatting, Clippy and Rust/Angular builds are verified. Socket tests are blocked by the sandbox (`EPERM`); `npm start` is configured, but HTTP listening needs verification on the operator host. The Server enables Tokio I/O drivers, reports startup errors without panics, and implements graceful SIGINT/SIGTERM shutdown; the in-process `/health` router test passes, while live HTTP and connection draining remain unverified. Build cache v2 checks artifact hashes and glibc before reuse, without executing binaries in `--no-build`. Older caches require a rebuild; installed configuration and data are preserved.

## Security principles

The project follows least privilege, audit-first behavior, minimal evidence collection, explicit policy authorization, and no arbitrary remote shell. The health endpoint exposes no sensitive data. Authentication, TLS, retention controls and tamper-evident audit storage are future work and must be in place before operational deployment.

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
