# BaradWatchU Server

*One Server to rule them all, One Server to find them, One Server to bring them all and in security bind them.*

[Leggi in italiano](LEGGIMI.md)

BaradWatchU is an endpoint security compliance auditing platform. The server will manage device enrollment, desired policies, audit evidence, fleet inventory and reports; the independent client agent will collect local observations and later send them to this server.

## Status

**Implemented in L0.1:** Rust/Axum HTTP service source with `GET /health`; Angular 18 dashboard scaffold that clearly reports that fleet data is unavailable.

**Implemented in L0.1.1:** product version `0.0.1`; Rust `--version`/`-V` and `--help`/`-h`; a Linux source-installer foundation with dependency audit, dry-run, build-cache validation, user/system prefixes and hash-manifest uninstall. Installer/service lifecycle and actual release artifacts remain unverified; no distribution channel is claimed as production-ready.

**Planned:** authenticated enrollment, policy assignment, audit ingestion and history, device inventory, reporting, and SQLite persistence behind a storage boundary that can later support PostgreSQL. None of these features are implemented yet.

## Architecture

- `crates/server`: Rust service binary; `src/main.rs` owns HTTP startup and health route; `src/storage.rs` marks the persistence boundary without an implementation.
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
- Node.js 20.11+ and npm 8+ for Angular 18 (Node 20 recommended).
- Network access on first dependency resolution unless dependencies are already cached.
- GNU/Linux with glibc 2.17+ for this source-build target.

## Commands

From the repository root:

```sh
cargo fmt --all -- --check
cargo test --workspace
cargo run -p baradwatchu-server
cargo run -p baradwatchu-server -- --version
cargo run -p baradwatchu-server -- --help
```

The service listens on `127.0.0.1:3000` by default; set `BARADWATCHU_SERVER_ADDR` to override. Check `http://127.0.0.1:3000/health` for JSON health status.

Build the dashboard separately:

```sh
cd web
npm install
npm run build
```

## Linux source installation

Supported installer detection: Arch Linux, Fedora, Debian and Ubuntu, including `ID_LIKE`. `--missing-deps` only inspects dependencies, reports missing local Angular packages and prints package-manager/project commands; it never installs system packages. Required source-build tools are Rust/Cargo 1.80+, Node.js 20.11+ and npm 8+; glibc 2.17+ is the GNU/Linux runtime baseline. A validated prebuilt cache does not require Node/Angular tooling, but this source installer builds those assets when building from source.

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

`--build-only` prepares and validates a cache without touching an installation. `-h` aliases `--help`, `-U` aliases `--uninstall`, and `--build-dir=DIR` selects the marked build cache. Exit codes are 0 for success, 1 for execution/validation failures, and 2 for invalid or conflicting options.

Source installation builds from this checkout. Arch `pacman`, Debian/Ubuntu `.deb`, and Fedora `.rpm` are planned in [`packaging/README.md`](packaging/README.md); none has a package recipe/artifact yet. The source installer refuses to mix with package-manager ownership.

No Angular test runner or tests are configured. Rust tests run with `cargo test --workspace`. In the initial environment, server and Angular builds could not complete because dependency registry access was unavailable; do not treat the source installer as end-to-end validated until real release builds pass.

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
