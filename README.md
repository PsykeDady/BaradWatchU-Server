# BaradWatchU Server

*One Server to rule them all, One Server to find them, One Server to bring them all and in security bind them.*

[Leggi in italiano](LEGGIMI.md)

BaradWatchU is an endpoint security compliance auditing platform. The server will manage device enrollment, desired policies, audit evidence, fleet inventory and reports; the independent client agent will collect local observations and later send them to this server.

## Status

**Implemented in L0.1:** Rust/Axum HTTP service source with `GET /health`; Angular 18 dashboard scaffold that clearly reports that fleet data is unavailable. These are development foundations only. Builds and runtime behavior remain unverified here because dependency registries were unreachable.

**Planned:** authenticated enrollment, policy assignment, audit ingestion and history, device inventory, reporting, and SQLite persistence behind a storage boundary that can later support PostgreSQL. None of these features are implemented yet.

## Architecture

- `crates/server`: Rust service binary; `src/main.rs` owns HTTP startup and health route; `src/storage.rs` marks the persistence boundary without an implementation.
- `web`: Angular dashboard, built separately and not yet served by the Rust process.
- Future API areas: enrollment, policies, audit ingestion, inventory and reporting. No placeholder business endpoints are exposed.
- SQLite is the planned initial database; schema and adapter work is deferred until persistence is in scope.

## Prerequisites

- Rust stable toolchain with Cargo and rustfmt (workspace baseline: Rust 1.80+).
- Node.js 20.11+ and npm 8+ for Angular 18 (Node 20 recommended).
- Network access on first dependency resolution unless dependencies are already cached.

## Commands

From the repository root:

```sh
cargo fmt --all -- --check
cargo test --workspace
cargo run -p baradwatchu-server
```

The service listens on `127.0.0.1:3000` by default; set `BARADWATCHU_SERVER_ADDR` to override. Check `http://127.0.0.1:3000/health` for JSON health status.

Build the dashboard separately:

```sh
cd web
npm install
npm run build
```

No Angular test runner or tests are configured in this bootstrap; Rust tests run with `cargo test --workspace`.

## Security principles

The project follows least privilege, audit-first behavior, minimal evidence collection, explicit policy authorization, and no arbitrary remote shell. The health endpoint exposes no sensitive data. Authentication, TLS, retention controls and tamper-evident audit storage are future work and must be in place before operational deployment.

## Requirements and roadmap

The canonical requirements and milestone gates are in the parent workspace's local `REQUIREMENTS.md` (§§ 2, 4.1, 8–14). That file is a local development document and is not a dependency or public file in this repository.

## Repository map

```text
Cargo.toml                 Rust workspace
crates/server/              Axum service and storage boundary
web/                        Independent Angular dashboard
```
