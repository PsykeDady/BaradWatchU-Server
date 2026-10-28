# Server BaradWatchU

*Un server per domarli, un server per trovarli, un server per ghermirli ed alla sicurezza incatenarli.*

[Read in English](README.md)

BaradWatchU è una piattaforma di audit della conformità di sicurezza degli endpoint. Il server gestirà l'arruolamento dei dispositivi, le policy desiderate, le evidenze di audit, l'inventario del parco macchine e i report; l'agente client indipendente raccoglierà osservazioni locali e in futuro le invierà al server.

## Stato

**Implementato in L0.1:** sorgente del servizio HTTP Rust/Axum con `GET /health`; scaffold della dashboard Angular 18 che indica chiaramente che i dati del parco macchine non sono disponibili. Sono solo basi di sviluppo. Qui build e comportamento runtime non sono verificati perché i registry delle dipendenze non erano raggiungibili.

**Pianificato:** arruolamento autenticato, assegnazione delle policy, acquisizione e cronologia degli audit, inventario dei dispositivi, report e persistenza SQLite dietro un confine di storage predisposto per PostgreSQL. Nessuna di queste funzionalità è ancora implementata.

## Architettura

- `crates/server`: eseguibile del servizio Rust; `src/main.rs` gestisce l'avvio HTTP e la rotta health; `src/storage.rs` definisce il confine di persistenza senza implementarlo.
- `web`: dashboard Angular, compilata separatamente e non ancora servita dal processo Rust.
- Aree API future: arruolamento, policy, acquisizione audit, inventario e report. Non sono esposte rotte funzionali segnaposto.
- SQLite è il database iniziale previsto; schema e adapter saranno realizzati quando la persistenza rientrerà nell'ambito.

## Prerequisiti

- Toolchain Rust stable con Cargo e rustfmt (base workspace: Rust 1.80+).
- Node.js 20.11+ e npm 8+ per Angular 18 (consigliato Node 20).
- Accesso di rete alla prima risoluzione delle dipendenze, salvo dipendenze già in cache.

## Comandi

Dalla radice del repository:

```sh
cargo fmt --all -- --check
cargo test --workspace
cargo run -p baradwatchu-server
```

Il servizio ascolta per impostazione predefinita su `127.0.0.1:3000`; impostare `BARADWATCHU_SERVER_ADDR` per cambiarlo. Verificare `http://127.0.0.1:3000/health` per lo stato JSON.

Compilare separatamente la dashboard:

```sh
cd web
npm install
npm run build
```

In questo bootstrap non sono configurati runner o test Angular; i test Rust si eseguono con `cargo test --workspace`.

## Principi di sicurezza

Il progetto segue minimo privilegio, audit in sola lettura, raccolta minima delle evidenze, autorizzazione esplicita delle policy e assenza di shell remota arbitraria. La rotta health non espone dati sensibili. Autenticazione, TLS, controlli di conservazione e storage audit antimanomissione sono lavori futuri da completare prima dell'uso operativo.

## Requisiti e roadmap

I requisiti canonici e le fasi sono nel file locale `REQUIREMENTS.md` della cartella padre (§§ 2, 4.1, 8–14). È un documento locale di sviluppo, non una dipendenza né un file pubblico di questo repository.

## Mappa del repository

```text
Cargo.toml                 Workspace Rust
crates/server/              Servizio Axum e confine storage
web/                        Dashboard Angular indipendente
```
