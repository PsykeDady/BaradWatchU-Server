# Server BaradWatchU

*Un server per domarli, un server per trovarli, un server per ghermirli ed alla sicurezza incatenarli.*

[Read in English](README.md)

BaradWatchU è una piattaforma di audit della conformità di sicurezza degli endpoint. Il server gestirà l'arruolamento dei dispositivi, le policy desiderate, le evidenze di audit, l'inventario del parco macchine e i report; l'agente client indipendente raccoglierà osservazioni locali e in futuro le invierà al server.

## Stato

**Implementato in L0.1:** sorgente del servizio HTTP Rust/Axum con `GET /health`; scaffold della dashboard Angular 18 che indica chiaramente che i dati del parco macchine non sono disponibili.

**Implementato in L0.1.1:** versione prodotto `0.0.1`; flag Rust `--version`/`-V` e `--help`/`-h`; base dell'installer Linux da sorgenti con audit dipendenze, dry-run, validazione cache build, prefissi utente/sistema e disinstallazione tramite manifest hash. Installer, ciclo di vita del servizio e artefatti release non sono ancora verificati; nessun canale è dichiarato pronto per la produzione.

**Pianificato:** arruolamento autenticato, assegnazione delle policy, acquisizione e cronologia degli audit, inventario dei dispositivi, report e persistenza SQLite dietro un confine di storage predisposto per PostgreSQL. Nessuna di queste funzionalità è ancora implementata.

## Architettura

- `crates/server`: eseguibile del servizio Rust; `src/main.rs` gestisce l'avvio HTTP e la rotta health; `src/storage.rs` definisce il confine di persistenza senza implementarlo.
- `web`: dashboard Angular, compilata separatamente e non ancora servita dal processo Rust.
- Aree API future: arruolamento, policy, acquisizione audit, inventario e report. Non sono esposte rotte funzionali segnaposto.
- SQLite è il database iniziale previsto; schema e adapter saranno realizzati quando la persistenza rientrerà nell'ambito.

## Versione e CLI

Server e Client hanno cicli di release indipendenti. La versione prodotto autorevole del Server è `[workspace.package].version` nel `Cargo.toml` radice di questo repository; i package Rust la ereditano. La versione Angular nel `package.json` e quella visualizzata nella dashboard sono generate/sincronizzate da questa fonte con `node web/sync-version.mjs` (eseguito anche automaticamente da `npm run build`). Per cambiare versione, aggiornare quella workspace secondo SemVer e lanciare il comando di sincronizzazione. La versione prodotto è distinta dalle future versioni API/protocollo/schema, ancora da definire.

```sh
cargo run -p baradwatchu-server -- --version
cargo run -p baradwatchu-server -- --help
```

L'eseguibile release supporta gli stessi flag senza avviare il server HTTP.

## Prerequisiti

- Toolchain Rust stable con Cargo e rustfmt (base workspace: Rust 1.80+).
- Node.js 20.11+ e npm 8+ per Angular 18 (consigliato Node 20).
- Accesso di rete alla prima risoluzione delle dipendenze, salvo dipendenze già in cache.
- GNU/Linux con glibc 2.17+ per questo target di compilazione.

## Comandi

Dalla radice del repository:

```sh
cargo fmt --all -- --check
cargo test --workspace
cargo run -p baradwatchu-server
cargo run -p baradwatchu-server -- --version
cargo run -p baradwatchu-server -- --help
```

Il servizio ascolta per impostazione predefinita su `127.0.0.1:3000`; impostare `BARADWATCHU_SERVER_ADDR` per cambiarlo. Verificare `http://127.0.0.1:3000/health` per lo stato JSON.

Compilare separatamente la dashboard:

```sh
cd web
npm install
npm run build
```

## Installazione Linux da sorgenti

Rilevamento installer supportato: Arch Linux, Fedora, Debian e Ubuntu, anche tramite `ID_LIKE`. `--missing-deps` controlla solo le dipendenze, rileva i package Angular locali mancanti e mostra comandi package manager/progetto; non installa pacchetti di sistema. Strumenti richiesti per compilare: Rust/Cargo 1.80+, Node.js 20.11+ e npm 8+; glibc 2.17+ è il requisito runtime GNU/Linux. Una cache precompilata e validata non richiede Node/Angular, mentre la build sorgente eseguita dall'installer compila anche questi asset.

```sh
./install.sh --help
./install.sh --missing-deps
./install.sh --dry-run --prefix=/tmp/baradwatchu-preview
./install.sh --local                         # copia di sviluppo limitata all'utente
./install.sh --build-only --build-dir="$HOME/.cache/baradwatchu/baradwatchu-server-0.0.1"
sudo ./install.sh --no-build --build-dir="$HOME/.cache/baradwatchu/baradwatchu-server-0.0.1" --prefix=/usr/local
./install.sh --uninstall --prefix=/usr/local
```

`--no-build` richiede una cache completa prodotta dallo stesso albero sorgente, versione e piattaforma. Per un prefisso di sistema, compilare prima come utente non privilegiato e poi installare con `sudo` e `--no-build`; non compilare come root. `--local` installa in `~/.local` per uso manuale di sviluppo. Nessuna modalità crea un servizio o una configurazione di produzione. La disinstallazione rimuove solo file invariati elencati nel manifest sorgente; rifiuta file gestiti da package manager o modificati e conserva configurazione/dati. Gli aggiornamenti usano lo stesso manifest. Nessun servizio viene riavviato.

`--build-only` prepara e valida una cache senza toccare un'installazione. `-h` è alias di `--help`, `-U` di `--uninstall` e `--build-dir=DIR` seleziona la cache marcata. Codici di uscita: 0 successo, 1 errore di esecuzione/validazione, 2 opzioni non valide o in conflitto.

L'installazione da sorgenti compila da questo checkout. Arch `pacman`, pacchetto `.deb` per Debian/Ubuntu e `.rpm` Fedora sono pianificati in [`packaging/README.md`](packaging/README.md); non esistono ancora ricette o artefatti. L'installer sorgente rifiuta conflitti di proprietà con package manager.

Non sono configurati runner o test Angular; i test Rust si eseguono con `cargo test --workspace`. Nell'ambiente iniziale build server e Angular non sono riuscite per l'indisponibilità dei registry delle dipendenze; l'installer non va considerato validato end-to-end finché build release reali non superano i controlli.

## Principi di sicurezza

Il progetto segue minimo privilegio, audit in sola lettura, raccolta minima delle evidenze, autorizzazione esplicita delle policy e assenza di shell remota arbitraria. La rotta health non espone dati sensibili. Autenticazione, TLS, controlli di conservazione e storage audit antimanomissione sono lavori futuri da completare prima dell'uso operativo.

## Requisiti e roadmap

I requisiti canonici e le fasi sono nel file locale `REQUIREMENTS.md` della cartella padre (§§ 2, 4.1, 8–14). È un documento locale di sviluppo, non una dipendenza né un file pubblico di questo repository.

## Mappa del repository

```text
Cargo.toml                 Workspace Rust
crates/server/              Servizio Axum e confine storage
web/                        Dashboard Angular indipendente
install.sh                  Installer Linux da sorgenti (servizio differito)
packaging/README.md         Piano pacchetti Linux e proprietà file
packaging/product.toml      Metadati piano: percorsi e proprietà
```
