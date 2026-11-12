# Server BaradWatchU

*Un server per domarli, un server per trovarli, un server per ghermirli ed alla sicurezza incatenarli.*

[Read in English](README.md)

BaradWatchU Server coordina audit delle postazioni con consenso attraverso il Client indipendente.

## Stato e architettura

L'MVP usa il backend Rust/Axum e la dashboard Angular 18 esistenti. L'autenticazione è
configurabile: LOCAL limitata al loopback per sviluppo oppure Google OIDC Authorization Code
+ PKCE con sessioni cookie backend e allowlist esplicita multi-admin. Entrambe usano lo stesso
pairing manuale Ed25519, inventario Client trusted, richieste/stati/risultati remoti e download
JSON. Esecuzione audit, consenso e cronologia locale restano nel Client.

- `crates/server/src/auth.rs`: discovery Google, scambio codice e verifica dei token firmati;
  i token restano nel backend e vengono scartati. LOCAL emette una sessione loopback con
  etichetta descrittiva operatore e scadenza a otto ore solo al browser che presenta il token di avvio (modello Client, vedi sotto); il logout revoca il token e la sessione successiva riceve nuovi token. Cookie Secure, HttpOnly, SameSite=Lax, limitati all'host;
  le modifiche richiedono token CSRF della sessione e Origin esatto.
- `storage.rs`: SQLite per seed identità, chiavi pubbliche Client e amministratori
  identificati da issuer Google + subject (con ultimo nome/email verificati). Cartella dati
  0700 e database 0600, riservati al proprietario; nessuna identità generata automaticamente.
- `tunnel.rs`, `tls.rs`: ingresso del tunnel aperto dal Client, TLS 1.3/chiavi raw Ed25519,
  verifica reciproca della fiducia e registro delle connessioni attive. Nessun TOFU o trust automatico.
- `http.rs`: API fleet protette e asset Angular compilati sulla stessa origine. OIDC controlla
  l'allowlist a ogni richiesta; LOCAL si affida al listener loopback verificato. La revoca
  admin OIDC vale anche per sessioni già aperte.
- Sessioni (8 ore) e riferimenti richieste (24 ore; massimo 4096) sono in memoria e si perdono
  al riavvio Server. I report ricevuti vengono conservati nel database SQLite esistente dopo il recupero dal Client,
  che li conserva per un'ora in memoria e mantiene separatamente la cronologia locale.
  Ogni operatore recupera le proprie richieste. Un processo Server per cartella dati.

Distribuzione policy, scheduling, remediation, ruoli complessi,
multi-tenancy, discovery, package nativi e packaging del servizio Server restano fuori dall'MVP.
L'installer sorgente continua a non creare un servizio di sistema.

## Versione e CLI

Server e Client hanno cicli di release indipendenti. La versione prodotto autorevole del Server è `[workspace.package].version` nel `Cargo.toml` radice di questo repository; i package Rust la ereditano. La versione Angular nel `package.json` e quella visualizzata nella dashboard sono generate/sincronizzate da questa fonte con `node web/sync-version.mjs` (eseguito anche automaticamente da `npm run build`). Per cambiare versione, aggiornare quella workspace secondo SemVer e lanciare il comando di sincronizzazione. La versione prodotto è distinta dalle versioni API/protocollo/schema; il protocollo remoto resta v1.

```sh
cargo run -p baradwatchu-server -- --version
cargo run -p baradwatchu-server -- --help
```

L'eseguibile release supporta gli stessi flag senza avviare il server HTTP.

## Prerequisiti

- Toolchain Rust stable con Cargo e rustfmt (base workspace: Rust 1.88+).
- Node.js 20.11.1 o successivo nella serie 20 e npm 8+; `web/.nvmrc` seleziona Node 20. I comandi rifiutano versioni Node incompatibili con un messaggio esplicito.
- Accesso di rete alla prima risoluzione delle dipendenze, salvo dipendenze già in cache.
- GNU/Linux con glibc 2.17+ per compilare; la cache registra la glibc effettiva del sistema di build e richiede conservativamente una versione uguale o successiva.
- Per la build sorgente completa: compilatori C/C++, make, Python 3 e tar (anche per eventuali dipendenze npm native).

## Comandi

Dalla radice del repository:

```sh
cargo fmt --all -- --check
cargo test --workspace --locked
cargo build --workspace --locked
cargo build --release --workspace --locked
cargo run -p baradwatchu-server
cargo run -p baradwatchu-server -- --version
cargo run -p baradwatchu-server -- --help
```

Il servizio ascolta per impostazione predefinita su `127.0.0.1:3000`; impostare `BARADWATCHU_SERVER_ADDR` come IP e porta per cambiarlo (IPv6: `[::1]:3000`). Errori di configurazione/bind restituiscono 1, argomenti CLI non validi 2; Ctrl-C/SIGTERM avvia lo shutdown graceful. Verificare `http://127.0.0.1:3000/health` per lo stato JSON.

Compilare separatamente la dashboard:

```sh
cd web
npm ci
npm start       # sviluppo locale
npm test        # test degli strumenti di versione
npm run build   # production
```

Usare `nvm use` in `web/`. Per il flusso completo compilare Angular e aprire
`http://localhost:3000`, servito da Rust. La configurazione viene scelta da
`BARADWATCHU_SERVER_CONFIG` se impostata; altrimenti il Server cerca
`/etc/baradwatchu/server.json`, poi `$XDG_CONFIG_HOME/baradwatchu/server.json` (normalmente
`~/.config/baradwatchu/server.json`). Se non esiste alcun file, parte la dashboard completa in modalità LOCAL sul loopback.
Se il file selezionato esiste ma non è leggibile, l'avvio fallisce: non viene scelta in silenzio
un'altra modalità di autenticazione.
Per sviluppo Angular live, `npm start` resta in primo piano sulla porta 4300 e inoltra `/api`
e `/auth` a `127.0.0.1:3000`; usare `http://localhost:4300` come `publicUrl`. OIDC usa anche
il callback Google corrispondente; LOCAL non richiede callback. Angular non avvia Rust.

## Modalità di autenticazione e sviluppo locale

La modalità si seleziona con `authMode` in `server.json`. Senza file o senza `authMode`
vale `LOCAL`; `OIDC` deve essere esplicita e richiede ancora configurazione Google e
amministratori autorizzati. Avviare `baradwatchu-server dashboard [--no-browser]` e lasciarlo
in esecuzione (`baradwatchu-server` senza argomenti parte senza aprire il browser).

L'avvio LOCAL segue la dashboard del Client: all'avvio il Server genera un token di avvio casuale
di 64 caratteri esadecimali e scrive `{schemaVersion, pid, origin, port, token}` in
`$XDG_RUNTIME_DIR/baradwatchu-server/dashboard.json` (in alternativa `<cartella dati>/run`;
cartella 0700, file 0600), stampa il link `http://localhost:3000/?k=TOKEN` e lo apre tramite il
launcher privato `open-dashboard.html`, così il token non compare mai su una riga di comando. Il
browser conserva il token per scheda (sessionStorage), lo toglie dalla barra degli indirizzi e lo
scambia una sola volta, con l'header `X-BaradWatchU-Token` su `/api/session`, per la sessione con
cookie HttpOnly e CSRF. Senza token `/api/session` risponde 401 `LOCAL_TOKEN_REQUIRED`. Eseguire
di nuovo `dashboard` con lo stesso utente riusa la sessione attiva (porta raggiungibile e PID che
esegue lo stesso eseguibile), come nel Client; il record viene rimosso allo spegnimento. Solo
l'utente che ha avviato il Server può leggere il token. Il Client usa `$XDG_RUNTIME_DIR/baradwatchu/`
e una porta effimera, quindi i due convivono.
L'installer usa `/usr/local`, compila come utente e richiede sudo per installare i file.
LOCAL indica l'autenticazione runtime, non i permessi d'installazione.
Una vecchia copia `~/.local/bin/baradwatchu-server` può precedere quella di sistema nel PATH:
usare `/usr/local/bin/baradwatchu-server` finché la vecchia installazione non viene rimossa esplicitamente.

Per sviluppare senza credenziali OAuth, creare `server.local.json`:

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

Compilare la dashboard con `(cd web && npm run build)` e aprire
`http://localhost:3000`. Se `localOperatorName` manca, il Server usa `USER`, poi
`LOGNAME`/`USERNAME`, poi l'etichetta generica `Operatore locale`. È solo un'etichetta descrittiva: l'accesso
loopback non autentica chi usa il browser e un servizio di sistema può risolvere il nome
del proprio account di servizio. LOCAL richiede bind su `127.0.0.1` o `::1`, URL pubblico
HTTP localhost con qualsiasi porta; l'avvio fallisce con bind wildcard o non loopback.
Gli header `Host` del browser diversi dall'origine configurata o da `127.0.0.1`/`[::1]`/`localhost`
con la porta di ascolto vengono rifiutati (421 `INVALID_HOST`, protezione da DNS rebinding); gli
header forwarded non vengono mai considerati. Usarla solo su una macchina locale/dev fidata,
mai dietro un proxy pubblico. Pairing Server/Client, mTLS, consenso esplicito e timeout
Client di 120 secondi restano invariati.

Per tornare a OIDC, impostare `"authMode": "OIDC"` (omettendo il campo vale LOCAL) e ripristinare il
blocco `google` da `server.example.json` con credenziali locali. Riavviare il Server.
`/api/auth-mode` restituisce `OIDC`, `/api/session` risponde 401 prima del login Google e
`/auth/login` avvia il flusso OIDC esistente; in OIDC la sessione LOCAL non viene emessa. Il logout LOCAL termina la sessione del browser corrente; non identifica né disconnette l’utente del sistema operativo. Una nuova sessione richiede di nuovo il token di avvio (conservato dalla stessa scheda o riaperto con `baradwatchu-server dashboard`).

## Configurare Google OAuth

1. In Google Cloud Console scegliere/creare un progetto. Aprire **Google Auth Platform → Branding**
   e configurare nome applicazione, email supporto e email di contatto.
2. In **Audience** scegliere **Internal** per l'organizzazione Workspace, se disponibile;
   altrimenti **External / Testing**, aggiungendo entrambi gli operatori come utenti di test.
3. In **Data Access** configurare solo `openid`, `email`, `profile` (la console può mostrare
   email/profile come `userinfo.email` e `userinfo.profile`). L'MVP non richiede API di dati
   Workspace né service account.
4. In **Clients → Create client** scegliere **Web application**. Aggiungere l'esatto redirect
   autorizzato **`http://localhost:3000/auth/callback`**. Questo flusso backend non richiede
   registrazione delle origini JavaScript. Per un'istanza distribuita aggiungere
   `https://TUO-SERVER/auth/callback`.
5. Copiare client ID e secret in una configurazione locale privata, mai in Git. Se l'organizzazione
   limita le app OAuth, l'amministratore Workspace deve consentire questo client.

Google ammette redirect web-app HTTP localhost in sviluppo; non occorre un dominio pubblico.
Vedere [il flusso web-server Google](https://developers.google.com/identity/protocols/oauth2/web-server)
e [la configurazione consenso](https://developers.google.com/workspace/guides/configure-oauth-consent).

```sh
cp server.example.json server.local.json
chmod 600 server.local.json
# Modificare i placeholder; impostare workspaceDomain al dominio Workspace oppure ometterlo.
export BARADWATCHU_SERVER_CONFIG="$PWD/server.local.json"
export BARADWATCHU_SERVER_DATA_DIR="$HOME/.local/state/baradwatchu-server"
cargo build --workspace --locked
(cd web && npm run build)
cargo run -p baradwatchu-server
```

`server.local.json` è ignorato da Git. In modalità OIDC, `publicUrl` deve essere un'origine HTTPS, salvo HTTP
sull'esatto host `localhost` con backend in ascolto su loopback. `google.redirectUri` deve
corrispondere a `publicUrl/auth/callback`. `webDir` opzionale cambia la cartella dashboard;
il default usa `share/baradwatchu-server/web` installato o la build nel checkout. La configurazione
Google si legge all'avvio: riavviare dopo modifiche. `workspaceDomain` verifica il claim firmato
`hd`, non il suffisso email, e non concede mai l'autorizzazione amministrativa.

I cookie restano Secure anche su localhost (verificato con Chrome); browser privi di questa
eccezione richiedono HTTPS locale. Fuori dallo sviluppo locale usare un reverse proxy TLS
davanti al backend loopback, esponendo solo l'origine HTTPS configurata. Inoltrare tutte le
rotte senza cambiare i percorsi; non esporre direttamente il listener HTTP backend.
Il Server non usa gli header forwarded per determinare l'origine pubblica.

## Primo amministratore e amministratori aggiuntivi

Accedere con Google dalla dashboard. Un utente Google valido fuori dall'allowlist vede solo
issuer/subject verificati e la schermata di autorizzazione richiesta. Non esiste un'API di
registrazione. Come account OS locale proprietario dei dati Server eseguire:

```sh
# Mantenere BARADWATCHU_SERVER_DATA_DIR uguale al valore del Server in esecuzione.
./target/debug/baradwatchu-server setup admin allow GOOGLE_SUBJECT_ONE
./target/debug/baradwatchu-server setup admin allow GOOGLE_SUBJECT_TWO
# La revoca vale dalla prossima richiesta API, senza riavviare.
./target/debug/baradwatchu-server setup admin revoke GOOGLE_SUBJECT_ONE
```

L'issuer è fissato a `https://accounts.google.com`; copiare ogni `sub` dalla relativa schermata
autenticata. Nome/email sono informativi e aggiornati dopo il login. Entrambi gli operatori
abilitati possono chiedere audit; il logout termina solo la sessione BaradWatchU, non quella
Google. Dopo l'abilitazione usare **Check authorization again** (o accedere nuovamente).
Questi piccoli comandi di provisioning locale funzionano anche con il binario installato.

## Pairing manuale e flusso audit

Generare l'identità Server dalla dashboard autorizzata oppure esplicitamente:

```sh
./target/debug/baradwatchu-server setup identity generate "Company Server"
./target/debug/baradwatchu-server setup identity export > server-public.json
```

La generazione rifiuta di sostituire un'identità esistente. Importare `server-public.json` sul
Client con `baradwatchu-agent trust import server-public.json`, dopo verifica indipendente del
fingerprint. Esportare l'identità Client (`baradwatchu-agent identity export --output client-public.json`)
e selezionare il file JSON nella dashboard Server. Nome e fingerprint sono mostrati dal file;
non occorre riscrivere il fingerprint. Verificare indipendentemente l'impronta mostrata prima di confermare. La chiave pubblica importata rimane la base della fiducia. Il Server non salva l'indirizzo del Client. Dopo la registrazione il modulo si svuota e
mostra il Client registrato. Il comando CLI equivalente è:

```sh
./target/debug/baradwatchu-server setup client import client-public.json "Workstation"
```

Il Client richiede il servizio di sistema in esecuzione, `remote enable` e la scheda **Connessioni attive** configurata con DNS oppure IP e porta del tunnel Server (predefinita 7445). Il Client apre il canale autenticato; la flotta Server mostra **Connesso** solo finché è attivo. Il tunnel Server ascolta per impostazione predefinita su `0.0.0.0:7445` (modificabile con `BARADWATCHU_SERVER_TUNNEL_ADDR`); esporre solo questa porta mTLS, mentre HTTP della dashboard LOCAL resta su loopback. Per il consenso servono sessione utente e tray collegate. Configurare firewall e routing per la porta Server. Aggiornare servizio **e**
agente Client: i vecchi lettori strict v1 rifiutano i metadati richiedente opzionali. Nessun
fallback automatico elimina l'attribuzione. Selezionare **Request audit** nel Server: il Client
chiede consenso nominando operatore Google e Server. Solo l'accettazione locale entro **120
secondi** avvia l'esecuzione. BUSY non accoda; UNAVAILABLE, REJECTED, EXPIRED e FAILED sono
mostrati esplicitamente. Dopo errori di connessione **Retry same request** mantiene lo stesso
ID; non creare automaticamente una seconda richiesta. Il polling si ferma sugli errori e può
essere ripreso.

Il report completato è visualizzato e scaricabile come JSON. Registra `LOCAL`/`REMOTE` e,
per audit remoti, nome operatore e riferimento Server. Cronologia e PDF Client riportano la
stessa attribuzione. La chiave trusted del Server autentica la richiesta; il nome non lo fa.
I vecchi report restano leggibili con origine sconosciuta. Email/sub Google non sono inviati
al Client. La durata del risultato di un'ora è distinta dai 120 secondi del consenso; il riavvio
del servizio Client perde i risultati in memoria, quello Server perde riferimenti/sessioni,
e nessuno dei due cancella la cronologia Client. La dashboard mantiene l'ultimo ID nella
memoria della scheda, associato all'operatore, per refresh finché il processo Server resta attivo.

La dashboard riprende la palette Ash & Ember del Client e consente di scegliere italiano o
inglese (preferenza condivisa con il Client tramite language.json). La scheda Requisiti elenca
il catalogo Client abbinato, con descrizioni localizzate, priorità, differenze per piattaforma,
percorsi e SHA-256. Aprendo una voce si può leggere il sorgente Client incluso. Il Server non
esegue questi file e non mostra risultati di esecuzione in questo catalogo.

Il risultato permette anche di aprire un PDF stampabile con il renderer Client (template
1.3.0), conservando versione Client, osservazioni e richiedente originali. La stampa usa il
JSON ricevuto senza eseguire controlli o modificare il report. Il Client deve ancora conservare
il risultato: la durata di un’ora si applica al recupero JSON e PDF. Nelle impostazioni si
sceglie lo stesso tema del Client: `$XDG_CONFIG_HOME/baradwatchu/report-theme.json` e
`themes/*.json` (normalmente sotto `~/.config/baradwatchu`). La condivisione è intenzionale.

Il Server legge il modello audit Client, rifiuta schemi invalidi e ID requisito duplicati e
segnala incoerenze nella sintassi dei digest, dichiarazioni VERIFIED, stati dei file, blocchi
di integrità delle cartelle e contatori installazione. I report storici senza provenienza
restano leggibili con evidenze sconosciute. Il digest del manifest è un’osservazione: non può
essere ricalcolato dalla sola lista di hash dei file. Le aspettative definite indipendentemente
sul Server restano distinte dalle dichiarazioni del Client.

## Installazione Linux da sorgenti


Prima di modificare i file durante installazione, aggiornamento o rimozione, l'installer arresta i processi dell'installazione selezionata appartenenti all'utente chiamante (anche tramite sudo). Confronta il percorso esatto dell'eseguibile, invia SIGTERM e attende fino a 10 secondi; `BARADWATCHU_STOP_TIMEOUT=1..99` cambia il limite. Un timeout interrompe l'operazione prima di modificare i file installati; non viene usato SIGKILL. I processi di altri utenti e di altri prefissi restano attivi e vengono segnalati. Riavviare manualmente con il comando installato `baradwatchu-server dashboard`. `--dry-run` mostra il piano effettivo senza arrestare processi. Verifiche del ciclo dei processi: `python3 tools/test-installer-lifecycle.py` (prefissi temporanei, senza root né installazione reale).

Il selettore lingua nelle Impostazioni salva `system`, `italian` o `english` nel file compatibile con il Client `baradwatchu/language.json`, nella directory di configurazione dell’account Server. Le etichette della dashboard provengono dai cataloghi JSON tramite `/api/messages`; la stampa PDF legge la stessa preferenza. La modifica richiede una sessione autorizzata e la protezione CSRF. È condivisa con il Client eseguito dallo stesso account, non è una preferenza OIDC per browser.

### Catalogo Client, aspettative Server e controlli personalizzati

Il binario Server include `catalog/builtin-tools.sha256`, configurazioni e sorgenti dei tool
Client abbinati per Linux e Windows. È il catalogo atteso predefinito e compare nella scheda
Requisiti con la versione Client abbinata. Il digest completo è mostrato nella dashboard;
quello del manifest incluso è `4d4ddfb5a3b3db91adef6061acaaa0f9d8b83583c5cc4be3eb4198fef4dc3aeb`.
Gli amministratori possono sostituire il manifest con quello di un pacchetto Client più
recente e verificato; la modifica per tutta la flotta viene salvata in SQLite e non richiede
la reinstallazione del Server. Nella scheda Requisiti il manifest attivo `builtin-tools.sha256`
è mostrato in sola lettura; per sostituirlo occorre selezionare un file con quel nome esatto
e confermare la modifica per tutta la flotta. Il ripristino riattiva il manifest incluso nel
Server installato. Un aggiornamento Server senza override adotta il nuovo catalogo incluso.
La sezione del manifest si trova dopo l’elenco e il modulo dei controlli personalizzati.

La scheda Requisiti permette anche di creare controlli personalizzati usando i campi del
Client: ID, nome, descrizione, priorità, file tool, argomenti e timeout. Il Server conserva
tool e metadati ma non li esegue. L’esportazione crea un pacchetto JSON portabile. Nel Client,
in Controlli personalizzati, selezionare **Importa pacchetto Server**, verificare i campi
precompilati e confermare; il Client calcola e registra lo SHA-256 del tool all’importazione.
Il Client lo esegue solo dopo il normale flusso locale di importazione e una successiva azione
di audit/controllo.

Per un audit ricevuto, il Server confronta ogni digest riportato per i file installati e
l’hash atteso dichiarato dal Client con il manifest atteso attivo. Distingue file mancanti,
aggiuntivi, duplicati e non verificati. Evidenza di installazione mancante o piattaforma
assente è sconosciuta. Una corrispondenza completa richiede il digest esatto del manifest e
tutti i file attesi con identità, stato e digest coerenti, senza file aggiuntivi. Sono
osservazioni autenticate via mTLS: non provano l’esecuzione dei controlli e non firmano il report.

I test estesi con Client reale verificano anche la cronologia Server dopo l’arresto del Client, isolamento/revoca degli operatori, cancellazione e uguaglianza byte per byte dei PDF con il Client usando lo stesso tema predefinito e lingua inglese. Eseguire con preferenze Server isolate:

```sh
python3 tools/test-remote-history.py --client /percorso/assoluto/baradwatchu-agent
# Opzionale: --artifacts /tmp/baradwatchu-pdf-review
```

La fixture disabilita i nove controlli integrati per una prova rapida di trasporto/consenso/report e accetta il consenso tramite CLI Client. Non verifica controlli privilegiati, finestre di consenso umano o login Google reale.

L’intestazione PDF del Client distingue origine remota e locale; i report storici senza attribuzione indicano origine sconosciuta.

### Cronologia dei report ricevuti

La scheda Cronologia elenca i report recuperati dall’operatore con identità Client, data di completamento, byte JSON occupati, apertura/download/stampa e conferme di eliminazione/svuotamento. Un report aperto, come nella vista del Client, ordina gli esiti per gravità (ERROR, FAIL, WARN, …) e offre filtri sui contatori di stato e ricerca per ID o nome. Il JSON viene conservato nel database SQLite privato esistente del Server, inclusi i campi originali sconosciuti a questa versione. Non viene generato alcun audit. Rispetto alla cache su file del Client per un solo account, il Server usa il database per separare le copie per operatore e ID richiesta (i timestamp possono coincidere tra Client). I PDF vengono renderizzati su richiesta dal JSON salvato, con renderer Client e tema condiviso; non viene conservato un file PDF aggiuntivo.

I report sopravvivono ai riavvii Server e alla scadenza della cache remota Client di un’ora, fino all’eliminazione esplicita. Solo l’operatore richiedente può accedervi e OIDC verifica sempre l’autorizzazione admin corrente. La rimozione della fiducia Client impedisce nuovi recuperi remoti ma conserva la cronologia già ricevuta. Recuperi ripetuti sono idempotenti; contenuti diversi per lo stesso ID richiesta vengono rifiutati. La cancellazione è locale al Server; recuperare nuovamente il risultato remoto può salvarne una nuova copia. I confronti usano le aspettative Server attuali. L’occupazione conta i byte dei contenuti JSON, non l’allocazione SQLite su disco; la cancellazione elimina i record senza garantire la riduzione immediata del file database. Non è configurata una scadenza automatica.

Rilevamento installer supportato: Arch Linux, Fedora, Debian e Ubuntu, anche tramite `ID_LIKE`. `--missing-deps` controlla solo le dipendenze, rileva i package Angular locali mancanti e mostra comandi package manager/progetto; non installa pacchetti di sistema. Strumenti richiesti per compilare: Rust/Cargo 1.88+, Node.js 20 >=20.11.1, npm 8+, C/C++, make, Python 3 e tar; glibc 2.17+ è il minimo controllato sul sistema di build. Una cache precompilata e validata non richiede Node/Angular, mentre la build sorgente eseguita dall'installer compila anche questi asset.

L'installer segue `web/.nvmrc`: se il Node attivo non è un Node 20 supportato, carica nvm
dell'utente e seleziona la versione indicata prima di controllare o usare npm. Usa così l'npm
associato a quel Node e non richiede pacchetti Node/npm di sistema se nvm fornisce già Node 20.

```sh
./install.sh --help
./install.sh --missing-deps
./install.sh --dry-run --prefix=/tmp/baradwatchu-preview
./install.sh                                  # compila come utente, installa in /usr/local con sudo
./install.sh --build-only --build-dir="$HOME/.cache/baradwatchu/baradwatchu-server-0.0.1"
sudo ./install.sh --no-build --build-dir="$HOME/.cache/baradwatchu/baradwatchu-server-0.0.1" --prefix=/usr/local
./install.sh --uninstall --prefix=/usr/local
```

`--no-build` richiede una cache completa prodotta dallo stesso albero sorgente, versione e piattaforma. `./install.sh` compila come utente corrente e poi usa sudo per installare in `/usr/local`. Per un prefisso di sistema, compilare prima come utente non privilegiato e installare poi con `sudo ./install.sh --no-build --prefix=/usr/local`; non compilare come root. Nessuna modalità crea un servizio o una configurazione di produzione. La disinstallazione rimuove solo file invariati elencati nel manifest sorgente; rifiuta file gestiti da package manager o modificati e conserva configurazione/dati. Gli aggiornamenti usano lo stesso manifest. Nessun servizio viene riavviato.

`--build-only` usa Cargo `--locked` e una copia temporanea di Angular nella cache: `npm ci` non sostituisce `node_modules` del checkout. Dipendenze, log npm e header node-gyp rimangono nella cache. I sorgenti devono restare invariati durante la build. `-h` è alias di `--help`, `-U` di `--uninstall` e `--build-dir=DIR` seleziona la cache marcata. Codici di uscita: 0 successo, 1 errore di esecuzione/validazione, 2 opzioni non valide o in conflitto.

L'installazione da sorgenti compila da questo checkout. Arch `pacman`, pacchetto `.deb` per Debian/Ubuntu e `.rpm` Fedora sono pianificati in [`packaging/README.md`](packaging/README.md); non esistono ancora ricette o artefatti. L'installer sorgente rifiuta conflitti di proprietà con package manager.

## Verifiche e limiti

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
# Compilare prima il Client nel proprio repository; test incrociato isolato esplicito:
BWU_CLIENT_BIN=/absolute/path/to/BaradWatchU-Client/target/debug/baradwatchu-agent \
  cargo test --lib two_oidc_admins --locked -- --ignored --nocapture
(cd web && npm test && npm run build)
# Richiede Chrome e WebSocket sperimentale di Node 20:
(cd web && node --experimental-websocket dashboard.smoke.mjs)
```

La verifica automatica copre provider OIDC simulato con firma RSA/scambio codice/PKCE, claim
non validi, replay, allowlist/CSRF/sessioni, trust manuale e framing HTTP. Il test esplicito usa
due operatori Google simulati, abilitati separatamente, attraverso router/mTLS Server reali e
processi Client servizio/link/audit reali ma isolati; il consenso locale viene dato dalla CLI.
Controlla entrambi i nomi in consenso, JSON restituito, cronologia in cache e PDF. Non usa
credenziali Google, servizio installato privilegiato o finestra consenso azionata da una persona.
Lo smoke browser verifica la dashboard compilata con API fixture, inclusi cookie Secure/HttpOnly
su HTTP localhost. La chiave RSA inclusa è solo di test, mai una credenziale operativa.

**Non verificati:** login Google reale con credenziali OAuth, due utenti Workspace reali,
proxy TLS di produzione e distribuzione del servizio privilegiato. Seguire la configurazione,
abilitare entrambi i subject reali, associare un Client reale, chiedere/accettare un audit per
operatore e controllare entrambi i nomi in consenso e risultato. Non si dichiara un end-to-end
riuscito con Google reale. MSRV Server passa a 1.88 per le dipendenze OIDC; la validazione usa
la toolchain locale più recente. Non è stata eseguita una reinstallazione sorgente completa
né la distribuzione del servizio per questo MVP.

La cache build v2 continua a verificare hash/glibc prima del riuso, senza eseguire binari con
`--no-build`. Le vecchie cache richiedono rebuild. Dati/configurazione utente sono conservati.
Gli esiti sono osservazioni del Client trusted, non certificazione indipendente o remediation Server.

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
