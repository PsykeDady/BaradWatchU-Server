use crate::{
    auth::{self, Auth, Session},
    config::Settings,
    storage::{self, PublicIdentity, RequirementBaseline, Store, TrustedClient},
    tunnel,
};
use axum::{
    extract::{rejection::JsonRejection, DefaultBodyLimit, Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

pub struct App {
    pub store: Store,
    pub auth: Auth,
    pub settings: Settings,
    requests: Mutex<HashMap<String, RequestRecord>>,
    connections: tokio::sync::Semaphore,
    pub tunnels: Arc<tunnel::Registry>,
    /// LOCAL only: random token written by the launcher to a private runtime file (Client model).
    launch_token: Option<String>,
    /// LOCAL only: Host header values accepted from browsers (DNS-rebinding guard).
    allowed_hosts: Vec<String>,
}
#[derive(Clone)]
struct RequestRecord {
    client: TrustedClient,
    operator_id: String,
    issued: u64,
    requester: Value,
    status: Value,
}
fn requester_metadata(operator_name: &str, server_name: &str) -> Value {
    json!({"operatorDisplayName":operator_name,"serverDisplayName":server_name})
}
impl App {
    pub fn new(store: Store, settings: Settings) -> Result<Arc<Self>, String> {
        Self::with_listen_address(store, settings, None)
    }
    pub fn with_listen_address(
        store: Store,
        settings: Settings,
        listen: Option<std::net::SocketAddr>,
    ) -> Result<Arc<Self>, String> {
        settings.validate()?;
        let local = settings.auth_mode == crate::config::AuthMode::Local;
        let launch_token = if local {
            Some(storage::random()?)
        } else {
            None
        };
        let mut allowed_hosts = Vec::new();
        if local {
            let url = url::Url::parse(settings.origin()).map_err(|_| "invalid publicUrl")?;
            let host = match url.host() {
                Some(url::Host::Ipv6(ip)) => format!("[{ip}]"),
                Some(host) => host.to_string(),
                None => return Err("invalid publicUrl".into()),
            };
            let port = url.port_or_known_default().ok_or("invalid publicUrl")?;
            allowed_hosts.push(format!("{host}:{port}"));
            if let Some(address) = listen {
                let port = address.port();
                for host in ["127.0.0.1", "[::1]", "localhost"] {
                    allowed_hosts.push(format!("{host}:{port}"));
                }
            }
        }
        let auth = Auth::new(
            settings.google.clone(),
            settings.local_operator_name.clone(),
        )?;
        Ok(Arc::new(Self {
            store,
            auth,
            settings,
            requests: Mutex::new(HashMap::new()),
            connections: tokio::sync::Semaphore::new(16),
            tunnels: Arc::new(tunnel::Registry::default()),
            launch_token,
            allowed_hosts,
        }))
    }
    /// The LOCAL launch token; `None` in OIDC mode.
    pub fn launch_token(&self) -> Option<&str> {
        self.launch_token.as_deref()
    }
}
/// Constant-time comparison, as in the Client dashboard.
fn token_matches(expected: &str, provided: Option<&str>) -> bool {
    let Some(provided) = provided else {
        return false;
    };
    expected.len() == provided.len()
        && expected
            .bytes()
            .zip(provided.bytes())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0
}
type ApiResult = Result<Response, ApiError>;
struct ApiError(StatusCode, String);
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({"error":self.1}))).into_response()
    }
}
fn bad(error: impl Into<String>) -> ApiError {
    ApiError(StatusCode::BAD_REQUEST, error.into())
}
fn unavailable(error: impl Into<String>) -> ApiError {
    ApiError(StatusCode::BAD_GATEWAY, error.into())
}
fn internal(error: impl Into<String>) -> ApiError {
    ApiError(StatusCode::INTERNAL_SERVER_ERROR, error.into())
}
pub fn router() -> Router {
    Router::new().route("/health", get(health))
}
pub fn application(app: Arc<App>) -> Router {
    let web = app.settings.web_path();
    Router::new()
        .route("/health", get(health))
        .route("/auth/login", get(login))
        .route("/auth/callback", get(callback))
        .route("/api/session", get(session))
        .route("/api/auth-mode", get(auth_mode))
        .route("/auth/logout", post(logout))
        .route("/api/identity", get(identity))
        .route("/api/identity/generate", post(generate))
        .route("/api/clients", get(clients).post(import_client))
        .route(
            "/api/requirements",
            get(requirements).post(save_requirement),
        )
        .route(
            "/api/requirements/{id}",
            axum::routing::delete(remove_requirement),
        )
        .route("/api/clients/{id}", axum::routing::delete(remove_client))
        .route("/api/clients/{id}/requests", post(create_request))
        .route("/api/requests", get(list_requests))
        .route("/api/requests/{id}", get(request_status))
        .route("/api/requests/{id}/result", get(request_result))
        .route("/api/requests/{id}/pdf", get(request_pdf))
        .route("/api/history", get(history).delete(clear_history))
        .route("/api/history/usage", get(history_usage))
        .route(
            "/api/history/{id}",
            get(history_report).delete(delete_history),
        )
        .route("/api/history/{id}/pdf", get(history_pdf))
        .route(
            "/api/expected-manifest",
            get(expected_manifest)
                .put(save_expected_manifest)
                .delete(remove_expected_manifest),
        )
        .route(
            "/api/requirement-definitions",
            get(requirement_definitions).post(save_requirement_definition),
        )
        .route(
            "/api/requirement-definitions/{id}",
            axum::routing::delete(remove_requirement_definition),
        )
        .route(
            "/api/custom-checks",
            get(server_custom_checks)
                .post(save_server_custom_check)
                .layer(DefaultBodyLimit::max(2 * 1024 * 1024)),
        )
        .route(
            "/api/custom-checks/{id}/export",
            get(export_server_custom_check),
        )
        .route(
            "/api/custom-checks/{id}",
            axum::routing::delete(remove_server_custom_check),
        )
        .route("/api/client-catalog/file", get(client_catalog_file))
        .route("/api/messages", get(messages))
        .route(
            "/api/configuration/language",
            get(language).put(update_language),
        )
        .route(
            "/api/report-theme",
            get(report_theme).put(update_report_theme),
        )
        .with_state(app.clone())
        .fallback_service(
            tower_http::services::ServeDir::new(web).append_index_html_on_directories(true),
        )
        .layer(DefaultBodyLimit::max(32 * 1024))
        .layer(axum::middleware::from_fn_with_state(app, local_host_guard))
        .layer(axum::middleware::from_fn(security_headers))
}
/// LOCAL: a browser always sends Host; refuse names other than the configured loopback
/// origin so a DNS-rebinding page cannot read the dashboard (Client checks Host likewise).
async fn local_host_guard(
    State(app): State<Arc<App>>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    if app.auth.is_local() {
        if let Some(host) = request.headers().get(header::HOST) {
            let allowed = host.to_str().is_ok_and(|host| {
                app.allowed_hosts
                    .iter()
                    .any(|allowed| allowed.eq_ignore_ascii_case(host))
            });
            if !allowed {
                return ApiError(StatusCode::MISDIRECTED_REQUEST, "INVALID_HOST".into())
                    .into_response();
            }
        }
    }
    next.run(request).await
}
async fn security_headers(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let mut response = next.run(request).await;
    let h = response.headers_mut();
    for (name, value) in [
        ("cache-control", "no-store"),
        ("referrer-policy", "no-referrer"),
        ("x-content-type-options", "nosniff"),
        ("x-frame-options", "DENY"),
        (
            "content-security-policy",
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
        ),
        ("strict-transport-security", "max-age=31536000"),
    ] {
        h.insert(
            axum::http::HeaderName::from_static(name),
            axum::http::HeaderValue::from_static(value),
        );
    }
    response
}
async fn health() -> Json<Value> {
    Json(json!({"status":"ok","service":"baradwatchu-server"}))
}
fn authenticated(app: &App, headers: &HeaderMap) -> Result<Session, ApiError> {
    let token = auth::read_cookie(headers, auth::SESSION_COOKIE)
        .ok_or(ApiError(StatusCode::UNAUTHORIZED, "LOGIN_REQUIRED".into()))?;
    app.auth
        .session(&token)
        .ok_or(ApiError(StatusCode::UNAUTHORIZED, "SESSION_EXPIRED".into()))
}
fn admin(app: &App, headers: &HeaderMap) -> Result<Session, ApiError> {
    let s = authenticated(app, headers)?;
    if !app.auth.is_local()
        && !s
            .operator
            .issuer
            .as_ref()
            .zip(s.operator.sub.as_ref())
            .is_some_and(|(issuer, sub)| {
                app.store.authorized(&storage::Operator {
                    issuer: issuer.clone(),
                    sub: sub.clone(),
                    name: s.operator.name.clone(),
                    email: s.operator.email.clone().unwrap_or_default(),
                })
            })
    {
        return Err(ApiError(
            StatusCode::FORBIDDEN,
            "ADMIN_NOT_AUTHORIZED".into(),
        ));
    }
    Ok(s)
}
fn csrf(app: &App, headers: &HeaderMap, s: &Session) -> Result<(), ApiError> {
    if headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) != Some(app.settings.origin())
        || headers.get("x-bwu-csrf").and_then(|v| v.to_str().ok()) != Some(&s.csrf)
    {
        return Err(ApiError(
            StatusCode::FORBIDDEN,
            "INVALID_CSRF_OR_ORIGIN".into(),
        ));
    }
    Ok(())
}
fn mutation(app: &App, headers: &HeaderMap) -> Result<Session, ApiError> {
    let s = admin(app, headers)?;
    csrf(app, headers, &s)?;
    Ok(s)
}
fn set_cookie(response: &mut Response, cookie: String) {
    response.headers_mut().append(
        header::SET_COOKIE,
        cookie.parse().expect("generated cookie"),
    );
}
async fn login(State(app): State<Arc<App>>, headers: HeaderMap) -> ApiResult {
    if app.auth.is_local() {
        return Err(ApiError(
            StatusCode::NOT_FOUND,
            "OIDC_DISABLED_IN_LOCAL_MODE".into(),
        ));
    }
    let old = auth::read_cookie(&headers, auth::LOGIN_COOKIE);
    let (url, token) = app.auth.login(old.as_deref()).await.map_err(unavailable)?;
    let mut response = Redirect::to(&url).into_response();
    set_cookie(&mut response, auth::login_cookie(&token));
    Ok(response)
}
#[derive(Deserialize)]
struct Callback {
    state: String,
    code: Option<String>,
    error: Option<String>,
}
async fn callback(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Query(query): Query<Callback>,
) -> ApiResult {
    if app.auth.is_local() {
        return Err(ApiError(
            StatusCode::NOT_FOUND,
            "OIDC_DISABLED_IN_LOCAL_MODE".into(),
        ));
    }
    let browser = auth::read_cookie(&headers, auth::LOGIN_COOKIE)
        .ok_or_else(|| bad("LOGIN_COOKIE_MISSING"))?;
    if query.error.is_some() {
        return Err(bad("GOOGLE_LOGIN_CANCELLED"));
    }
    let op = app
        .auth
        .callback(
            &browser,
            &query.state,
            query.code.as_deref().ok_or_else(|| bad("MISSING_CODE"))?,
        )
        .await
        .map_err(bad)?;
    app.store.update_operator(&op).map_err(unavailable)?;
    let old = auth::read_cookie(&headers, auth::SESSION_COOKIE);
    let token = app
        .auth
        .establish(op, old.as_deref())
        .map_err(unavailable)?;
    let mut response = Redirect::to("/").into_response();
    set_cookie(&mut response, auth::session_cookie(&token));
    set_cookie(&mut response, auth::cookie(auth::LOGIN_COOKIE, "", 0));
    Ok(response)
}
async fn session(State(app): State<Arc<App>>, headers: HeaderMap) -> ApiResult {
    let (s, local_token) = if app.auth.is_local() {
        match auth::read_cookie(&headers, auth::SESSION_COOKIE)
            .and_then(|token| app.auth.session(&token).map(|session| (token, session)))
        {
            Some(pair) => (pair.1, Some(pair.0)),
            None => {
                // Like the Client token: only the owner of the private runtime file can start a session.
                let provided = headers
                    .get("x-baradwatchu-token")
                    .and_then(|value| value.to_str().ok());
                if !app
                    .launch_token()
                    .is_some_and(|expected| token_matches(expected, provided))
                {
                    return Err(ApiError(
                        StatusCode::UNAUTHORIZED,
                        "LOCAL_TOKEN_REQUIRED".into(),
                    ));
                }
                let (token, session) = app.auth.local_session().map_err(unavailable)?;
                (session, Some(token))
            }
        }
    } else {
        (authenticated(&app, &headers)?, None)
    };
    let authorized = app.auth.is_local()
        || s.operator
            .issuer
            .as_ref()
            .zip(s.operator.sub.as_ref())
            .is_some_and(|(issuer, sub)| {
                app.store.authorized(&storage::Operator {
                    issuer: issuer.clone(),
                    sub: sub.clone(),
                    name: s.operator.name.clone(),
                    email: s.operator.email.clone().unwrap_or_default(),
                })
            });
    let mut response=Json(json!({"mode":if app.auth.is_local(){"LOCAL"}else{"OIDC"},"operator":s.operator,"authorized":authorized,"csrf":s.csrf})).into_response();
    if let Some(token) = local_token {
        set_cookie(&mut response, auth::session_cookie(&token));
    }
    Ok(response)
}
async fn auth_mode(State(app): State<Arc<App>>) -> Json<Value> {
    Json(json!({"mode":if app.auth.is_local(){"LOCAL"}else{"OIDC"}}))
}
async fn logout(State(app): State<Arc<App>>, headers: HeaderMap) -> ApiResult {
    let s = authenticated(&app, &headers)?;
    csrf(&app, &headers, &s)?;
    if let Some(token) = auth::read_cookie(&headers, auth::SESSION_COOKIE) {
        if app.auth.is_local() {
            app.auth.revoke_local_session(&token);
        } else {
            app.auth.logout(&token);
        }
    }
    let mut r = Json(json!({"ok":true})).into_response();
    set_cookie(&mut r, auth::cookie(auth::SESSION_COOKIE, "", 0));
    Ok(r)
}
async fn identity(State(app): State<Arc<App>>, headers: HeaderMap) -> ApiResult {
    admin(&app, &headers)?;
    Ok(Json(app.store.identity().map_err(unavailable)?).into_response())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Generate {
    name: String,
    confirm: bool,
}
async fn generate(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Json(body): Json<Generate>,
) -> ApiResult {
    mutation(&app, &headers)?;
    if !body.confirm {
        return Err(bad("explicit confirmation required"));
    }
    Ok(Json(app.store.generate(&body.name).map_err(bad)?).into_response())
}
async fn clients(State(app): State<Arc<App>>, headers: HeaderMap) -> ApiResult {
    admin(&app, &headers)?;
    let clients: Vec<Value> = app.store.clients().map_err(unavailable)?.into_iter().map(|client| {
        let connected = app.tunnels.connected(&client.id);
        let reported_name = app.tunnels.reported_name(&client.id);
        json!({"id":client.id,"name":client.name,"publicKey":client.public_key,"fingerprint":client.fingerprint,"connected":connected,"reportedName":reported_name})
    }).collect();
    Ok(Json(clients).into_response())
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Import {
    identity: PublicIdentity,
    name: String,
    confirm_fingerprint: String,
}
async fn import_client(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Json(body): Json<Import>,
) -> ApiResult {
    mutation(&app, &headers)?;
    let client = app
        .store
        .import(body.identity, &body.name, &body.confirm_fingerprint)
        .map_err(bad)?;
    Ok(Json(json!({"id":client.id,"name":client.name,"publicKey":client.public_key,"fingerprint":client.fingerprint,"connected":false})).into_response())
}
async fn remove_client(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult {
    mutation(&app, &headers)?;
    app.store.remove_client(&id).map_err(unavailable)?;
    app.tunnels.disconnect(&id);
    Ok(Json(json!({"ok":true})).into_response())
}
async fn requirements(State(app): State<Arc<App>>, headers: HeaderMap) -> ApiResult {
    admin(&app, &headers)?;
    Ok(Json(app.store.requirement_baselines().map_err(unavailable)?).into_response())
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RequirementInput {
    id: String,
    name: String,
    expected_sha256: String,
    enabled: bool,
}
async fn save_requirement(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Json(body): Json<RequirementInput>,
) -> ApiResult {
    mutation(&app, &headers)?;
    let item = RequirementBaseline {
        id: body.id,
        name: body.name,
        expected_sha256: body.expected_sha256,
        enabled: body.enabled,
    };
    app.store.save_requirement_baseline(&item).map_err(bad)?;
    Ok(Json(item).into_response())
}
async fn remove_requirement(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult {
    mutation(&app, &headers)?;
    app.store
        .remove_requirement_baseline(&id)
        .map_err(unavailable)?;
    Ok(Json(json!({"ok":true})).into_response())
}
fn valid_id(id: &str) -> bool {
    (8..=64).contains(&id.len())
        && id
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Create {
    request_id: String,
}
async fn create_request(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path(client_id): Path<String>,
    Json(body): Json<Create>,
) -> ApiResult {
    let s = mutation(&app, &headers)?;
    if !valid_id(&body.request_id) {
        return Err(bad("invalid requestId"));
    }
    let client = app
        .store
        .clients()
        .map_err(unavailable)?
        .into_iter()
        .find(|c| c.id == client_id)
        .ok_or(ApiError(
            StatusCode::NOT_FOUND,
            "CLIENT_NOT_REGISTERED".into(),
        ))?;
    let identity = app
        .store
        .identity()
        .map_err(unavailable)?
        .ok_or_else(|| bad("GENERATE_SERVER_IDENTITY_FIRST"))?;
    let record = {
        let mut requests = app.requests.lock().unwrap();
        requests.retain(|_, r| storage::now_ms().saturating_sub(r.issued) < 24 * 60 * 60 * 1000);
        if let Some(r) = requests.get(&body.request_id) {
            if r.operator_id != s.operator.id || r.client.id != client_id {
                return Err(ApiError(StatusCode::CONFLICT, "REQUEST_ID_CONFLICT".into()));
            }
            r.clone()
        } else {
            if requests.len() >= 4096 {
                return Err(ApiError(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "REQUEST_LIMIT".into(),
                ));
            }
            let r = RequestRecord {
                client,
                operator_id: s.operator.id.clone(),
                issued: storage::now_ms(),
                requester: requester_metadata(
                    &s.operator.name,
                    identity.name.as_deref().unwrap_or("BaradWatchU Server"),
                ),
                status: json!({"state":"QUEUED","resultAvailable":false}),
            };
            requests.insert(body.request_id.clone(), r.clone());
            r
        }
    };
    let payload = json!({"schemaVersion":"baradwatchu.remote-audit-request.v1","requestId":body.request_id,"operation":"AUDIT_REPORT","issuedAtUnixMs":record.issued,"requester":record.requester});
    forward(
        &app,
        &record,
        &body.request_id,
        "POST",
        "/v1/audit-requests".into(),
        Some(payload),
        false,
    )
    .await
}
async fn list_requests(State(app): State<Arc<App>>, headers: HeaderMap) -> ApiResult {
    let s = admin(&app, &headers)?;
    let now = storage::now_ms();
    let mut entries: Vec<Value> = app.requests.lock().unwrap().iter()
        .filter(|(_, r)| r.operator_id == s.operator.id && now.saturating_sub(r.issued) < 24 * 60 * 60 * 1000)
        .map(|(id, r)| json!({"requestId":id,"clientId":r.client.id,"clientName":r.client.name,"issuedAtUnixMs":r.issued,"status":r.status}))
        .collect();
    entries.sort_by(|a, b| {
        b["issuedAtUnixMs"]
            .as_u64()
            .cmp(&a["issuedAtUnixMs"].as_u64())
    });
    Ok(Json(entries).into_response())
}
fn record(app: &App, headers: &HeaderMap, id: &str) -> Result<RequestRecord, ApiError> {
    let s = admin(app, headers)?;
    let r = app
        .requests
        .lock()
        .unwrap()
        .get(id)
        .filter(|r| {
            r.operator_id == s.operator.id
                && storage::now_ms().saturating_sub(r.issued) < 24 * 60 * 60 * 1000
        })
        .cloned()
        .ok_or(ApiError(StatusCode::NOT_FOUND, "REQUEST_NOT_FOUND".into()))?;
    if !app
        .store
        .clients()
        .map_err(unavailable)?
        .iter()
        .any(|c| c.id == r.client.id && c.public_key == r.client.public_key)
    {
        return Err(ApiError(
            StatusCode::FORBIDDEN,
            "CLIENT_TRUST_REMOVED".into(),
        ));
    }
    Ok(r)
}
async fn request_status(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult {
    let r = record(&app, &headers, &id)?;
    forward(
        &app,
        &r,
        &id,
        "GET",
        format!("/v1/audit-requests/{id}"),
        None,
        false,
    )
    .await
}
async fn request_result(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult {
    let r = record(&app, &headers, &id)?;
    forward(
        &app,
        &r,
        &id,
        "GET",
        format!("/v1/audit-requests/{id}/result"),
        None,
        true,
    )
    .await
}
async fn report_theme(State(app): State<Arc<App>>, headers: HeaderMap) -> ApiResult {
    admin(&app, &headers)?;
    let text = crate::pdf::dashboard_theme_json().map_err(|e| bad(e.0))?;
    Ok(([(header::CONTENT_TYPE, "application/json")], text).into_response())
}
async fn update_report_theme(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> ApiResult {
    mutation(&app, &headers)?;
    let text = crate::pdf::dashboard_update_theme(&body.to_string()).map_err(|e| bad(e.0))?;
    Ok(([(header::CONTENT_TYPE, "application/json")], text).into_response())
}
async fn request_pdf(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult {
    let r = record(&app, &headers, &id)?;
    let _permit = app
        .connections
        .try_acquire()
        .map_err(|_| ApiError(StatusCode::SERVICE_UNAVAILABLE, "SERVER_BUSY".into()))?;
    let reply = tunnel::request(
        app.tunnels.clone(),
        r.client.clone(),
        "GET",
        format!("/v1/audit-requests/{id}/result"),
        None,
    )
    .await
    .map_err(unavailable)?;
    validate_reply(&reply, &id, &r.client.id, true).map_err(unavailable)?;
    if reply.code != 200 {
        return Ok((
            StatusCode::from_u16(reply.code).map_err(|_| unavailable("invalid remote status"))?,
            Json(reply.body),
        )
            .into_response());
    }
    let report = crate::report_integrity::parse(&reply.body["report"]).map_err(unavailable)?;
    app.store
        .remember_report(&r.operator_id, &id, &r.client, &reply.body["report"])
        .map_err(unavailable)?;
    let bytes = tokio::task::spawn_blocking(move || crate::pdf::render_received(&report))
        .await
        .map_err(|_| unavailable("PDF_RENDER_FAILED"))?
        .map_err(bad)?;
    Ok((
        [
            (header::CONTENT_TYPE, "application/pdf"),
            (
                header::CONTENT_DISPOSITION,
                "inline; filename=baradwatchu-client-audit.pdf",
            ),
        ],
        bytes,
    )
        .into_response())
}
async fn forward(
    app: &App,
    r: &RequestRecord,
    id: &str,
    method: &'static str,
    path: String,
    body: Option<Value>,
    result: bool,
) -> ApiResult {
    let _permit = app
        .connections
        .try_acquire()
        .map_err(|_| ApiError(StatusCode::SERVICE_UNAVAILABLE, "SERVER_BUSY".into()))?;
    let mut reply = tunnel::request(app.tunnels.clone(), r.client.clone(), method, path, body)
        .await
        .map_err(unavailable)?;
    validate_reply(&reply, id, &r.client.id, result).map_err(unavailable)?;
    if !result && reply.body["state"].is_string() {
        if let Some(saved) = app.requests.lock().unwrap().get_mut(id) {
            saved.status = reply.body.clone();
        }
    }
    if result && reply.code == 200 {
        let report = crate::report_integrity::parse(&reply.body["report"]).map_err(unavailable)?;
        app.store
            .remember_report(&r.operator_id, id, &r.client, &reply.body["report"])
            .map_err(unavailable)?;
        reply.body["serverRequirementComparison"] = comparison(app, &report)?;
    }
    Ok((
        StatusCode::from_u16(reply.code).map_err(|_| unavailable("invalid remote HTTP status"))?,
        Json(reply.body),
    )
        .into_response())
}
fn validate_reply(
    reply: &tunnel::Reply,
    id: &str,
    device: &str,
    result: bool,
) -> Result<(), String> {
    let b = &reply.body;
    if b["schemaVersion"] == "baradwatchu.remote-error.v1"
        && reply.code >= 400
        && b["error"].is_string()
    {
        return Ok(());
    }
    if b["requestId"] != id || b["deviceId"] != device {
        return Err("CLIENT_RESPONSE_ID_MISMATCH".into());
    }
    if result
        && reply.code == 200
        && b["schemaVersion"] == "baradwatchu.remote-audit-result.v1"
        && b["report"]["schemaVersion"] == "baradwatchu.audit.v1"
    {
        return Ok(());
    }
    if b["schemaVersion"] != "baradwatchu.remote-audit-status.v1"
        || !matches!(
            b["state"].as_str(),
            Some(
                "PENDING_CONSENT"
                    | "RUNNING"
                    | "COMPLETED"
                    | "REJECTED"
                    | "EXPIRED"
                    | "FAILED"
                    | "BUSY"
                    | "UNAVAILABLE"
            )
        )
    {
        return Err("INVALID_CLIENT_RESPONSE".into());
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{to_bytes, Body},
        http::Request,
    };
    use tower::ServiceExt;
    #[test]
    fn requester_metadata_uses_the_current_operator_display_name() {
        assert_eq!(
            requester_metadata("Operatore locale", "Server di sviluppo"),
            json!({"operatorDisplayName":"Operatore locale","serverDisplayName":"Server di sviluppo"})
        );
    }
    #[tokio::test]
    async fn history_api_is_private_and_delete_requires_csrf() {
        let state = local_app();
        let routes = application(state.clone());
        let client = TrustedClient {
            id: "BWU-test".into(),
            name: "Test".into(),
            public_key: "key".into(),
            fingerprint: "SHA256:test".into(),
        };
        let value = json!({"schemaVersion":"baradwatchu.audit.v1","completedAtUnixMs":123,"results":[],"extra":"preserved"});
        state
            .store
            .remember_report("LOCAL", "ours", &client, &value)
            .unwrap();
        state
            .store
            .remember_report("other", "theirs", &client, &value)
            .unwrap();
        for path in [
            "/api/history",
            "/api/history/usage",
            "/api/history/ours",
            "/api/history/ours/pdf",
        ] {
            let response = routes
                .clone()
                .oneshot(Request::get(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }
        let response = routes
            .clone()
            .oneshot(session_request(&state))
            .await
            .unwrap();
        let cookie = response.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        let session: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap();
        let response = routes
            .clone()
            .oneshot(
                Request::get("/api/history/theirs")
                    .header(header::COOKIE, &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let response = routes
            .clone()
            .oneshot(
                Request::get("/api/history/ours")
                    .header(header::COOKIE, &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let saved: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 65536).await.unwrap()).unwrap();
        assert_eq!(saved["report"], value);
        let response = routes
            .clone()
            .oneshot(
                Request::delete("/api/history")
                    .header(header::COOKIE, &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let response = routes
            .oneshot(
                Request::delete("/api/history")
                    .header(header::COOKIE, cookie)
                    .header(header::ORIGIN, "http://localhost:3000")
                    .header("x-bwu-csrf", session["csrf"].as_str().unwrap())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(state.store.history("LOCAL").unwrap().is_empty());
        assert_eq!(state.store.history("other").unwrap().len(), 1);
    }
    #[tokio::test]
    async fn manifest_api_requires_authorization_csrf_and_explicit_provisioning() {
        for state in [app(), local_app()] {
            let routes = application(state.clone());
            for method in ["GET", "DELETE"] {
                let response = routes
                    .clone()
                    .oneshot(
                        Request::builder()
                            .method(method)
                            .uri("/api/expected-manifest")
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            }
            assert!(state.store.expected_manifest().unwrap().is_none());
        }
        let state = local_app();
        let routes = application(state.clone());
        let response = routes
            .clone()
            .oneshot(session_request(&state))
            .await
            .unwrap();
        let cookie = response.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        let session: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap();
        let text = include_str!("../tests/fixtures/client-builtin-tools.sha256");
        let body = json!({"text":text}).to_string();
        let response = routes
            .clone()
            .oneshot(
                Request::put("/api/expected-manifest")
                    .header(header::COOKIE, &cookie)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(state.store.expected_manifest().unwrap().is_none());
        let response = routes
            .oneshot(
                Request::put("/api/expected-manifest")
                    .header(header::COOKIE, cookie)
                    .header(header::ORIGIN, "http://localhost:3000")
                    .header("x-bwu-csrf", session["csrf"].as_str().unwrap())
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            state.store.expected_manifest().unwrap().as_deref(),
            Some(text)
        );
    }
    #[tokio::test]
    async fn requirement_definition_routes_require_authorization_and_csrf() {
        for state in [app(), local_app()] {
            let routes = application(state);
            let response = routes
                .clone()
                .oneshot(
                    Request::get("/api/requirement-definitions")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            let response = routes
                .clone()
                .oneshot(
                    Request::delete("/api/requirement-definitions/CUSTOM-001")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }
        let state = local_app();
        let routes = application(state.clone());
        let response = routes
            .clone()
            .oneshot(session_request(&state))
            .await
            .unwrap();
        let cookie = response.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        let session: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap();
        let body = r#"{"schemaVersion":"baradwatchu.custom-checks.v1","id":"CUSTOM-001","name":"Test","description":"","enabled":false,"priority":"HIGH","overrideBuiltinId":"REQ-001"}"#;
        let response = routes
            .clone()
            .oneshot(
                Request::post("/api/requirement-definitions")
                    .header(header::COOKIE, &cookie)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(state.store.requirement_definitions().unwrap().is_empty());
        let response = routes
            .clone()
            .oneshot(
                Request::post("/api/requirement-definitions")
                    .header(header::COOKIE, &cookie)
                    .header(header::ORIGIN, "http://localhost:3000")
                    .header("x-bwu-csrf", session["csrf"].as_str().unwrap())
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            state.store.requirement_definitions().unwrap()[0]
                .override_builtin_id
                .as_deref(),
            Some("REQ-001")
        );
    }
    #[tokio::test]
    async fn local_logout_revokes_token_and_next_session_rotates_it() {
        let state = local_app();
        let routes = application(state.clone());
        let first = routes
            .clone()
            .oneshot(session_request(&state))
            .await
            .unwrap();
        let first_cookie = first.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        let first_value: Value =
            serde_json::from_slice(&to_bytes(first.into_body(), 4096).await.unwrap()).unwrap();
        let logout = routes
            .clone()
            .oneshot(
                Request::post("/auth/logout")
                    .header(header::COOKIE, &first_cookie)
                    .header(header::ORIGIN, "http://localhost:3000")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("x-bwu-csrf", first_value["csrf"].as_str().unwrap())
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(logout.status(), StatusCode::OK);
        let stale = routes
            .clone()
            .oneshot(
                Request::get("/api/clients")
                    .header(header::COOKIE, &first_cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(stale.status(), StatusCode::UNAUTHORIZED);
        let second = routes.oneshot(session_request(&state)).await.unwrap();
        let second_cookie = second.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap();
        assert_ne!(first_cookie, second_cookie);
        let second_value: Value =
            serde_json::from_slice(&to_bytes(second.into_body(), 4096).await.unwrap()).unwrap();
        assert_ne!(first_value["csrf"], second_value["csrf"]);
    }
    #[tokio::test]
    async fn language_settings_require_authorization_and_csrf() {
        for state in [app(), local_app()] {
            let routes = application(state);
            let response = routes
                .clone()
                .oneshot(
                    Request::get("/api/configuration/language")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            let response = routes
                .clone()
                .oneshot(
                    Request::put("/api/configuration/language")
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Body::from(r#"{"language":"english"}"#))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            let catalog = routes
                .oneshot(Request::get("/api/messages").body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(catalog.status(), StatusCode::OK);
            let catalog: Value =
                serde_json::from_slice(&to_bytes(catalog.into_body(), 65536).await.unwrap())
                    .unwrap();
            assert!(catalog["messages"]["server.settings"].is_string());
            assert!(catalog.get("operator").is_none());
        }
        let state = local_app();
        let routes = application(state.clone());
        let response = routes
            .clone()
            .oneshot(session_request(&state))
            .await
            .unwrap();
        let cookie = response.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        let response = routes
            .oneshot(
                Request::put("/api/configuration/language")
                    .header(header::COOKIE, cookie)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"language":"english"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
    #[tokio::test]
    async fn health_returns_the_bootstrap_contract() {
        let r = router()
            .oneshot(Request::get("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        let v: Value =
            serde_json::from_slice(&to_bytes(r.into_body(), 1024).await.unwrap()).unwrap();
        assert_eq!(v, json!({"status":"ok","service":"baradwatchu-server"}));
    }
    fn app() -> Arc<App> {
        App::new(
            Store::memory(),
            Settings {
                auth_mode: crate::config::AuthMode::Oidc,
                public_url: "https://server.example".into(),
                google: Some(crate::config::OidcConfig {
                    client_id: "id".into(),
                    client_secret: "secret".into(),
                    redirect_uri: "https://server.example/auth/callback".into(),
                    workspace_domain: None,
                }),
                local_operator_name: None,
                web_dir: None,
            },
        )
        .unwrap()
    }
    fn session_request(app: &App) -> Request<Body> {
        let mut request = Request::get("/api/session");
        if let Some(token) = app.launch_token() {
            request = request.header("x-baradwatchu-token", token);
        }
        request.body(Body::empty()).unwrap()
    }
    fn local_app() -> Arc<App> {
        App::new(
            Store::memory(),
            Settings {
                auth_mode: crate::config::AuthMode::Local,
                public_url: "http://localhost:3000".into(),
                google: None,
                local_operator_name: Some("Operatore di sviluppo".into()),
                web_dir: None,
            },
        )
        .unwrap()
    }
    #[tokio::test]
    async fn local_session_requires_launch_token_and_loopback_host() {
        let app = App::with_listen_address(
            Store::memory(),
            local_app().settings.clone(),
            Some("127.0.0.1:3000".parse().unwrap()),
        )
        .unwrap();
        let token = app.launch_token().unwrap().to_owned();
        assert_eq!(token.len(), 64);
        let router = application(app.clone());
        let status = |request: Request<Body>| {
            let router = router.clone();
            async move { router.oneshot(request).await.unwrap().status() }
        };
        let get = || Request::get("/api/session");
        assert_eq!(
            status(get().body(Body::empty()).unwrap()).await,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            status(
                get()
                    .header("x-baradwatchu-token", "0".repeat(64))
                    .body(Body::empty())
                    .unwrap()
            )
            .await,
            StatusCode::UNAUTHORIZED
        );
        for host in ["attacker.example:3000", "localhost:4000", "127.0.0.2:3000"] {
            assert_eq!(
                status(
                    get()
                        .header(header::HOST, host)
                        .header("x-baradwatchu-token", &token)
                        .body(Body::empty())
                        .unwrap()
                )
                .await,
                StatusCode::MISDIRECTED_REQUEST,
                "{host}"
            );
        }
        assert_eq!(
            status(
                Request::get("/")
                    .header(header::HOST, "attacker.example")
                    .body(Body::empty())
                    .unwrap()
            )
            .await,
            StatusCode::MISDIRECTED_REQUEST
        );
        for host in [
            "localhost:3000",
            "127.0.0.1:3000",
            "[::1]:3000",
            "LOCALHOST:3000",
        ] {
            assert_eq!(
                status(
                    get()
                        .header(header::HOST, host)
                        .header("x-baradwatchu-token", &token)
                        .body(Body::empty())
                        .unwrap()
                )
                .await,
                StatusCode::OK,
                "{host}"
            );
        }
        // OIDC never has a launch token and keeps reverse-proxy Host values.
        let oidc = super::tests::app();
        assert!(oidc.launch_token().is_none());
        let response = application(oidc)
            .oneshot(
                Request::get("/api/auth-mode")
                    .header(header::HOST, "server.example")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
    #[tokio::test]
    async fn local_session_unlocks_shared_protected_api_and_disables_oidc_routes() {
        let app = local_app();
        let router = application(app.clone());
        let mode = router
            .clone()
            .oneshot(Request::get("/api/auth-mode").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let mode: Value =
            serde_json::from_slice(&to_bytes(mode.into_body(), 1024).await.unwrap()).unwrap();
        assert_eq!(mode["mode"], "LOCAL");
        let response = router.clone().oneshot(session_request(&app)).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let cookie = response.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        let session: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 2048).await.unwrap()).unwrap();
        assert_eq!(session["mode"], "LOCAL");
        assert_eq!(session["operator"]["name"], "Operatore di sviluppo");
        assert_eq!(session["operator"]["id"], "LOCAL");
        assert!(session["operator"]["issuer"].is_null());
        assert!(session["authorized"].as_bool().unwrap());
        let anonymous_clients = router
            .clone()
            .oneshot(Request::get("/api/clients").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(anonymous_clients.status(), StatusCode::UNAUTHORIZED);
        let clients = router
            .clone()
            .oneshot(
                Request::get("/api/clients")
                    .header(header::COOKIE, &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(clients.status(), StatusCode::OK);
        let csrf = session["csrf"].as_str().unwrap();
        let generated = router
            .clone()
            .oneshot(
                Request::post("/api/identity/generate")
                    .header(header::COOKIE, &cookie)
                    .header(header::ORIGIN, "http://localhost:3000")
                    .header("x-bwu-csrf", csrf)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"name":"Local Server","confirm":true}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(generated.status(), StatusCode::OK);
        let login = router
            .oneshot(Request::get("/auth/login").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(login.status(), StatusCode::NOT_FOUND);
    }
    #[tokio::test]
    async fn protected_routes_require_explicit_allowlist_and_csrf() {
        let app = app();
        let op = storage::Operator {
            issuer: storage::ISSUER.into(),
            sub: "one".into(),
            name: "Mario".into(),
            email: "m@example.com".into(),
        };
        let token = app.auth.establish(op, None).unwrap();
        let cookie = format!("{}={token}", auth::SESSION_COOKIE);
        for (cookie_value, status) in [
            ("".to_string(), StatusCode::UNAUTHORIZED),
            (cookie.clone(), StatusCode::FORBIDDEN),
        ] {
            let r = application(app.clone())
                .oneshot(
                    Request::get("/api/clients")
                        .header(header::COOKIE, cookie_value)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(r.status(), status);
        }
        app.store.allow("one").unwrap();
        let r = application(app.clone())
            .oneshot(
                Request::get("/api/clients")
                    .header(header::COOKIE, &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        let r = application(app.clone())
            .oneshot(
                Request::post("/api/identity/generate")
                    .header(header::COOKIE, &cookie)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"name":"Server","confirm":true}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
        app.store.revoke("one").unwrap();
        let r = application(app)
            .oneshot(
                Request::get("/api/clients")
                    .header(header::COOKIE, cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
    }
    #[tokio::test]
    async fn oidc_mode_has_no_local_session_or_local_auth_bypass() {
        let app = app();
        let router = application(app.clone());
        let session = router.clone().oneshot(session_request(&app)).await.unwrap();
        assert_eq!(session.status(), StatusCode::UNAUTHORIZED);
        assert!(session.headers().get(header::SET_COOKIE).is_none());
        let mode = router
            .oneshot(Request::get("/api/auth-mode").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let value: Value =
            serde_json::from_slice(&to_bytes(mode.into_body(), 1024).await.unwrap()).unwrap();
        assert_eq!(value["mode"], "OIDC");
    }
}

async fn language(State(app): State<Arc<App>>, headers: HeaderMap) -> ApiResult {
    admin(&app, &headers)?;
    Ok(Json(crate::preferences::language_view()).into_response())
}
async fn update_language(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Json(body): Json<crate::preferences::LanguageRequest>,
) -> ApiResult {
    mutation(&app, &headers)?;
    Ok(Json(crate::preferences::save_language(body).map_err(|e| bad(e.0))?).into_response())
}

// Presentation catalog only: usable on the OIDC login screen, no operator data.
async fn messages() -> Json<Value> {
    Json(crate::preferences::language_view())
}

async fn requirement_definitions(State(app): State<Arc<App>>, headers: HeaderMap) -> ApiResult {
    admin(&app, &headers)?;
    Ok(Json(app.store.requirement_definitions().map_err(unavailable)?).into_response())
}
async fn save_requirement_definition(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Json(body): Json<crate::requirement_config::CheckConfiguration>,
) -> ApiResult {
    mutation(&app, &headers)?;
    app.store.save_requirement_definition(&body).map_err(bad)?;
    Ok(Json(body).into_response())
}
async fn remove_requirement_definition(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult {
    mutation(&app, &headers)?;
    app.store
        .remove_requirement_definition(&id)
        .map_err(unavailable)?;
    Ok(Json(json!({"ok":true})).into_response())
}

async fn server_custom_checks(State(app): State<Arc<App>>, headers: HeaderMap) -> ApiResult {
    admin(&app, &headers)?;
    let views = app
        .store
        .server_custom_checks()
        .map_err(unavailable)?
        .iter()
        .map(crate::custom_checks::CustomCheck::public_view)
        .collect::<Result<Vec<_>, _>>()
        .map_err(unavailable)?;
    Ok(Json(views).into_response())
}
async fn save_server_custom_check(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    body: Result<Json<crate::custom_checks::CustomCheck>, JsonRejection>,
) -> ApiResult {
    mutation(&app, &headers)?;
    let Json(body) = body.map_err(|rejection| {
        let detail = rejection.body_text();
        eprintln!("[WARN] custom-check save rejected while decoding JSON: {detail}");
        bad(format!("Richiesta di salvataggio non valida: {detail}"))
    })?;
    let tool = body.validate().map_err(|detail| {
        eprintln!(
            "[WARN] custom-check save rejected during validation id={:?}: {detail}",
            body.id
        );
        bad(format!("Controllo personalizzato non salvato: {detail}"))
    })?;
    use sha2::Digest as _;
    let sha256 = format!("{:x}", sha2::Sha256::digest(&tool));
    eprintln!(
        "[INFO] custom-check save requested id={:?} file={:?} tool_bytes={}",
        body.id,
        body.file_name,
        tool.len()
    );
    if let Err(error) = app.store.save_server_custom_check(&body) {
        eprintln!(
            "[ERROR] custom-check persistence failed id={:?}: {error}",
            body.id
        );
        return Err(internal(
            "Il Server non è riuscito a salvare il controllo personalizzato. Consulta i log del Server.",
        ));
    }
    eprintln!(
        "[INFO] custom-check saved id={:?} tool_sha256={sha256}",
        body.id
    );
    Ok(Json(body.public_view().map_err(internal)?).into_response())
}
async fn export_server_custom_check(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult {
    admin(&app, &headers)?;
    let item = app.store.server_custom_check(&id).map_err(unavailable)?;
    item.validate().map_err(unavailable)?;
    Ok(Json(item).into_response())
}
async fn remove_server_custom_check(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult {
    mutation(&app, &headers)?;
    app.store
        .remove_server_custom_check(&id)
        .map_err(unavailable)?;
    Ok(Json(json!({"ok":true})).into_response())
}
#[derive(Deserialize)]
struct CatalogFileQuery {
    path: String,
}
async fn client_catalog_file(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Query(query): Query<CatalogFileQuery>,
) -> ApiResult {
    admin(&app, &headers)?;
    let bytes = crate::client_catalog::file(&query.path)
        .ok_or_else(|| bad("Client catalog file not found"))?;
    Ok(Json(json!({"path":query.path,"source":String::from_utf8_lossy(bytes)})).into_response())
}

async fn expected_manifest(State(app): State<Arc<App>>, headers: HeaderMap) -> ApiResult {
    admin(&app, &headers)?;
    let configured = app.store.expected_manifest().map_err(unavailable)?;
    let (text, source) = configured
        .as_deref()
        .map(|text| (text, "configured"))
        .unwrap_or((crate::manifest::default_text(), "bundled"));
    Ok(Json(crate::manifest::view(text, source).map_err(unavailable)?).into_response())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestInput {
    text: String,
}
async fn save_expected_manifest(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Json(body): Json<ManifestInput>,
) -> ApiResult {
    mutation(&app, &headers)?;
    app.store.save_expected_manifest(&body.text).map_err(bad)?;
    Ok(Json(crate::manifest::view(&body.text, "configured").map_err(bad)?).into_response())
}
async fn remove_expected_manifest(State(app): State<Arc<App>>, headers: HeaderMap) -> ApiResult {
    mutation(&app, &headers)?;
    app.store.remove_expected_manifest().map_err(unavailable)?;
    Ok(Json(
        crate::manifest::view(crate::manifest::default_text(), "bundled").map_err(unavailable)?,
    )
    .into_response())
}

fn comparison(app: &App, report: &crate::report::AuditReport) -> Result<Value, ApiError> {
    let mut result = crate::report_integrity::inspect(
        report,
        &app.store.requirement_baselines().map_err(unavailable)?,
    );
    let manifest = app
        .store
        .expected_manifest()
        .map_err(unavailable)?
        .unwrap_or_else(|| crate::manifest::default_text().to_owned());
    result["manifest"] = crate::manifest::compare(&manifest, report).map_err(unavailable)?;
    result["definitions"] = json!(app
        .store
        .requirement_definitions()
        .map_err(unavailable)?
        .iter()
        .map(|d| d.compare(report))
        .collect::<Vec<_>>());
    Ok(result)
}
async fn history(State(app): State<Arc<App>>, headers: HeaderMap) -> ApiResult {
    let s = admin(&app, &headers)?;
    Ok(Json(app.store.history(&s.operator.id).map_err(unavailable)?).into_response())
}
async fn history_usage(State(app): State<Arc<App>>, headers: HeaderMap) -> ApiResult {
    let s = admin(&app, &headers)?;
    Ok(Json(
        app.store
            .history_usage(&s.operator.id)
            .map_err(unavailable)?,
    )
    .into_response())
}
fn saved_report(app: &App, headers: &HeaderMap, id: &str) -> Result<Value, ApiError> {
    let s = admin(app, headers)?;
    app.store
        .history_report(&s.operator.id, id)
        .map_err(unavailable)?
        .ok_or(ApiError(StatusCode::NOT_FOUND, "REPORT_NOT_FOUND".into()))
}
async fn history_report(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult {
    let report = saved_report(&app, &headers, &id)?;
    let parsed = crate::report_integrity::parse(&report).map_err(unavailable)?;
    Ok(
        Json(json!({"report":report,"serverRequirementComparison":comparison(&app,&parsed)?}))
            .into_response(),
    )
}
async fn history_pdf(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult {
    let value = saved_report(&app, &headers, &id)?;
    let report = crate::report_integrity::parse(&value).map_err(unavailable)?;
    let _permit = app
        .connections
        .try_acquire()
        .map_err(|_| ApiError(StatusCode::SERVICE_UNAVAILABLE, "SERVER_BUSY".into()))?;
    let bytes = tokio::task::spawn_blocking(move || crate::pdf::render_received(&report))
        .await
        .map_err(|_| unavailable("PDF_RENDER_FAILED"))?
        .map_err(bad)?;
    Ok((
        [
            (header::CONTENT_TYPE, "application/pdf"),
            (
                header::CONTENT_DISPOSITION,
                "inline; filename=baradwatchu-client-audit.pdf",
            ),
        ],
        bytes,
    )
        .into_response())
}
async fn delete_history(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult {
    let s = mutation(&app, &headers)?;
    Ok(Json(
        app.store
            .remove_history(&s.operator.id, Some(&id))
            .map_err(unavailable)?,
    )
    .into_response())
}
async fn clear_history(State(app): State<Arc<App>>, headers: HeaderMap) -> ApiResult {
    let s = mutation(&app, &headers)?;
    Ok(Json(
        app.store
            .remove_history(&s.operator.id, None)
            .map_err(unavailable)?,
    )
    .into_response())
}
