use crate::{
    auth::{self, Auth, Session},
    config::Settings,
    remote,
    storage::{self, PublicIdentity, Store, TrustedClient},
};
use axum::{
    extract::{DefaultBodyLimit, Path, Query, State},
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
}
#[derive(Clone)]
struct RequestRecord {
    client: TrustedClient,
    operator_id: String,
    issued: u64,
    requester: Value,
}
fn requester_metadata(operator_name: &str, server_name: &str) -> Value {
    json!({"operatorDisplayName":operator_name,"serverDisplayName":server_name})
}
impl App {
    pub fn new(store: Store, settings: Settings) -> Result<Arc<Self>, String> {
        settings.validate()?;
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
        }))
    }
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
        .route("/api/clients/{id}", axum::routing::delete(remove_client))
        .route("/api/clients/{id}/requests", post(create_request))
        .route("/api/requests/{id}", get(request_status))
        .route("/api/requests/{id}/result", get(request_result))
        .with_state(app)
        .fallback_service(
            tower_http::services::ServeDir::new(web).append_index_html_on_directories(true),
        )
        .layer(DefaultBodyLimit::max(32 * 1024))
        .layer(axum::middleware::from_fn(security_headers))
}
async fn security_headers(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let mut response = next.run(request).await;
    let h = response.headers_mut();
    for (name,value) in [("cache-control","no-store"),("referrer-policy","no-referrer"),("x-content-type-options","nosniff"),("x-frame-options","DENY"),("content-security-policy","default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"),("strict-transport-security","max-age=31536000")] {h.insert(axum::http::HeaderName::from_static(name),axum::http::HeaderValue::from_static(value));}
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
    let (s, local_token) = if let Some((token, local)) = app.auth.local_session() {
        (local, Some(token))
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
    let mut response = Json(json!({"mode":if app.auth.is_local(){"LOCAL"}else{"OIDC"},"operator":s.operator,"authorized":authorized,"csrf":s.csrf})).into_response();
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
        if !app.auth.is_local() {
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
    Ok(Json(app.store.clients().map_err(unavailable)?).into_response())
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Import {
    identity: PublicIdentity,
    name: String,
    endpoint: String,
    confirm_fingerprint: String,
}
async fn import_client(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Json(body): Json<Import>,
) -> ApiResult {
    mutation(&app, &headers)?;
    Ok(Json(
        app.store
            .import(
                body.identity,
                &body.name,
                &body.endpoint,
                &body.confirm_fingerprint,
            )
            .map_err(bad)?,
    )
    .into_response())
}
async fn remove_client(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult {
    mutation(&app, &headers)?;
    app.store.remove_client(&id).map_err(unavailable)?;
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
    let reply = remote::request(
        app.store.signing_key().map_err(bad)?,
        r.client.clone(),
        method,
        path,
        body,
    )
    .await
    .map_err(unavailable)?;
    validate_reply(&reply, id, &r.client.id, result).map_err(unavailable)?;
    Ok((
        StatusCode::from_u16(reply.code).map_err(|_| unavailable("invalid remote HTTP status"))?,
        Json(reply.body),
    )
        .into_response())
}
fn validate_reply(
    reply: &remote::Reply,
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
        let response = router
            .clone()
            .oneshot(Request::get("/api/session").body(Body::empty()).unwrap())
            .await
            .unwrap();
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
        let session = router
            .clone()
            .oneshot(Request::get("/api/session").body(Body::empty()).unwrap())
            .await
            .unwrap();
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
