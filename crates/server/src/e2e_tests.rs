//! Google is simulated; Server handlers, PKCE verification and Client processes are real.
use crate::{
    client_fixture::Fixture,
    http::{self, App},
    oidc_tests::MockOidc,
    storage::{self, PublicIdentity, Store},
};
use axum::{
    body::{to_bytes, Body},
    http::{header, Request, StatusCode},
    Router,
};
use serde_json::{json, Value};
use std::{sync::Arc, time::Duration};
use tower::ServiceExt;
async fn call(
    router: &Router,
    path: &str,
    method: &str,
    cookie: &str,
    csrf: &str,
    body: Value,
) -> (StatusCode, Value) {
    let mut req = Request::builder()
        .method(method)
        .uri(path)
        .header(header::COOKIE, cookie);
    if method != "GET" {
        req = req
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ORIGIN, "http://localhost:3000")
            .header("x-bwu-csrf", csrf);
    }
    let response = router
        .clone()
        .oneshot(
            req.body(if method == "GET" {
                Body::empty()
            } else {
                Body::from(body.to_string())
            })
            .unwrap(),
        )
        .await
        .unwrap();
    let code = response.status();
    let bytes = to_bytes(response.into_body(), 8 * 1024 * 1024)
        .await
        .unwrap();
    (code, serde_json::from_slice(&bytes).unwrap())
}
async fn verify_history_pdf(
    router: &Router,
    id: &str,
    cookie: &str,
    csrf: &str,
    report: &Value,
    client_pdf: &[u8],
) {
    let (code, history) = call(router, "/api/history", "GET", cookie, csrf, Value::Null).await;
    assert_eq!(code, StatusCode::OK);
    assert_eq!(history.as_array().unwrap().len(), 1);
    assert_eq!(history[0]["id"], id);
    let (code, saved) = call(
        router,
        &format!("/api/history/{id}"),
        "GET",
        cookie,
        csrf,
        Value::Null,
    )
    .await;
    assert_eq!(code, StatusCode::OK);
    assert_eq!(&saved["report"], report);
    let response = router
        .clone()
        .oneshot(
            Request::get(format!("/api/history/{id}/pdf"))
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CONTENT_TYPE], "application/pdf");
    let pdf = to_bytes(response.into_body(), 16 * 1024 * 1024)
        .await
        .unwrap();
    assert!(pdf.starts_with(b"%PDF-1.7"));
    assert_eq!(
        pdf.as_ref(),
        client_pdf,
        "Server and Client rendering of the received report must match with the same language/theme"
    );
    if let Ok(directory) = std::env::var("BWU_E2E_ARTIFACT_DIR") {
        std::fs::write(
            std::path::Path::new(&directory).join(format!("{id}.pdf")),
            &pdf,
        )
        .unwrap();
    }
}
async fn login(router: &Router, mock: &MockOidc, sub: &str, name: &str) -> (String, String) {
    let response = router
        .clone()
        .oneshot(Request::get("/auth/login").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let url = response.headers()[header::LOCATION].to_str().unwrap();
    let browser = response.headers()[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let (code, state) = mock.grant(url, sub, name, json!({}));
    let response = router
        .clone()
        .oneshot(
            Request::get(format!("/auth/callback?code={code}&state={state}"))
                .header(header::COOKIE, browser)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let header = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|h| h.to_str().ok())
        .find(|h| h.starts_with("__Host-bwu-session="))
        .unwrap();
    assert!(
        header.contains("Secure") && header.contains("HttpOnly") && header.contains("SameSite=Lax")
    );
    let cookie = header.split(';').next().unwrap().to_owned();
    let (status, session) = call(router, "/api/session", "GET", &cookie, "", Value::Null).await;
    assert_eq!(status, StatusCode::OK);
    (cookie, session["csrf"].as_str().unwrap().to_owned())
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires BWU_CLIENT_BIN and local sockets; run explicitly after building Client"]
async fn local_mode_operator_name_reaches_consent_and_audit_report() {
    let settings = crate::config::Settings {
        auth_mode: crate::config::AuthMode::Local,
        public_url: "http://localhost:3000".into(),
        google: None,
        local_operator_name: Some("Mario Rossi locale".into()),
        web_dir: None,
    };
    let app = App::new(Store::memory(), settings).unwrap();
    app.store.generate("Local Development Server").unwrap();
    let mut client = Fixture::new("server-local-mode");
    client.trust(
        &app.store.signing_key().unwrap(),
        "Local Development Server",
    );
    client.start_tray();
    client.start_link();
    let public: PublicIdentity = serde_json::from_str(&client.ok(&["identity", "export"])).unwrap();
    let fingerprint = public.fingerprint.clone().unwrap();
    app.store
        .import(public, "Local Test Client", &fingerprint)
        .unwrap();
    let router = http::application(app.clone());
    let (token, session) = app.auth.local_session().unwrap();
    let cookie = format!("{}={token}", crate::auth::SESSION_COOKIE);
    let id = "local-mode-request-001";
    let path = format!("/api/clients/{}/requests", client.device_id);
    let (status, pending) = call(
        &router,
        &path,
        "POST",
        &cookie,
        &session.csrf,
        json!({"requestId":id}),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{pending}");
    let consent = client.pending_remote();
    assert!(consent["prompt"]
        .as_str()
        .unwrap()
        .contains("Mario Rossi locale"));
    assert_eq!(
        consent["expiresAtUnixMs"].as_u64().unwrap() - consent["createdAtUnixMs"].as_u64().unwrap(),
        120_000
    );
    client.ok(&["consent", "accept", consent["requestId"].as_str().unwrap()]);
    for _ in 0..100 {
        let (_, state) = call(
            &router,
            &format!("/api/requests/{id}"),
            "GET",
            &cookie,
            &session.csrf,
            Value::Null,
        )
        .await;
        if state["state"] == "COMPLETED" {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let (status, result) = call(
        &router,
        &format!("/api/requests/{id}/result"),
        "GET",
        &cookie,
        &session.csrf,
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{result}");
    assert_eq!(result["report"]["initiator"]["origin"], "REMOTE");
    assert_eq!(
        result["report"]["initiator"]["operatorDisplayName"],
        "Mario Rossi locale"
    );
    let stamp = result["report"]["completedAtUnixMs"].as_u64().unwrap();
    let cached: Value = serde_json::from_slice(
        &std::fs::read(
            client
                .root
                .join(format!("cache/baradwatchu/audit/reports/{stamp}.json")),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(cached["initiator"], result["report"]["initiator"]);
    let pdf = std::fs::read(result["report"]["pdf"]["path"].as_str().unwrap()).unwrap();
    assert!(String::from_utf8_lossy(&pdf).contains("Mario Rossi locale"));
    // Stop all fixture Client processes: saved history/PDF must work without remote access.
    drop(client);
    verify_history_pdf(&router, id, &cookie, &session.csrf, &result["report"], &pdf).await;
    let (code, removed) = call(
        &router,
        &format!("/api/history/{id}"),
        "DELETE",
        &cookie,
        &session.csrf,
        json!({}),
    )
    .await;
    assert_eq!(code, StatusCode::OK);
    assert_eq!(removed["removedAudits"], 1);
    assert_eq!(
        call(
            &router,
            &format!("/api/history/{id}"),
            "GET",
            &cookie,
            &session.csrf,
            Value::Null
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires BWU_CLIENT_BIN and local sockets; run explicitly after building Client"]
async fn two_oidc_admins_request_real_client_audits_with_named_consent() {
    let mock = MockOidc::start().await;
    let mut app = App::new(Store::memory(), MockOidc::settings()).unwrap();
    Arc::get_mut(&mut app)
        .unwrap()
        .auth
        .use_mock(mock.metadata.clone());
    app.store.generate("Company Server").unwrap();
    app.store.allow("operator-one").unwrap();
    app.store.allow("operator-two").unwrap();
    let mut client = Fixture::new("server-mvp");
    client.trust(&app.store.signing_key().unwrap(), "Company Server");
    client.start_tray();
    client.start_link();
    let public: PublicIdentity = serde_json::from_str(&client.ok(&["identity", "export"])).unwrap();
    let fp = public.fingerprint.clone().unwrap();
    app.store.import(public, "Isolated Client", &fp).unwrap();
    let router = http::application(app.clone());
    let (stranger, csrf) = login(&router, &mock, "stranger", "Unauthorized User").await;
    assert_eq!(
        call(
            &router,
            "/api/clients",
            "GET",
            &stranger,
            &csrf,
            Value::Null
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    for (sub, name) in [
        ("operator-one", "Mario Rossi"),
        ("operator-two", "Giulia Bianchi"),
    ] {
        let (cookie, csrf) = login(&router, &mock, sub, name).await;
        let (status, clients) =
            call(&router, "/api/clients", "GET", &cookie, &csrf, Value::Null).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(clients[0]["id"], client.device_id);
        let id = format!("server-mvp-{sub}");
        let path = format!("/api/clients/{}/requests", client.device_id);
        let (status, pending) = call(
            &router,
            &path,
            "POST",
            &cookie,
            &csrf,
            json!({"requestId":id}),
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED, "{pending}");
        assert_eq!(pending["state"], "PENDING_CONSENT");
        let consent = client.pending_remote();
        assert!(consent["prompt"].as_str().unwrap().contains(name));
        assert!(consent["prompt"]
            .as_str()
            .unwrap()
            .contains("Company Server"));
        let ttl = consent["expiresAtUnixMs"].as_u64().unwrap()
            - consent["createdAtUnixMs"].as_u64().unwrap();
        assert_eq!(ttl, 120_000);
        let (busy_code, busy) = call(
            &router,
            &path,
            "POST",
            &cookie,
            &csrf,
            json!({"requestId":format!("busy-{sub}")}),
        )
        .await;
        assert_eq!(busy_code, StatusCode::CONFLICT);
        assert_eq!(busy["state"], "BUSY");
        // Duplicate sends preserve a single pending request.
        let (status, duplicate) = call(
            &router,
            &path,
            "POST",
            &cookie,
            &csrf,
            json!({"requestId":id}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(duplicate["requestId"], id);
        client.ok(&["consent", "accept", consent["requestId"].as_str().unwrap()]);
        let mut completed = false;
        for _ in 0..100 {
            let (_, state) = call(
                &router,
                &format!("/api/requests/{id}"),
                "GET",
                &cookie,
                &csrf,
                Value::Null,
            )
            .await;
            if state["state"] == "COMPLETED" {
                completed = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(completed);
        let (status, result) = call(
            &router,
            &format!("/api/requests/{id}/result"),
            "GET",
            &cookie,
            &csrf,
            Value::Null,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{result}");
        assert_eq!(result["report"]["initiator"]["origin"], "REMOTE");
        assert_eq!(result["report"]["initiator"]["operatorDisplayName"], name);
        assert_eq!(
            result["report"]["initiator"]["serverId"],
            app.store.identity().unwrap().unwrap().id.unwrap()
        );
        let stamp = result["report"]["completedAtUnixMs"].as_u64().unwrap();
        let cached: Value = serde_json::from_slice(
            &std::fs::read(
                client
                    .root
                    .join(format!("cache/baradwatchu/audit/reports/{stamp}.json")),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(cached["initiator"], result["report"]["initiator"]);
        let pdf = std::fs::read(result["report"]["pdf"]["path"].as_str().unwrap()).unwrap();
        assert!(String::from_utf8_lossy(&pdf).contains(name));
        verify_history_pdf(&router, &id, &cookie, &csrf, &result["report"], &pdf).await;
        let other_id = if sub == "operator-one" {
            "server-mvp-operator-two"
        } else {
            "server-mvp-operator-one"
        };
        assert_eq!(
            call(
                &router,
                &format!("/api/history/{other_id}"),
                "GET",
                &cookie,
                &csrf,
                Value::Null
            )
            .await
            .0,
            StatusCode::NOT_FOUND
        );

        app.store.revoke(sub).unwrap();
        assert_eq!(
            call(&router, "/api/history", "GET", &cookie, &csrf, Value::Null)
                .await
                .0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            call(&router, "/api/clients", "GET", &cookie, &csrf, Value::Null)
                .await
                .0,
            StatusCode::FORBIDDEN
        );
    }
    assert!(storage::now_ms() > 0);
}
