//! Test-only OIDC provider: real RSA signatures and code/PKCE exchange on loopback.
use crate::{auth, config, storage};
use axum::{
    extract::{Form, State},
    http::StatusCode,
    routing::post,
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use openidconnect::{
    core::{CoreJwsSigningAlgorithm, CoreProviderMetadata, CoreRsaPrivateSigningKey},
    JsonWebKeyId, PrivateSigningKey,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
struct Grant {
    challenge: String,
    claims: Value,
}
type Grants = Arc<Mutex<HashMap<String, Grant>>>;
pub(crate) struct MockOidc {
    pub metadata: CoreProviderMetadata,
    grants: Grants,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for MockOidc {
    fn drop(&mut self) {
        self.task.abort();
    }
}
fn key() -> CoreRsaPrivateSigningKey {
    CoreRsaPrivateSigningKey::from_pem(
        include_str!("../tests/fixtures/oidc-test-only.pem"),
        Some(JsonWebKeyId::new("test-only".into())),
    )
    .unwrap()
}
async fn token(
    State(grants): State<Grants>,
    Form(form): Form<HashMap<String, String>>,
) -> Result<Json<Value>, StatusCode> {
    let grant = grants
        .lock()
        .unwrap()
        .remove(form.get("code").ok_or(StatusCode::BAD_REQUEST)?)
        .ok_or(StatusCode::BAD_REQUEST)?;
    let verifier = form.get("code_verifier").ok_or(StatusCode::BAD_REQUEST)?;
    if form.get("grant_type").map(String::as_str) != Some("authorization_code")
        || URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes())) != grant.challenge
        || form.get("redirect_uri").map(String::as_str)
            != Some("http://localhost:3000/auth/callback")
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","kid":"test-only","typ":"JWT"}"#);
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&grant.claims).unwrap());
    let message = format!("{header}.{payload}");
    let mut signature = key()
        .sign(
            &CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
            message.as_bytes(),
        )
        .unwrap();
    if grant.claims["testCorruptSignature"] == true {
        signature[0] ^= 1;
    }
    Ok(Json(
        json!({"access_token":"test-access-token","token_type":"Bearer","id_token":format!("{message}.{}",URL_SAFE_NO_PAD.encode(signature))}),
    ))
}
impl MockOidc {
    pub async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let grants = Arc::new(Mutex::new(HashMap::new()));
        let router = Router::new()
            .route("/token", post(token))
            .with_state(grants.clone());
        let task = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        let metadata=serde_json::from_value(json!({"issuer":storage::ISSUER,"authorization_endpoint":"https://accounts.google.com/o/oauth2/v2/auth","token_endpoint":format!("http://{addr}/token"),"jwks_uri":"https://unused.invalid/keys","response_types_supported":["code"],"subject_types_supported":["public"],"id_token_signing_alg_values_supported":["RS256"]})).unwrap();
        let metadata: CoreProviderMetadata = metadata;
        let metadata = metadata.set_jwks(openidconnect::core::CoreJsonWebKeySet::new(vec![
            key().as_verification_key()
        ]));
        Self {
            metadata,
            grants,
            task,
        }
    }
    pub fn settings() -> config::Settings {
        config::Settings {
            auth_mode: config::AuthMode::Oidc,
            public_url: "http://localhost:3000".into(),
            google: Some(config::OidcConfig {
                client_id: "test-client".into(),
                client_secret: "test-secret".into(),
                redirect_uri: "http://localhost:3000/auth/callback".into(),
                workspace_domain: Some("example.com".into()),
            }),
            local_operator_name: None,
            web_dir: None,
        }
    }
    pub fn grant(&self, url: &str, sub: &str, name: &str, overrides: Value) -> (String, String) {
        let url = url::Url::parse(url).unwrap();
        let params: HashMap<_, _> = url.query_pairs().into_owned().collect();
        assert_eq!(params["code_challenge_method"], "S256");
        assert_eq!(params["response_type"], "code");
        assert!(params["scope"].contains("openid"));
        let now = storage::now_ms() / 1000;
        let mut claims = json!({"iss":storage::ISSUER,"sub":sub,"aud":"test-client","azp":"test-client","exp":now+300,"iat":now,"nonce":params["nonce"],"name":name,"email":format!("{sub}@example.com"),"email_verified":true,"hd":"example.com"});
        if let Some(fields) = overrides.as_object() {
            for (k, v) in fields {
                claims[k] = v.clone();
            }
        }
        let code = storage::random().unwrap();
        self.grants.lock().unwrap().insert(
            code.clone(),
            Grant {
                challenge: params["code_challenge"].clone(),
                claims,
            },
        );
        (code, params["state"].clone())
    }
}
#[tokio::test]
async fn oidc_code_pkce_signed_claims_and_replays() {
    let mock = MockOidc::start().await;
    let mut auth = auth::Auth::new(MockOidc::settings().google, None).unwrap();
    auth.use_mock(mock.metadata.clone());
    for (claims, valid) in [
        (json!({}), true),
        (json!({"iss":"https://evil.example"}), false),
        (json!({"aud":"another-client"}), false),
        (json!({"nonce":"wrong"}), false),
        (json!({"exp":1}), false),
        (json!({"email_verified":false}), false),
        (json!({"hd":"other.example"}), false),
        (json!({"azp":"another-client"}), false),
        (json!({"at_hash":"wrong"}), false),
        (json!({"testCorruptSignature":true}), false),
    ] {
        let (url, browser) = auth.login(None).await.unwrap();
        let (code, state) = mock.grant(&url, "operator-one", "Mario Rossi", claims.clone());
        let result = auth.callback(&browser, &state, &code).await;
        assert_eq!(
            result.is_ok(),
            valid,
            "claims: {claims}, result: {result:?}"
        );
        assert!(auth.callback(&browser, &state, &code).await.is_err());
    }
    let (url, browser) = auth.login(None).await.unwrap();
    let (code, state) = mock.grant(&url, "operator-one", "Mario Rossi", json!({}));
    mock.grants
        .lock()
        .unwrap()
        .get_mut(&code)
        .unwrap()
        .challenge = "wrong".into();
    assert!(auth.callback(&browser, &state, &code).await.is_err());
}
