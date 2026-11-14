//! Backend sessions for Google OIDC and explicitly enabled loopback LOCAL mode.
use crate::{
    config::OidcConfig,
    storage::{self, Operator, Result, ISSUER},
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use openidconnect::{
    core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata},
    AuthorizationCode, ClientId, ClientSecret, CsrfToken, EndpointMaybeSet, EndpointNotSet,
    EndpointSet, IssuerUrl, Nonce, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope,
};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Mutex, time::Duration};

type GoogleClient = CoreClient<
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointMaybeSet,
    EndpointMaybeSet,
>;
pub const SESSION_COOKIE: &str = "__Host-bwu-session";
pub const LOGIN_COOKIE: &str = "__Host-bwu-login";
const SESSION_MS: u64 = 8 * 60 * 60 * 1000;
const LOGIN_MS: u64 = 10 * 60 * 1000;
struct Login {
    state: String,
    nonce: Nonce,
    verifier: PkceCodeVerifier,
    expires: u64,
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OperatorIdentity {
    pub id: String,
    pub name: String,
    pub email: Option<String>,
    pub issuer: Option<String>,
    pub sub: Option<String>,
}
#[derive(Clone)]
pub struct Session {
    pub operator: OperatorIdentity,
    pub csrf: String,
    pub expires: u64,
}
pub struct Auth {
    #[cfg(test)]
    pub(crate) mock_provider: Option<CoreProviderMetadata>,
    config: Option<OidcConfig>,
    local_session: Mutex<Option<(String, Session)>>,
    local_name: Option<String>,
    http: reqwest::Client,
    logins: Mutex<HashMap<String, Login>>,
    sessions: Mutex<HashMap<String, Session>>,
}
impl Auth {
    pub fn new(config: Option<OidcConfig>, local_name: Option<String>) -> Result<Self> {
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(15))
            .https_only(true)
            .build()
            .map_err(|_| "OIDC HTTP initialization failed")?;
        let local_name = if config.is_none() {
            Some(local_name.unwrap_or_else(process_operator_name))
        } else {
            None
        };
        let local_session = Mutex::new(None);
        Ok(Self {
            #[cfg(test)]
            mock_provider: None,
            config,
            local_session,
            local_name,
            http,
            logins: Mutex::new(HashMap::new()),
            sessions: Mutex::new(HashMap::new()),
        })
    }
    pub fn is_local(&self) -> bool {
        self.config.is_none()
    }
    /// Create or reuse an eight-hour loopback session. LOCAL identity is descriptive, not OS authentication.
    pub fn local_session(&self) -> Result<(String, Session)> {
        let now = storage::now_ms();
        let mut current = self.local_session.lock().unwrap();
        if let Some(existing) = current
            .as_ref()
            .filter(|(_, session)| session.expires > now)
        {
            return Ok(existing.clone());
        }
        let token = storage::random()?;
        let csrf = storage::random()?;
        let session = Session {
            operator: OperatorIdentity {
                id: "LOCAL".into(),
                name: self
                    .local_name
                    .clone()
                    .unwrap_or_else(process_operator_name),
                email: None,
                issuer: None,
                sub: None,
            },
            csrf,
            expires: now + SESSION_MS,
        };
        let mut sessions = self.sessions.lock().unwrap();
        sessions.retain(|_, v| v.expires > now);
        if sessions.len() >= 1024 {
            return Err("too many sessions".into());
        }
        sessions.insert(token.clone(), session.clone());
        *current = Some((token.clone(), session.clone()));
        Ok((token, session))
    }
    pub fn revoke_local_session(&self, token: &str) {
        // Keep lock order identical to local_session() to avoid logout/session races.
        let mut current = self.local_session.lock().unwrap();
        self.sessions.lock().unwrap().remove(token);
        if current.as_ref().is_some_and(|(active, _)| active == token) {
            *current = None;
        }
    }
    async fn client(&self) -> Result<GoogleClient> {
        #[cfg(test)]
        if let Some(metadata) = &self.mock_provider {
            let config = self
                .config
                .as_ref()
                .ok_or("OIDC is disabled in LOCAL mode")?;
            return Ok(CoreClient::from_provider_metadata(
                metadata.clone(),
                ClientId::new(config.client_id.clone()),
                Some(ClientSecret::new(config.client_secret.clone())),
            )
            .set_redirect_uri(RedirectUrl::new(config.redirect_uri.clone()).unwrap()));
        }
        let config = self
            .config
            .as_ref()
            .ok_or("OIDC is disabled in LOCAL mode")?;
        let metadata = CoreProviderMetadata::discover_async(
            IssuerUrl::new(ISSUER.into()).unwrap(),
            &self.http,
        )
        .await
        .map_err(|_| "Google OIDC discovery unavailable")?;
        Ok(CoreClient::from_provider_metadata(
            metadata,
            ClientId::new(config.client_id.clone()),
            Some(ClientSecret::new(config.client_secret.clone())),
        )
        .set_redirect_uri(
            RedirectUrl::new(config.redirect_uri.clone())
                .map_err(|_| "invalid OIDC redirect URI")?,
        ))
    }
    pub async fn login(&self, previous: Option<&str>) -> Result<(String, String)> {
        let client = self.client().await?;
        let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
        let mut request = client
            .authorize_url(
                CoreAuthenticationFlow::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            .add_scope(Scope::new("email".into()))
            .add_scope(Scope::new("profile".into()))
            .set_pkce_challenge(challenge);
        if let Some(domain) = &self
            .config
            .as_ref()
            .ok_or("OIDC is disabled in LOCAL mode")?
            .workspace_domain
        {
            request = request.add_extra_param("hd", domain);
        }
        let (url, state, nonce) = request.url();
        let token = storage::random()?;
        let mut logins = self.logins.lock().unwrap();
        logins.retain(|_, v| v.expires > storage::now_ms());
        if let Some(previous) = previous {
            logins.remove(previous);
        }
        if logins.len() >= 1024 {
            return Err("too many pending logins; retry later".into());
        }
        logins.insert(
            token.clone(),
            Login {
                state: state.secret().clone(),
                nonce,
                verifier,
                expires: storage::now_ms() + LOGIN_MS,
            },
        );
        Ok((url.to_string(), token))
    }
    pub async fn callback(&self, browser: &str, state: &str, code: &str) -> Result<Operator> {
        let login = self.take_login(browser, state)?;
        let client = self.client().await?;
        let response = client
            .exchange_code(AuthorizationCode::new(code.into()))
            .map_err(|_| "Google token endpoint unavailable")?
            .set_pkce_verifier(login.verifier)
            .request_async(&self.http)
            .await
            .map_err(|_| "Google code exchange failed")?;
        let token = response
            .extra_fields()
            .id_token()
            .ok_or("missing Google ID token")?;
        let claims = token
            .claims(&client.id_token_verifier(), &login.nonce)
            .map_err(|_| "invalid Google ID token")?;
        use openidconnect::{AccessTokenHash, OAuth2TokenResponse};
        if let Some(expected) = claims.access_token_hash() {
            let verifier = client.id_token_verifier();
            let actual = AccessTokenHash::from_token(
                response.access_token(),
                token.signing_alg().map_err(|_| "invalid token algorithm")?,
                token
                    .signing_key(&verifier)
                    .map_err(|_| "invalid token signing key")?,
            )
            .map_err(|_| "invalid access token hash")?;
            if &actual != expected {
                return Err("invalid access token hash".into());
            }
        }
        // The original signed payload is read only AFTER library signature/issuer/audience/
        // nonce/expiry validation. hd and azp are Google-specific authorization constraints.
        let encoded = token.to_string();
        let payload = encoded.split('.').nth(1).ok_or("invalid Google token")?;
        let extra: GoogleClaims = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(payload)
                .map_err(|_| "invalid Google claims")?,
        )
        .map_err(|_| "invalid Google claims")?;
        let config = self
            .config
            .as_ref()
            .ok_or("OIDC is disabled in LOCAL mode")?;
        validate_google_claims(&extra, config, storage::now_ms() / 1000)?;
        let email = claims
            .email()
            .filter(|_| claims.email_verified() == Some(true))
            .ok_or("Google email must be verified")?
            .as_str()
            .to_owned();
        let name = claims
            .name()
            .and_then(|n| n.get(None))
            .map(|n| n.as_str())
            .filter(|v| storage::label(v))
            .ok_or("Google profile has no valid display name")?
            .to_owned();
        let sub = claims.subject().as_str().to_owned();
        if sub.is_empty() || sub.len() > 255 {
            return Err("invalid Google subject".into());
        }
        Ok(Operator {
            issuer: ISSUER.into(),
            sub,
            name,
            email,
        })
    }
    fn take_login(&self, browser: &str, state: &str) -> Result<Login> {
        let login = self
            .logins
            .lock()
            .unwrap()
            .remove(browser)
            .ok_or("login expired or browser cookie missing")?;
        if login.expires <= storage::now_ms() || login.state != state {
            return Err("invalid or expired login state".into());
        }
        Ok(login)
    }
    pub fn establish(&self, op: Operator, previous: Option<&str>) -> Result<String> {
        let token = storage::random()?;
        let csrf = storage::random()?;
        let mut sessions = self.sessions.lock().unwrap();
        sessions.retain(|_, v| v.expires > storage::now_ms());
        if let Some(previous) = previous {
            sessions.remove(previous);
        }
        if sessions.len() >= 1024 {
            return Err("too many sessions".into());
        }
        sessions.insert(
            token.clone(),
            Session {
                operator: OperatorIdentity {
                    id: format!("{}:{}", op.issuer, op.sub),
                    name: op.name,
                    email: Some(op.email),
                    issuer: Some(op.issuer),
                    sub: Some(op.sub),
                },
                csrf,
                expires: storage::now_ms() + SESSION_MS,
            },
        );
        Ok(token)
    }
    pub fn session(&self, token: &str) -> Option<Session> {
        let mut sessions = self.sessions.lock().unwrap();
        sessions.retain(|_, v| v.expires > storage::now_ms());
        sessions.get(token).cloned()
    }
    pub fn logout(&self, token: &str) {
        self.sessions.lock().unwrap().remove(token);
    }
}
fn process_operator_name() -> String {
    ["USER", "LOGNAME", "USERNAME"]
        .into_iter()
        .filter_map(|key| std::env::var(key).ok())
        .find(|name| storage::label(name))
        // Generic label in the Server language (shared language preference).
        .unwrap_or_else(|| {
            baradwatchu_messages::message(
                "server.localOperator",
                baradwatchu_messages::configured_language(),
            )
            .to_owned()
        })
}
#[derive(Deserialize)]
struct GoogleClaims {
    #[serde(default)]
    hd: Option<String>,
    #[serde(default)]
    azp: Option<String>,
    aud: serde_json::Value,
    iat: u64,
}
fn validate_google_claims(c: &GoogleClaims, config: &OidcConfig, now: u64) -> Result<()> {
    if c.iat > now + 60 || now.saturating_sub(c.iat) > 600 {
        return Err("Google ID token issue time outside login window".into());
    }
    if c.azp.as_ref().is_some_and(|v| v != &config.client_id)
        || (c.aud.as_array().is_some_and(|v| v.len() > 1)
            && c.azp.as_deref() != Some(&config.client_id))
    {
        return Err("invalid Google authorized party".into());
    }
    if config
        .workspace_domain
        .as_ref()
        .is_some_and(|d| c.hd.as_ref() != Some(d))
    {
        return Err("Google Workspace domain is not allowed".into());
    }
    Ok(())
}
pub fn cookie(name: &str, token: &str, seconds: u64) -> String {
    format!("{name}={token}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={seconds}")
}
pub fn session_cookie(token: &str) -> String {
    cookie(SESSION_COOKIE, token, SESSION_MS / 1000)
}
pub fn login_cookie(token: &str) -> String {
    cookie(LOGIN_COOKIE, token, LOGIN_MS / 1000)
}
pub fn read_cookie(headers: &axum::http::HeaderMap, name: &str) -> Option<String> {
    let mut values = headers
        .get_all(axum::http::header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|v| v.trim().split_once('='))
        .filter(|(key, _)| *key == name)
        .map(|(_, v)| v.to_owned());
    let first = values.next()?;
    if values.next().is_some() {
        None
    } else {
        Some(first)
    }
}
#[cfg(test)]
impl Auth {
    pub(crate) fn use_mock(&mut self, metadata: CoreProviderMetadata) {
        self.mock_provider = Some(metadata);
        self.http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn config() -> OidcConfig {
        OidcConfig {
            client_id: "id".into(),
            client_secret: "secret".into(),
            redirect_uri: "https://server.example/auth/callback".into(),
            workspace_domain: Some("example.com".into()),
        }
    }
    #[test]
    fn hosted_domain_azp_and_issue_time_are_checked() {
        let mut c = GoogleClaims {
            hd: Some("example.com".into()),
            azp: Some("id".into()),
            aud: serde_json::json!(["id", "other"]),
            iat: 1000,
        };
        assert!(validate_google_claims(&c, &config(), 1000).is_ok());
        c.hd = None;
        assert!(validate_google_claims(&c, &config(), 1000).is_err());
        c.hd = Some("example.com".into());
        c.azp = None;
        assert!(validate_google_claims(&c, &config(), 1000).is_err());
        c.azp = Some("id".into());
        assert!(validate_google_claims(&c, &config(), 2000).is_err());
    }
    #[test]
    fn local_session_has_descriptive_identity_without_oidc_claims() {
        let auth = Auth::new(None, Some("Operatore dev".into())).unwrap();
        let (token, session) = auth.local_session().unwrap();
        assert_eq!(auth.session(&token).unwrap().csrf, session.csrf);
        auth.revoke_local_session(&token);
        assert!(auth.session(&token).is_none());
        let (rotated, next) = auth.local_session().unwrap();
        assert_ne!(rotated, token);
        assert_ne!(next.csrf, session.csrf);
        assert!(auth.is_local());
        assert!(auth.session(&token).is_none());
        assert_eq!(
            auth.session(&rotated).unwrap().operator.name,
            "Operatore dev"
        );
        assert_eq!(session.operator.id, "LOCAL");
        assert!(session.operator.issuer.is_none());
        assert!(session.operator.sub.is_none());
        assert!(session.operator.email.is_none());
    }
    #[test]
    fn session_rotation_logout_and_expiry() {
        let a = Auth::new(Some(config()), None).unwrap();
        let op = Operator {
            issuer: ISSUER.into(),
            sub: "one".into(),
            name: "Mario".into(),
            email: "m@example.com".into(),
        };
        let first = a.establish(op.clone(), None).unwrap();
        let next = a.establish(op, Some(&first)).unwrap();
        assert!(a.session(&first).is_none());
        assert!(a.session(&next).is_some());
        a.sessions.lock().unwrap().get_mut(&next).unwrap().expires = 0;
        assert!(a.session(&next).is_none());
        a.logout(&next);
        assert!(a.session(&next).is_none());
    }
    #[test]
    fn state_is_bound_to_browser_single_use_and_expires() {
        let a = Auth::new(Some(config()), None).unwrap();
        let (_, v) = PkceCodeChallenge::new_random_sha256();
        a.logins.lock().unwrap().insert(
            "browser".into(),
            Login {
                state: "state".into(),
                nonce: Nonce::new_random(),
                verifier: v,
                expires: storage::now_ms() + 1000,
            },
        );
        assert!(a.take_login("other", "state").is_err());
        assert!(a.take_login("browser", "wrong").is_err());
        assert!(a.take_login("browser", "state").is_err());
    }
}
