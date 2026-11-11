use std::{env, net::SocketAddr};

/// Startup configuration. Without a discovered file LOCAL is used on loopback.
pub struct Config {
    pub address: SocketAddr,
    pub settings: Settings,
}

impl Config {
    pub fn from_env() -> Result<Self, String> {
        let address = match env::var("BARADWATCHU_SERVER_ADDR") {
            Ok(value) => value,
            Err(env::VarError::NotPresent) => "127.0.0.1:3000".to_owned(),
            Err(env::VarError::NotUnicode(_)) => {
                return Err("BARADWATCHU_SERVER_ADDR must contain valid Unicode".to_owned());
            }
        };
        let mut config = Self::from_address(&address)?;
        let explicit = env::var_os("BARADWATCHU_SERVER_CONFIG").map(std::path::PathBuf::from);
        let user = user_config_path();
        if let Some(path) = select_config_path(
            explicit,
            std::path::PathBuf::from("/etc/baradwatchu/server.json"),
            user,
        )? {
            let bytes = std::fs::read(&path).map_err(|error| {
                format!(
                    "cannot read Server configuration {}: {error}",
                    path.display()
                )
            })?;
            let settings: Settings =
                serde_json::from_slice(&bytes).map_err(|_| "invalid Server configuration JSON")?;
            settings.validate()?;
            validate_binding(config.address, &settings)?;
            config.settings = settings;
        }
        config.settings.validate()?;
        validate_binding(config.address, &config.settings)?;
        Ok(config)
    }

    fn from_address(address: &str) -> Result<Self, String> {
        let address: SocketAddr = address.parse().map_err(|_| {
            "BARADWATCHU_SERVER_ADDR must be an IP address and port, e.g. 127.0.0.1:3000 or [::1]:3000".to_owned()
        })?;
        Ok(Self {
            address,
            settings: Settings {
                public_url: format!("http://localhost:{}", address.port()),
                ..Settings::default()
            },
        })
    }
}
fn user_config_path() -> Option<std::path::PathBuf> {
    let base = env::var_os("XDG_CONFIG_HOME")
        .map(std::path::PathBuf::from)
        .filter(|path| path.is_absolute())
        .or_else(|| {
            env::var_os("HOME").map(|home| std::path::PathBuf::from(home).join(".config"))
        })?;
    Some(base.join("baradwatchu").join("server.json"))
}
fn select_config_path(
    explicit: Option<std::path::PathBuf>,
    system: std::path::PathBuf,
    user: Option<std::path::PathBuf>,
) -> Result<Option<std::path::PathBuf>, String> {
    if let Some(path) = explicit {
        return Ok(Some(path));
    }
    for path in std::iter::once(Some(system))
        .chain(std::iter::once(user))
        .flatten()
    {
        if path.try_exists().map_err(|_| {
            format!(
                "cannot inspect Server configuration path {}",
                path.display()
            )
        })? {
            return Ok(Some(path));
        }
    }
    Ok(None)
}
fn validate_binding(address: SocketAddr, settings: &Settings) -> Result<(), String> {
    if settings.auth_mode == AuthMode::Local {
        let exact_loopback = match address.ip() {
            std::net::IpAddr::V4(ip) => ip == std::net::Ipv4Addr::LOCALHOST,
            std::net::IpAddr::V6(ip) => ip == std::net::Ipv6Addr::LOCALHOST,
        };
        if !exact_loopback {
            return Err(
                "LOCAL authentication requires a loopback listen address (127.0.0.1 or ::1)".into(),
            );
        }
    } else if settings.public_url.starts_with("http:") && !address.ip().is_loopback() {
        return Err("HTTP localhost development requires a loopback listen address".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{select_config_path, AuthMode, Config};

    #[test]
    fn accepts_ipv4_ipv6_and_ephemeral_port() {
        for address in ["127.0.0.1:3000", "[::1]:3000", "127.0.0.1:0"] {
            assert_eq!(
                Config::from_address(address).unwrap().address.to_string(),
                address
            );
        }
    }

    #[test]
    fn public_origin_is_https_or_localhost_with_exact_callback() {
        let mut s = crate::oidc_tests::MockOidc::settings();
        assert!(s.validate().is_ok());
        for origin in [
            "http://server.example",
            "http://localhost.evil.example",
            "https://user:pass@server.example",
            "https://server.example/path",
            "https://server.example?x=1",
        ] {
            s.public_url = origin.into();
            s.google.as_mut().unwrap().redirect_uri = format!("{origin}/auth/callback");
            assert!(s.validate().is_err());
        }
        s.public_url = "https://server.example".into();
        s.google.as_mut().unwrap().redirect_uri = "https://evil.example/auth/callback".into();
        assert!(s.validate().is_err());
        s.google.as_mut().unwrap().redirect_uri = "https://server.example/auth/callback".into();
        assert!(s.validate().is_ok());
    }

    #[test]
    fn rejects_invalid_listen_addresses_before_startup() {
        for address in ["", "localhost:3000", "127.0.0.1", "127.0.0.1:65536"] {
            assert!(Config::from_address(address).is_err());
        }
    }

    #[test]
    fn local_mode_needs_no_google_and_rejects_non_loopback_bindings() {
        let local = r#"{"authMode":"LOCAL","publicUrl":"http://localhost:3000","localOperatorName":"Mario Rossi"}"#;
        let settings: super::Settings = serde_json::from_str(local).unwrap();
        assert_eq!(settings.auth_mode, AuthMode::Local);
        assert!(settings.validate().is_ok());
        for address in [
            "0.0.0.0:3000",
            "127.0.0.2:3000",
            "192.0.2.10:3000",
            "[::]:3000",
        ] {
            let parsed = Config::from_address(address).unwrap();
            assert!(super::validate_binding(parsed.address, &settings).is_err());
        }
        assert!(super::validate_binding(
            Config::from_address("127.0.0.1:3000").unwrap().address,
            &settings
        )
        .is_ok());
        assert!(super::validate_binding(
            Config::from_address("[::1]:3000").unwrap().address,
            &settings
        )
        .is_ok());
        let ipv6: super::Settings =
            serde_json::from_str(r#"{"authMode":"LOCAL","publicUrl":"http://[::1]:3000"}"#)
                .unwrap();
        assert!(ipv6.validate().is_ok());
        assert!(serde_json::from_str::<super::Settings>(
            r#"{"authMode":"LOCAL","publicUrl":"http://example.com:3000"}"#
        )
        .unwrap()
        .validate()
        .is_err());
        assert!(serde_json::from_str::<super::Settings>(
            r#"{"authMode":"LOCAL","publicUrl":"http://localhost:3000","google":{"clientId":"id","clientSecret":"secret","redirectUri":"http://localhost:3000/auth/callback"}}"#
        )
        .unwrap()
        .validate()
        .is_err());
    }

    #[test]
    fn omitted_mode_defaults_to_local_and_oidc_remains_explicit() {
        let json = r#"{"authMode":"OIDC","publicUrl":"https://server.example","google":{"clientId":"id","clientSecret":"secret","redirectUri":"https://server.example/auth/callback"}}"#;
        let settings: super::Settings = serde_json::from_str(json).unwrap();
        assert_eq!(settings.auth_mode, AuthMode::Oidc);
        assert!(settings.validate().is_ok());
        let local: super::Settings = serde_json::from_str("{}").unwrap();
        assert_eq!(local.auth_mode, AuthMode::Local);
        assert!(local.validate().is_ok());
        assert!(super::validate_binding("0.0.0.0:3000".parse().unwrap(), &local).is_err());
        assert!(super::validate_binding("127.0.0.1:3000".parse().unwrap(), &local).is_ok());
    }

    #[test]
    fn config_path_priority_is_explicit_then_system_then_user() {
        let dir = std::env::temp_dir().join(format!(
            "bwu-config-path-{}",
            crate::storage::random().unwrap()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let system = dir.join("etc/server.json");
        let user = dir.join("home/server.json");
        std::fs::create_dir_all(system.parent().unwrap()).unwrap();
        std::fs::create_dir_all(user.parent().unwrap()).unwrap();
        std::fs::write(&system, "{}").unwrap();
        std::fs::write(&user, "{}").unwrap();
        let explicit = dir.join("explicit.json");
        assert_eq!(
            select_config_path(None, system.clone(), Some(user.clone())).unwrap(),
            Some(system.clone())
        );
        assert_eq!(
            select_config_path(Some(explicit.clone()), system.clone(), Some(user.clone())).unwrap(),
            Some(explicit)
        );
        std::fs::remove_file(&system).unwrap();
        assert_eq!(
            select_config_path(None, system.clone(), Some(user.clone())).unwrap(),
            Some(user.clone())
        );
        assert_eq!(
            select_config_path(Some(system.clone()), system.clone(), Some(user.clone())).unwrap(),
            Some(system.clone())
        );
        std::fs::remove_file(&user).unwrap();
        assert_eq!(select_config_path(None, system, Some(user)).unwrap(), None);
        std::fs::remove_dir_all(dir).unwrap();
    }
}

#[derive(Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OidcConfig {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    #[serde(default)]
    pub workspace_domain: Option<String>,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuthMode {
    #[default]
    Local,
    Oidc,
}
#[derive(Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Settings {
    #[serde(default)]
    pub auth_mode: AuthMode,
    #[serde(default = "default_public_url")]
    pub public_url: String,
    #[serde(default)]
    pub google: Option<OidcConfig>,
    #[serde(default)]
    pub local_operator_name: Option<String>,
    #[serde(default)]
    pub web_dir: Option<std::path::PathBuf>,
}
fn default_public_url() -> String {
    "http://localhost:3000".into()
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            auth_mode: AuthMode::Local,
            public_url: default_public_url(),
            google: None,
            local_operator_name: None,
            web_dir: None,
        }
    }
}
impl Settings {
    pub fn validate(&self) -> Result<(), String> {
        let url = url::Url::parse(&self.public_url).map_err(|_| "invalid publicUrl")?;
        if url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.path() != "/"
        {
            return Err(
                "publicUrl must be an origin without credentials, path, query or fragment".into(),
            );
        }
        match self.auth_mode {
            AuthMode::Local => {
                if self.google.is_some() {
                    return Err("LOCAL mode must not contain Google credentials".into());
                }
                let loopback_host = url.host().is_some_and(|host| match host {
                    url::Host::Domain(name) => name == "localhost",
                    url::Host::Ipv4(address) => address == std::net::Ipv4Addr::LOCALHOST,
                    url::Host::Ipv6(address) => address.is_loopback(),
                });
                if url.scheme() != "http" || !loopback_host {
                    return Err(
                        "LOCAL publicUrl must use HTTP and localhost, 127.0.0.1 or [::1]".into(),
                    );
                }
                if self
                    .local_operator_name
                    .as_ref()
                    .is_some_and(|name| !storage::label(name))
                {
                    return Err("localOperatorName must be 1-128 printable characters".into());
                }
            }
            AuthMode::Oidc => {
                if self.local_operator_name.is_some() {
                    return Err("localOperatorName is only valid in LOCAL mode".into());
                }
                if !(url.scheme() == "https"
                    || (url.scheme() == "http" && url.host_str() == Some("localhost")))
                {
                    return Err(
                        "OIDC publicUrl must be HTTPS (HTTP localhost is allowed for development)"
                            .into(),
                    );
                }
                let google = self
                    .google
                    .as_ref()
                    .ok_or("OIDC mode requires Google credentials")?;
                if google.redirect_uri
                    != format!("{}/auth/callback", self.public_url.trim_end_matches('/'))
                    || google.client_id.is_empty()
                    || google.client_secret.is_empty()
                {
                    return Err("Google redirectUri must be publicUrl/auth/callback; clientId and clientSecret are required".into());
                }
                if google.workspace_domain.as_ref().is_some_and(|v| {
                    v.is_empty() || v.contains('@') || v.chars().any(char::is_whitespace)
                }) {
                    return Err("invalid workspaceDomain".into());
                }
            }
        }
        Ok(())
    }
    pub fn origin(&self) -> &str {
        self.public_url.trim_end_matches('/')
    }
    pub fn web_path(&self) -> std::path::PathBuf {
        if let Some(path) = &self.web_dir {
            return path.clone();
        }
        if let Ok(exe) = std::env::current_exe() {
            if let Some(prefix) = exe.parent().and_then(|p| p.parent()) {
                let path = prefix.join("share/baradwatchu-server/web");
                if path.is_dir() {
                    return path;
                }
            }
        }
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../web/dist/server-dashboard/browser")
    }
}
use crate::storage;
pub fn data_dir() -> Result<std::path::PathBuf, String> {
    if let Some(dir) = env::var_os("BARADWATCHU_SERVER_DATA_DIR") {
        return Ok(dir.into());
    }
    if let Some(dir) = env::var_os("XDG_STATE_HOME") {
        return Ok(std::path::PathBuf::from(dir).join("baradwatchu-server"));
    }
    let home = env::var_os("HOME").ok_or("set BARADWATCHU_SERVER_DATA_DIR")?;
    Ok(std::path::PathBuf::from(home).join(".local/state/baradwatchu-server"))
}
