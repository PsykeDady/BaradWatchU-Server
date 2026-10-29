use std::{env, net::SocketAddr};

/// Startup configuration. Persistence and credentials are not configured yet.
pub struct Config {
    pub address: SocketAddr,
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
        Self::from_address(&address)
    }

    fn from_address(address: &str) -> Result<Self, String> {
        let address = address.parse().map_err(|_| {
            "BARADWATCHU_SERVER_ADDR must be an IP address and port, e.g. 127.0.0.1:3000 or [::1]:3000".to_owned()
        })?;
        Ok(Self { address })
    }
}

#[cfg(test)]
mod tests {
    use super::Config;

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
    fn rejects_invalid_listen_addresses_before_startup() {
        for address in ["", "localhost:3000", "127.0.0.1", "127.0.0.1:65536"] {
            assert!(Config::from_address(address).is_err());
        }
    }
}
