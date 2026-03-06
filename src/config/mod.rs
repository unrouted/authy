use std::{path::PathBuf, sync::Arc};

use acl::AccessRule;
use anyhow::{Context, Result};
use figment::{
    Figment,
    providers::{Env, Format, Serialized, Yaml},
};
use jwt_simple::prelude::ES256KeyPair;
use p256::ecdsa::SigningKey;
use p256::pkcs8::EncodePrivateKey;
use platform_dirs::AppDirs;
use sec1::DecodeEcPrivateKey;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{config::files::RecursiveFileProvider, jwt::JWKSPublicKey};

pub(crate) mod acl;
pub(crate) mod files;

#[derive(Clone)]
pub struct KeyPair {
    pub original: String,
    pub key_pair: Arc<ES256KeyPair>,
}

impl std::fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyPair")
            .field("original", &self.original)
            .finish()
    }
}

impl Serialize for KeyPair {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.original)
    }
}

fn load_keypair(pem: &str) -> Result<ES256KeyPair> {
    let signing_key = SigningKey::from_sec1_pem(pem)?;
    let der = signing_key.to_pkcs8_der()?;
    ES256KeyPair::from_der(der.as_bytes())
}

impl<'de> Deserialize<'de> for KeyPair {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let pem: String = Deserialize::deserialize(deserializer)?;
        let key_pair = Arc::new(load_keypair(&pem).unwrap());

        Ok(KeyPair {
            original: pem,
            key_pair,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct AuthenticationConfig {
    pub key_pair: KeyPair,
    pub users: Vec<User>,
    pub acls: Vec<AccessRule>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum User {
    Password {
        username: String,
        password: String,
    },
    Token {
        username: String,
        issuer: JWKSPublicKey,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct Configuration {
    pub url: String,
    pub authentication: Option<AuthenticationConfig>,
}

impl Configuration {
    pub fn figment(configs: Vec<PathBuf>) -> Figment {
        let fig = Figment::from(Serialized::defaults(Configuration::default()));

        let app_dirs = AppDirs::new(Some("disty"), true).unwrap();
        let config_dir = app_dirs.config_dir;
        let config_path = config_dir.join("config.yaml");

        let fig = match config_path.exists() {
            true => fig.admerge(RecursiveFileProvider::new(Yaml::file(config_path))),
            false => fig,
        };

        let fig = configs.into_iter().fold(fig, |fig, config_path| {
            fig.admerge(RecursiveFileProvider::new(Yaml::file(config_path)))
        });

        fig.admerge(RecursiveFileProvider::new(Env::prefixed("AUTHY_")))
    }

    pub fn config(figment: Figment) -> Result<Configuration> {
        let config: Configuration = figment.extract().context("Failed to load configuration")?;

        Ok(config)
    }
}

impl Default for Configuration {
    fn default() -> Self {
        Self {
            url: "http://localhost".into(),
            authentication: None,
        }
    }
}
