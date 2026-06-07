use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use jsonwebtoken::EncodingKey;

#[derive(Debug, Deserialize, Clone)]
pub struct Settings {
    pub server: ServerSettings,
    pub auth: AuthSettings,
    pub kerberos: KerberosSettings,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ServerSettings {
    pub host: String,
    pub port: u16,
    pub issuer: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct AuthSettings {
    pub private_key_path: String,
    pub key_id: String,
    pub kty: String,
    #[serde(rename = "use")]
    pub jwk_use: String,
    pub alg: String,
    pub n: String,
    pub e: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct KerberosSettings {
    pub enabled: bool,
    pub keytab_path: String,
    pub service_principal: String,
}

#[derive(Clone)]
pub struct AppState {
    pub codes: Arc<RwLock<HashMap<String, AuthCodeData>>>,
    pub settings: Settings,
    pub private_key: EncodingKey,
    pub public_key_jwk: serde_json::Value,
}

#[derive(Clone)]
pub struct AuthCodeData {
    pub upn: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub nonce: Option<String>,
}

#[derive(Deserialize, Debug)]
pub struct AuthRequest {
    pub client_id: String,
    pub redirect_uri: String,
    pub response_type: String,
    pub scope: String,
    pub state: Option<String>,
    pub nonce: Option<String>,
}

#[derive(Deserialize, Debug)]
pub struct TokenRequest {
    pub grant_type: String,
    pub code: String,
    pub redirect_uri: String,
    pub client_id: String,
    pub client_secret: Option<String>,
}

#[derive(Serialize, Debug)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub id_token: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub exp: i64,
    pub iat: i64,
    pub nonce: Option<String>,
    pub upn: String,
}
