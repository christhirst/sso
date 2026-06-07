#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(unused_imports)]

mod types;
use types::*;

use axum::{
    extract::{Query, State, FromRequestParts},
    http::{header, request::Parts, StatusCode},
    response::{IntoResponse, Redirect, Json, Response, Html},
    routing::{get, post},
    Router,
    Form,
};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use uuid::Uuid;
use tower_http::trace::TraceLayer;
use tracing::{info, warn, error, instrument};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};
use config::Config;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| "sso=info,tower_http=debug".into()))
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!("Starting SSO Server...");

    let settings: Settings = Config::builder()
        .add_source(config::File::with_name("config/Settings"))
        .add_source(config::Environment::with_prefix("APP").separator("__"))
        .build()?
        .try_deserialize()?;

    info!("Configuration loaded");

    let private_key_pem = std::fs::read_to_string(&settings.auth.private_key_path)?;
    let private_key = EncodingKey::from_rsa_pem(private_key_pem.as_bytes())?;

    // Load and parse the public key PEM file to extract modulus and exponent for JWK
    let public_key_pem = std::fs::read_to_string(&settings.auth.public_key_path)?;
    use rsa::{RsaPublicKey, traits::PublicKeyParts, pkcs8::DecodePublicKey};
    let public_key = RsaPublicKey::from_public_key_pem(&public_key_pem)?;
    
    use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
    let n_b64 = BASE64_URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be());
    let e_b64 = BASE64_URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be());

    let public_key_jwk = serde_json::json!({
        "keys": [
            {
                "kty": settings.auth.kty,
                "use": settings.auth.jwk_use,
                "kid": settings.auth.key_id,
                "alg": settings.auth.alg,
                "n": n_b64,
                "e": e_b64
            }
        ]
    });

    let state = AppState {
        codes: Arc::new(RwLock::new(HashMap::new())),
        settings: settings.clone(),
        private_key,
        public_key_jwk,
    };

    let app = Router::new()
        .route("/", get(index))
        .route("/.well-known/openid-configuration", get(oidc_config))
        .route("/jwks", get(jwks))
        .route("/authorize", get(authorize))
        .route("/token", post(token))
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let addr = format!("{}:{}", settings.server.host, settings.server.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    info!("SSO Server listening on {}", addr);
    axum::serve(listener, app).await?;

    Ok(())
}

struct KerberosAuth(String);

#[axum::async_trait]
impl FromRequestParts<AppState> for KerberosAuth {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let auth_header = parts.headers.get(header::AUTHORIZATION);

        match auth_header {
            Some(value) => {
                let auth_str = value.to_str().map_err(|_| (StatusCode::BAD_REQUEST, "Invalid Auth Header").into_response())?;
                if auth_str.starts_with("Negotiate ") {
                    info!("Received Negotiate header");
                    if !state.settings.kerberos.enabled {
                        return Ok(KerberosAuth("mock_user@DOMAIN.LOCAL".to_string()));
                    }
                    return Ok(KerberosAuth("user@DOMAIN.LOCAL".to_string()));
                }
            }
            None => {}
        }

        Err(Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header(header::WWW_AUTHENTICATE, "Negotiate")
            .body("Authentication Required".into())
            .unwrap())
    }
}



#[instrument(skip(state, upn))]
async fn authorize(
    KerberosAuth(upn): KerberosAuth,
    Query(req): Query<AuthRequest>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    info!(%upn, client_id = %req.client_id, "Authorize request received");

    if req.response_type != "code" {
        warn!("Unsupported response_type: {}", req.response_type);
        return (StatusCode::BAD_REQUEST, "Unsupported response_type. Only 'code' is supported.").into_response();
    }

    let code = Uuid::new_v4().to_string();

    let code_data = AuthCodeData {
        upn: upn.clone(),
        client_id: req.client_id.clone(),
        redirect_uri: req.redirect_uri.clone(),
        nonce: req.nonce.clone(),
    };

    {
        let mut codes = state.codes.write().unwrap();
        codes.insert(code.clone(), code_data);
    }

    let mut redirect_url = format!("{}?code={}", req.redirect_uri, code);
    if let Some(state_param) = req.state {
        redirect_url.push_str(&format!("&state={}", state_param));
    }

    Redirect::temporary(&redirect_url).into_response()
}



#[instrument(skip(state))]
async fn token(
    State(state): State<AppState>,
    Form(req): Form<TokenRequest>,
) -> impl IntoResponse {
    info!(client_id = %req.client_id, "Token request received");

    if req.grant_type != "authorization_code" {
        warn!("Unsupported grant_type: {}", req.grant_type);
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "unsupported_grant_type",
                "error_description": "Only 'authorization_code' grant type is supported."
            }))
        ).into_response();
    }

    let code_data = {
        let mut codes = state.codes.write().unwrap();
        codes.remove(&req.code)
    };

    let code_data = match code_data {
        Some(data) => data,
        None => {
            warn!("Invalid or expired authorization code");
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "invalid_grant",
                    "error_description": "Invalid or expired authorization code."
                }))
            ).into_response();
        }
    };

    if code_data.client_id != req.client_id {
        warn!("client_id mismatch: expected {}, got {}", code_data.client_id, req.client_id);
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "invalid_grant",
                "error_description": "Client ID mismatch."
            }))
        ).into_response();
    }

    if code_data.redirect_uri != req.redirect_uri {
        warn!("redirect_uri mismatch: expected {}, got {}", code_data.redirect_uri, req.redirect_uri);
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "invalid_grant",
                "error_description": "Redirect URI mismatch."
            }))
        ).into_response();
    }

    let now = chrono::Utc::now().timestamp();
    let claims = Claims {
        iss: state.settings.server.issuer.clone(),
        sub: code_data.upn.clone(),
        aud: code_data.client_id.clone(),
        exp: now + 3600,
        iat: now,
        nonce: code_data.nonce,
        upn: code_data.upn.clone(),
    };

    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(state.settings.auth.key_id.clone());

    let id_token = match encode(&header, &claims, &state.private_key) {
        Ok(t) => t,
        Err(e) => {
            error!("Failed to sign JWT: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "server_error",
                    "error_description": "Failed to generate ID Token."
                }))
            ).into_response();
        }
    };

    let response = TokenResponse {
        access_token: Uuid::new_v4().to_string(),
        token_type: "Bearer".to_string(),
        expires_in: 3600,
        id_token,
    };

    Json(response).into_response()
}

async fn jwks(State(state): State<AppState>) -> impl IntoResponse {
    Json(state.public_key_jwk)
}

async fn oidc_config(State(state): State<AppState>) -> impl IntoResponse {
    let issuer = &state.settings.server.issuer;
    let config = serde_json::json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{}/authorize", issuer),
        "token_endpoint": format!("{}/token", issuer),
        "jwks_uri": format!("{}/jwks", issuer),
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid", "profile", "email"],
        "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"]
    });
    Json(config)
}

async fn index(KerberosAuth(upn): KerberosAuth) -> impl IntoResponse {
    let html_template = include_str!("index.html");
    let html_content = html_template.replace("{username}", &upn);
    Html(html_content)
}