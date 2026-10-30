//! JWT auth for `POST /api/v4/verify`: ES256 bearer tokens verified against
//! per-service public keys configured at startup (no JWKS).

use std::collections::HashMap;
use std::sync::Arc;

use api_types::{VerificationMsg, VerificationResult};
use axum::extract::{FromRef, FromRequestParts};
use axum::http::{header::AUTHORIZATION, request::Parts, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use eyre::{bail, Context};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use tracing::warn;

const LEEWAY_SECONDS: u64 = 60;

#[derive(Debug, Deserialize)]
struct Claims {
    sub: String,
}

#[derive(Debug, Deserialize)]
struct RawServiceKeys {
    current: String,
    #[serde(default)]
    previous: Option<String>,
}

struct ServiceKeys {
    current: DecodingKey,
    previous: Option<DecodingKey>,
}

impl ServiceKeys {
    fn candidates(&self) -> impl Iterator<Item = &DecodingKey> {
        std::iter::once(&self.current).chain(self.previous.iter())
    }
}

/// Trusted public keys keyed by service name (`sub`), built once at startup.
pub struct JwtKeyStore {
    keys: HashMap<String, ServiceKeys>,
}

/// Rejection reason. All map to a coarse `401`; the variant only tags telemetry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthError {
    MissingToken,
    BadScheme,
    Malformed,
    BadAlg,
    MissingSub,
    InvalidClaims,
    MissingOrInvalidExp,
    UnknownSub,
    BadSignature,
    Expired,
    NotYetValid,
    ValidationFailed,
}

impl AuthError {
    pub fn class(self) -> &'static str {
        match self {
            AuthError::MissingToken => "missing_token",
            AuthError::BadScheme => "bad_scheme",
            AuthError::Malformed => "malformed",
            AuthError::BadAlg => "bad_alg",
            AuthError::MissingSub => "missing_sub",
            AuthError::InvalidClaims => "invalid_claims",
            AuthError::MissingOrInvalidExp => "missing_or_invalid_exp",
            AuthError::UnknownSub => "unknown_sub",
            AuthError::BadSignature => "bad_signature",
            AuthError::Expired => "expired",
            AuthError::NotYetValid => "not_yet_valid",
            AuthError::ValidationFailed => "validation_failed",
        }
    }

    /// Static explanations only: never echo JWT contents or library errors
    /// that may include values from an untrusted claim.
    fn reason(self) -> &'static str {
        match self {
            Self::MissingToken => "Authorization header or bearer token is missing",
            Self::BadScheme => "Authorization header must use Bearer <jwt>",
            Self::Malformed => "JWT structure, encoding, or JSON is malformed",
            Self::BadAlg => "JWT algorithm is unsupported; ES256 is required",
            Self::MissingSub => "JWT is missing the required sub claim",
            Self::InvalidClaims => "JWT claims must be an object with a string sub claim",
            Self::MissingOrInvalidExp => "JWT exp claim is missing or is not a valid numeric date",
            Self::UnknownSub => "JWT sub has no configured trusted public keys",
            Self::BadSignature => {
                "JWT signature did not verify against the configured keys for sub"
            }
            Self::Expired => "JWT has expired beyond the 60-second clock-skew allowance",
            Self::NotYetValid => {
                "JWT nbf is in the future beyond the 60-second clock-skew allowance"
            }
            Self::ValidationFailed => "JWT validation failed with an unexpected validator error",
        }
    }
}

impl JwtKeyStore {
    /// Parses `{service: {current: <PEM>, previous?: <PEM>}}`. Fails closed on an
    /// empty map, bad JSON, or an un-parseable key so startup can refuse to serve.
    pub fn from_json(raw: &str) -> eyre::Result<Self> {
        let parsed: HashMap<String, RawServiceKeys> = serde_json::from_str(raw).wrap_err(
            "jwt_trusted_keys must be a JSON object of {service: {current, previous?}}",
        )?;

        if parsed.is_empty() {
            bail!("jwt_trusted_keys must configure at least one trusted service key");
        }

        let mut keys = HashMap::with_capacity(parsed.len());
        for (sub, raw_keys) in parsed {
            let current = DecodingKey::from_ec_pem(raw_keys.current.as_bytes())
                .wrap_err_with(|| format!("invalid `current` public key for service {sub:?}"))?;
            let previous = raw_keys
                .previous
                .as_deref()
                .map(|pem| {
                    DecodingKey::from_ec_pem(pem.as_bytes()).wrap_err_with(|| {
                        format!("invalid `previous` public key for service {sub:?}")
                    })
                })
                .transpose()?;
            keys.insert(sub, ServiceKeys { current, previous });
        }

        Ok(Self { keys })
    }

    pub fn authenticate(&self, token: &str) -> Result<String, AuthError> {
        let header = decode_header(token).map_err(|err| {
            // Unknown algorithm names (including `none`) are reported as JSON
            // errors by jsonwebtoken's Header deserializer. Classify them
            // without parsing error text or logging the untrusted header.
            let unsupported_algorithm = token
                .split('.')
                .next()
                .and_then(|part| data_encoding::BASE64URL_NOPAD.decode(part.as_bytes()).ok())
                .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
                .is_some_and(|header| {
                    header
                        .get("alg")
                        .and_then(|alg| alg.as_str())
                        .is_some_and(|alg| alg != "ES256")
                });
            if unsupported_algorithm {
                AuthError::BadAlg
            } else {
                map_jwt_error(&err)
            }
        })?;
        if header.alg != Algorithm::ES256 {
            return Err(AuthError::BadAlg);
        }

        // The unverified `sub` only selects which key to check; the signature is
        // still fully verified below, so a forged `sub` cannot help an attacker.
        let sub = unverified_sub(token)?;
        let service_keys = self.keys.get(&sub).ok_or(AuthError::UnknownSub)?;

        let mut validation = Validation::new(Algorithm::ES256);
        validation.leeway = LEEWAY_SECONDS;
        validation.validate_exp = true;
        validation.validate_nbf = true;
        validation.set_required_spec_claims(&["exp", "sub"]);
        validation.validate_aud = false;

        let mut last_err = AuthError::BadSignature;
        for key in service_keys.candidates() {
            match decode::<Claims>(token, key, &validation) {
                Ok(data) => {
                    if data.claims.sub != sub {
                        return Err(AuthError::BadSignature);
                    }
                    return Ok(sub);
                }
                Err(err) => {
                    let mapped = map_jwt_error(&err);
                    // Only a signature mismatch can be resolved by trying the
                    // previous key. Preserve claim failures after a matching key
                    // instead of masking them with that other key's mismatch.
                    if mapped != AuthError::BadSignature {
                        return Err(mapped);
                    }
                    last_err = mapped;
                }
            }
        }
        Err(last_err)
    }
}

fn unverified_sub(token: &str) -> Result<String, AuthError> {
    let mut parts = token.split('.');
    let (_header, payload, _sig) = (
        parts.next().ok_or(AuthError::Malformed)?,
        parts.next().ok_or(AuthError::Malformed)?,
        parts.next().ok_or(AuthError::Malformed)?,
    );
    if parts.next().is_some() {
        return Err(AuthError::Malformed);
    }
    let bytes = data_encoding::BASE64URL_NOPAD
        .decode(payload.as_bytes())
        .map_err(|_| AuthError::Malformed)?;
    let claims: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|_| AuthError::Malformed)?;
    let claims = claims.as_object().ok_or(AuthError::InvalidClaims)?;
    claims
        .get("sub")
        .ok_or(AuthError::MissingSub)?
        .as_str()
        .map(str::to_owned)
        .ok_or(AuthError::InvalidClaims)
}

fn map_jwt_error(err: &jsonwebtoken::errors::Error) -> AuthError {
    use jsonwebtoken::errors::ErrorKind;
    match err.kind() {
        ErrorKind::ExpiredSignature => AuthError::Expired,
        ErrorKind::ImmatureSignature => AuthError::NotYetValid,
        ErrorKind::InvalidSignature => AuthError::BadSignature,
        ErrorKind::InvalidAlgorithm | ErrorKind::InvalidAlgorithmName => AuthError::BadAlg,
        ErrorKind::MissingRequiredClaim(claim) if claim == "exp" => AuthError::MissingOrInvalidExp,
        ErrorKind::MissingRequiredClaim(claim) if claim == "sub" => AuthError::MissingSub,
        ErrorKind::InvalidToken
        | ErrorKind::Base64(_)
        | ErrorKind::Json(_)
        | ErrorKind::Utf8(_) => AuthError::Malformed,
        _ => AuthError::ValidationFailed,
    }
}

fn reject(err: AuthError) -> Response {
    let class = err.class();
    metrics::counter!("verify_auth.rejected", "class" => class).increment(1);
    let span = tracing::Span::current();
    span.record("auth.outcome", "rejected");
    span.record("auth.error_kind", class);
    warn!(
        event = "authentication_rejected",
        stage = "authentication",
        error_kind = class,
        reason = err.reason(),
        http.status_code = 401,
        "request rejected because authentication failed"
    );
    (
        StatusCode::UNAUTHORIZED,
        Json(VerificationResult {
            msg: VerificationMsg::Unauthorized,
        }),
    )
        .into_response()
}

/// Guards a route: a handler taking this argument requires a valid token, one
/// without it is unauthenticated. Carries the authenticated `sub`.
#[derive(Debug, Clone)]
pub struct AuthenticatedService(pub String);

impl<S> FromRequestParts<S> for AuthenticatedService
where
    Arc<JwtKeyStore>: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let store = Arc::<JwtKeyStore>::from_ref(state);

        let token = match parts.headers.get(AUTHORIZATION) {
            None => return Err(reject(AuthError::MissingToken)),
            Some(value) => {
                let raw = value.to_str().map_err(|_| reject(AuthError::BadScheme))?;
                match raw.split_once(' ') {
                    Some((scheme, token)) if scheme.eq_ignore_ascii_case("Bearer") => {
                        let token = token.trim();
                        if token.is_empty() {
                            return Err(reject(AuthError::MissingToken));
                        }
                        token
                    }
                    _ => return Err(reject(AuthError::BadScheme)),
                }
            }
        };

        match store.authenticate(token) {
            Ok(sub) => {
                tracing::Span::current().record("auth.outcome", "accepted");
                metrics::counter!("verify_auth.accepted", "sub" => sub.clone()).increment(1);
                Ok(AuthenticatedService(sub))
            }
            Err(err) => Err(reject(err)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PUB: &str = "-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEUSNoOTQ1btpM2g/qgEu0WcHiWyI/
atv3mk0wsGC8wFettFG2AK6UDoOvNmIeQ6rsUOzqe3i8Rziw5s724OWdKw==
-----END PUBLIC KEY-----
";

    fn json_current_only(sub: &str) -> String {
        let mut map = serde_json::Map::new();
        map.insert(sub.to_string(), serde_json::json!({ "current": PUB }));
        serde_json::Value::Object(map).to_string()
    }

    #[test]
    fn empty_map_is_rejected() {
        assert!(JwtKeyStore::from_json("{}").is_err());
    }

    #[test]
    fn non_json_is_rejected() {
        assert!(JwtKeyStore::from_json("not json").is_err());
    }

    #[test]
    fn invalid_pem_is_rejected() {
        let raw =
            r#"{"svc":{"current":"-----BEGIN PUBLIC KEY-----\nnope\n-----END PUBLIC KEY-----"}}"#;
        assert!(JwtKeyStore::from_json(raw).is_err());
    }

    #[test]
    fn current_only_entry_is_valid() {
        let store = JwtKeyStore::from_json(&json_current_only("svc")).expect("valid config");
        let keys = store.keys.get("svc").expect("service present");
        assert!(keys.previous.is_none());
    }

    #[test]
    fn current_and_previous_entry_loads_both() {
        let raw = format!(r#"{{"svc":{{"current":{PUB:?},"previous":{PUB:?}}}}}"#);
        let store = JwtKeyStore::from_json(&raw).expect("valid config");
        assert!(store.keys.get("svc").unwrap().previous.is_some());
    }
}
