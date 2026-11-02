//! `Json<T>`-equivalent extractor with a body-size and JSON-nesting-depth
//! ceiling enforced before deserialization. Rejections other than those two
//! (bad `Content-Type`, malformed JSON, wrong shape) delegate to axum's own
//! `Json<T>`, so their status codes (415/400/422) are unchanged.

use axum::body::Body;
use axum::extract::rejection::JsonRejection;
use axum::extract::{FromRef, FromRequest, Request};
use axum::http::{header::CONTENT_LENGTH, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::de::DeserializeOwned;
use serde_json::json;

use crate::cfg::config::Config;

// A real 4.x verify request nests a few levels deep; this stays well below
// serde_json's own internal recursion guard.
const MAX_JSON_NESTING_DEPTH: usize = 16;

pub struct BoundedJson<T>(pub T);

/// The standard JSON extractor with an observable, payload-free rejection.
pub struct LoggedJson<T>(pub T);

fn log_json_rejection(rejection: JsonRejection) -> Response {
    let error_kind = match &rejection {
        JsonRejection::JsonDataError(_) => "invalid_json_shape",
        JsonRejection::JsonSyntaxError(_) => "invalid_json_syntax",
        JsonRejection::MissingJsonContentType(_) => "missing_json_content_type",
        JsonRejection::BytesRejection(_) => "body_read_failed",
        _ => "json_rejected",
    };
    // Rejection text can echo input values. Log only the class and status.
    tracing::warn!(
        stage = "request_decode",
        error_kind,
        http.status_code = rejection.status().as_u16(),
        "request JSON rejected"
    );
    rejection.into_response()
}

impl<T, S> FromRequest<S> for LoggedJson<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        Json::<T>::from_request(req, state)
            .await
            .map(|Json(value)| Self(value))
            .map_err(log_json_rejection)
    }
}

fn too_large(error_kind: &'static str) -> Response {
    tracing::warn!(
        stage = "request_decode",
        error_kind,
        http.status_code = 413,
        "request body rejected"
    );
    (
        StatusCode::PAYLOAD_TOO_LARGE,
        Json(json!({ "msg": "request_too_large" })),
    )
        .into_response()
}

fn nesting_within_bound(bytes: &[u8], max_depth: usize) -> bool {
    let mut depth: usize = 0;
    let mut in_string = false;
    let mut escaped = false;
    for &b in bytes {
        if in_string {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_string = false;
            }
            continue;
        }
        match b {
            b'"' => in_string = true,
            b'{' | b'[' => {
                depth += 1;
                if depth > max_depth {
                    return false;
                }
            }
            b'}' | b']' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    true
}

impl<T, S> FromRequest<S> for BoundedJson<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
    Config: FromRef<S>,
{
    type Rejection = Response;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let max_body_bytes = Config::from_ref(state).max_body_bytes.as_u64() as usize;

        let declared_oversized = req
            .headers()
            .get(CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<usize>().ok())
            .is_some_and(|len| len > max_body_bytes);
        if declared_oversized {
            return Err(too_large("declared_body_too_large"));
        }

        let (parts, body) = req.into_parts();
        let bytes = axum::body::to_bytes(body, max_body_bytes)
            .await
            .map_err(|_| too_large("body_limit_or_read_failed"))?;

        if !nesting_within_bound(&bytes, MAX_JSON_NESTING_DEPTH) {
            return Err(too_large("json_nesting_too_deep"));
        }

        let rebuilt = Request::from_parts(parts, Body::from(bytes));
        let Json(value) = Json::<T>::from_request(rebuilt, state)
            .await
            .map_err(log_json_rejection)?;
        Ok(BoundedJson(value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shallow_json_is_within_bound() {
        let body = br#"{"a":{"b":[1,2,3]},"c":"}{[]"}"#;
        assert!(nesting_within_bound(body, 16));
    }

    #[test]
    fn deep_nesting_exceeds_bound() {
        let body = vec![b'['; 20];
        assert!(!nesting_within_bound(&body, 16));
    }

    #[test]
    fn brackets_inside_strings_do_not_count() {
        let mut body = br#"{"k":""#.to_vec();
        body.extend(std::iter::repeat_n(b'[', 20));
        body.extend_from_slice(br#""}"#);
        assert!(nesting_within_bound(&body, 16));
    }

    #[test]
    fn escaped_quote_does_not_end_the_string_early() {
        let mut body = br#"{"k":"\""#.to_vec();
        body.extend(std::iter::repeat_n(b'[', 20));
        body.extend_from_slice(br#""}"#);
        assert!(nesting_within_bound(&body, 16));
    }
}
