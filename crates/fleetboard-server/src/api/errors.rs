//! One error type for every handler: a status and a sentence, sent as `{"detail": "..."}`.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use serde_json::json;

#[derive(Debug)]
pub struct ApiError(pub StatusCode, pub String);

impl ApiError {
    pub fn bad(msg: impl Into<String>) -> Self {
        Self(StatusCode::UNPROCESSABLE_ENTITY, msg.into())
    }
    pub fn not_found(msg: impl Into<String>) -> Self {
        Self(StatusCode::NOT_FOUND, msg.into())
    }
    pub fn conflict(msg: impl Into<String>) -> Self {
        Self(StatusCode::CONFLICT, msg.into())
    }
}

impl From<rusqlite::Error> for ApiError {
    /// A UNIQUE violation becomes a 409 with a hint; anything else is a 500 with the text logged.
    fn from(e: rusqlite::Error) -> Self {
        let text = e.to_string();
        if text.contains("UNIQUE") {
            let what = if text.contains("hosts.name") {
                "name"
            } else {
                "address"
            };
            return Self::conflict(format!("A host with that {what} already exists."));
        }
        tracing::error!("database: {text}");
        Self(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Database error; see the server log.".into(),
        )
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({"detail": self.1}))).into_response()
    }
}
