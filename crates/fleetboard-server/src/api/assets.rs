//! The dashboard's files, compiled into the binary from `web/` (in debug builds rust-embed reads
//! them from disk, so UI work needs no rebuild). `/` is `index.html`; everything else is served by
//! name; nothing outside `web/` can ever be reached.

use axum::body::Body;
use axum::extract::Request;
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use rust_embed::RustEmbed;
use serde_json::json;

#[derive(RustEmbed)]
#[folder = "$CARGO_MANIFEST_DIR/../../web/"]
struct Web;

pub async fn serve(req: Request<Body>) -> Response {
    let path = req.uri().path().trim_start_matches('/');
    let name = if path.is_empty() { "index.html" } else { path };
    if req.method() != axum::http::Method::GET && req.method() != axum::http::Method::HEAD {
        return (
            StatusCode::METHOD_NOT_ALLOWED,
            Json(json!({"detail": "Method not allowed"})),
        )
            .into_response();
    }
    match Web::get(name) {
        Some(file) => {
            let mime = mime_guess::from_path(name).first_or_octet_stream();
            let etag = format!(
                "\"{}-{}\"",
                crate::VERSION,
                hex8(&file.metadata.sha256_hash())
            );
            if req
                .headers()
                .get(header::IF_NONE_MATCH)
                .and_then(|v| v.to_str().ok())
                == Some(etag.as_str())
            {
                return StatusCode::NOT_MODIFIED.into_response();
            }
            (
                [
                    (
                        header::CONTENT_TYPE,
                        HeaderValue::from_str(mime.as_ref())
                            .unwrap_or(HeaderValue::from_static("application/octet-stream")),
                    ),
                    (header::CACHE_CONTROL, HeaderValue::from_static("no-cache")), // revalidate every time, cheap with the ETag
                    (
                        header::ETAG,
                        HeaderValue::from_str(&etag).unwrap_or(HeaderValue::from_static("\"x\"")),
                    ),
                ],
                file.data.into_owned(),
            )
                .into_response()
        }
        None => (StatusCode::NOT_FOUND, Json(json!({"detail": "Not found"}))).into_response(),
    }
}

/// The first eight hex digits of a hash, enough to tell versions apart in an ETag.
fn hex8(bytes: &[u8]) -> String {
    bytes.iter().take(4).map(|b| format!("{b:02x}")).collect()
}
