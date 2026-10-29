//! `GET /api/live`: the Server-Sent Events stream the dashboard draws from, and `GET /api/ring`,
//! the ten-minute trail for the sparklines' first paint.
//!
//! The first event is the current state so the page paints at once. Then one `tick` per poll, a
//! `: ping` comment every 20 s so dead connections are noticed, and after five minutes an `event:
//! bye` and a clean close: the browser reconnects, and Mnemerynne's proxy re-checks that the person
//! is still signed in and still in the group.

use std::convert::Infallible;
use std::time::Duration;

use axum::extract::{Query, State};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::Json;
use futures::Stream;
use serde::Deserialize;
use serde_json::json;
use tokio::sync::broadcast::error::RecvError;

use super::errors::ApiError;
use super::AppState;

/// How long one stream lives before it says goodbye.
pub const STREAM_LIFETIME: Duration = Duration::from_secs(5 * 60);

pub async fn stream(
    State(st): State<AppState>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let mut rx = st.poller.subscribe();
    let first = st.poller.current_event();
    let s = async_stream::stream! {
        yield Ok(Event::default().event("tick").data(serde_json::to_string(&*first).unwrap_or_default()));
        let deadline = tokio::time::sleep(STREAM_LIFETIME);
        tokio::pin!(deadline);
        loop {
            tokio::select! {
                _ = &mut deadline => {
                    yield Ok(Event::default().event("bye").data("reconnect"));
                    break;
                }
                got = rx.recv() => match got {
                    Ok(ev) => yield Ok(Event::default().event("tick").data(serde_json::to_string(&*ev).unwrap_or_default())),
                    Err(RecvError::Lagged(_)) => continue,     // a slow browser skips ticks, never errors
                    Err(RecvError::Closed) => break,
                }
            }
        }
    };
    Sse::new(s).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(20))
            .text("ping"),
    )
}

#[derive(Deserialize)]
pub struct RingQuery {
    pub host: i64,
}

/// `GET /api/ring?host=ID`: the in-memory trail, oldest first.
pub async fn ring(
    State(st): State<AppState>,
    Query(q): Query<RingQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let points = st
        .poller
        .ring(q.host)
        .ok_or_else(|| ApiError::not_found("No such host."))?;
    Ok(Json(json!({"host": q.host, "points": points})))
}
