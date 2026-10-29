//! `GET /api/history?host=ID&from=U&to=U&step=10|60|300`: averaged points from the 24-hour table.
//! The range is clamped to the retention window and the step raised until at most 1440 points
//! come back, so a careless request can't pull 8640 rows.

use axum::extract::{Query, State};
use axum::response::Json;
use serde::Deserialize;
use serde_json::json;

use super::errors::ApiError;
use super::AppState;
use crate::db::RETAIN_SECONDS;

const MAX_POINTS: u64 = 1440;
const STEPS: [u64; 3] = [10, 60, 300];

#[derive(Deserialize)]
pub struct HistoryQuery {
    pub host: i64,
    pub from: Option<u64>,
    pub to: Option<u64>,
    pub step: Option<u64>,
}

/// Pick the finest allowed step that keeps the point count under the cap.
pub fn choose_step(wanted: Option<u64>, span: u64) -> u64 {
    let mut step = STEPS
        .iter()
        .copied()
        .find(|s| Some(*s) == wanted)
        .unwrap_or(10);
    while span / step > MAX_POINTS {
        step = match step {
            10 => 60,
            60 => 300,
            _ => step * 2,
        };
    }
    step
}

pub async fn history(
    State(st): State<AppState>,
    Query(q): Query<HistoryQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    st.db
        .get_host(q.host)?
        .ok_or_else(|| ApiError::not_found("No such host."))?;
    let now = crate::now_unix();
    let to = q.to.unwrap_or(now).min(now + 60);
    let from = q
        .from
        .unwrap_or(to.saturating_sub(3600))
        .max(now.saturating_sub(RETAIN_SECONDS));
    if from >= to {
        return Err(ApiError::bad("`from` must be before `to`."));
    }
    let step = choose_step(q.step, to - from);
    let db = st.db.clone();
    let points = tokio::task::spawn_blocking(move || db.history(q.host, from, to, step))
        .await
        .map_err(|_| {
            ApiError(
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "History query failed.".into(),
            )
        })??;
    Ok(Json(
        json!({"host": q.host, "from": from, "to": to, "step": step, "points": points}),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_step_grows_until_the_points_fit() {
        assert_eq!(choose_step(Some(10), 3600), 10); // 360 points
        assert_eq!(choose_step(Some(10), 6 * 3600), 60); // 2160 at 10 s → 360 at 60 s
        assert_eq!(choose_step(Some(60), 24 * 3600), 60); // 1440 exactly fits
        assert_eq!(choose_step(None, 24 * 3600 + 60), 300); // one more minute makes 1441 points: too many
        assert_eq!(choose_step(Some(7), 100), 10); // unknown steps fall back to 10
    }
}
