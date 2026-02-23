use axum::{extract::Json, http::StatusCode, response::IntoResponse, routing::post, Router};
use serde::{Deserialize, Serialize};

use syntax_engine::{evaluate_with_config, Decision, EngineConfig, FinalDecision, TransactionIntent};

#[derive(Debug, Deserialize)]
pub struct EvaluateRequest {
    pub user_id: String,
    pub amount_cents: u64,
    pub is_pep: bool,
    pub has_active_kyc: bool,
    pub timestamp_utc_ms: u64,
    pub risk_bps: u16,
    pub ui_hash_valid: bool,
}

#[derive(Debug, Serialize)]
pub struct EvaluateResponse {
    pub final_decision: FinalDecision,
    pub trace: Vec<Decision>,
    pub audit_hash: String,
}

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
}

pub fn app() -> Router {
    Router::new().route("/evaluate", post(evaluate_handler))
}

async fn evaluate_handler(Json(req): Json<EvaluateRequest>) -> impl IntoResponse {
    if req.amount_cents == 0 {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse { error: "amount_cents must be > 0".to_string() }),
        )
            .into_response();
    }
    if req.risk_bps >= 10_000 {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse { error: "risk_bps must be < 10000".to_string() }),
        )
            .into_response();
    }

    let tx = TransactionIntent {
        user_id: &req.user_id,
        amount_cents: req.amount_cents,
        is_pep: req.is_pep,
        has_active_kyc: req.has_active_kyc,
        timestamp_utc_ms: req.timestamp_utc_ms,
        risk_bps: req.risk_bps,
        ui_hash_valid: req.ui_hash_valid,
    };

    let (final_decision, trace, audit_hash) =
        evaluate_with_config(&tx, EngineConfig::default());

    let response = EvaluateResponse { final_decision, trace, audit_hash };
    (StatusCode::OK, Json(response)).into_response()
}
