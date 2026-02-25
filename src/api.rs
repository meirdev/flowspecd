use crate::config::ApiConfig;
use crate::flowspec::FlowSpecEngine;
use crate::stats::StatsCollector;
use axum::{
    extract::State,
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use serde::Serialize;
use std::sync::Arc;

#[derive(Clone)]
pub struct ApiState {
    pub flowspec_engine: Arc<FlowSpecEngine>,
    pub stats: StatsCollector,
}

pub async fn run_api(config: ApiConfig, state: ApiState) -> anyhow::Result<()> {
    let app = Router::new()
        .route("/health", get(health))
        .route("/stats", get(get_stats))
        .route("/stats/global", get(get_global_stats))
        .route("/stats/interfaces", get(get_interface_stats))
        .route("/stats/rules", get(get_rule_stats))
        .route("/rules", get(get_rules))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(config.listen).await?;
    tracing::info!("REST API listening on {}", config.listen);

    axum::serve(listener, app).await?;
    Ok(())
}

async fn health() -> impl IntoResponse {
    Json(serde_json::json!({
        "status": "healthy",
        "service": "rust-router"
    }))
}

#[derive(Serialize)]
struct StatsResponse {
    uptime_secs: u64,
    global: crate::stats::GlobalStatsSnapshot,
    interfaces: std::collections::HashMap<String, crate::stats::InterfaceStatsSnapshot>,
    rules: std::collections::HashMap<String, crate::stats::RuleStatsSnapshot>,
}

async fn get_stats(State(state): State<ApiState>) -> impl IntoResponse {
    let response = StatsResponse {
        uptime_secs: state.stats.uptime_secs(),
        global: state.stats.global().snapshot(),
        interfaces: state.stats.all_interface_stats(),
        rules: state.stats.all_rule_stats(),
    };
    Json(response)
}

async fn get_global_stats(State(state): State<ApiState>) -> impl IntoResponse {
    Json(serde_json::json!({
        "uptime_secs": state.stats.uptime_secs(),
        "stats": state.stats.global().snapshot()
    }))
}

async fn get_interface_stats(State(state): State<ApiState>) -> impl IntoResponse {
    Json(state.stats.all_interface_stats())
}

async fn get_rule_stats(State(state): State<ApiState>) -> impl IntoResponse {
    Json(state.stats.all_rule_stats())
}

async fn get_rules(State(state): State<ApiState>) -> impl IntoResponse {
    let rules = state.flowspec_engine.list_rules();
    Json(serde_json::json!({
        "count": rules.len(),
        "rules": rules
    }))
}
