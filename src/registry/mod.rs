use std::sync::Arc;

use axum::{Router, http::HeaderValue, routing::get};
use tower_http::request_id::{MakeRequestId, PropagateRequestIdLayer, SetRequestIdLayer};
use tower_http::trace::{DefaultMakeSpan, DefaultOnRequest, DefaultOnResponse, TraceLayer};
use tracing::Level;
use uuid::Uuid;

use crate::state::RegistryState;

mod token;

use tower_http::request_id::RequestId;

#[derive(Clone)]
struct RequestIdGenerator;

impl MakeRequestId for RequestIdGenerator {
    fn make_request_id<B>(&mut self, _request: &http::Request<B>) -> Option<RequestId> {
        let uuid = Uuid::new_v4().to_string();
        Some(RequestId::from(HeaderValue::from_str(&uuid).unwrap()))
    }
}

pub fn router(state: Arc<RegistryState>) -> Router {
    Router::new()
        .route("/auth/token", get(token::token))
        .with_state(state)
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(DefaultMakeSpan::new().level(Level::INFO))
                .on_request(DefaultOnRequest::new().level(Level::INFO))
                .on_response(DefaultOnResponse::new().level(Level::INFO)),
        )
        .layer(PropagateRequestIdLayer::x_request_id())
        .layer(SetRequestIdLayer::x_request_id(RequestIdGenerator))
}
