use axum::{
    body::Body,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use tracing::error;

pub(crate) enum RegistryError {
    Unhandled(anyhow::Error),
}

pub(crate) fn format_error(e: &anyhow::Error) -> String {
    let mut s = String::new();
    s.push_str(&format!("{}", e));
    for cause in e.chain().skip(1) {
        s.push_str(&format!("\nCaused by: {}", cause));
    }
    s
}

impl IntoResponse for RegistryError {
    fn into_response(self) -> Response {
        match self {
            Self::Unhandled(err) => {
                error!(
                    error = %format_error(&err),
                    backtrace = ?err.backtrace(),
                    "Registry error"
                );
                Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Body::empty())
            }
        }
        .unwrap_or_else(|err| {
            let err = err.into();
            error!(
                error = %format_error(&err),
                backtrace = ?err.backtrace(),
                "Registry error"
            );
            (StatusCode::INTERNAL_SERVER_ERROR, Body::empty()).into_response()
        })
    }
}

impl<E> From<E> for RegistryError
where
    E: Into<anyhow::Error>,
{
    fn from(err: E) -> Self {
        let err = err.into();
        error!(
            error = %format_error(&err),
            backtrace = ?err.backtrace(),
            "Registry error"
        );
        Self::Unhandled(err)
    }
}
