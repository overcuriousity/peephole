use crate::admin::views::Chrome;
use askama::Template;
use axum::{
    http::StatusCode,
    response::{Html, IntoResponse, Response},
};

#[derive(Template)]
#[template(path = "error.html")]
struct ErrorPage {
    chrome: Chrome,
    title: &'static str,
    detail: String,
}

#[derive(Debug)]
pub enum AppError {
    NotFound,
    BadRequest(String),
    Internal(anyhow::Error),
}

pub type AppResult<T> = Result<T, AppError>;

impl From<anyhow::Error> for AppError {
    fn from(e: anyhow::Error) -> Self {
        AppError::Internal(e)
    }
}
impl From<sqlx::Error> for AppError {
    fn from(e: sqlx::Error) -> Self {
        AppError::Internal(e.into())
    }
}
impl From<askama::Error> for AppError {
    fn from(e: askama::Error) -> Self {
        AppError::Internal(e.into())
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, title, detail) = match self {
            AppError::NotFound => (
                StatusCode::NOT_FOUND,
                "Not found",
                "Nothing lives at this address.".to_string(),
            ),
            AppError::BadRequest(m) => (StatusCode::BAD_REQUEST, "Bad request", m),
            AppError::Internal(e) => {
                tracing::error!(error = ?e, "request failed");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Something broke",
                    "The error has been logged.".to_string(),
                )
            }
        };
        let page = ErrorPage {
            chrome: Chrome::new(false, ""),
            title,
            detail,
        };
        match page.render() {
            Ok(html) => (status, Html(html)).into_response(),
            Err(_) => (status, title).into_response(),
        }
    }
}

/// Render any template into an `Html` response, mapping template errors.
pub fn render<T: Template>(t: &T) -> AppResult<Html<String>> {
    Ok(Html(t.render()?))
}

pub async fn not_found() -> AppError {
    AppError::NotFound
}
