//! Assets compiled into the binary. URLs carry `?v=STAMP` (content hash from
//! build.rs) so they can be cached for a year.
use crate::admin::AdminState;
use axum::{
    Router,
    extract::Path,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use std::sync::Arc;

pub const STAMP: &str = env!("ASSET_STAMP");
pub const VERSION: &str = env!("PEEPHOLE_VERSION");

struct Asset {
    path: &'static str,
    mime: &'static str,
    bytes: &'static [u8],
}

static ASSETS: &[Asset] = &[
    Asset {
        path: "app.css",
        mime: "text/css; charset=utf-8",
        bytes: include_bytes!("../../assets/app.css"),
    },
    Asset {
        path: "js/theme.js",
        mime: "text/javascript; charset=utf-8",
        bytes: include_bytes!("../../assets/js/theme.js"),
    },
    Asset {
        path: "js/app.js",
        mime: "text/javascript; charset=utf-8",
        bytes: include_bytes!("../../assets/js/app.js"),
    },
    Asset {
        path: "js/charts.js",
        mime: "text/javascript; charset=utf-8",
        bytes: include_bytes!("../../assets/js/charts.js"),
    },
    Asset {
        path: "fonts/inter-400.woff2",
        mime: "font/woff2",
        bytes: include_bytes!("../../assets/fonts/inter-400.woff2"),
    },
    Asset {
        path: "fonts/inter-500.woff2",
        mime: "font/woff2",
        bytes: include_bytes!("../../assets/fonts/inter-500.woff2"),
    },
    Asset {
        path: "fonts/inter-600.woff2",
        mime: "font/woff2",
        bytes: include_bytes!("../../assets/fonts/inter-600.woff2"),
    },
    Asset {
        path: "fonts/jetbrains-mono-400.woff2",
        mime: "font/woff2",
        bytes: include_bytes!("../../assets/fonts/jetbrains-mono-400.woff2"),
    },
    Asset {
        path: "fonts/jetbrains-mono-500.woff2",
        mime: "font/woff2",
        bytes: include_bytes!("../../assets/fonts/jetbrains-mono-500.woff2"),
    },
    Asset {
        path: "logo.svg",
        mime: "image/svg+xml",
        bytes: include_bytes!("../../assets/logo.svg"),
    },
    Asset {
        path: "world.svg",
        mime: "image/svg+xml",
        bytes: include_bytes!("../../assets/world.svg"),
    },
];

pub fn router() -> Router<Arc<AdminState>> {
    Router::new().route("/assets/{*path}", get(serve)).route(
        "/logo.svg",
        get(|| async { serve(Path("logo.svg".into())).await }),
    )
}

async fn serve(Path(path): Path<String>) -> Response {
    match ASSETS.iter().find(|a| a.path == path) {
        Some(a) => (
            [
                (header::CONTENT_TYPE, a.mime),
                (header::CACHE_CONTROL, "public, max-age=31536000, immutable"),
            ],
            a.bytes,
        )
            .into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}
