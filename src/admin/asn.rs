//! A network's page: the ASN roll-up (`store::asn`) and its busiest IPs,
//! with pivots into the filtered lists. Admin only and read-only.
use crate::admin::AdminState;
use crate::admin::auth::SessionUser;
use crate::admin::error::{AppError, AppResult, render};
use crate::admin::views::Chrome;
use crate::store::asn::AsnRollup;
use crate::store::browse::{IpFilter, IpSummary};
use askama::Template;
use axum::{
    Router,
    extract::{Path, State},
    response::Html,
    routing::get,
};
use std::sync::Arc;

/// IPs listed on the page; the rest are on `/ips?asn=N`.
pub const ASN_IPS: usize = 50;

pub fn routes() -> Router<Arc<AdminState>> {
    Router::new().route("/admin/asn/{n}", get(asn))
}

/// The page of `n`.
pub fn asn_href(n: i64) -> String {
    format!("/admin/asn/{n}")
}

#[derive(Template)]
#[template(path = "asn.html")]
struct AsnPage {
    chrome: Chrome,
    asn: u32,
    /// `None`: no IP recorded in the network.
    r: Option<AsnRollup>,
    ips: Vec<IpSummary>,
    /// `_ip_row.html`: no bulk delete here; the bar scale.
    can_delete: bool,
    count_max: i64,
}

async fn asn(
    _u: SessionUser,
    State(st): State<Arc<AdminState>>,
    Path(n): Path<String>,
) -> AppResult<Html<String>> {
    let asn: u32 = n
        .parse()
        .map_err(|_| AppError::BadRequest("An ASN is a number.".into()))?;
    let r = st.store.asn_rollup(asn.into()).await?;
    let ips = if r.is_some() {
        let f = IpFilter {
            asn: Some(asn.into()),
            ..Default::default()
        };
        let mut items = st.store.list_ips(&f).await?.items;
        items.truncate(ASN_IPS);
        items
    } else {
        vec![]
    };
    render(&AsnPage {
        chrome: Chrome::new(true, "ips"),
        count_max: ips.iter().map(|i| i.request_count).max().unwrap_or(0),
        asn,
        r,
        ips,
        can_delete: false,
    })
}

#[cfg(test)]
mod tests {
    use crate::admin::devices::tests::{app, send};
    use axum::body::Body;
    use axum::http::{Request, StatusCode};

    #[tokio::test]
    async fn the_network_page_rolls_up_its_ips() {
        let (state, cookie, app, _d) = app().await;
        crate::store::asn::tests::seed(&state.store).await;
        let get = |path: &str| {
            Request::get(path)
                .header("cookie", &cookie)
                .header("sec-fetch-site", "same-origin")
        };

        let (st, h, _) = send(&app, Request::get("/admin/asn/64500"), Body::empty()).await;
        assert_eq!(st, StatusCode::SEE_OTHER);
        assert_eq!(h["location"], "/login");

        let (st, _, html) = send(&app, get("/admin/asn/64500"), Body::empty()).await;
        assert_eq!(st, StatusCode::OK);
        for want in [
            "<h1>Example Net <span class=\"mono\">AS64500</span></h1>",
            "<span class=\"label\">IPs</span><div class=\"value\">2</div>",
            "<span class=\"label\">Requests</span><div class=\"value\">3</div>",
            "href=\"/ips?asn=64500&amp;label=wp\">wp <span class=\"muted\">×2</span>",
            "href=\"/ips?asn=64500&amp;label=env\"",
            "href=\"/ips?asn=64500&amp;port=22\"",
            "href=\"/admin/campaigns/203.0.113.1\">#7 <span class=\"muted\">×2</span>",
            "href=\"/ip/203.0.113.1\"",
            "href=\"/ip/203.0.113.2\"",
            "<a href=\"/ips?asn=64500\">All IPs →</a>",
        ] {
            assert!(html.contains(want), "{want} missing:\n{html}");
        }
        assert!(!html.contains("198.51.100.1"), "another network: {html}");
        assert!(!html.contains("port=23"), "a closed port: {html}");
        assert!(!html.contains("bulk-delete"), "{html}");

        // A network with no recorded IP: the page, empty.
        let (st, _, empty) = send(&app, get("/admin/asn/64999"), Body::empty()).await;
        assert_eq!(st, StatusCode::OK);
        assert!(empty.contains("No IP recorded in AS64999."), "{empty}");
        assert!(!empty.contains("All IPs"), "{empty}");

        for bad in ["abc", "-1", "4294967296", "1.5"] {
            let (st, _, _) = send(&app, get(&format!("/admin/asn/{bad}")), Body::empty()).await;
            assert_eq!(st, StatusCode::BAD_REQUEST, "{bad}");
        }
    }
}
