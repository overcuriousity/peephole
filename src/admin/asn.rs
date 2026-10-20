//! A network's page, an ASN or an RDAP network: the roll-up
//! (`store::asn`) and its busiest IPs, with pivots into the filtered lists.
//! Admin only and read-only.
use crate::admin::AdminState;
use crate::admin::auth::SessionUser;
use crate::admin::error::{AppError, AppResult, render};
use crate::admin::public::{IntelFact, page_props, urlencode};
use crate::admin::views::Chrome;
use crate::store::asn::{Rollup, RollupKey};
use crate::store::browse::{IpFilter, IpSummary};
use crate::store::evidence::IpProps;
use askama::Template;
use axum::{
    Router,
    extract::{Path, State},
    response::Html,
    routing::get,
};
use std::collections::HashMap;
use std::sync::Arc;

/// IPs listed on the page; the rest are on `/ips?asn=N` (`/ips?net=H`).
pub const ASN_IPS: usize = 50;

pub fn routes() -> Router<Arc<AdminState>> {
    Router::new()
        .route("/admin/asn/{n}", get(asn))
        .route("/admin/net/{handle}", get(net))
}

/// The page of `n`.
pub fn asn_href(n: i64) -> String {
    format!("/admin/asn/{n}")
}

/// The page of the RDAP network `handle`.
pub fn net_href(handle: &str) -> String {
    format!("/admin/net/{}", urlencode(handle))
}

/// The RDAP facts the network page shows under its title.
const NET_FACTS: [&str; 5] = ["Range", "CIDRs", "Type", "Country", "Registrant"];

#[derive(Template)]
#[template(path = "asn.html")]
struct AsnPage {
    chrome: Chrome,
    asn: u32,
    /// `None`: no IP recorded in the network.
    r: Option<Rollup>,
    ips: Vec<IpSummary>,
    /// `_rollup.html`: the network's `/ips` filter.
    base: String,
    /// `_ip_row.html`: no bulk delete here; the bar scale.
    can_delete: bool,
    count_max: i64,
    props: HashMap<String, IpProps>,
}

#[derive(Template)]
#[template(path = "net.html")]
struct NetPage {
    chrome: Chrome,
    handle: String,
    /// The network's RDAP facts, as its busiest IP's card picks them.
    facts: Vec<IntelFact>,
    r: Option<Rollup>,
    ips: Vec<IpSummary>,
    base: String,
    can_delete: bool,
    count_max: i64,
    props: HashMap<String, IpProps>,
}

/// The network's busiest IPs, when it has any.
async fn top_ips(st: &AdminState, r: &Option<Rollup>, f: IpFilter) -> AppResult<Vec<IpSummary>> {
    if r.is_none() {
        return Ok(vec![]);
    }
    let mut items = st.store.list_ips(&f).await?.items;
    items.truncate(ASN_IPS);
    Ok(items)
}

async fn asn(
    _u: SessionUser,
    State(st): State<Arc<AdminState>>,
    Path(n): Path<String>,
) -> AppResult<Html<String>> {
    let asn: u32 = n
        .parse()
        .map_err(|_| AppError::BadRequest("An ASN is a number.".into()))?;
    let r = st.store.rollup(&RollupKey::Asn(asn.into())).await?;
    let f = IpFilter {
        asn: Some(asn.into()),
        ..Default::default()
    };
    let ips = top_ips(&st, &r, f).await?;
    let props = page_props(&st, true, ips.iter().map(|i| i.ip.as_str())).await?;
    render(&AsnPage {
        props,
        chrome: Chrome::new(true, "ips"),
        count_max: ips.iter().map(|i| i.request_count).max().unwrap_or(0),
        base: format!("asn={asn}"),
        asn,
        r,
        ips,
        can_delete: false,
    })
}

async fn net(
    _u: SessionUser,
    State(st): State<Arc<AdminState>>,
    Path(handle): Path<String>,
) -> AppResult<Html<String>> {
    // Checked before any query: no stored handle is longer.
    if handle.trim().is_empty() || handle.chars().count() > crate::store::rdap_net::MAX_LEN {
        return Err(AppError::BadRequest(
            "An RDAP handle is 1 to 200 characters.".into(),
        ));
    }
    let r = st.store.rollup(&RollupKey::Net(handle.clone())).await?;
    let f = IpFilter {
        net: Some(handle.clone()),
        ..Default::default()
    };
    let ips = top_ips(&st, &r, f).await?;
    let facts = match ips.first() {
        Some(i) => match st.store.rdap_pick(&i.ip).await? {
            Some(crate::store::data::RdapPick::Chosen(a)) => crate::admin::public::intel_facts(
                crate::intel::RDAP,
                &serde_json::Value::Object(a.data),
                false,
            )
            .into_iter()
            .filter(|f| NET_FACTS.contains(&f.label.as_str()))
            .collect(),
            _ => vec![],
        },
        None => vec![],
    };
    let props = page_props(&st, true, ips.iter().map(|i| i.ip.as_str())).await?;
    render(&NetPage {
        props,
        chrome: Chrome::new(true, "ips"),
        count_max: ips.iter().map(|i| i.request_count).max().unwrap_or(0),
        base: format!("net={}", urlencode(&handle)),
        handle,
        facts,
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

    #[tokio::test]
    async fn the_rdap_network_page_rolls_up_its_ips() {
        let (state, cookie, app, _d) = app().await;
        crate::store::asn::tests::seed(&state.store).await;
        let get = |path: &str| {
            Request::get(path)
                .header("cookie", &cookie)
                .header("sec-fetch-site", "same-origin")
        };

        let (st, h, _) = send(&app, Request::get("/admin/net/NET-1"), Body::empty()).await;
        assert_eq!(st, StatusCode::SEE_OTHER);
        assert_eq!(h["location"], "/login");

        let (st, _, html) = send(&app, get("/admin/net/NET-1"), Body::empty()).await;
        assert_eq!(st, StatusCode::OK);
        for want in [
            "<h1>Example RDAP · <span class=\"mono\">NET-1</span></h1>",
            "Range <span class=\"mono\">192.0.2.0 - 192.0.2.255</span>",
            "Registrant <span>Example Registrant</span>",
            "<span class=\"label\">IPs</span><div class=\"value\">2</div>",
            "<span class=\"label\">Requests</span><div class=\"value\">3</div>",
            "href=\"/ips?net=NET-1&amp;label=wp\">wp <span class=\"muted\">×2</span>",
            "href=\"/ips?net=NET-1&amp;port=22\"",
            "href=\"/admin/campaigns/203.0.113.1\">#7 <span class=\"muted\">×2</span>",
            "href=\"/ip/203.0.113.1\"",
            "href=\"/ip/203.0.113.2\"",
            "<a href=\"/ips?net=NET-1\">All IPs →</a>",
        ] {
            assert!(html.contains(want), "{want} missing:\n{html}");
        }
        assert!(!html.contains("198.51.100.1"), "another network: {html}");

        // A handle with spaces, as RIPE gives them, travels percent-encoded.
        assert_eq!(
            super::net_href("195.63.0.0 - 195.63.31.255"),
            "/admin/net/195.63.0.0%20-%20195.63.31.255"
        );

        let (st, _, empty) = send(&app, get("/admin/net/nope"), Body::empty()).await;
        assert_eq!(st, StatusCode::OK);
        assert!(
            empty.contains("No IP recorded in this RDAP network."),
            "{empty}"
        );
        assert!(!empty.contains("All IPs"), "{empty}");

        let long = "x".repeat(201);
        let (st, _, _) = send(&app, get(&format!("/admin/net/{long}")), Body::empty()).await;
        assert_eq!(st, StatusCode::BAD_REQUEST);
        let (st, _, _) = send(
            &app,
            get(&format!("/admin/net/{}", &long[1..])),
            Body::empty(),
        )
        .await;
        assert_eq!(st, StatusCode::OK, "200 characters is allowed");
    }
}
