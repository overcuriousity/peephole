//! The top bar's search box: works out what was typed and opens its page.
//! An IP, a network, `AS123`, `#<request or campaign number>`, `C12`, a
//! path, an upload's sha256, a label, or a linking value (fingerprint,
//! host key, JA4…), or a host name (the Lookup page).
use crate::admin::AdminState;
use crate::admin::auth::SessionUser;
use crate::admin::error::{AppResult, render};
use crate::admin::public::urlencode;
use crate::admin::views::{Chrome, link_href};
use askama::Template;
use axum::{
    Router,
    extract::{Query, State},
    response::{IntoResponse, Redirect, Response},
    routing::get,
};
use std::net::IpAddr;
use std::sync::Arc;

pub fn routes() -> Router<Arc<AdminState>> {
    Router::new().route("/admin/search", get(search))
}

#[derive(serde::Deserialize, Default)]
pub struct SearchQuery {
    pub q: Option<String>,
}

/// What a search text is.
#[derive(Debug, PartialEq, Eq)]
enum Input {
    Empty,
    Ip(IpAddr),
    Net(ipnet::IpNet),
    Asn(u32),
    /// `#12`: a request id or a campaign number.
    Number(i64),
    /// `C12`, `campaign 12`.
    Campaign(i64),
    /// 64 hex digits, lowercased: an upload, or a linking value.
    Sha256(String),
    Path(String),
    /// A host name: the Lookup page resolves it.
    Host(String),
    Value(String),
}

fn classify(q: &str) -> Input {
    let q = q.trim();
    if q.is_empty() {
        return Input::Empty;
    }
    if let Ok(ip) = q.parse::<IpAddr>() {
        return Input::Ip(crate::net::canonical(ip));
    }
    if let Ok(net) = q.parse::<ipnet::IpNet>() {
        return Input::Net(net.trunc());
    }
    if let Some(n) = q
        .strip_prefix("AS")
        .or_else(|| q.strip_prefix("as"))
        .or_else(|| q.strip_prefix("As"))
        .and_then(|n| n.parse::<u32>().ok())
    {
        return Input::Asn(n);
    }
    if let Some(n) = q.strip_prefix('#').and_then(positive) {
        return Input::Number(n);
    }
    let lower = q.to_ascii_lowercase();
    if let Some(n) = lower
        .strip_prefix("campaign")
        .map(str::trim_start)
        .or_else(|| lower.strip_prefix('c'))
        .and_then(positive)
    {
        return Input::Campaign(n);
    }
    if q.len() == 64 && q.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Input::Sha256(lower);
    }
    if q.starts_with('/') {
        return Input::Path(q.to_string());
    }
    if let Some(name) = crate::intel::dns::valid_name(q) {
        return Input::Host(name);
    }
    Input::Value(q.to_string())
}

/// A number from 1 up, digits only.
fn positive(n: &str) -> Option<i64> {
    n.bytes()
        .all(|b| b.is_ascii_digit())
        .then(|| n.parse::<i64>().ok())
        .flatten()
        .filter(|&n| n > 0)
}

#[derive(Template)]
#[template(path = "admin_search.html")]
struct SearchPage {
    chrome: Chrome,
    q: String,
    /// `(kind name, item page)` of each kind holding the value.
    found: Vec<(&'static str, String)>,
    /// `C12` typed and there is no campaign 12.
    no_campaign: Option<i64>,
}

async fn search(
    _u: SessionUser,
    State(st): State<Arc<AdminState>>,
    Query(sq): Query<SearchQuery>,
) -> AppResult<Response> {
    let q = sq.q.unwrap_or_default().trim().to_string();
    // Where the text could lead, `(kind name, page)`: one place opens,
    // more are listed.
    let mut found: Vec<(&'static str, String)> = vec![];
    let mut no_campaign = None;
    let to = match classify(&q) {
        Input::Empty => None,
        Input::Ip(ip) => Some(if st.store.ip_by_addr(&ip.to_string()).await?.is_some() {
            format!("/ip/{ip}")
        } else {
            format!("/admin/lookup?ip={}", urlencode(&ip.to_string()))
        }),
        Input::Net(n) => Some(format!("/ips?q={}", urlencode(&n.to_string()))),
        Input::Asn(n) => Some(crate::admin::asn::asn_href(n.into())),
        Input::Number(n) => {
            if st.store.request_by_id(n).await?.is_some() {
                found.push(("Request", format!("/admin/requests/{n}")));
            }
            if let Some(key) = st.store.campaign_by_num(n).await? {
                found.push(("Campaign", format!("/admin/campaigns/{key}")));
            }
            None
        }
        Input::Campaign(n) => match st.store.campaign_by_num(n).await? {
            Some(key) => Some(format!("/admin/campaigns/{key}")),
            None => {
                no_campaign = Some(n);
                None
            }
        },
        Input::Sha256(h) => {
            let bytes = data_encoding::HEXLOWER
                .decode(h.as_bytes())
                .unwrap_or_default();
            let mut conn = st.store.read.acquire().await?;
            if crate::store::uploads::has_upload(&mut conn, &bytes).await? {
                found.push(("Upload", format!("/admin/uploads?sha256={h}")));
            }
            drop(conn);
            values(&st, &q, &mut found).await?;
            None
        }
        Input::Path(p) => Some(format!("/requests?path={}", urlencode(&p))),
        // A name the links or labels know (a file name such as
        // `wp-login.php`) is searched as one; any other name goes to Lookup.
        Input::Host(h) => {
            values(&st, &q, &mut found).await?;
            found
                .is_empty()
                .then(|| format!("/admin/lookup?ip={}", urlencode(&h)))
        }
        Input::Value(v) => {
            values(&st, &v, &mut found).await?;
            None
        }
    };
    let to = to.or_else(|| match found.as_slice() {
        [(_, href)] => Some(href.clone()),
        _ => None,
    });
    Ok(match to {
        Some(to) => Redirect::to(&to).into_response(),
        None => render(&SearchPage {
            chrome: Chrome::new(true, "admin"),
            q,
            found,
            no_campaign,
        })?
        .into_response(),
    })
}

/// The label named `v`, then each link kind holding `v`.
async fn values(
    st: &AdminState,
    v: &str,
    found: &mut Vec<(&'static str, String)>,
) -> AppResult<()> {
    if st.store.label_exists(v).await? {
        found.push(("Label", format!("/ips?label={}", urlencode(v))));
    }
    for k in st.store.find_value(v).await? {
        found.push((k.name(), link_href(k.key(), v)));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_what_was_typed() {
        assert_eq!(classify("  "), Input::Empty);
        assert_eq!(
            classify("203.0.113.5"),
            Input::Ip("203.0.113.5".parse().unwrap())
        );
        assert_eq!(
            classify("2001:DB8::1"),
            Input::Ip("2001:db8::1".parse().unwrap())
        );
        assert_eq!(
            classify("203.0.113.9/24"),
            Input::Net("203.0.113.0/24".parse().unwrap())
        );
        assert_eq!(classify("AS64500"), Input::Asn(64500));
        assert_eq!(classify("as13335"), Input::Asn(13335));
        assert_eq!(classify("#42"), Input::Number(42));
        assert_eq!(classify("C12"), Input::Campaign(12));
        assert_eq!(classify("c7"), Input::Campaign(7));
        assert_eq!(classify("campaign 12"), Input::Campaign(12));
        assert_eq!(classify("Campaign12"), Input::Campaign(12));
        let hash = "9F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08";
        assert_eq!(classify(hash), Input::Sha256(hash.to_ascii_lowercase()));
        assert_eq!(classify(&hash[1..]), Input::Value(hash[1..].into()));
        assert_eq!(classify("wp"), Input::Value("wp".into()));
        assert_eq!(
            classify("/wp-login.php"),
            Input::Path("/wp-login.php".into())
        );
        assert_eq!(
            classify("t13d1516h2_8daaf6152771"),
            Input::Value("t13d1516h2_8daaf6152771".into())
        );
        assert_eq!(classify("example.com"), Input::Host("example.com".into()));
        assert_eq!(classify("EXAMPLE.COM."), Input::Host("example.com".into()));
        assert_eq!(classify("not a host"), Input::Value("not a host".into()));
        assert_eq!(classify("localhost"), Input::Value("localhost".into()));
        assert_eq!(classify("ASX"), Input::Value("ASX".into()));
        assert_eq!(classify("#x"), Input::Value("#x".into()));
        // Out of range or signed: not a number.
        assert_eq!(classify("#0"), Input::Value("#0".into()));
        assert_eq!(classify("#-1"), Input::Value("#-1".into()));
        assert_eq!(classify("#+5"), Input::Value("#+5".into()));
        assert_eq!(
            classify("#99999999999999999999"),
            Input::Value("#99999999999999999999".into())
        );
        assert_eq!(classify("cafe"), Input::Value("cafe".into()));
        assert_eq!(classify("campaign"), Input::Value("campaign".into()));
    }

    use crate::admin::devices::tests::{app, send};
    use axum::body::Body;
    use axum::http::{Request, StatusCode, header::LOCATION};

    /// `(status, redirect target, body)` of searching for `q`.
    async fn go(app: &axum::Router, cookie: &str, q: &str) -> (StatusCode, String, String) {
        let req = Request::get(format!("/admin/search?q={}", urlencode(q)))
            .header("cookie", cookie)
            .header("sec-fetch-site", "same-origin");
        let (status, h, body) = send(app, req, Body::empty()).await;
        let to = h
            .get(LOCATION)
            .map(|v| v.to_str().unwrap().to_string())
            .unwrap_or_default();
        (status, to, body)
    }

    #[tokio::test]
    async fn finds_uploads_campaigns_and_labels() {
        let (st, cookie, app, _d) = app().await;
        let up = crate::admin::uploads::tests::upload(&st, "u1", "a.php", b"<?php", true).await;
        let hash = data_encoding::HEXUPPER.encode(&up.sha256);
        let ip = st
            .store
            .upsert_ip("192.0.2.3".parse().unwrap())
            .await
            .unwrap();
        let rid = st
            .store
            .insert_request(&crate::store::requests::NewRequest {
                ip_id: ip.id,
                method: "GET".into(),
                path: "/".into(),
                headers_json: "[]".into(),
                labels_json: r#"["searchlabel"]"#.into(),
                ..Default::default()
            })
            .await
            .unwrap();
        for (key, num) in [("192.0.2.3", rid), ("192.0.2.4", rid + 1)] {
            sqlx::query(
                "INSERT INTO campaigns (key, num, anchor_ip_id, size, first_seen, last_seen,
                    hard_edges, soft_edges, v, computed_at)
                 VALUES (?, ?, ?, 2, '2026-10-01 00:00:00', '2026-10-01 00:00:00', 1, 0, 2,
                    '2026-10-01 00:00:00')",
            )
            .bind(key)
            .bind(num)
            .bind(ip.id)
            .execute(&st.store.pool)
            .await
            .unwrap();
        }
        assert_eq!(
            st.store.campaign_by_num(rid + 1).await.unwrap().as_deref(),
            Some("192.0.2.4")
        );
        assert_eq!(st.store.campaign_by_num(99).await.unwrap(), None);

        let n = rid + 1;
        for (q, want) in [
            (
                hash.clone(),
                format!("/admin/uploads?sha256={}", hash.to_lowercase()),
            ),
            (format!("C{n}"), "/admin/campaigns/192.0.2.4".into()),
            (format!("campaign {n}"), "/admin/campaigns/192.0.2.4".into()),
            (format!("#{n}"), "/admin/campaigns/192.0.2.4".into()),
            ("searchlabel".into(), "/ips?label=searchlabel".into()),
        ] {
            let (status, to, _) = go(&app, &cookie, &q).await;
            assert_eq!(
                (status, to.as_str()),
                (StatusCode::SEE_OTHER, want.as_str()),
                "{q}"
            );
        }

        // `#N` that is both a request and a campaign lists both.
        let (status, _, body) = go(&app, &cookie, &format!("#{rid}")).await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            body.contains(&format!("href=\"/admin/requests/{rid}\"")),
            "{body}"
        );
        assert!(
            body.contains("href=\"/admin/campaigns/192.0.2.3\""),
            "{body}"
        );

        let (status, _, body) = go(&app, &cookie, "C99").await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("No campaign #99."), "{body}");
        let (status, _, body) = go(&app, &cookie, &"0".repeat(64)).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("Nothing found"), "{body}");
    }
}
