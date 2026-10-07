//! The top bar's search box: works out what was typed and opens its page.
//! An IP, a network, `AS123`, `#<request id>`, a path, or a linking value
//! (fingerprint, host key, JA4…), or a host name (the Lookup page).
use crate::admin::AdminState;
use crate::admin::auth::SessionUser;
use crate::admin::error::{AppResult, render};
use crate::admin::public::urlencode;
use crate::admin::views::{Chrome, link_href};
use crate::store::links::LinkKind;
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
    Request(i64),
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
    if let Some(id) = q.strip_prefix('#').and_then(|n| n.parse::<i64>().ok()) {
        return Input::Request(id);
    }
    if q.starts_with('/') {
        return Input::Path(q.to_string());
    }
    if let Some(name) = crate::intel::dns::valid_name(q) {
        return Input::Host(name);
    }
    Input::Value(q.to_string())
}

#[derive(Template)]
#[template(path = "admin_search.html")]
struct SearchPage {
    chrome: Chrome,
    q: String,
    /// `(kind name, item page)` of each kind holding the value.
    found: Vec<(&'static str, String)>,
}

async fn search(
    _u: SessionUser,
    State(st): State<Arc<AdminState>>,
    Query(sq): Query<SearchQuery>,
) -> AppResult<Response> {
    let q = sq.q.unwrap_or_default().trim().to_string();
    // A name the links know as a value (a file name such as
    // `wp-login.php`) is searched as one; any other name goes to Lookup.
    let input = match classify(&q) {
        Input::Host(h) if st.store.find_value(&q).await?.is_empty() => Input::Host(h),
        Input::Host(_) => Input::Value(q.clone()),
        i => i,
    };
    let to = match input {
        Input::Empty => None,
        Input::Ip(ip) => Some(if st.store.ip_by_addr(&ip.to_string()).await?.is_some() {
            format!("/ip/{ip}")
        } else {
            format!("/admin/lookup?ip={}", urlencode(&ip.to_string()))
        }),
        Input::Net(n) => Some(format!("/ips?q={}", urlencode(&n.to_string()))),
        Input::Asn(n) => Some(format!("/ips?asn={n}")),
        Input::Request(id) => Some(format!("/admin/requests/{id}")),
        Input::Path(p) => Some(format!("/requests?path={}", urlencode(&p))),
        Input::Host(h) => Some(format!("/admin/lookup?ip={}", urlencode(&h))),
        Input::Value(v) => {
            let kinds = st.store.find_value(&v).await?;
            match kinds.as_slice() {
                [k] => Some(link_href(k.key(), &v)),
                _ => {
                    let found = kinds
                        .iter()
                        .map(|k: &LinkKind| (k.name(), link_href(k.key(), &v)))
                        .collect();
                    return Ok(render(&SearchPage {
                        chrome: Chrome::new(true, "admin"),
                        q,
                        found,
                    })?
                    .into_response());
                }
            }
        }
    };
    Ok(match to {
        Some(to) => Redirect::to(&to).into_response(),
        None => render(&SearchPage {
            chrome: Chrome::new(true, "admin"),
            q,
            found: vec![],
        })?
        .into_response(),
    })
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
        assert_eq!(classify("#42"), Input::Request(42));
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
    }
}
