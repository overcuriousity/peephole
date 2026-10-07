//! Cluster › Credits: what this node holds, earned and spent, what every
//! member holds in this node's view, and how the price comes about.
use crate::admin::AdminState;
use crate::admin::auth::SessionUser;
use crate::admin::cluster::{back_to, node};
use crate::admin::error::{AppResult, render};
use crate::admin::views::Chrome;
use crate::cluster::identity::NodeId;
use crate::credits::ledger::{Earned, OfferState};
use crate::credits::{self, Mc, mint, show};
use askama::Template;
use axum::{
    Router,
    extract::{Form, State},
    response::{Html, Response},
    routing::{get, post},
};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

const PAGE: &str = "/admin/cluster/credits";
/// Rows shown per list.
const ROWS: usize = 100;

pub fn routes() -> Router<Arc<AdminState>> {
    Router::new()
        .route(PAGE, get(page))
        .route("/admin/cluster/credits/send", post(send))
}

/// The date of a lot's day.
pub fn date_of(day: u32) -> String {
    chrono::DateTime::from_timestamp(day as i64 * 86_400, 0)
        .map(|t| t.format("%Y-%m-%d").to_string())
        .unwrap_or_default()
}

/// The minute an entry is dated (UTC).
pub fn when(hlc: u64) -> String {
    chrono::DateTime::from_timestamp_millis(crate::cluster::hlc::physical_ms(hlc) as i64)
        .map(|t| t.format("%Y-%m-%d %H:%M").to_string())
        .unwrap_or_default()
}

/// When a lot of `day` is gone, seen from `today`.
fn expires_in(day: u32, today: u32) -> String {
    match (day + credits::LOT_DAYS - 1).saturating_sub(today) {
        0 => "today".into(),
        1 => "in 1 day".into(),
        n => format!("in {n} days"),
    }
}

struct DayRow {
    date: String,
    amount: String,
    expires: String,
}

struct NodeRow {
    name: String,
    balance: String,
    /// Where it forwards its credits, as its transfers of the week show.
    collects: String,
}

struct EarnedRow {
    at: String,
    /// The scan's page, when the scan is held here.
    scan: Option<i64>,
    ip: String,
    level: u8,
    /// "1", "2", or a dash when the scan does not count.
    counts: String,
    note: String,
}

struct SpentRow {
    at: String,
    server: String,
    providers: String,
    offered: String,
    charged: String,
    state: &'static str,
}

struct MovedRow {
    at: String,
    from: String,
    to: String,
    amount: String,
    /// It named more than was there.
    short: bool,
}

struct MemberRow {
    key: String,
    name: String,
    balance: String,
    earned: String,
    spent: String,
    /// Why it does not earn in full here; empty: it does.
    standing: String,
    /// Its share of the mint and its allowances over the last 7 days.
    minted: String,
    allowance: String,
    /// What it charged others over the last 7 days.
    sales: String,
}

struct PriceView {
    /// What a funded scan job costs here.
    scan: String,
    scan_bids: u32,
    capacity_per_hour: String,
    utilization: String,
    /// What a probe costs here; None: this node does not probe.
    probe: Option<String>,
    /// What resolving a name for another member costs here.
    resolve: String,
    /// `(provider label, price, paid lookups it serves a day)`.
    offers: Vec<(String, String, String)>,
}

/// One good in the price table: this node's price, its move over 24
/// hours, what members announce, and its demand and supply now.
struct GoodRow {
    key: String,
    label: String,
    /// This node's price; a dash when it does not offer the good.
    price: String,
    /// "+12 %" over 24 hours, and `up`, `down` or `flat`.
    change: Option<(String, &'static str)>,
    /// Lowest–highest that members announce; empty: nobody does.
    band: String,
    demand: String,
    supply: String,
    /// Prices over 7 days, in credits, for the sparkline.
    spark: String,
}

/// One day of this node's money: income by source, and spending.
#[derive(serde::Serialize, Default, Debug, PartialEq)]
struct FlowDay {
    day: String,
    mint: f64,
    allowance: f64,
    sales: f64,
    spent: f64,
}

/// A good's chart series, for the page script.
#[derive(serde::Serialize)]
struct Series {
    label: String,
    points: Vec<credits::history::Point>,
}

/// The price a point charts: this node's, else the members' median.
fn charted(p: &credits::history::Point) -> Option<i64> {
    p.own_mc.or(p.median_mc)
}

/// The move of `points`' price over the last 24 hours, in percent; None
/// without a price a day back.
fn change(points: &[credits::history::Point]) -> Option<f64> {
    let last = points.iter().rev().find(|p| charted(p).is_some())?;
    let base = points
        .iter()
        .find(|p| p.hour >= last.hour - 24 && charted(p).is_some())?;
    let (a, b) = (charted(base)? as f64, charted(last)? as f64);
    (base.hour < last.hour && a > 0.0).then(|| (b - a) / a * 100.0)
}

fn shown_change(pct: f64) -> (String, &'static str) {
    let trend = match pct {
        p if p > 0.5 => "up",
        p if p < -0.5 => "down",
        _ => "flat",
    };
    (format!("{pct:+.0} %"), trend)
}

/// What a good is called on the page.
fn good_label(good: &str) -> String {
    match good {
        credits::price::SCAN => "Scan job".into(),
        credits::price::PROBE => "Probe".into(),
        credits::price::RESOLVE => "Name resolution".into(),
        p => crate::intel::provider_info(p)
            .map(|i| i.label.to_string())
            .unwrap_or_else(|| p.to_string()),
    }
}

#[derive(Template)]
#[template(path = "admin_cluster_credits.html")]
struct CreditsPage {
    chrome: Chrome,
    balance: String,
    held: String,
    days: Vec<DayRow>,
    /// This node has an owner: its nodes and their total.
    fleet: Option<(String, Vec<NodeRow>)>,
    earned: Vec<EarnedRow>,
    /// Scans that wait to be judged.
    waiting: i64,
    spent: Vec<SpentRow>,
    moved: Vec<MovedRow>,
    members: Vec<MemberRow>,
    /// Earned over the entries read, and what is in circulation now.
    totals: (String, String),
    price: PriceView,
    /// `(key, name)` of the members credits can be sent to.
    receivers: Vec<(String, String)>,
    /// This node's closed days, newest first: `(date, mint share, allowance)`.
    income: Vec<(String, String, String)>,
    /// Today: scans of this node counted so far, and whether it recorded a
    /// request today (so the allowance is due).
    accruing: (u32, bool),
    /// Every good this node prices or members announce.
    goods: Vec<GoodRow>,
    /// The scan price's move over 24 hours.
    scan_change: Option<(String, &'static str)>,
    /// `{good: {label, points}}` for the price chart.
    market_json: String,
    /// This node's last 7 days of income and spending, oldest first.
    flow_json: String,
}

async fn page(_u: SessionUser, State(st): State<Arc<AdminState>>) -> AppResult<Html<String>> {
    let node = node(&st)?;
    let me = node.id();
    let book = credits::book_fresh(node).await?;
    let l = &book.ledger;
    let members = node.members();
    let name = |id: &NodeId| {
        if *id == me {
            "this node".to_string()
        } else {
            members
                .get(id)
                .map_or_else(|| id.short(), |m| m.name.clone())
        }
    };
    let siblings = crate::cluster::owner::fleet::siblings(&node.store).await?;

    let days = l
        .by_day(&me)
        .into_iter()
        .map(|(day, mc)| DayRow {
            date: date_of(day),
            amount: show(mc),
            expires: expires_in(day, l.today),
        })
        .collect();
    let collects = match siblings.is_empty() {
        true => HashMap::new(),
        false => crate::admin::cluster_owner::collect_targets(node, &siblings).await,
    };
    let fleet = (!siblings.is_empty()).then(|| {
        let all: Vec<NodeId> = std::iter::once(me)
            .chain(siblings.iter().copied())
            .collect();
        let total: u64 = all.iter().map(|id| book.balance(id)).sum();
        let rows = all
            .iter()
            .map(|id| NodeRow {
                name: name(id),
                balance: show(book.balance(id)),
                collects: collects.get(id).cloned().unwrap_or_default(),
            })
            .collect();
        (show(total), rows)
    });

    // The ledger walks 8 days (a lot's life and one): the page says 7.
    let week = book.now_ms.saturating_sub(7 * credits::DAY_MS) << 16;
    let mut earned = vec![];
    for p in book.paid.iter().rev().filter(|p| p.scan.hlc >= week) {
        if p.scan.scanner != me || earned.len() >= ROWS {
            continue;
        }
        let scan: Option<i64> = sqlx::query_scalar("SELECT id FROM scans WHERE uid = ?")
            .bind(&p.scan.scan_uid)
            .fetch_optional(&st.store.read)
            .await?;
        earned.push(EarnedRow {
            at: when(p.scan.hlc),
            scan,
            ip: p.scan.ip.clone(),
            level: p.scan.job_level,
            counts: if p.weight == 0 {
                "\u{2014}".into()
            } else {
                p.weight.to_string()
            },
            note: p.note.clone(),
        });
    }
    let waiting: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM scans s JOIN scan_jobs j ON j.uid = s.job_uid
         WHERE j.status = 'done' AND s.origin = j.scanner AND s.audit_of IS NULL
           AND (j.scanner = ?1 OR j.origin = ?1) AND MAX(s.hlc, COALESCE(j.hlc, 0)) >= ?2
           AND NOT EXISTS (SELECT 1 FROM credit_scans c WHERE c.job_uid = j.uid)",
    )
    .bind(&me.0[..])
    .bind(crate::cluster::hlc::to_db(week))
    .fetch_one(&st.store.read)
    .await?;

    let spent = l
        .offers
        .iter()
        .rev()
        .filter(|o| o.payer == me)
        .take(ROWS)
        .map(|o| {
            let (charged, state) = match &o.state {
                OfferState::Open => (0, "open"),
                OfferState::Lapsed => (0, "lapsed"),
                OfferState::Charged { charged } => (
                    *charged,
                    // A server that declines, whose providers all failed,
                    // or a scanner that delivered nothing, gives the offer
                    // back with a receipt of nothing.
                    if *charged == 0 {
                        "nothing charged: declined or not answered at the server"
                    } else if o.covered < o.offered {
                        "charged (not fully covered at the server)"
                    } else {
                        "charged"
                    },
                ),
            };
            SpentRow {
                at: when(o.hlc),
                server: name(&o.to),
                providers: o.answered.join(", "),
                offered: show(o.offered),
                charged: show(charged),
                state,
            }
        })
        .collect();
    let moved = l
        .transfers
        .iter()
        .rev()
        .filter(|t| t.from == me || t.to == me)
        .take(ROWS)
        .map(|t| MovedRow {
            at: when(t.hlc),
            from: name(&t.from),
            to: name(&t.to),
            amount: show(t.moved),
            short: t.moved < t.named,
        })
        .collect();

    let mut income: BTreeMap<u32, (Mc, Mc)> = BTreeMap::new();
    for e in book.minted.iter().filter(|e| e.node == me) {
        income.entry(credits::day_of(e.hlc)).or_default().0 += e.mc;
    }
    for e in book.allowances.iter().filter(|e| e.node == me) {
        income.entry(credits::day_of(e.hlc)).or_default().1 += e.mc;
    }
    let income: Vec<(String, String, String)> = income
        .into_iter()
        .rev()
        .take(credits::LOT_DAYS as usize)
        .map(|(d, (m, a))| (date_of(d), show(m), show(a)))
        .collect();
    let today = (book.now_ms / credits::DAY_MS) as u32;
    let counted = book
        .paid
        .iter()
        .filter(|p| p.weight > 0 && p.scan.scanner == me && credits::day_of(p.scan.hlc) == today)
        .count() as u32;
    let recorded = !mint::active_days(&node.store.pool, &[me], today, today)
        .await?
        .is_empty();
    let accruing = (counted, recorded);
    let sum_week = |list: &[Earned], id: &NodeId| -> Mc {
        list.iter()
            .filter(|e| e.node == *id && e.hlc >= week)
            .map(|e| e.mc)
            .sum()
    };

    let mut rows: Vec<MemberRow> = members
        .values()
        .filter(|m| m.active)
        .map(|m| {
            let t = l.week_tally(&m.id);
            MemberRow {
                key: m.id.to_string(),
                name: name(&m.id),
                balance: show(book.balance(&m.id)),
                earned: show(t.earned),
                spent: show(t.spent),
                standing: book.standing(&m.id).reasons().join("; "),
                minted: show(sum_week(&book.minted, &m.id)),
                allowance: show(sum_week(&book.allowances, &m.id)),
                sales: show(t.served),
            }
        })
        .collect();
    rows.sort_by(|a, b| a.name.cmp(&b.name));
    let totals = (
        show(l.week.values().map(|t| t.earned).sum()),
        show(l.circulating()),
    );

    let t = node.price_table();
    let label = |p: &str| {
        crate::intel::provider_info(p)
            .map(|i| i.label.to_string())
            .unwrap_or_else(|| p.to_string())
    };
    let price = PriceView {
        scan: t.sell_mc.map_or_else(|| "–".into(), |m| show(m as u64)),
        scan_bids: 0,
        capacity_per_hour: format!("{:.0}", (t.capacity.per_day / 24.0).max(0.0)),
        utilization: format!("{:.0}", t.capacity.utilization * 100.0),
        probe: t.probe_mc.map(|m| show(m as u64)),
        resolve: show(t.resolve_mc as u64),
        offers: t
            .offers
            .iter()
            .map(|o| {
                (
                    label(&o.provider),
                    show(o.price_mc as u64),
                    o.on_demand.to_string(),
                )
            })
            .collect(),
    };
    // The market over 7 days, from the hourly snapshots.
    let since = credits::history::hour_of(book.now_ms) - 7 * 24;
    let mut by_good: BTreeMap<String, Vec<credits::history::Point>> = BTreeMap::new();
    for p in credits::history::all_since(&st.store.read, since).await? {
        by_good.entry(p.good.clone()).or_default().push(p);
    }
    let rank = |g: &str| match g {
        credits::price::SCAN => 0,
        credits::price::PROBE => 1,
        credits::price::RESOLVE => 2,
        _ => 3,
    };
    let mut keys: Vec<&String> = by_good.keys().collect();
    keys.sort_by_key(|k| (rank(k), good_label(k)));
    let mc = |m: Option<i64>| m.map_or("\u{2014}".to_string(), |m| show(m.max(0) as u64));
    let goods: Vec<GoodRow> = keys
        .iter()
        .map(|k| {
            let pts = &by_good[*k];
            let last = pts.last().expect("a key has points");
            GoodRow {
                key: k.to_string(),
                label: good_label(k),
                price: mc(last.own_mc),
                change: change(pts).map(shown_change),
                band: match (last.lo_mc, last.hi_mc) {
                    (Some(lo), Some(hi)) if lo == hi => show(lo.max(0) as u64),
                    (Some(lo), Some(hi)) => {
                        format!("{}–{}", show(lo.max(0) as u64), show(hi.max(0) as u64))
                    }
                    _ => String::new(),
                },
                demand: format!("{:.1}", last.demand),
                supply: format!("{:.1}", last.supply),
                spark: serde_json::to_string(
                    &pts.iter()
                        .filter_map(charted)
                        .map(|m| m as f64 / 1000.0)
                        .collect::<Vec<_>>(),
                )
                .unwrap_or_else(|_| "[]".into()),
            }
        })
        .collect();
    let scan_change = by_good
        .get(credits::price::SCAN)
        .and_then(|p| change(p))
        .map(shown_change);
    let market_json = serde_json::to_string(
        &by_good
            .into_iter()
            .map(|(k, points)| {
                (
                    k.clone(),
                    Series {
                        label: good_label(&k),
                        points,
                    },
                )
            })
            .collect::<BTreeMap<_, _>>(),
    )
    .unwrap_or_else(|_| "{}".into());

    // This node's money, per day: income by source and spending.
    let first = today.saturating_sub(6);
    let mut flow: BTreeMap<u32, FlowDay> = (first..=today)
        .map(|d| {
            (
                d,
                FlowDay {
                    day: date_of(d)[5..].to_string(),
                    ..Default::default()
                },
            )
        })
        .collect();
    let cr = |mc: Mc| mc as f64 / 1000.0;
    for e in book.minted.iter().filter(|e| e.node == me) {
        if let Some(f) = flow.get_mut(&credits::day_of(e.hlc)) {
            f.mint += cr(e.mc);
        }
    }
    for e in book.allowances.iter().filter(|e| e.node == me) {
        if let Some(f) = flow.get_mut(&credits::day_of(e.hlc)) {
            f.allowance += cr(e.mc);
        }
    }
    for o in &l.offers {
        let OfferState::Charged { charged } = o.state else {
            continue;
        };
        let Some(f) = flow.get_mut(&credits::day_of(o.hlc)) else {
            continue;
        };
        if o.to == me && o.payer != me {
            f.sales += cr(charged);
        }
        if o.payer == me && o.to != me {
            f.spent += cr(charged);
        }
    }
    let flow_json = serde_json::to_string(&flow.into_values().collect::<Vec<_>>())
        .unwrap_or_else(|_| "[]".into());

    let receivers = members
        .values()
        .filter(|m| m.active && m.id != me && !node.is_blocked(&m.id))
        .map(|m| (m.id.to_string(), m.name.clone()))
        .collect();
    render(&CreditsPage {
        chrome: Chrome::new(true, "admin"),
        balance: show(book.balance(&me)),
        held: show(l.held(&me)),
        days,
        fleet,
        earned,
        waiting,
        spent,
        moved,
        members: rows,
        totals,
        price,
        receivers,
        income,
        accruing,
        goods,
        scan_change,
        market_json,
        flow_json,
    })
}

#[derive(serde::Deserialize)]
struct SendForm {
    to: String,
    amount: String,
}

async fn send(
    _u: SessionUser,
    State(st): State<Arc<AdminState>>,
    Form(f): Form<SendForm>,
) -> AppResult<Response> {
    let node = node(&st)?;
    let (Ok(to), Some(mc)) = (NodeId::parse(&f.to), credits::parse_amount(&f.amount)) else {
        return Ok(back_to(
            PAGE,
            None,
            Some("Choose a member and an amount like 0.5.".into()),
        ));
    };
    Ok(match crate::credits::fleet::send(node, to, mc).await {
        Ok(sent) => back_to(
            PAGE,
            Some(format!("Sent {} credits to {}.", show(sent), to.short())),
            None,
        ),
        Err(e) => back_to(PAGE, None, Some(format!("Not sent: {e:#}"))),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn days_and_times_read_as_utc() {
        // 2026-10-06 is day 20_732 of the epoch.
        assert_eq!(date_of(20_732), "2026-10-06");
        let noon = (20_732u64 * 86_400_000 + 12 * 3_600_000 + 34 * 60_000) << 16;
        assert_eq!(when(noon), "2026-10-06 12:34");
        assert_eq!(expires_in(20_732, 20_732), "in 6 days");
        assert_eq!(expires_in(20_727, 20_732), "in 1 day");
        assert_eq!(expires_in(20_726, 20_732), "today");
    }

    fn pt(hour: i64, own: Option<i64>, median: Option<i64>) -> credits::history::Point {
        credits::history::Point {
            hour,
            good: "scan".into(),
            own_mc: own,
            lo_mc: median,
            median_mc: median,
            hi_mc: median,
            demand: 0.0,
            supply: 0.0,
        }
    }

    #[test]
    fn the_price_move_over_a_day() {
        // 100 → 150 within the last 24 hours; older points do not count.
        let p = [
            pt(70, Some(40), None),
            pt(80, Some(100), None),
            pt(100, Some(150), None),
        ];
        assert_eq!(change(&p), Some(50.0));
        assert_eq!(shown_change(50.0), ("+50 %".into(), "up"));
        assert_eq!(shown_change(-20.0), ("-20 %".into(), "down"));
        assert_eq!(shown_change(0.2).1, "flat");
        // The members' median stands in for a good this node does not offer.
        assert_eq!(
            change(&[pt(1, None, Some(200)), pt(2, None, Some(100))]),
            Some(-50.0)
        );
        // One point, or none priced: no move.
        assert_eq!(change(&[pt(1, Some(5), None)]), None);
        assert_eq!(change(&[pt(1, None, None), pt(2, None, None)]), None);
        assert_eq!(good_label("scan"), "Scan job");
    }

    #[test]
    fn the_page_shows_where_credits_come_from() {
        let page = CreditsPage {
            chrome: crate::admin::views::Chrome::new(true, "admin"),
            balance: "1250.00".into(),
            held: "0.00".into(),
            days: vec![],
            fleet: None,
            earned: vec![],
            waiting: 0,
            spent: vec![],
            moved: vec![],
            members: vec![MemberRow {
                key: "k".into(),
                name: "node-alpha".into(),
                balance: "1250.00".into(),
                earned: "255.00".into(),
                spent: "0.00".into(),
                standing: String::new(),
                minted: "250.00".into(),
                allowance: "5.00".into(),
                sales: "1.20".into(),
            }],
            totals: ("255.00".into(), "812.00".into()),
            price: PriceView {
                scan: "0.05".into(),
                scan_bids: 3,
                capacity_per_hour: "40".into(),
                utilization: "12".into(),
                probe: None,
                resolve: "0.01".into(),
                offers: vec![("MaxMind GeoLite2".into(), "0.02".into(), "1000".into())],
            },
            receivers: vec![],
            income: vec![("2026-10-06".into(), "250.00".into(), "5.00".into())],
            accruing: (12, true),
            goods: vec![],
            scan_change: None,
            market_json: "{}".into(),
            flow_json: "[]".into(),
        };
        // The template states these amounts in words.
        assert_eq!(
            (mint::MINT_PER_DAY, mint::ALLOWANCE_PER_DAY),
            (1_000_000, 5_000)
        );
        let html = page.render().unwrap();
        for want in [
            "2026-10-06",
            "250.00",
            "5.00",
            "1.20",
            "812.00",
            "0.05",
            "12 scans counted so far",
            "1000 credits are split among the scanners",
        ] {
            assert!(html.contains(want), "{want} missing");
        }
        assert!(!html.contains("destroyed"));
    }
}
