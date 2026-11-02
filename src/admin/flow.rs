//! The flow map on a campaign's page: bands sized by requests, running
//! through the five stages of each chain ([`crate::store::chains`]). This
//! only computes numbers and text; `_chain_flow.html` draws them as
//! server-rendered SVG, and every word of attacker text goes through the
//! template's escaping.
use crate::store::chains::{Chain, Mark, StageRow};

/// Boxes a chain shows in one stage; the rest group into "n more".
pub const STAGE_BOXES: usize = 12;
/// A label's characters drawn in a box; the box's title holds all of it.
const TEXT_CHARS: usize = 22;

const MARGIN: f64 = 10.0;
const COL_W: f64 = 150.0;
const COL_STEP: f64 = 210.0;
const HEAD_H: f64 = 22.0;
const LANE_HEAD: f64 = 20.0;
const LANE_GAP: f64 = 16.0;
const BOX_MIN: f64 = 30.0;
const BOX_GAP: f64 = 6.0;
/// The tallest stage of a chain, in pixels, when requests are many.
const TALL: f64 = 300.0;
/// Pixels per request, at most, so one request is not a wall.
const PER_REQUEST_MAX: f64 = 8.0;
/// A band is never thinner than this, so a gap stays visible.
const BAND_MIN: f64 = 6.0;

/// Round to one decimal, so a number prints short.
fn r1(x: f64) -> f64 {
    (x * 10.0).round() / 10.0
}

#[derive(Debug, Default)]
pub struct FlowView {
    pub width: f64,
    pub height: f64,
    pub cols: Vec<FlowCol>,
    pub lanes: Vec<FlowLane>,
    pub boxes: Vec<FlowBox>,
    pub bands: Vec<FlowBand>,
    /// The table alternative: every row of every chain.
    pub rows: Vec<FlowRow>,
    /// Pieces past what the chains hold, in no stage.
    pub more: i64,
}

impl FlowView {
    pub fn is_empty(&self) -> bool {
        self.lanes.is_empty()
    }
}

#[derive(Debug)]
pub struct FlowCol {
    pub name: &'static str,
    pub x: f64,
    pub y: f64,
}

/// One chain's heading.
#[derive(Debug)]
pub struct FlowLane {
    pub title: String,
    pub x: f64,
    pub y: f64,
}

#[derive(Debug)]
pub struct FlowBox {
    pub x: f64,
    pub y: f64,
    pub w: f64,
    pub h: f64,
    /// Cut to fit the box.
    pub label: String,
    /// The label whole, the detail and the mark in words.
    pub title: String,
    /// `3 req · seen`
    pub sub: String,
    pub class: &'static str,
}

#[derive(Debug)]
pub struct FlowBand {
    /// The ribbon's outline, from numbers only.
    pub d: String,
    /// How thick it is where it leaves: follows the requests.
    pub width: f64,
    pub requests: i64,
    pub class: &'static str,
    pub title: String,
}

#[derive(Debug)]
pub struct FlowRow {
    pub chain: String,
    pub stage: &'static str,
    pub label: String,
    pub detail: String,
    pub requests: i64,
    pub mark: &'static str,
    pub joiner: bool,
}

/// A box before it is placed.
struct Item {
    label: String,
    detail: String,
    requests: i64,
    mark: Mark,
}

impl Item {
    fn of(r: &StageRow) -> Self {
        Item {
            label: r.label.clone(),
            detail: r.detail.clone(),
            requests: r.requests,
            mark: r.mark,
        }
    }
}

/// The weakest evidence in a stage of a chain; a gap only when all are.
fn weakest(marks: impl Iterator<Item = Mark> + Clone) -> Mark {
    let has = |m: Mark| marks.clone().any(|x| x == m);
    if has(Mark::DeadEnd) {
        Mark::DeadEnd
    } else if marks.clone().all(|m| m == Mark::Gap) {
        Mark::Gap
    } else if has(Mark::Claimed) {
        Mark::Claimed
    } else if has(Mark::External) {
        Mark::External
    } else {
        Mark::Seen
    }
}

/// `rows` as the boxes of one stage: up to [`STAGE_BOXES`], then "n more".
fn items(rows: &[StageRow]) -> Vec<Item> {
    let mut items: Vec<Item> = rows.iter().take(STAGE_BOXES).map(Item::of).collect();
    let rest = rows.get(STAGE_BOXES..).unwrap_or_default();
    if !rest.is_empty() {
        items.push(Item {
            label: format!("{} more", rest.len()),
            detail: "grouped; the table lists each".into(),
            requests: rest.iter().map(|r| r.requests).sum(),
            mark: weakest(rest.iter().map(|r| r.mark)),
        });
    }
    items
}

fn cut(s: &str) -> String {
    match s.char_indices().nth(TEXT_CHARS) {
        Some((end, _)) => format!("{}…", &s[..end]),
        None => s.to_string(),
    }
}

fn plural(n: i64) -> &'static str {
    if n == 1 { "" } else { "s" }
}

pub fn flow(chains: &[Chain]) -> FlowView {
    let mut v = FlowView::default();
    if chains.is_empty() {
        return v;
    }
    let sum = |it: &[Item]| it.iter().map(|i| i.requests).sum::<i64>();
    let staged: Vec<[Vec<Item>; 5]> = chains
        .iter()
        .map(|c| std::array::from_fn(|i| items(&c.stages[i].rows)))
        .collect();
    let busiest = staged.iter().flatten().map(|s| sum(s)).max().unwrap_or(0);
    let scale = if busiest > 0 {
        (TALL / busiest as f64).min(PER_REQUEST_MAX)
    } else {
        0.0
    };
    let height_of = |i: &Item| BOX_MIN.max(i.requests as f64 * scale);
    let x_of = |col: usize| MARGIN + col as f64 * COL_STEP;
    v.width = x_of(4) + COL_W + MARGIN;
    for (i, s) in chains[0].stages.iter().enumerate() {
        v.cols.push(FlowCol {
            name: s.name,
            x: x_of(i),
            y: HEAD_H - 6.0,
        });
    }
    let mut y = HEAD_H;
    for (chain, stages) in chains.iter().zip(&staged) {
        let title = chain.title();
        v.more += chain.more;
        v.lanes.push(FlowLane {
            title: format!(
                "{title} · {} IP{} · {} source{}",
                chain.ips,
                plural(chain.ips),
                chain.sources,
                plural(chain.sources)
            ),
            x: MARGIN,
            y: y + LANE_HEAD - 6.0,
        });
        y += LANE_HEAD;
        let stack = |s: &[Item]| {
            let h: f64 = s.iter().map(height_of).sum();
            h + BOX_GAP * s.len().saturating_sub(1) as f64
        };
        let lane_h = stages.iter().map(|s| stack(s)).fold(0.0, f64::max);
        let mut blocks = vec![];
        for (col, s) in stages.iter().enumerate() {
            let mut by = y;
            for item in s {
                let h = r1(height_of(item));
                v.boxes.push(FlowBox {
                    x: x_of(col),
                    y: r1(by),
                    w: COL_W,
                    h,
                    label: cut(&item.label),
                    title: format!(
                        "{} — {} — {} request{} — {}",
                        item.label,
                        item.detail,
                        item.requests,
                        plural(item.requests),
                        item.mark.word()
                    ),
                    sub: format!("{} req · {}", item.requests, item.mark.word()),
                    class: item.mark.class(),
                });
                by += h + BOX_GAP;
            }
            blocks.push((y, stack(s), sum(s), weakest(s.iter().map(|i| i.mark))));
        }
        for col in 0..4 {
            let (ay, ah, areq, from) = blocks[col];
            let (by, bh, breq, mark) = blocks[col + 1];
            // Nothing known on either side: the band is a gap too.
            let mark = if from == Mark::Gap { Mark::Gap } else { mark };
            let requests = areq.min(breq);
            let thick = (requests as f64 * scale).max(BAND_MIN).min(ah.min(bh));
            let (a, b) = (ay + (ah - thick) / 2.0, by + (bh - thick) / 2.0);
            let (x0, x1) = (x_of(col) + COL_W, x_of(col + 1));
            let m = (x0 + x1) / 2.0;
            let (a, b, t) = (r1(a), r1(b), r1(thick));
            v.bands.push(FlowBand {
                d: format!(
                    "M{x0} {a} C{m} {a} {m} {b} {x1} {b} L{x1} {} C{m} {} {m} {} {x0} {} Z",
                    r1(b + t),
                    r1(b + t),
                    r1(a + t),
                    r1(a + t)
                ),
                width: t,
                requests,
                class: mark.class(),
                title: format!(
                    "{} to {}: {requests} request{} — {}",
                    chain.stages[col].name,
                    chain.stages[col + 1].name,
                    plural(requests),
                    mark.word()
                ),
            });
        }
        y += lane_h + LANE_GAP;
        for stage in &chain.stages {
            for r in &stage.rows {
                v.rows.push(FlowRow {
                    chain: title.clone(),
                    stage: stage.name,
                    label: r.label.clone(),
                    detail: r.detail.clone(),
                    requests: r.requests,
                    mark: r.mark.word(),
                    joiner: r.joiner,
                });
            }
        }
    }
    v.height = r1(y);
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::chains::Stage;
    use askama::Template;

    #[derive(Template)]
    #[template(path = "_chain_flow.html")]
    struct Page<'a> {
        flow: &'a FlowView,
    }

    fn row(label: &str, requests: i64, mark: Mark) -> StageRow {
        StageRow {
            piece: None,
            label: label.into(),
            detail: "detail".into(),
            mark,
            joiner: false,
            here: false,
            dim: false,
            href: None,
            requests,
        }
    }

    fn chain(stages: [Vec<StageRow>; 5]) -> Chain {
        let names = ["Exploit", "Command", "Delivery", "Payload", "Follow-up"];
        let mut i = 0;
        Chain {
            key: None,
            stages: stages.map(|rows| {
                i += 1;
                Stage {
                    name: names[i - 1],
                    rows,
                }
            }),
            ips: 2,
            sources: 3,
            first_seen: "2026-10-01 00:00:00".into(),
            last_seen: "2026-10-02 00:00:00".into(),
            more: 0,
        }
    }

    fn plain(n: i64) -> [Vec<StageRow>; 5] {
        std::array::from_fn(|_| vec![row("a", n, Mark::Seen)])
    }

    fn html(v: &FlowView) -> String {
        Page { flow: v }.render().unwrap()
    }

    #[test]
    fn band_width_follows_requests() {
        let small = flow(&[chain(plain(10))]);
        let big = flow(&[chain(plain(40))]);
        assert_eq!(small.bands.len(), 4);
        assert!(big.bands[0].width > small.bands[0].width * 3.0, "{big:?}");
        // Within one map, the busier chain has the wider band.
        let both = flow(&[chain(plain(40)), chain(plain(10))]);
        assert!(both.bands[0].width > both.bands[4].width * 3.0);
        assert_eq!(both.bands[0].requests, 40);
    }

    #[test]
    fn gap_is_drawn_as_gap() {
        let mut s = plain(5);
        s[3] = vec![row("No payload seen", 0, Mark::Gap)];
        let v = flow(&[chain(s)]);
        assert_eq!(v.bands[2].class, "gap");
        assert_eq!(v.bands[3].class, "gap");
        assert!(v.bands[2].width >= BAND_MIN);
        assert_eq!(v.bands[0].class, "seen");
        let h = html(&v);
        assert!(h.contains("flow-box gap"), "{h}");
        assert!(h.contains("flow-band gap"), "{h}");
        assert!(h.contains("0 req · gap"), "{h}");
    }

    #[test]
    fn dead_end_and_claimed_carry_words() {
        let mut s = plain(5);
        s[1] = vec![row("c", 2, Mark::Claimed)];
        s[4] = vec![row("GET /x", 3, Mark::DeadEnd)];
        let h = html(&flow(&[chain(s)]));
        assert!(h.contains("2 req · claimed"), "{h}");
        assert!(h.contains("3 req · dead end"), "{h}");
        assert!(h.contains("flow-box dead-end"), "{h}");
    }

    #[test]
    fn over_12_pieces_group_into_n_more() {
        let mut s = plain(1);
        s[1] = (0..15)
            .map(|i| row(&format!("r{i}"), 2, Mark::Claimed))
            .collect();
        let v = flow(&[chain(s)]);
        let in_col = v.boxes.iter().filter(|b| b.x == v.cols[1].x).count();
        assert_eq!(in_col, STAGE_BOXES + 1);
        let more = v.boxes.iter().find(|b| b.label == "3 more").unwrap();
        assert_eq!(more.sub, "6 req · claimed");
        assert!(v.boxes.iter().all(|b| b.label != "r12"));
        // The table still has them.
        assert!(v.rows.iter().any(|r| r.label == "r14"));
    }

    #[test]
    fn table_alternative_has_every_row() {
        let mut s = plain(1);
        s[2] = (0..14)
            .map(|i| row(&format!("d{i}"), 1, Mark::Seen))
            .collect();
        let v = flow(&[chain(s)]);
        assert_eq!(v.rows.len(), 4 + 14);
        let h = html(&v);
        for i in 0..14 {
            assert!(
                h.contains(&format!("<td class=\"mono\">d{i}</td>")),
                "{i}\n{h}"
            );
        }
        assert!(h.contains("<table"), "{h}");
    }

    #[test]
    fn hostile_label_is_escaped_in_svg() {
        let evil = "</text><script>alert(1)</script>";
        let mut s = plain(2);
        s[0] = vec![row(evil, 2, Mark::Claimed)];
        let mut c = chain(s);
        c.stages[2].rows[0].label = evil.into();
        let h = html(&flow(&[c]));
        assert!(!h.contains("<script>"), "{h}");
        assert!(!h.contains("</text><script"), "{h}");
        assert!(h.contains("&#60;/text&#62;&#60;script&#62;"), "{h}");
        assert!(!h.contains("|safe") && !h.contains("href=\"http"), "{h}");
    }

    #[test]
    fn no_chains_no_flow() {
        let v = flow(&[]);
        assert!(v.is_empty());
    }

    #[test]
    fn a_600_piece_campaign_renders_under_a_second() {
        let big = || {
            let many = |n: i64| -> Vec<StageRow> {
                (0..n)
                    .map(|i| row(&format!("piece-{i}"), 1 + i % 7, Mark::Claimed))
                    .collect()
            };
            chain([many(80), many(40), many(40), many(20), many(20)])
        };
        let chains = [big(), big(), big()];
        let start = std::time::Instant::now();
        let v = flow(&chains);
        let h = html(&v);
        assert!(start.elapsed().as_millis() < 1000, "{:?}", start.elapsed());
        assert_eq!(v.rows.len(), 600);
        assert!(h.contains("piece-199") || h.contains("piece-79"));
    }
}
