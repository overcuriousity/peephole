//! Lookup credits: earned by completed counter-scans, spent on lookups.
//! Every node computes every balance for itself, from its own copy of the
//! log; see docs/superpowers/specs/2026-10-06-lookup-credits-design.md.
pub mod entries;

/// Millicredits: 1 credit = 1000 mc. Sums are `u64`, amounts on the wire
/// `u32`.
pub type Mc = u64;
pub const CREDIT: Mc = 1000;

pub const DAY_MS: u64 = 86_400_000;
/// A credit can be used on the day it was earned and the 6 after.
pub const LOT_DAYS: u32 = 7;
/// An offer without a receipt lapses after this long.
pub const OFFER_TTL_MS: u64 = 15 * 60 * 1000;

/// The UTC day an entry belongs to, from its HLC.
pub fn day_of(hlc: u64) -> u32 {
    (crate::cluster::hlc::physical_ms(hlc) / DAY_MS) as u32
}

/// An amount in credits with two decimals ("0.25").
pub fn show(mc: Mc) -> String {
    let cents = (mc + 5) / 10;
    format!("{}.{:02}", cents / 100, cents % 100)
}

/// An amount typed by an operator ("1", "0.25"): more than nothing, at
/// most three decimals.
pub fn parse_amount(s: &str) -> Option<Mc> {
    let s = s.trim();
    let (whole, frac) = s.split_once('.').unwrap_or((s, ""));
    if whole.is_empty()
        || frac.len() > 3
        || !whole.bytes().all(|b| b.is_ascii_digit())
        || !frac.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    let whole: Mc = whole.parse().ok()?;
    let frac: Mc = format!("{frac:0<3}").parse().ok()?;
    let mc = whole.checked_mul(CREDIT)?.checked_add(frac)?;
    (mc > 0).then_some(mc)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn days_and_amounts() {
        let hlc = |ms: u64| ms << 16;
        assert_eq!(day_of(hlc(0)), 0);
        assert_eq!(day_of(hlc(DAY_MS - 1)), 0);
        assert_eq!(day_of(hlc(DAY_MS)), 1);
        assert_eq!(day_of(hlc(20_000 * DAY_MS + 5) | 7), 20_000);
        assert_eq!(show(0), "0.00");
        assert_eq!(show(250), "0.25");
        assert_eq!(show(1000), "1.00");
        assert_eq!(show(12_345), "12.35", "rounded to cents");
        assert_eq!(show(4), "0.00");
        assert_eq!(parse_amount("1"), Some(1000));
        assert_eq!(parse_amount("0.25"), Some(250));
        assert_eq!(parse_amount(" 12.5 "), Some(12_500));
        assert_eq!(parse_amount("0.001"), Some(1));
        for bad in ["", "-1", "1.2345", "abc", "1e3", "0", "0.0"] {
            assert_eq!(parse_amount(bad), None, "{bad}");
        }
    }
}
