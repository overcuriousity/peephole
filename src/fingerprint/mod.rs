use serde_json::Value;
use sha2::{Digest, Sha256};

/// Stable attributes that define a browser fingerprint (spec §8.2).
const STABLE_KEYS: [&str; 7] = [
    "canvas",
    "webgl_renderer",
    "fonts_hash",
    "audio",
    "screen",
    "timezone",
    "platform",
];

pub fn fp_hash(attrs: &Value) -> String {
    let mut h = Sha256::new();
    for key in STABLE_KEYS {
        h.update(key.as_bytes());
        h.update(b"=");
        h.update(
            attrs
                .get(key)
                .and_then(Value::as_str)
                .unwrap_or("")
                .as_bytes(),
        );
        h.update(b";");
    }
    data_encoding::HEXLOWER.encode(&h.finalize())
}

pub fn bot_tells(attrs: &Value, behavior: &Value) -> crate::classify::BotTells {
    let webdriver = attrs
        .get("webdriver")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let fill = behavior.get("fill_seconds").and_then(Value::as_f64);
    let mouse = behavior
        .get("mouse_events")
        .and_then(Value::as_i64)
        .unwrap_or(0);
    let inhuman_fill = matches!(fill, Some(s) if s < 1.0 && mouse == 0);
    crate::classify::BotTells {
        webdriver,
        inhuman_fill,
    }
}

/// Human-friendly pairs for the "What we see about you" panel (spec §8.3).
pub fn panel_summary(attrs: &Value, behavior: &Value, seen_ips: i64) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = vec![];
    let get = |k: &str| {
        attrs
            .get(k)
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_string()
    };
    out.push(("Browser".into(), get("ua")));
    out.push(("Platform".into(), get("platform")));
    out.push(("Screen".into(), get("screen")));
    out.push(("Timezone".into(), get("timezone")));
    out.push((
        "Languages".into(),
        attrs
            .get("languages")
            .map(|v| v.to_string())
            .unwrap_or_else(|| "unknown".into()),
    ));
    out.push((
        "Fonts detected".into(),
        attrs
            .get("fonts_count")
            .map(|v| v.to_string())
            .unwrap_or_else(|| "0".into()),
    ));
    out.push(("WebGL renderer".into(), get("webgl_renderer")));
    if seen_ips > 0 {
        out.push((
            "Recognized".into(),
            format!("this fingerprint was seen before from {seen_ips} other IP address(es)"),
        ));
    }
    let fill = behavior.get("fill_seconds").and_then(Value::as_f64);
    let mouse = behavior
        .get("mouse_events")
        .and_then(Value::as_i64)
        .unwrap_or(0);
    match fill {
        Some(s) if s < 1.0 && mouse == 0 => out.push((
            "Behavior".into(),
            format!("form filled in {s:.1}s with zero mouse movement — inhuman"),
        )),
        Some(s) => out.push((
            "Behavior".into(),
            format!("form filled in {s:.1}s with {mouse} mouse events"),
        )),
        None => out.push((
            "Behavior".into(),
            format!("{mouse} mouse events observed so far"),
        )),
    }
    if attrs
        .get("webdriver")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        out.push((
            "Automation".into(),
            "navigator.webdriver is true — this browser is remote-controlled".into(),
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn fp_hash_is_stable_and_sensitive() {
        let a = json!({"canvas":"abc","webgl_renderer":"Mesa Intel","fonts_hash":"f1","audio":"0.42","screen":"1920x1080x24","timezone":"Europe/Berlin","platform":"Linux x86_64","unstable_noise":"xyz"});
        let b = json!({"canvas":"abc","webgl_renderer":"Mesa Intel","fonts_hash":"f1","audio":"0.42","screen":"1920x1080x24","timezone":"Europe/Berlin","platform":"Linux x86_64","unstable_noise":"DIFFERENT"});
        assert_eq!(
            fp_hash(&a),
            fp_hash(&b),
            "unstable fields must not affect hash"
        );
        let c = json!({"canvas":"def","webgl_renderer":"Mesa Intel","fonts_hash":"f1","audio":"0.42","screen":"1920x1080x24","timezone":"Europe/Berlin","platform":"Linux x86_64"});
        assert_ne!(fp_hash(&a), fp_hash(&c));
    }

    #[test]
    fn bot_tells_detects_webdriver_and_inhuman_fill() {
        let attrs = json!({"webdriver": true});
        let behavior = json!({"fill_seconds": 0.4, "mouse_events": 0});
        let t = bot_tells(&attrs, &behavior);
        assert!(t.webdriver);
        assert!(t.inhuman_fill);
        let human = bot_tells(
            &json!({"webdriver": false}),
            &json!({"fill_seconds": 12.0, "mouse_events": 140}),
        );
        assert!(!human.webdriver);
        assert!(!human.inhuman_fill);
    }

    #[test]
    fn panel_summary_is_plain_language() {
        let attrs = json!({"ua":"Mozilla/5.0 HeadlessChrome","screen":"1920x1080x24","timezone":"UTC","languages":["en-US"],"fonts_count": 12});
        let behavior = json!({"fill_seconds": 0.5, "mouse_events": 0});
        let pairs = panel_summary(&attrs, &behavior, 3);
        let text = pairs
            .iter()
            .map(|(k, v)| format!("{k}: {v}"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(text.contains("HeadlessChrome"));
        assert!(text.contains("3 other IP"));
        assert!(text.to_lowercase().contains("inhuman"));
    }
}
