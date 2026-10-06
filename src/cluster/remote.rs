//! What a node tells other members about its runtime settings. Any member
//! may ask ([`Msg::ConfigGet`]); the cluster pages show every scanner's
//! pace from the answers.
use super::Node;
use super::identity::NodeId;
use super::msg::Msg;
use super::status::PaceInfo;
use crate::settings::Settings;
use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// How long to wait for a node's answer.
pub const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// A node's runtime settings as it reports them to a member that asks.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct State {
    /// Whether the node accepts changes from config key holders at all.
    pub open: bool,
    pub version: u64,
    pub pace: PaceInfo,
    pub cooldown_hours: i64,
    pub roles: Vec<String>,
    /// What the node's own queue metrics suggest (scanners only).
    pub recommended: Option<PaceInfo>,
}

pub fn pace_info(p: crate::scan::pace::Pace) -> PaceInfo {
    PaceInfo {
        max_workers: p.max_workers as u32,
        max_scans_per_hour: p.max_scans_per_hour,
        timeout_secs: p.timeout_secs,
    }
}

/// This node's settings, as it reports them.
pub async fn state(node: &Node, settings: &Settings) -> State {
    let s = settings.snapshot();
    let recommended = match (s.roles.scanner, node.store.queue_metrics().await) {
        (true, Ok(m)) => {
            let others = crate::scan::pace::others(
                node,
                m.avg_scan_secs
                    .unwrap_or(crate::scan::pace::DEFAULT_SCAN_SECS),
            );
            Some(pace_info(
                crate::scan::pace::recommend(&m, s.pace, others).pace,
            ))
        }
        _ => None,
    };
    State {
        open: node.cfg.remote_config,
        version: s.version,
        pace: pace_info(s.pace),
        cooldown_hours: s.cooldown_hours,
        roles: s.roles.names().into_iter().map(str::to_string).collect(),
        recommended,
    }
}

/// Answer other members' questions about this node's settings.
pub fn serve(node: &Arc<Node>, settings: Settings) {
    let weak = Arc::downgrade(node);
    node.on_message(Arc::new(move |_from, msg| {
        let (settings, weak) = (settings.clone(), weak.clone());
        Box::pin(async move {
            let node = weak.upgrade()?;
            match msg {
                Msg::ConfigGet => Some(Msg::ConfigState(state(&node, &settings).await)),
                _ => None,
            }
        })
    }));
}

/// Ask `target` for its runtime settings.
pub async fn get(node: &Arc<Node>, target: NodeId) -> Result<State> {
    match node.request(target, Msg::ConfigGet, TIMEOUT).await? {
        Msg::ConfigState(s) => Ok(s),
        other => bail!("unexpected answer {other:?}"),
    }
}
