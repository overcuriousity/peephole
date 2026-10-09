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

/// What a node of an earlier version is told when it sends a config key
/// request.
pub const CONFIG_KEY_GONE: &str =
    "config keys were replaced by the ownership key (this node runs a newer version)";

/// A node's runtime settings as it reports them to a member that asks.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct State {
    /// Always false: config keys are gone. Kept so nodes of earlier versions
    /// decode the answer.
    pub open: bool,
    pub version: u64,
    pub pace: PaceInfo,
    /// Always [`crate::scan::pace::COOLDOWN_HOURS`]: kept so nodes of
    /// earlier versions decode the answer.
    pub cooldown_hours: i64,
    pub roles: Vec<String>,
    /// Always None: pace recommendations are gone. Kept so nodes of earlier
    /// versions decode the answer.
    pub recommended: Option<PaceInfo>,
}

pub fn pace_info(p: crate::scan::pace::Pace) -> PaceInfo {
    PaceInfo {
        max_workers: p.max_workers as u32,
        max_scans_per_hour: crate::scan::pace::ANNOUNCED_PER_HOUR,
        timeout_secs: p.timeout_secs,
    }
}

/// This node's settings, as it reports them.
pub fn state(settings: &Settings) -> State {
    let s = settings.snapshot();
    State {
        open: false,
        version: s.version,
        pace: pace_info(s.pace),
        cooldown_hours: crate::scan::pace::COOLDOWN_HOURS,
        roles: s.roles.names().into_iter().map(str::to_string).collect(),
        recommended: None,
    }
}

/// Answer other members' questions about this node's settings.
pub fn serve(node: &Arc<Node>, settings: Settings) {
    let weak = Arc::downgrade(node);
    node.on_message(Arc::new(move |_from, msg| {
        let (settings, weak) = (settings.clone(), weak.clone());
        Box::pin(async move {
            // Only while the node runs.
            weak.upgrade()?;
            match msg {
                Msg::ConfigGet => Some(Msg::ConfigState(state(&settings))),
                Msg::ConfigSet { .. } => Some(Msg::ConfigSetReply {
                    version: None,
                    error: Some(CONFIG_KEY_GONE.into()),
                }),
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
