//! Long-lived tasks that must not die silently, and a panic hook that logs.
//!
//! One policy, the one [`run`](crate::run)'s `Background` applies to the
//! tasks it spawns: a supervised task that **panics** is logged at `error`
//! with its name and **stops the node**. `run` returns the error and systemd
//! starts the node again (`Restart=on-failure`). A node that had lost, say,
//! its replication or heartbeat would otherwise go on reporting healthy.
//! Restarting in place was rejected because a panic may leave shared state
//! (a poisoned lock, a half-updated map) that a restarted loop inherits.
//!
//! This module serves tasks spawned below `run`, where `Background` is out
//! of reach. A task that returns has ended on purpose (shutdown, nothing to
//! do) and is not reported. A task cancelled through its handle (`abort`)
//! is not a panic either.

use futures::FutureExt;
use std::panic::AssertUnwindSafe;
use std::sync::LazyLock;
use tokio::sync::watch;
use tokio::task::JoinHandle;

/// Records the first supervised task that panicked.
pub struct Supervisor {
    failed: watch::Sender<Option<String>>,
}

impl Default for Supervisor {
    fn default() -> Self {
        Self {
            failed: watch::Sender::new(None),
        }
    }
}

impl Supervisor {
    /// Spawns `task`. If it panics, logs that at `error` with `name` and
    /// marks this supervisor failed (see [`Supervisor::failed`]).
    pub fn spawn<F>(&'static self, name: &'static str, task: F) -> JoinHandle<()>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        tokio::spawn(async move {
            if let Err(panic) = AssertUnwindSafe(task).catch_unwind().await {
                let msg = panic_message(&*panic);
                tracing::error!(task = name, panic = %msg, "supervised task panicked; stopping the node");
                self.failed.send_if_modified(|f| {
                    let first = f.is_none();
                    if first {
                        *f = Some(format!("task {name} panicked: {msg}"));
                    }
                    first
                });
            }
        })
    }

    /// The first panic of a supervised task; never returns without one.
    pub async fn failed(&self) -> anyhow::Error {
        let mut rx = self.failed.subscribe();
        // The sender lives in `self`, so waiting cannot fail.
        let failed = rx
            .wait_for(Option::is_some)
            .await
            .map(|f| f.clone().unwrap_or_default())
            .unwrap_or_default();
        anyhow::anyhow!("{failed}")
    }
}

static GLOBAL: LazyLock<Supervisor> = LazyLock::new(Supervisor::default);

/// Spawns a long-lived task under the process-wide supervisor: a panic is
/// logged with `name` and stops the node (the module's policy). For
/// per-request tasks, use `tokio::spawn`.
pub fn spawn_supervised<F>(name: &'static str, task: F) -> JoinHandle<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    GLOBAL.spawn(name, task)
}

/// The first panic of a task spawned by [`spawn_supervised`].
pub async fn failed() -> anyhow::Error {
    GLOBAL.failed().await
}

/// Logs every panic through `tracing` (message, location, thread) before
/// the default hook prints it, so a panic in any task, supervised or not,
/// lands in the journal with the rest of the log.
pub fn install_panic_hook() {
    let default = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let thread = std::thread::current();
        tracing::error!(
            panic = %panic_message(info.payload()),
            location = %info.location().map(ToString::to_string).unwrap_or_default(),
            thread = thread.name().unwrap_or("<unnamed>"),
            "panic"
        );
        default(info);
    }));
}

fn panic_message(payload: &(dyn std::any::Any + Send)) -> &str {
    payload
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
        .unwrap_or("<non-string panic payload>")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// A supervised task that panics is named in the failure; one that
    /// returns or is aborted is not a failure.
    #[tokio::test]
    async fn a_panicking_supervised_task_fails_the_supervisor() {
        let sup: &'static Supervisor = Box::leak(Box::default());
        let soon = Duration::from_millis(200);
        sup.spawn("done", async {}).await.unwrap();
        let forever = sup.spawn("forever", std::future::pending());
        forever.abort();
        assert!(forever.await.unwrap_err().is_cancelled());
        assert!(tokio::time::timeout(soon, sup.failed()).await.is_err());

        // The task itself ends cleanly: the panic is caught and reported.
        sup.spawn("replication", async { panic!("sync bug") })
            .await
            .unwrap();
        let e = tokio::time::timeout(soon, sup.failed())
            .await
            .expect("the panic is noticed");
        assert_eq!(e.to_string(), "task replication panicked: sync bug");
        // Later panics keep the first.
        sup.spawn("heartbeat", async { panic!("{}", String::from("other")) })
            .await
            .unwrap();
        assert!(sup.failed().await.to_string().contains("replication"));
    }
}
