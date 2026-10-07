//! Scan-queue change notifications. Publishers: the trap (enqueue) and the
//! scan workers (running/done/failed). Subscriber: the admin SSE stream.
use tokio::sync::broadcast;

#[derive(Clone, Debug, serde::Serialize, sqlx::FromRow)]
pub struct QueueJob {
    pub id: i64,
    pub ip: String,
    pub level: i64,
    pub status: String,
    pub queued_at: String,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
    pub error: Option<String>,
    /// Distributed mode: the node running (or that ran) the scan.
    pub scanner: Option<String>,
    /// Distributed mode: the node that hands out this job.
    pub arbiter: Option<String>,
    /// A retry of a failed scan: not handed out before then.
    pub retry_at: Option<String>,
}

#[derive(Clone)]
pub struct Notifier {
    tx: broadcast::Sender<QueueJob>,
}

impl Notifier {
    pub fn new() -> Self {
        let (tx, _rx) = broadcast::channel(256);
        Self { tx }
    }
    /// Never fails: with no subscribers the event is simply dropped.
    pub fn publish(&self, job: QueueJob) {
        let _ = self.tx.send(job);
    }
    pub fn subscribe(&self) -> broadcast::Receiver<QueueJob> {
        self.tx.subscribe()
    }
}

impl Default for Notifier {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn publish_reaches_subscribers_and_lag_is_reported() {
        let n = Notifier::new();
        let mut rx = n.subscribe();
        n.publish(QueueJob {
            id: 1,
            ip: "203.0.113.1".into(),
            level: 2,
            status: "queued".into(),
            queued_at: "now".into(),
            started_at: None,
            finished_at: None,
            error: None,
            scanner: None,
            arbiter: None,
            retry_at: None,
        });
        assert_eq!(rx.recv().await.unwrap().id, 1);
        // Overflow the channel (capacity 256) → Lagged.
        for i in 0..300 {
            n.publish(QueueJob {
                id: i,
                ip: String::new(),
                level: 1,
                status: "queued".into(),
                queued_at: String::new(),
                started_at: None,
                finished_at: None,
                error: None,
                scanner: None,
                arbiter: None,
                retry_at: None,
            });
        }
        assert!(matches!(
            rx.recv().await,
            Err(tokio::sync::broadcast::error::RecvError::Lagged(_))
        ));
    }
}
