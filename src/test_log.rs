//! Test-only capture of log lines, for asserting what is (and is not)
//! logged. One global subscriber for the whole test binary (not
//! `set_default`): with a scoped one, a test on another thread registering
//! the same callsite can cache "never" for it (tracing-core
//! `DefaultCallsite::register`), and the capture comes back empty. Each
//! capture collects the current thread's lines only, so it needs a
//! current-thread runtime.

thread_local! {
    static CAPTURED: std::cell::RefCell<Option<Vec<u8>>> = const { std::cell::RefCell::new(None) };
}

/// Writes into this thread's capture, if one is running.
struct Capture;

impl std::io::Write for Capture {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        CAPTURED.with(|c| c.borrow_mut().as_mut().map(|v| v.extend_from_slice(b)));
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Run `f` and return its output with the log lines it wrote on this
/// thread, at every level and from every crate.
pub async fn capture<T>(f: impl Future<Output = T>) -> (T, String) {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        let sub = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_ansi(false)
            .with_writer(|| Capture)
            .finish();
        tracing::subscriber::set_global_default(sub).expect("no other global subscriber");
    });
    CAPTURED.with(|c| *c.borrow_mut() = Some(Vec::new()));
    let out = f.await;
    let logs = CAPTURED.with(|c| c.borrow_mut().take()).unwrap_or_default();
    (out, String::from_utf8(logs).unwrap())
}
