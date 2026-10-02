//! The request head as the client sent it: a copy of the first bytes read
//! from the connection, cut after the blank line.

use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// What a [`Tee`] copied, shared with the request handler.
pub type HeadBuf = Arc<Mutex<Vec<u8>>>;

/// A stream that keeps a copy of the first `cap` bytes read through it.
pub struct Tee<S> {
    inner: S,
    buf: HeadBuf,
    cap: usize,
}

impl<S> Tee<S> {
    pub fn new(inner: S, buf: HeadBuf, cap: usize) -> Self {
        Self { inner, buf, cap }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Tee<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = out.filled().len();
        let r = Pin::new(&mut self.inner).poll_read(cx, out);
        if let Poll::Ready(Ok(())) = r {
            let cap = self.cap;
            let mut b = self.buf.lock().unwrap_or_else(|p| p.into_inner());
            let room = cap.saturating_sub(b.len());
            let new = &out.filled()[before..];
            b.extend_from_slice(&new[..new.len().min(room)]);
        }
        r
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Tee<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, data)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }
    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

/// The request head in `buf`: everything through the first blank line.
pub fn head_of(buf: &[u8]) -> Option<&[u8]> {
    buf.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| &buf[..i + 4])
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn head_of_cuts_after_the_blank_line() {
        assert_eq!(
            head_of(b"GET / HTTP/1.1\r\nA: b\r\n\r\nbody"),
            Some(&b"GET / HTTP/1.1\r\nA: b\r\n\r\n"[..])
        );
        assert_eq!(head_of(b"GET / HTTP/1.1\r\nA: b\r\n"), None);
    }

    #[tokio::test]
    async fn tee_copies_what_is_read_up_to_its_cap() {
        let (mut a, b) = tokio::io::duplex(64);
        let buf = HeadBuf::default();
        let mut t = Tee::new(b, buf.clone(), 4);
        a.write_all(b"0123456789").await.unwrap();
        drop(a);
        let mut out = vec![];
        t.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, b"0123456789");
        assert_eq!(&*buf.lock().unwrap(), b"0123");
    }
}
