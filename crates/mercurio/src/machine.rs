//! Sans-IO socket protocols: a [`Machine`] runs a protocol written as an `async fn` against an in-memory [`Wire`] instead of a socket. It never does I/O: [`Machine::next`] says what it needs ([`Output`]) and [`Machine::input`] hands it the result. [`drive`] pumps a real [`AsyncConn`]; a test feeds bytes directly.

use std::collections::VecDeque;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll, Waker};

use crate::error::{Error, Result};
use crate::transport::{AsyncConn, BoxFuture};

/// What the protocol needs next.
#[derive(Debug)]
pub enum Output {
    /// Send these bytes, then call [`Machine::next`] again.
    Write(Vec<u8>),
    /// Read from the peer and pass the result to [`Machine::input`].
    Read,
    /// Upgrade the connection to TLS and pass the result to [`Machine::input`].
    StartTls,
    /// The session ended.
    Done(Result<()>),
}

/// The answer to an [`Output::Read`] or [`Output::StartTls`].
#[derive(Debug)]
pub enum Input<'a> {
    /// Bytes from the peer; empty when it closed the stream.
    Data(&'a [u8]),
    /// The read failed.
    ReadError(io::Error),
    /// The TLS upgrade finished.
    Tls(Result<()>),
    /// Sending the last [`Output::Write`] failed; the protocol sees the error on its next read, as on a socket.
    WriteError(io::Error),
}

#[derive(Debug, Default)]
struct WireState {
    inbox: VecDeque<u8>,
    outbox: Vec<u8>,
    eof: bool,
    read_error: Option<io::Error>,
    tls: bool,
    tls_result: Option<Result<()>>,
    /// What the protocol is parked on.
    want: Option<Want>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Want {
    Read,
    StartTls,
}

type Shared = Arc<Mutex<WireState>>;

fn lock(s: &Shared) -> std::sync::MutexGuard<'_, WireState> {
    s.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The [`AsyncConn`] a protocol runs on inside a [`Machine`]: writes go to an outbox, reads come from what [`Machine::input`] delivered, and an empty inbox parks the protocol.
#[derive(Debug)]
pub struct Wire(Shared);

/// Resolves when the wire can answer a read; parks the protocol (with [`Want::Read`]) until then.
struct ReadReady<'a>(&'a Shared, &'a mut [u8]);

impl Future for ReadReady<'_> {
    type Output = io::Result<usize>;
    fn poll(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        let shared = self.0.clone();
        let mut s = lock(&shared);
        if !s.inbox.is_empty() {
            let n = self.1.len().min(s.inbox.len());
            for (dst, src) in self.1.iter_mut().zip(s.inbox.drain(..n)) {
                *dst = src;
            }
            return Poll::Ready(Ok(n));
        }
        if let Some(e) = s.read_error.take() {
            return Poll::Ready(Err(e));
        }
        if s.eof {
            return Poll::Ready(Ok(0));
        }
        s.want = Some(Want::Read);
        Poll::Pending
    }
}

/// Resolves with the TLS result; parks the protocol (with [`Want::StartTls`]) until then.
struct TlsReady<'a>(&'a Shared);

impl Future for TlsReady<'_> {
    type Output = Result<()>;
    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        let mut s = lock(self.0);
        if let Some(r) = s.tls_result.take() {
            return Poll::Ready(r);
        }
        s.want = Some(Want::StartTls);
        Poll::Pending
    }
}

impl AsyncConn for Wire {
    fn read<'a>(&'a mut self, buf: &'a mut [u8]) -> BoxFuture<'a, io::Result<usize>> {
        Box::pin(ReadReady(&self.0, buf))
    }
    fn write_all<'a>(&'a mut self, data: &'a [u8]) -> BoxFuture<'a, io::Result<()>> {
        lock(&self.0).outbox.extend_from_slice(data);
        Box::pin(std::future::ready(Ok(())))
    }
    fn flush(&mut self) -> BoxFuture<'_, io::Result<()>> {
        Box::pin(std::future::ready(Ok(())))
    }
    fn start_tls(&mut self) -> BoxFuture<'_, Result<()>> {
        Box::pin(TlsReady(&self.0))
    }
    fn is_tls(&self) -> bool {
        lock(&self.0).tls
    }
}

/// A protocol session as a state machine over bytes (see the module docs).
pub struct Machine {
    wire: Shared,
    session: Option<BoxFuture<'static, Result<()>>>,
}

impl std::fmt::Debug for Machine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Machine").field("wire", &*lock(&self.wire)).finish_non_exhaustive()
    }
}

impl Machine {
    /// Run `session` on a [`Wire`]; `tls` is whether the stream starts encrypted.
    pub fn new<F>(tls: bool, session: impl FnOnce(Wire) -> F) -> Self
    where
        F: Future<Output = Result<()>> + Send + 'static,
    {
        let wire: Shared = Arc::new(Mutex::new(WireState { tls, ..WireState::default() }));
        Self { session: Some(Box::pin(session(Wire(wire.clone())))), wire }
    }

    /// The next thing the protocol needs. Pending writes always come first.
    pub fn next(&mut self) -> Output {
        loop {
            let mut s = lock(&self.wire);
            if !s.outbox.is_empty() {
                return Output::Write(std::mem::take(&mut s.outbox));
            }
            match s.want {
                Some(Want::Read) => return Output::Read,
                Some(Want::StartTls) => return Output::StartTls,
                None => {}
            }
            drop(s);
            let Some(session) = self.session.as_mut() else {
                return Output::Done(Err(Error::Message("the session already ended".into())));
            };
            match session.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
                Poll::Ready(r) => {
                    self.session = None;
                    let mut s = lock(&self.wire);
                    if !s.outbox.is_empty() {
                        // Flush the last writes (QUIT) before reporting the end.
                        let out = std::mem::take(&mut s.outbox);
                        drop(s);
                        self.session = Some(Box::pin(std::future::ready(r)));
                        return Output::Write(out);
                    }
                    return Output::Done(r);
                }
                Poll::Pending if Self::stalled(&lock(&self.wire)) => {
                    self.session = None;
                    return Output::Done(Err(Error::Message(
                        "the protocol waited on something other than its wire".into(),
                    )));
                }
                Poll::Pending => {}
            }
        }
    }

    /// Parked without asking for anything: the protocol awaited something other than its wire.
    fn stalled(s: &WireState) -> bool {
        s.want.is_none() && s.outbox.is_empty()
    }

    /// Hand the protocol what it asked for.
    pub fn input(&mut self, input: Input<'_>) {
        let mut s = lock(&self.wire);
        s.want = None;
        match input {
            Input::Data([]) => s.eof = true,
            Input::Data(data) => s.inbox.extend(data),
            Input::ReadError(e) => s.read_error = Some(e),
            Input::WriteError(e) => {
                s.outbox.clear();
                s.read_error = Some(e);
            }
            Input::Tls(r) => {
                if r.is_ok() {
                    s.tls = true;
                }
                s.tls_result = Some(r);
            }
        }
    }
}

/// Run `machine` on a real connection until it is done.
pub async fn drive(mut machine: Machine, conn: &mut dyn AsyncConn) -> Result<()> {
    let mut buf = [0u8; crate::net::READ_CHUNK];
    loop {
        match machine.next() {
            Output::Write(data) => {
                let sent = match conn.write_all(&data).await {
                    Ok(()) => conn.flush().await,
                    Err(e) => Err(e),
                };
                if let Err(e) = sent {
                    machine.input(Input::WriteError(e));
                }
            }
            Output::Read => match conn.read(&mut buf).await {
                Ok(n) => machine.input(Input::Data(&buf[..n])),
                Err(e) => machine.input(Input::ReadError(e)),
            },
            Output::StartTls => {
                let r = conn.start_tls().await;
                machine.input(Input::Tls(r));
            }
            Output::Done(r) => return r,
        }
    }
}
