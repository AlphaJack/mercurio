//! Sans-IO socket protocols: a [`Protocol`] never does I/O. [`Protocol::next`] says what it needs ([`Output`]) and [`Protocol::input`] hands it the result. [`drive`] pumps a real [`AsyncConn`]; a test feeds bytes directly.

use std::io;
use std::time::Duration;

use crate::error::Result;
use crate::transport::{AsyncConn, AsyncTransport, ChannelBinding};

/// A socket protocol as a state machine over bytes: [`Protocol::next`] says what it needs, [`Protocol::input`] answers [`Output::Read`] and [`Output::StartTls`] (and reports a failed [`Output::Write`]).
pub trait Protocol: Send {
    /// The next thing the protocol needs.
    fn next(&mut self) -> Output;
    /// Hand the protocol what it asked for.
    fn input(&mut self, input: Input<'_>);
}

/// A borrowed machine is driven the same way, so its result can be read after [`drive`] or [`run`] returns.
impl<P: Protocol + ?Sized> Protocol for &mut P {
    fn next(&mut self) -> Output {
        (**self).next()
    }
    fn input(&mut self, input: Input<'_>) {
        (**self).input(input);
    }
}

/// What the protocol needs next.
#[derive(Debug)]
pub enum Output {
    /// Send these bytes, then call [`Protocol::next`] again.
    Write(Vec<u8>),
    /// Read from the peer and pass the result to [`Protocol::input`].
    Read,
    /// Upgrade the connection to TLS and pass the result to [`Protocol::input`].
    StartTls,
    /// Ask the connection for its TLS channel binding data and pass it to [`Protocol::input`].
    ChannelBinding(ChannelBinding),
    /// Wait this long (through the transport), then call [`Protocol::next`] again.
    Sleep(Duration),
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
    /// The answer to [`Output::ChannelBinding`]; `None` when the connection cannot provide it.
    ChannelBinding(Option<Vec<u8>>),
    /// Sending the last [`Output::Write`] failed.
    WriteError(io::Error),
}

/// Received bytes cut into lines, for line-based protocols.
#[derive(Debug, Default)]
pub struct LineBuf(Vec<u8>);

impl LineBuf {
    /// Append bytes from the peer.
    pub fn push(&mut self, data: &[u8]) {
        self.0.extend_from_slice(data);
    }

    /// The next complete line without its `\r\n` (or `\n`); `None` until one has arrived.
    pub fn next_line(&mut self) -> Option<String> {
        let pos = self.0.iter().position(|b| *b == b'\n')?;
        let mut line: Vec<u8> = self.0.drain(..=pos).collect();
        line.pop();
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        Some(String::from_utf8_lossy(&line).into_owned())
    }

    /// Everything buffered after the last line (the first binary bytes once a protocol leaves its line phase).
    pub fn take(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.0)
    }

    /// Drop what is buffered (plaintext left over before a TLS upgrade).
    pub fn clear(&mut self) {
        self.0.clear();
    }
}

/// Run `machine` on a real connection until it is done; waits go through `transport`.
pub async fn drive(machine: impl Protocol, conn: &mut dyn AsyncConn, transport: &dyn AsyncTransport) -> Result<()> {
    pump(machine, conn, Some(transport), &mut [0u8; crate::net::READ_CHUNK]).await
}

/// [`drive`] for a machine that never asks to wait ([`Output::Sleep`] ends it with an error), reading into `buf` (the caller's, so a connection can keep one).
#[cfg(any(feature = "transport-tokio", feature = "transport-blocking"))]
pub async fn run(machine: impl Protocol, conn: &mut dyn AsyncConn, buf: &mut [u8]) -> Result<()> {
    pump(machine, conn, None, buf).await
}

async fn pump(
    mut machine: impl Protocol,
    conn: &mut dyn AsyncConn,
    transport: Option<&dyn AsyncTransport>,
    buf: &mut [u8],
) -> Result<()> {
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
            Output::Read => match conn.read(buf).await {
                Ok(n) => machine.input(Input::Data(&buf[..n])),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => machine.input(Input::ReadError(e)),
            },
            Output::StartTls => {
                let r = conn.start_tls().await;
                machine.input(Input::Tls(r));
            }
            Output::ChannelBinding(kind) => machine.input(Input::ChannelBinding(conn.channel_binding(kind))),
            Output::Sleep(d) => match transport {
                Some(t) => t.sleep(d).await,
                None => return Err(crate::error::Error::Unsupported("waiting inside this exchange".into())),
            },
            Output::Done(r) => return r,
        }
    }
}
