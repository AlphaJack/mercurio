//! [`Env`]: the wall clock, the randomness and the environment variables services read, supplied by the transport so plans can be reproduced.

use std::fmt;
use std::sync::{Arc, LazyLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// The wall clock, the random source and the environment variables of a send.
///
/// Services never read the system clock, random generator or environment themselves: they ask the [`crate::Context`] (`ctx.env()`), which gets its `Env` from [`crate::Transport::env`] / [`crate::AsyncTransport::env`]. The default is [`SystemEnv`]; a test or a deterministic replay returns its own (see [`crate::testing::FixedEnv`]).
///
/// Only [`Env::now`] and [`Env::fill_random`] are required; the other methods derive from them.
pub trait Env: Send + Sync + fmt::Debug {
    /// The current wall-clock time.
    fn now(&self) -> SystemTime;

    /// Fill `buf` with random bytes. Keys, nonces and IVs come from here, so a real implementation must be cryptographically secure.
    fn fill_random(&self, buf: &mut [u8]);

    /// An environment variable (`DBUS_SESSION_BUS_ADDRESS`, ...); `None` when unset or not Unicode. Default: the process environment.
    fn var(&self, name: &str) -> Option<String> {
        std::env::var(name).ok()
    }

    /// Unix time in seconds.
    fn unix_time(&self) -> u64 {
        self.since_epoch().as_secs()
    }

    /// Unix time in milliseconds.
    fn unix_time_ms(&self) -> u128 {
        self.since_epoch().as_millis()
    }

    /// Unix time in fractional seconds.
    fn unix_time_f64(&self) -> f64 {
        self.since_epoch().as_secs_f64()
    }

    /// Time since the Unix epoch; zero before it.
    fn since_epoch(&self) -> Duration {
        self.now().duration_since(UNIX_EPOCH).unwrap_or_default()
    }

    /// Random lowercase hex string of `n_bytes * 2` chars.
    fn random_hex(&self, n_bytes: usize) -> String {
        let mut b = vec![0u8; n_bytes];
        self.fill_random(&mut b);
        crate::crypto::hex(&b)
    }

    /// Random RFC 4122 version 4 UUID.
    fn uuid4(&self) -> String {
        let mut b = [0u8; 16];
        self.fill_random(&mut b);
        crate::crypto::uuid_v4(b)
    }
}

/// The real clock and the operating system's secure random generator (through `ring`).
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemEnv;

impl Env for SystemEnv {
    #[expect(clippy::disallowed_methods, reason = "the system environment reads the real clock")]
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }

    #[expect(
        clippy::expect_used,
        reason = "keys, nonces and IVs from an unfilled buffer would be predictable; no caller can recover from a missing OS RNG"
    )]
    #[expect(clippy::disallowed_methods, reason = "the system environment reads the OS random generator")]
    fn fill_random(&self, buf: &mut [u8]) {
        use ring::rand::SecureRandom;
        ring::rand::SystemRandom::new().fill(buf).expect("system RNG available");
    }
}

static SYSTEM: LazyLock<Arc<dyn Env>> = LazyLock::new(|| Arc::new(SystemEnv));

/// The shared [`SystemEnv`]: what transports return unless they supply their own.
pub fn system() -> &'static Arc<dyn Env> {
    &SYSTEM
}
