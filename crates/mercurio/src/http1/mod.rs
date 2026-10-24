//! HTTP/1.1 without I/O, for the in-house client: URLs and proxies, the request bytes and response heads, and one exchange as [`crate::machine::Protocol`] machines.

pub(crate) mod client;
pub(crate) mod exchange;
pub(crate) mod proxy;
pub(crate) mod url;
pub(crate) mod wire;
