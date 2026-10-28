//! Warnings raised while one URL is delivered: logged as before, and kept for its [`crate::ReportEntry::warnings`].
//!
//! [`collect`] wraps a URL's delivery; while it is polled, [`note`] adds to that URL's list. The list is set around each poll, so URLs delivered concurrently on one thread each keep their own, on any executor.

use std::cell::RefCell;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

type Sink = Arc<Mutex<Vec<String>>>;

thread_local! {
    static SINK: RefCell<Option<Sink>> = const { RefCell::new(None) };
}

/// Keep `message` for the URL being delivered, once; outside a delivery it is only logged.
pub(crate) fn note(message: String) {
    SINK.with(|s| {
        if let Some(sink) = &*s.borrow()
            && let Ok(mut list) = sink.lock()
            && !list.contains(&message)
        {
            list.push(message);
        }
    });
}

/// Run `fut`, returning its output and the warnings noted while it ran.
pub(crate) async fn collect<F: Future>(fut: F) -> (F::Output, Vec<String>) {
    let sink = Sink::default();
    let out = Collecting { inner: Box::pin(fut), sink: sink.clone() }.await;
    let warnings = sink.lock().map(|mut l| std::mem::take(&mut *l)).unwrap_or_default();
    (out, warnings)
}

struct Collecting<F> {
    inner: Pin<Box<F>>,
    sink: Sink,
}

impl<F: Future> Future for Collecting<F> {
    type Output = F::Output;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<F::Output> {
        let this = &mut *self;
        let outer = SINK.with(|s| s.replace(Some(this.sink.clone())));
        let res = this.inner.as_mut().poll(cx);
        SINK.with(|s| *s.borrow_mut() = outer);
        res
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_delivery_keeps_its_own_warnings() {
        let (_, outside) = pollster::block_on(collect(async {}));
        note("not in a delivery".into());
        let ((), a) = pollster::block_on(collect(async {
            note("a".into());
            let ((), inner) = collect(async { note("b".into()) }).await;
            assert_eq!(inner, ["b"]);
            note("a".into());
        }));
        assert_eq!((outside, a), (Vec::<String>::new(), vec!["a".to_owned()]));
    }
}
