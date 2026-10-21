//! A counting semaphore shared by both facades: [`Semaphore::acquire`] on any executor and [`Semaphore::acquire_blocking`] on threads, served first come, first served.

use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll, Waker};
use std::thread::Thread;

/// How to wake a waiter: a task or a parked thread.
enum Wake {
    Task(Waker),
    Thread(Thread),
}

impl Wake {
    fn wake(&self) {
        match self {
            Wake::Task(w) => w.wake_by_ref(),
            Wake::Thread(t) => t.unpark(),
        }
    }
}

struct State {
    permits: usize,
    next_id: u64,
    /// Waiters in arrival order; only the first may take a free permit.
    queue: VecDeque<(u64, Wake)>,
}

impl State {
    /// Take a permit when one is free and it is `id`'s turn (`None`: a newcomer, whose turn it is only when nobody waits).
    fn try_take(&mut self, id: Option<u64>) -> bool {
        let turn = match (id, self.queue.front()) {
            (_, None) => true,
            (Some(id), Some((first, _))) => *first == id,
            (None, Some(_)) => false,
        };
        if self.permits == 0 || !turn {
            return false;
        }
        self.permits -= 1;
        if id.is_some() {
            self.queue.pop_front();
        }
        self.wake_first();
        true
    }

    /// Wake the first waiter if a permit is free for it.
    fn wake_first(&self) {
        if self.permits > 0
            && let Some((_, w)) = self.queue.front()
        {
            w.wake();
        }
    }

    fn enqueue(&mut self, wake: Wake) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        self.queue.push_back((id, wake));
        id
    }
}

pub(crate) struct Semaphore {
    state: Mutex<State>,
}

impl Semaphore {
    pub(crate) fn new(permits: usize) -> Self {
        Self { state: Mutex::new(State { permits, next_id: 0, queue: VecDeque::new() }) }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Wait for a permit without blocking the thread. Dropping the future gives up its place in the queue.
    pub(crate) fn acquire(&self) -> Acquire<'_> {
        Acquire { sem: self, id: None }
    }

    /// Park the thread until a permit is free.
    pub(crate) fn acquire_blocking(&self) -> Permit<'_> {
        let mut state = self.lock();
        if state.try_take(None) {
            return Permit(self);
        }
        let id = state.enqueue(Wake::Thread(std::thread::current()));
        loop {
            drop(state);
            std::thread::park();
            state = self.lock();
            if state.try_take(Some(id)) {
                return Permit(self);
            }
        }
    }
}

/// A held permit; dropping it frees it for the next waiter.
#[must_use]
pub(crate) struct Permit<'a>(&'a Semaphore);

impl Drop for Permit<'_> {
    fn drop(&mut self) {
        let mut state = self.0.lock();
        state.permits += 1;
        state.wake_first();
    }
}

/// The future of [`Semaphore::acquire`].
pub(crate) struct Acquire<'a> {
    sem: &'a Semaphore,
    /// The place in the queue, once it has one.
    id: Option<u64>,
}

impl<'a> Future for Acquire<'a> {
    type Output = Permit<'a>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Permit<'a>> {
        let this = self.get_mut();
        let mut state = this.sem.lock();
        if state.try_take(this.id) {
            this.id = None;
            return Poll::Ready(Permit(this.sem));
        }
        match this.id {
            Some(id) => {
                if let Some((_, wake)) = state.queue.iter_mut().find(|(i, _)| *i == id) {
                    *wake = Wake::Task(cx.waker().clone());
                }
            }
            None => this.id = Some(state.enqueue(Wake::Task(cx.waker().clone()))),
        }
        Poll::Pending
    }
}

impl Drop for Acquire<'_> {
    fn drop(&mut self) {
        if let Some(id) = self.id {
            let mut state = self.sem.lock();
            let first = state.queue.front().is_some_and(|(i, _)| *i == id);
            state.queue.retain(|(i, _)| *i != id);
            if first {
                state.wake_first();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use futures_util::FutureExt;

    use super::*;

    #[test]
    fn never_hands_out_more_than_its_permits() {
        let sem = Arc::new(Semaphore::new(3));
        let (inside, peak) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
        std::thread::scope(|s| {
            for _ in 0..16 {
                let (sem, inside, peak) = (sem.clone(), inside.clone(), peak.clone());
                s.spawn(move || {
                    for _ in 0..50 {
                        let _p = sem.acquire_blocking();
                        let n = inside.fetch_add(1, Ordering::SeqCst) + 1;
                        peak.fetch_max(n, Ordering::SeqCst);
                        std::thread::yield_now();
                        inside.fetch_sub(1, Ordering::SeqCst);
                    }
                });
            }
        });
        assert_eq!(peak.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn async_waiters_are_served_in_order_and_may_give_up() {
        let sem = Semaphore::new(1);
        let held = sem.acquire().await;
        let mut first = Box::pin(sem.acquire());
        let mut second = Box::pin(sem.acquire());
        assert!(first.as_mut().now_or_never().is_none());
        assert!(second.as_mut().now_or_never().is_none());
        assert!(sem.acquire().now_or_never().is_none(), "a newcomer waits behind the queue");
        drop(held);
        drop(first);
        let permit =
            tokio::time::timeout(Duration::from_secs(1), second).await.expect("the dropped waiter passed its turn on");
        assert!(sem.acquire().now_or_never().is_none());
        drop(permit);
        assert!(sem.acquire().now_or_never().is_some());
    }

    #[test]
    fn threads_and_tasks_share_the_queue() {
        let sem = Arc::new(Semaphore::new(1));
        let held = sem.acquire_blocking();
        let waiter = {
            let sem = sem.clone();
            std::thread::spawn(move || drop(sem.acquire_blocking()))
        };
        while sem.lock().queue.is_empty() {
            std::thread::yield_now();
        }
        drop(held);
        waiter.join().unwrap();
        drop(pollster::block_on(sem.acquire()));
    }
}
