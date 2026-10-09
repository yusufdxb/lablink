//! Bounded-concurrency execution for active scans: exactly `concurrency`
//! worker tasks pull targets from a shared queue, so the number of live tasks
//! never depends on the size of the range.

use std::collections::VecDeque;
use std::future::Future;
use std::sync::{Arc, Mutex};
use tokio_util::sync::CancellationToken;

/// Apply `f` to every item with at most `concurrency` in flight. Results are
/// returned in completion order. Stops early (returning partial results) on
/// cancellation.
pub async fn bounded<T, R, F, Fut>(
    items: Vec<T>,
    concurrency: usize,
    cancel: CancellationToken,
    f: F,
) -> Vec<R>
where
    T: Send + 'static,
    R: Send + 'static,
    F: Fn(T) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = R> + Send,
{
    let queue = Arc::new(Mutex::new(VecDeque::from(items)));
    let f = Arc::new(f);
    let mut set = tokio::task::JoinSet::new();
    for _ in 0..concurrency.max(1) {
        let (q, f, cancel) = (queue.clone(), f.clone(), cancel.clone());
        set.spawn(async move {
            let mut out = Vec::new();
            loop {
                let next = q.lock().unwrap_or_else(|p| p.into_inner()).pop_front();
                let Some(item) = next else { break };
                tokio::select! {
                    biased;
                    _ = cancel.cancelled() => break,
                    r = f(item) => out.push(r),
                }
            }
            out
        });
    }
    let mut results = Vec::new();
    while let Some(r) = set.join_next().await {
        if let Ok(mut v) = r {
            results.append(&mut v);
        }
    }
    results
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    #[tokio::test]
    async fn never_exceeds_concurrency() {
        let live = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let (l, p) = (live.clone(), peak.clone());
        let out = bounded(
            (0..200).collect(),
            8,
            CancellationToken::new(),
            move |i: u32| {
                let (l, p) = (l.clone(), p.clone());
                async move {
                    let now = l.fetch_add(1, Ordering::SeqCst) + 1;
                    p.fetch_max(now, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(1)).await;
                    l.fetch_sub(1, Ordering::SeqCst);
                    i
                }
            },
        )
        .await;
        assert_eq!(out.len(), 200);
        assert!(peak.load(Ordering::SeqCst) <= 8);
    }

    #[tokio::test]
    async fn cancellation_stops_early() {
        let cancel = CancellationToken::new();
        let c2 = cancel.clone();
        let out = bounded((0..1000).collect(), 4, cancel, move |i: u32| {
            let c = c2.clone();
            async move {
                if i == 10 {
                    c.cancel();
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
                i
            }
        })
        .await;
        assert!(out.len() < 1000);
    }
}
