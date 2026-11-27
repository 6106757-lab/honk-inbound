use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::time::{Instant, sleep_until};

use super::DRAIN_DEADLINE;

const CHECK: Duration = Duration::from_millis(100);

#[derive(Default)]
pub(super) struct CopyProgress {
    pub(super) read: AtomicU64,
    pub(super) written: AtomicU64,
}

impl CopyProgress {
    pub(super) fn snapshot(&self) -> (u64, u64) {
        (
            self.read.load(Ordering::Relaxed),
            self.written.load(Ordering::Relaxed),
        )
    }
}

pub(super) async fn drain_copy_idle(upload: &CopyProgress, download: &CopyProgress) {
    drain_idle((upload.snapshot(), download.snapshot()), || {
        (upload.snapshot(), download.snapshot())
    })
    .await;
}

pub(super) async fn drain_idle<T: PartialEq>(mut last: T, progress: impl Fn() -> T) {
    let mut now = Instant::now();
    let mut deadline = now + DRAIN_DEADLINE;
    loop {
        sleep_until(deadline.min(now + CHECK)).await;
        now = Instant::now();
        let current = progress();
        if current != last {
            last = current;
            deadline = now + DRAIN_DEADLINE;
        } else if now >= deadline {
            tracing::debug!("relay drain stalled; closing both directions");
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::FutureExt;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;
    use tokio::time::sleep;

    const WINDOW: Duration = DRAIN_DEADLINE;
    const MARGIN: Duration = Duration::from_millis(10);

    #[tokio::test(start_paused = true)]
    async fn delayed_poll_does_not_extend_the_splice_drain() {
        let counter = AtomicU64::new(0);
        let drain = drain_idle(0, || counter.load(Ordering::Relaxed));
        tokio::pin!(drain);
        // The inner sleep registers only on the first poll.
        assert!(drain.as_mut().now_or_never().is_none());
        // Hold the drain unpolled past the deadline, then poll once: the
        // deadline scheme ends it, the old stalled-count scheme would not.
        sleep(WINDOW * 2).await;
        drain
            .as_mut()
            .now_or_never()
            .expect("a delayed poll extended the drain");
    }

    #[tokio::test(start_paused = true)]
    async fn progress_just_before_the_deadline_renews_the_drain() {
        let counter = AtomicU64::new(0);
        let drain = drain_idle(0, || counter.load(Ordering::Relaxed));
        tokio::pin!(drain);
        assert!(drain.as_mut().now_or_never().is_none());
        sleep(WINDOW - MARGIN).await;
        counter.fetch_add(1, Ordering::Relaxed);
        // Poll right after the progress so the renewed deadline registers.
        assert!(drain.as_mut().now_or_never().is_none());
        sleep(WINDOW - MARGIN).await;
        assert!(drain.as_mut().now_or_never().is_none());
        sleep(MARGIN * 2).await;
        drain
            .as_mut()
            .now_or_never()
            .expect("progress just before the deadline did not renew it");
    }
}
