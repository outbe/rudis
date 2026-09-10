use std::{
    sync::Mutex,
    time::{Duration, Instant},
};

#[derive(Debug)]
pub(crate) struct LogRateLimiter {
    window: Duration,
    state: Mutex<State>,
}

#[derive(Debug)]
struct State {
    last_emit: Option<Instant>,
    suppressed: u64,
}

impl LogRateLimiter {
    pub(crate) const fn new(window: Duration) -> Self {
        Self {
            window,
            state: Mutex::new(State {
                last_emit: None,
                suppressed: 0,
            }),
        }
    }

    pub(crate) fn check(&self) -> Option<u64> {
        let now = Instant::now();
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };

        let should_emit = match state.last_emit {
            Some(last_emit) => now.duration_since(last_emit) >= self.window,
            None => true,
        };

        if should_emit {
            state.last_emit = Some(now);
            let suppressed = state.suppressed;
            state.suppressed = 0;
            Some(suppressed)
        } else {
            state.suppressed = state.suppressed.saturating_add(1);
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::LogRateLimiter;

    #[test]
    fn suppresses_within_window_and_reports_count() {
        let limiter = LogRateLimiter::new(Duration::from_secs(60));

        assert_eq!(limiter.check(), Some(0));
        assert_eq!(limiter.check(), None);
        assert_eq!(limiter.check(), None);
    }

    #[test]
    fn zero_window_emits_and_returns_suppressed_count() {
        let limiter = LogRateLimiter::new(Duration::ZERO);

        assert_eq!(limiter.check(), Some(0));
        assert_eq!(limiter.check(), Some(0));
    }
}
