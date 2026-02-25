use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Accept,
    Drop,
    RateLimit(u64),
}

#[derive(Debug)]
pub struct RateLimiter {
    bytes_per_second: u64,
    tokens: AtomicU64,
    last_update: parking_lot::Mutex<Instant>,
}

impl RateLimiter {
    pub fn new(bytes_per_second: u64) -> Self {
        Self {
            bytes_per_second,
            tokens: AtomicU64::new(bytes_per_second),
            last_update: parking_lot::Mutex::new(Instant::now()),
        }
    }

    pub fn allow(&self, bytes: u64) -> bool {
        self.refill_tokens();

        loop {
            let current = self.tokens.load(Ordering::Acquire);
            if current < bytes {
                return false;
            }
            if self.tokens.compare_exchange_weak(
                current,
                current - bytes,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ).is_ok() {
                return true;
            }
        }
    }

    fn refill_tokens(&self) {
        let mut last = self.last_update.lock();
        let now = Instant::now();
        let elapsed = now.duration_since(*last);
        let new_tokens = (elapsed.as_secs_f64() * self.bytes_per_second as f64) as u64;

        if new_tokens > 0 {
            let current = self.tokens.load(Ordering::Acquire);
            let new_total = (current + new_tokens).min(self.bytes_per_second * 2);
            self.tokens.store(new_total, Ordering::Release);
            *last = now;
        }
    }

    pub fn bytes_per_second(&self) -> u64 {
        self.bytes_per_second
    }
}

impl Clone for RateLimiter {
    fn clone(&self) -> Self {
        Self::new(self.bytes_per_second)
    }
}
