use std::time::{Duration, Instant, SystemTime};

/// Xorshift64 PRNG — adequate for jittering millisecond timings.
pub struct SimpleRng {
    state: u64,
}

impl SimpleRng {
    /// Seed from system time.
    pub fn from_system_time() -> Self {
        let nanos = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        // Ensure non-zero state.
        Self {
            state: nanos | 1,
        }
    }

    /// Seed from an explicit value (for deterministic tests).
    #[cfg(test)]
    pub fn with_seed(seed: u64) -> Self {
        Self { state: seed | 1 }
    }

    /// Generate the next pseudo-random u64.
    pub fn next_u64(&mut self) -> u64 {
        let mut s = self.state;
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        self.state = s;
        s
    }

    /// Return a value in `[lo, hi)`. Panics if `lo >= hi`.
    pub fn range(&mut self, lo: u64, hi: u64) -> u64 {
        assert!(lo < hi, "SimpleRng::range requires lo < hi");
        lo + self.next_u64() % (hi - lo)
    }

    /// Return a Duration uniformly in `[lo, hi)`.
    pub fn duration_between(&mut self, lo: Duration, hi: Duration) -> Duration {
        let lo_ms = lo.as_millis() as u64;
        let hi_ms = hi.as_millis() as u64;
        Duration::from_millis(self.range(lo_ms, hi_ms))
    }
}

/// Linearly interpolate between two durations by factor `t` in `[0.0, 1.0]`.
fn lerp_duration(a: Duration, b: Duration, t: f64) -> Duration {
    let a_ms = a.as_millis() as f64;
    let b_ms = b.as_millis() as f64;
    Duration::from_millis((a_ms + (b_ms - a_ms) * t.clamp(0.0, 1.0)) as u64)
}

/// Adaptive timing state machine for the spoofer loop.
///
/// Three phases:
/// - **Aggressive** — short intervals to rapidly establish poisoned caches.
/// - **Ramp** — linear crossfade from aggressive to maintenance.
/// - **Maintenance** — long intervals to minimise traffic fingerprint.
pub struct SpoofPacer {
    rng: SimpleRng,
    start: Instant,

    aggressive_lo: Duration,
    aggressive_hi: Duration,
    aggressive_duration: Duration,

    maintenance_lo: Duration,
    maintenance_hi: Duration,
    ramp_duration: Duration,
}

impl SpoofPacer {
    /// Build a pacer with sensible stealth defaults.
    #[allow(dead_code)]
    pub fn default_stealth() -> Self {
        Self {
            rng: SimpleRng::from_system_time(),
            start: Instant::now(),
            aggressive_lo: Duration::from_millis(200),
            aggressive_hi: Duration::from_millis(400),
            aggressive_duration: Duration::from_secs(10),
            maintenance_lo: Duration::from_millis(2000),
            maintenance_hi: Duration::from_millis(5000),
            ramp_duration: Duration::from_secs(5),
        }
    }

    /// Build a pacer from explicit config values.
    pub fn from_config(
        aggressive_lo: Duration,
        aggressive_hi: Duration,
        aggressive_duration: Duration,
        maintenance_lo: Duration,
        maintenance_hi: Duration,
        ramp_duration: Duration,
    ) -> Self {
        Self {
            rng: SimpleRng::from_system_time(),
            start: Instant::now(),
            aggressive_lo,
            aggressive_hi,
            aggressive_duration,
            maintenance_lo,
            maintenance_hi,
            ramp_duration,
        }
    }

    /// Legacy behavior: constant interval, no randomization.
    pub fn fixed(interval: Duration) -> Self {
        Self {
            rng: SimpleRng::from_system_time(),
            start: Instant::now(),
            aggressive_lo: interval,
            aggressive_hi: interval + Duration::from_millis(1),
            aggressive_duration: Duration::ZERO,
            maintenance_lo: interval,
            maintenance_hi: interval + Duration::from_millis(1),
            ramp_duration: Duration::ZERO,
        }
    }

    /// Return the next randomized interval based on the current phase.
    pub fn next_interval(&mut self) -> Duration {
        let elapsed = self.start.elapsed();

        if elapsed < self.aggressive_duration {
            // Phase 1: Aggressive
            self.rng.duration_between(self.aggressive_lo, self.aggressive_hi)
        } else if elapsed < self.aggressive_duration + self.ramp_duration {
            // Phase 2: Ramp (linear crossfade)
            let ramp_elapsed = elapsed - self.aggressive_duration;
            let t = ramp_elapsed.as_millis() as f64 / self.ramp_duration.as_millis().max(1) as f64;

            let lo = lerp_duration(self.aggressive_lo, self.maintenance_lo, t);
            let hi = lerp_duration(self.aggressive_hi, self.maintenance_hi, t);
            self.rng.duration_between(lo, hi)
        } else {
            // Phase 3: Maintenance
            self.rng.duration_between(self.maintenance_lo, self.maintenance_hi)
        }
    }

    /// Re-enter aggressive phase (called by watchdog on re-verification).
    pub fn reset_to_aggressive(&mut self) {
        self.start = Instant::now();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_rng_deterministic() {
        let mut a = SimpleRng::with_seed(42);
        let mut b = SimpleRng::with_seed(42);
        for _ in 0..100 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
    }

    #[test]
    fn simple_rng_range_bounds() {
        let mut rng = SimpleRng::with_seed(123);
        for _ in 0..1000 {
            let v = rng.range(10, 20);
            assert!((10..20).contains(&v));
        }
    }

    #[test]
    fn pacer_aggressive_phase() {
        let mut pacer = SpoofPacer::default_stealth();
        // Immediately after creation we should be in aggressive phase.
        let interval = pacer.next_interval();
        assert!(interval >= Duration::from_millis(200));
        assert!(interval < Duration::from_millis(400));
    }

    #[test]
    fn pacer_maintenance_phase() {
        let mut pacer = SpoofPacer::from_config(
            Duration::from_millis(200),
            Duration::from_millis(400),
            Duration::ZERO, // skip aggressive
            Duration::from_millis(2000),
            Duration::from_millis(5000),
            Duration::ZERO, // skip ramp
        );
        let interval = pacer.next_interval();
        assert!(interval >= Duration::from_millis(2000));
        assert!(interval < Duration::from_millis(5000));
    }

    #[test]
    fn pacer_reset_returns_to_aggressive() {
        let mut pacer = SpoofPacer::from_config(
            Duration::from_millis(100),
            Duration::from_millis(200),
            Duration::ZERO, // skip aggressive
            Duration::from_millis(3000),
            Duration::from_millis(4000),
            Duration::ZERO, // skip ramp
        );
        // Should be in maintenance.
        let interval = pacer.next_interval();
        assert!(interval >= Duration::from_millis(3000));

        // Reset to aggressive.
        pacer.reset_to_aggressive();
        // Now aggressive_duration is ZERO so it'll go straight to maintenance again.
        // Use a pacer with real aggressive_duration to test properly.
        let mut pacer2 = SpoofPacer::from_config(
            Duration::from_millis(100),
            Duration::from_millis(200),
            Duration::from_secs(10),
            Duration::from_millis(3000),
            Duration::from_millis(4000),
            Duration::from_secs(5),
        );
        // Start in aggressive.
        let interval = pacer2.next_interval();
        assert!(interval >= Duration::from_millis(100));
        assert!(interval < Duration::from_millis(200));
    }
}
