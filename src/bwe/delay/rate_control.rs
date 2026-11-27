use std::fmt;
use std::time::{Duration, Instant};

use super::super::macros::log_rate_control_applied_change;
use super::super::macros::log_rate_control_observed_bitrate;
use super::super::macros::log_rate_control_state;
use crate::rtp_::Bitrate;

use super::super::BandwidthUsage;
use super::link_capacity_estimator::LinkCapacityEstimator;

// Recommended values from https://datatracker.ietf.org/doc/html/draft-ietf-rmcat-gcc-02#section-5
/// The ratio of current estimated bandwidth to use when decreasing the rate.
const BETA: f64 = 0.85;
/// The coefficient used for multiplicative rate increase.
const MULTIPLICATIVE_INCREASE_COEF: f64 = 1.08;
/// The maximal ratio of the observed bitrate that we allow estimating in a single increase.
const MAX_ESTIMATE_RATIO: f64 = 1.5;
/// Default backoff time added to RTT for response time calculation (kDefaultBackoffTimeInMs in WebRTC).
const DEFAULT_BACKOFF_TIME: Duration = Duration::from_millis(100);
/// A type used to estimates a suitable send bitrate.
///
/// Inputs to the rate controller are:
/// * The observed received bitrate(via TWCC feddback).
/// * RTT.
/// * Congestion estimates from the delay controller.
pub struct RateControl {
    state: State,

    estimated_bitrate: Bitrate,
    min_bitrate: Bitrate,
    max_bitrate: Bitrate,

    link_capacity: LinkCapacityEstimator,
    /// The last time we updated the estimated bitrate.
    last_estimate_update: Option<Instant>,
    // Last RTT estimate in micro-seconds
    last_rtt: Option<Duration>,
}

impl RateControl {
    pub fn new(start_bitrate: Bitrate, min_bitrate: Bitrate, max_bitrate: Bitrate) -> Self {
        log_rate_control_state!(State::Increase as i8);

        Self {
            state: State::Increase,

            estimated_bitrate: start_bitrate,
            min_bitrate,
            max_bitrate,

            link_capacity: LinkCapacityEstimator::default(),
            last_estimate_update: None,
            last_rtt: None,
        }
    }

    /// Update with input from the delay controller.
    pub fn update(
        &mut self,
        signal: Signal,
        observed_bitrate: Bitrate,
        rtt: Option<Duration>,
        now: Instant,
    ) {
        if let Some(rtt) = rtt {
            self.last_rtt = Some(rtt);
        }

        if signal == Signal::Overuse && !self.time_to_reduce_further(now, observed_bitrate) {
            return;
        }

        if self.state == State::Hold && signal == Signal::Normal {
            self.last_estimate_update = Some(now);
        }
        self.state = self.state.transition(signal);
        log_rate_control_observed_bitrate!(
            observed_bitrate.as_f64(),
            self.link_capacity
                .estimate_kbps()
                .map(|avg| avg.to_string())
                .unwrap_or_default()
        );

        match self.state {
            State::Increase => {
                self.increase(observed_bitrate, now);
            }
            State::Decrease => self.decrease(observed_bitrate, now),
            State::Hold => {
                // Do nothing
            }
        }
    }

    /// Check if it's time to reduce the bitrate further.
    ///
    /// This implements WebRTC's TimeToReduceFurther logic which prevents
    /// rapid successive decreases, especially after probe results.
    ///
    /// Returns true if:
    /// 1. Enough time (1 RTT, clamped to 10-200ms) has passed since last change, OR
    /// 2. Throughput is critically low (< 50% of current estimate)
    fn time_to_reduce_further(&self, now: Instant, observed_bitrate: Bitrate) -> bool {
        let Some(last_change) = self.last_estimate_update else {
            return true; // No previous change, allow decrease
        };

        // WebRTC uses: clamp(rtt, 10ms, 200ms)
        let rtt = self.last_rtt.unwrap_or(DEFAULT_BACKOFF_TIME);
        let reduction_interval = rtt.clamp(Duration::from_millis(10), Duration::from_millis(200));

        let time_since_change = now.saturating_duration_since(last_change);

        if time_since_change >= reduction_interval {
            return true;
        }

        // If throughput is critically low (< 50% of estimate), allow immediate decrease
        let threshold = self.estimated_bitrate * 0.5;
        observed_bitrate < threshold
    }

    /// The current estimated bitrate.
    pub fn estimated_bitrate(&self) -> Bitrate {
        self.estimated_bitrate
    }

    /// Set a probe result indicating discovered capacity.
    ///
    /// When a probe succeeds, it means the network can handle at least this bitrate.
    /// We use this to quickly increase our estimate without waiting for gradual ramp-up.
    ///
    /// Apply a probe result directly to the estimate.
    ///
    /// This matches WebRTC's behavior where probe results are accepted unconditionally
    /// (subject only to min/max clamping), regardless of whether they're higher or lower
    /// than the current estimate. The timestamp is updated to prevent the next regular
    /// update from immediately overriding the probe result.
    ///
    /// WebRTC does NOT change the rate control state when applying a probe - the state
    /// remains unchanged to avoid triggering unintended AIMD behavior.
    pub fn set_probe_result(&mut self, probe_bitrate: Bitrate, now: Instant) {
        // WebRTC calls SetEstimate() directly without filtering by current estimate
        // or changing the rate control state. Accept the probe result unconditionally
        // (update_estimate handles clamping to min/max bounds).
        self.update_estimate(probe_bitrate, now);

        // Do NOT change self.state - keep current state to match WebRTC behavior.
        // Changing state here could trigger unintended AIMD decrease/increase logic.
    }

    fn increase(&mut self, observed_bitrate: Bitrate, now: Instant) {
        self.link_capacity.reset_if_exceeded(observed_bitrate);

        // WebRTC limits increases to 1.5x observed throughput to avoid unlimited growth
        // when we're already above what we're actually sending
        // See: aimd_rate_control.cc line 251-252
        let increase_limit = observed_bitrate * MAX_ESTIMATE_RATIO + Bitrate::kbps(10);

        if self.estimated_bitrate >= increase_limit {
            // WebRTC updates time_last_bitrate_change_ even when skipping increase
            // (see aimd_rate_control.cc line 281, which is outside the increase check)
            // This prevents stale timestamps from allowing premature decreases
            self.last_estimate_update = Some(now);
            return;
        }

        // Initialize timestamp if this is the first increase call, otherwise use existing value.
        // Note: In practice, last_estimate_update is always Some here because either:
        // 1) We returned early above and set it, or
        // 2) A previous call to decrease() or increase() already set it
        let last_estimate_update = self.last_estimate_update.unwrap_or(now);
        if self.last_estimate_update.is_none() {
            self.last_estimate_update = Some(now);
        }

        let since_last_update = now - last_estimate_update;
        assert!(since_last_update >= Duration::ZERO);
        let near_convergence = self.link_capacity.estimate_kbps().is_some();

        let new_estimate = if near_convergence {
            // Additive increase
            log_rate_control_applied_change!("increase_additive");
            let response_time = self.last_rtt.unwrap_or(Duration::ZERO) + DEFAULT_BACKOFF_TIME;

            let bits_per_second =
                self.estimated_packet_size() / (2.0 * response_time.as_secs_f64());
            self.estimated_bitrate.as_f64()
                + bits_per_second.max(4_000.0) * since_last_update.as_secs_f64()
        } else {
            // Multiplicative increase
            log_rate_control_applied_change!("increase_multiplicative");
            let eta = MULTIPLICATIVE_INCREASE_COEF.powf(since_last_update.as_secs_f64().min(1.0));
            let increase = ((eta - 1.0) * self.estimated_bitrate.as_f64()).max(1_000.0);

            self.estimated_bitrate.as_f64() + increase
        };

        self.update_estimate(new_estimate.min(increase_limit.as_f64()).into(), now);
    }

    fn decrease(&mut self, observed_bitrate: Bitrate, now: Instant) {
        log_rate_control_applied_change!("decrease");
        let mut new_estimate = (observed_bitrate * BETA).round();
        // Leave extra room to drain queues at low throughput, as in libWebRTC.
        let additional_backoff = Bitrate::kbps(5);
        if new_estimate > additional_backoff {
            new_estimate = new_estimate - additional_backoff;
        }

        if new_estimate > self.estimated_bitrate {
            if let Some(capacity) = self.link_capacity.estimate_kbps() {
                new_estimate = Bitrate::bps((BETA * capacity * 1000.0).round() as u64);
            }
            new_estimate = new_estimate.min(self.estimated_bitrate);
        }
        self.link_capacity.on_overuse(observed_bitrate);
        // According to https://datatracker.ietf.org/doc/html/draft-ietf-rmcat-gcc-02#section-6 we
        // should wait until this happens as consequence of the delay control, but libWebRTC does
        // it immediately.
        self.state = State::Hold;
        log_rate_control_state!(self.state as i8);
        self.update_estimate(new_estimate, now);
    }

    fn update_estimate(&mut self, bitrate: Bitrate, now: Instant) {
        self.estimated_bitrate = bitrate.clamp(self.min_bitrate, self.max_bitrate);
        self.last_estimate_update = Some(now);
    }

    fn estimated_packet_size(&self) -> f64 {
        // Assume 30 FPS video dominates the send rate
        let bits_per_frame = self.estimated_bitrate.as_f64() / 30.0;
        let packets_per_frame = (bits_per_frame / (1200.0 * 8.0)).ceil();

        bits_per_frame / packets_per_frame
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signal {
    Overuse,
    Underuse,
    Normal,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
enum State {
    Increase = 1,
    Hold = 0,
    #[default]
    Decrease = -1,
}

impl State {
    fn transition(&self, signal: Signal) -> Self {
        let new_state = match (self, signal) {
            (_, Signal::Overuse) => Self::Decrease,
            (_, Signal::Underuse) => Self::Hold,
            // https://datatracker.ietf.org/doc/html/draft-ietf-rmcat-gcc-02#section-6 says to
            // transition to Hold here, but libWebRTC stays in decrease. We will eventually
            // transition to Hold on Underuse.
            (Self::Decrease, Signal::Normal) => Self::Hold,
            (Self::Hold | Self::Increase, Signal::Normal) => Self::Increase,
        };

        if new_state != *self {
            log_rate_control_state!(new_state as i8);
        }

        new_state
    }
}

impl From<BandwidthUsage> for Signal {
    fn from(value: BandwidthUsage) -> Self {
        match value {
            BandwidthUsage::Overuse => Signal::Overuse,
            BandwidthUsage::Normal => Signal::Normal,
            BandwidthUsage::Underuse => Signal::Underuse,
        }
    }
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            State::Hold => write!(f, "hold"),
            State::Increase => write!(f, "increase"),
            State::Decrease => write!(f, "decrease"),
        }
    }
}

impl fmt::Display for Signal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Signal::Overuse => write!(f, "overuse"),
            Signal::Underuse => write!(f, "underuse"),
            Signal::Normal => write!(f, "normal"),
        }
    }
}

#[cfg(test)]
mod test {
    use std::time::Duration;

    use super::{RateControl, Signal, State};

    mod state {
        use super::{Signal, State};

        #[test]
        fn test_state_transitions() {
            // Tests based on the table in
            // https://datatracker.ietf.org/doc/html/draft-ietf-rmcat-gcc-02#section-5

            // Hold
            let hold = State::Hold;
            assert_eq!(hold.transition(Signal::Overuse), State::Decrease);
            assert_eq!(hold.transition(Signal::Normal), State::Increase);
            assert_eq!(hold.transition(Signal::Underuse), State::Hold);

            // Increase
            let increase = State::Increase;
            assert_eq!(increase.transition(Signal::Overuse), State::Decrease);
            assert_eq!(increase.transition(Signal::Normal), State::Increase);
            assert_eq!(increase.transition(Signal::Underuse), State::Hold);

            // Decrease
            let decrease = State::Decrease;
            assert_eq!(decrease.transition(Signal::Overuse), State::Decrease);
            assert_eq!(decrease.transition(Signal::Normal), State::Hold);
            assert_eq!(decrease.transition(Signal::Underuse), State::Hold);
        }
    }

    mod rate_controller {
        use std::time::Instant;

        use super::{RateControl, Signal, duration_ms};

        fn make_control(estimated_bitrate: u64) -> RateControl {
            RateControl::new(estimated_bitrate.into(), 10_000.into(), 50_000_000.into())
        }

        #[test]
        fn test_initial_estimate() {
            let rate_controller = make_control(100_000);

            assert_eq!(rate_controller.estimated_bitrate().as_u64(), 100_000);
        }

        #[test]
        fn test_normal_yields_multiplicative_increase() {
            let now = Instant::now();
            let mut rate_controller = make_control(100_000);
            // Seed last estimate value
            rate_controller.update(Signal::Normal, 85_000.into(), None, now);
            assert_eq!(
                rate_controller.estimated_bitrate().as_u64(),
                101_000,
                "Initial estimate should increase by the minimum(1Kbit/s)"
            );

            rate_controller.update(Signal::Normal, 95_000.into(), None, now + duration_ms(500));
            assert_eq!(rate_controller.estimated_bitrate().as_u64(), 104_963);

            rate_controller.update(Signal::Normal, 97_000.into(), None, now + duration_ms(1000));
            assert_eq!(rate_controller.estimated_bitrate().as_u64(), 109_081);
        }

        #[test]
        fn test_normal_to_under_use_yields_hold() {
            let now = Instant::now();
            let mut rate_controller = make_control(100_000);
            // Seed last estimate value
            rate_controller.update(Signal::Normal, 85_000.into(), None, now);
            assert_eq!(
                rate_controller.estimated_bitrate().as_u64(),
                101_000,
                "Initial estimate should increase by the minimum(1Kbit/s)"
            );

            // Should remain in increase and increase estimate
            rate_controller.update(Signal::Normal, 95_000.into(), None, now + duration_ms(500));
            assert_eq!(rate_controller.estimated_bitrate().as_u64(), 104_963);

            // Should transition to hold
            rate_controller.update(
                Signal::Underuse,
                97_000.into(),
                None,
                now + duration_ms(1000),
            );
            assert_eq!(rate_controller.estimated_bitrate().as_u64(), 104_963);

            // Should remain in hold and not modify estimates
            rate_controller.update(
                Signal::Underuse,
                97_000.into(),
                None,
                now + duration_ms(2000),
            );
            assert_eq!(rate_controller.estimated_bitrate().as_u64(), 104_963);
        }

        #[test]
        fn test_immediate_overuse() {
            let now = Instant::now();
            let mut rate_controller = make_control(100_000);
            // Seed last estimate value
            rate_controller.update(Signal::Normal, 85_000.into(), None, now);

            rate_controller.update(Signal::Overuse, 90_000.into(), None, now + duration_ms(500));
            assert_eq!(
                rate_controller.estimated_bitrate().as_u64(),
                71_500,
                "When overuse is detected we should reduce the estimate to \
                85% of the observed rate minus 5 kbit/s immediately"
            );
        }

        #[test]
        fn additional_backoff_threshold() {
            let now = Instant::now();
            for (observed, expected) in [(5_881u64, 4_999), (5_882, 5_000), (5_883, 1)] {
                let mut control = RateControl::new(100_000.into(), 0.into(), 100_000.into());
                control.update(Signal::Overuse, observed.into(), None, now);
                assert_eq!(control.estimated_bitrate().as_u64(), expected);
            }
        }

        #[test]
        fn test_immediate_overuse_then_stable() {
            let now = Instant::now();
            let mut rate_controller = make_control(100_000);
            // Seed last estimate value
            rate_controller.update(Signal::Normal, 85_000.into(), Some(duration_ms(80)), now);

            rate_controller.update(Signal::Overuse, 90_000.into(), None, now + duration_ms(500));
            assert_eq!(rate_controller.estimated_bitrate().as_u64(), 71_500);

            rate_controller.update(
                Signal::Overuse,
                75_000.into(),
                None,
                now + duration_ms(1000),
            );
            assert_eq!(rate_controller.estimated_bitrate().as_u64(), 58_750);

            rate_controller.update(Signal::Normal, 60_000.into(), None, now + duration_ms(1500));
            assert_eq!(rate_controller.estimated_bitrate().as_u64(), 58_750);

            // The first normal sample starts the clock. Over the next second a
            // 30 fps, one-packet frame and 180 ms response time give 5.44 kbit/s.
            rate_controller.update(Signal::Normal, 60_000.into(), None, now + duration_ms(2500));
            assert!((rate_controller.estimated_bitrate().as_f64() - 64_190.0).abs() < 1.0);

            rate_controller.update(Signal::Normal, 70_000.into(), None, now + duration_ms(3500));
            assert!((rate_controller.estimated_bitrate().as_f64() - 70_134.0).abs() < 1.0);
        }
    }

    fn duration_ms(ms: u64) -> Duration {
        Duration::from_millis(ms)
    }
}
