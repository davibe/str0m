//! Bandwidth probing controller - decides when and how to probe network capacity.
//!
//! This module implements WebRTC's `ProbeController` state machine for discovering available
//! bandwidth through intentional bursts of packets at rates higher than current estimates.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use super::{ProbeClusterConfig, ProbeKind};
use crate::rtp_::{Bitrate, TwccClusterId};
use crate::util::{already_happened, not_happening};

// Port notes:
// This module ports WebRTC's `ProbeController` behavior from:
// `webrtc/modules/congestion_controller/goog_cc/probe_controller.cc`
//
// Key integration difference: WebRTC returns vectors of probe clusters, while str0m
// returns a single `ProbeClusterConfig` per `handle_timeout()` call. Configs are queued
// internally and `poll_timeout()` returns `already_happened()` until the queue is drained.

/// WebRTC: `kMaxWaitingTimeForProbingResult`.
const MAX_WAITING_TIME_FOR_PROBING_RESULT: Duration = Duration::from_secs(1);

/// WebRTC: `kBitrateDropThreshold`, `kBitrateDropTimeout`, `kProbeFractionAfterDrop`,
/// `kProbeUncertainty`, `kAlrEndedTimeout`, `kMinTimeBetweenAlrProbes`.
const BITRATE_DROP_THRESHOLD: f64 = 0.66;
const BITRATE_DROP_TIMEOUT: Duration = Duration::from_secs(5);
const PROBE_FRACTION_AFTER_DROP: f64 = 0.85;
const PROBE_UNCERTAINTY: f64 = 0.05;
const ALR_ENDED_TIMEOUT: Duration = Duration::from_secs(3);
const MIN_TIME_BETWEEN_ALR_PROBES: Duration = Duration::from_secs(5);

const STAGNATION_INTERVAL: Duration = Duration::from_secs(15);

/// WebRTC: inline `* 2` in probe_controller.cc InitiateProbing().
/// Allows probing up to 2x max_bitrate to account for bursty streams.
const MAX_PROBE_BITRATE_FACTOR: f64 = 2.0;

/// WebRTC's `BandwidthLimitedCause` (subset used by probing gating).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BandwidthLimitedCause {
    RttBasedBackoff,
    LossLimitedBweIncreasing,
    LossLimitedBwe,
    DelayBasedLimited,
    DelayBasedLimitedDelayIncreased,
}

pub struct ProbeControl {
    config: Config,
    next_timeout: Instant,
    next_process_tick: Option<Instant>,
    enabled: bool,

    desired_bitrate: Option<Bitrate>,
    prev_desired: Option<Bitrate>,

    last_estimate: Option<Bitrate>,
    last_cause: BandwidthLimitedCause,

    alr_start: Option<Instant>,
    alr_stop: Option<Instant>,

    last_probe: Option<LastProbe>,

    // Baseline for str0m’s stagnation probe, independent of normal estimate updates.
    stagnation_baseline: Option<(Bitrate, Instant)>,
    last_stagnation_probe: Option<Instant>,
    large_drop: Option<LargeDrop>,
    last_recovery_request: Option<Instant>,

    next_cluster_id: TwccClusterId,
    pending: VecDeque<ProbeClusterConfig>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
struct LastProbe {
    when: Instant,
    kind: ProbeKind,
    further: Bitrate,
    was_estimate: Option<Bitrate>,
    allow_further: bool,
}

struct LargeDrop {
    when: Instant,
    bitrate_before: Bitrate,
}

impl Default for ProbeControl {
    fn default() -> Self {
        Self {
            config: Config::default(),
            enabled: false,
            next_timeout: not_happening(),
            next_process_tick: None,
            desired_bitrate: None,
            prev_desired: None,
            last_estimate: None,
            last_cause: BandwidthLimitedCause::DelayBasedLimited,
            alr_start: None,
            alr_stop: None,
            next_cluster_id: 0.into(),
            last_probe: None,
            stagnation_baseline: None,
            last_stagnation_probe: None,
            large_drop: None,
            last_recovery_request: None,
            pending: VecDeque::new(),
        }
    }
}

impl ProbeControl {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn enable(&mut self, v: bool) {
        if !self.enabled && v {
            self.enabled = true;
            self.request_immediate();
        } else if self.enabled && !v {
            self.enabled = false;
            self.pending.clear();
            self.last_estimate = None;
            self.desired_bitrate = None;
            self.prev_desired = None;
            self.last_probe = None;
            self.stagnation_baseline = None;
            self.last_stagnation_probe = None;
            self.large_drop = None;
            self.last_recovery_request = None;
            self.next_timeout = not_happening();
        }
    }

    pub fn set_desired_bitrate(&mut self, v: Bitrate) {
        // Don't accept Bitrate::ZERO as first ever value.
        if self.desired_bitrate.is_none() && v.is_zero() {
            return;
        }
        self.desired_bitrate = Some(v);
        self.request_immediate();
    }

    pub fn set_estimated_bitrate(
        &mut self,
        now: Instant,
        v: Bitrate,
        cause: BandwidthLimitedCause,
    ) {
        // Don't accept Bitrate::ZERO as first ever value.
        if self.last_estimate.is_none() && v.is_zero() {
            return;
        }

        if self.last_estimate == Some(v) && self.last_cause == cause {
            return;
        }
        if self
            .stagnation_baseline
            .is_none_or(|(base, _)| v < base * 0.95 || v > base * 1.05)
        {
            self.stagnation_baseline = Some((v, now));
        }
        if let Some(previous) = self.last_estimate {
            if v < previous * BITRATE_DROP_THRESHOLD {
                self.large_drop = Some(LargeDrop {
                    when: now,
                    bitrate_before: previous,
                });
            }
        }
        self.last_estimate = Some(v);
        self.last_cause = cause;
        self.request_immediate();
    }

    pub fn set_alr_start_time(&mut self, t: Instant) {
        if self.alr_start.is_some() {
            return;
        }
        self.alr_start = Some(t);
        self.alr_stop = None;
        self.request_immediate();
    }

    pub fn set_alr_stop_time(&mut self, t: Instant) {
        if self.alr_start.is_none() || self.alr_stop.is_some() {
            return;
        }
        self.alr_start = None;
        self.alr_stop = Some(t);
        self.request_immediate();
    }

    fn request_immediate(&mut self) {
        self.next_timeout = already_happened();
    }

    pub fn poll_timeout(&self) -> Instant {
        self.next_timeout
    }

    pub fn handle_timeout(&mut self, now: Instant) -> Option<ProbeClusterConfig> {
        // GoogCC checks periodic ALR probes in OnProcessInterval. Feedback can
        // unlock probing between ticks, but only recovery and follow-up probes
        // are triggered by feedback itself.
        let tick = self.next_process_tick.unwrap_or(now);
        let process_tick = now >= tick;
        if process_tick {
            self.next_process_tick = Some(Self::process_tick_after(tick, now));
        }
        // Spurious call before timeout is due - ignore.
        if now < self.next_timeout {
            return None;
        }

        // Timeout fired - reset to not_happening until we compute the next one.
        self.next_timeout = not_happening();

        // Probing is disabled until first packet sent and padding queue exists.
        if !self.enabled {
            return None;
        }

        // We need to have both desired AND last_estimate set to
        // start considering probing.
        let desired = self.desired_bitrate?;
        let estimate = self.last_estimate?;

        // Consume allocation changes even when probing is blocked or already pending.
        // A decrease establishes the baseline for the next increase; a blocked increase
        // must not be replayed later when congestion or initial probing clears.
        let prev_desired = self.prev_desired.replace(desired);

        // Return pending probes first.
        if let Some(config) = self.pending.pop_front() {
            // Schedule another.
            self.request_immediate();
            return Some(config);
        }

        // Can't probe in certain bandwidth-limited states.
        if !self.can_probe(estimate) {
            return None;
        }

        // Try each probe type in order - only one fires per timeout.
        let _ = self.maybe_initial(now, desired, estimate)
            || self.maybe_exponential(now, desired, estimate)
            || self.maybe_allocation(now, desired, prev_desired, estimate)
            || (process_tick && self.maybe_periodic_alr(now, desired, estimate))
            || self.maybe_stagnant(now, desired, estimate);

        // Update timeout based on current state.
        self.next_timeout = self.compute_next_timeout(now);

        if !self.pending.is_empty() {
            self.request_immediate();
        }

        self.pending.pop_front()
    }

    fn maybe_initial(&mut self, now: Instant, desired: Bitrate, estimate: Bitrate) -> bool {
        // Initial probes only fire once at startup.
        if self.last_probe.is_some() {
            return false;
        }

        // Queue 3× and 6× of estimate.
        let p1 = estimate * self.config.first_exponential_probe_scale;
        let p2 = estimate * self.config.second_exponential_probe_scale;

        self.queue_probe(p1, ProbeKind::Initial, desired, now);
        self.queue_probe(p2, ProbeKind::Initial, desired, now);
        true
    }

    fn maybe_exponential(&mut self, now: Instant, desired: Bitrate, estimate: Bitrate) -> bool {
        // Wait for pending probes to be dispatched first.
        if !self.pending.is_empty() {
            return false;
        }

        // Need a previous probe to continue from.
        let Some(last) = self.last_probe else {
            return false;
        };

        // Estimate must exceed 70% of last probe rate to trigger further probing.
        if !self.waiting_for_result(now) || estimate <= last.further {
            return false;
        }

        let is_same = Some(estimate) == last.was_estimate;
        let time_since = self.time_since_last_probe(now);

        // Don't re-probe at the same estimate; wait for new result or timeout.
        if is_same && time_since < MAX_WAITING_TIME_FOR_PROBING_RESULT {
            return false;
        }

        let scale = self.last_cause.probe_scale(&self.config);
        let target = estimate * scale;

        // Already probed at max rate; no point probing again.
        let max = desired * MAX_PROBE_BITRATE_FACTOR;
        if target >= max && last.further >= max * self.config.further_probe_threshold {
            return false;
        }

        self.queue_probe(target, ProbeKind::Exponential, desired, now);

        true
    }

    fn maybe_allocation(
        &mut self,
        now: Instant,
        desired: Bitrate,
        prev_desired: Option<Bitrate>,
        estimate: Bitrate,
    ) -> bool {
        // Don't interfere with initial probing phase.
        if self.is_during_initial(now) {
            return false;
        }

        // Need a previous desired value to compare against.
        let Some(prev) = prev_desired else {
            return false;
        };

        // Allocation increases can probe both inside and outside ALR.
        // Unchanged or decreased demand must not trigger probing.
        if desired <= prev {
            return false;
        }

        // No point probing if we already have enough bandwidth.
        if desired <= estimate {
            return false;
        }

        // Allocation probes at 1× and 2× of desired, capped by 2× estimate
        let current_bwe_limit = estimate * self.config.allocation_probe_limit_by_current_scale;

        let kind = ProbeKind::Allocation {
            in_alr: self.in_alr(),
        };
        let p1 = (desired * self.config.first_allocation_probe_scale).min(current_bwe_limit);
        self.queue_probe(p1, kind, desired, now);

        let p2 = (desired * self.config.second_allocation_probe_scale).min(current_bwe_limit);
        if p2 > p1 {
            self.queue_probe(p2, kind, desired, now);
        }

        true
    }

    fn maybe_periodic_alr(&mut self, now: Instant, desired: Bitrate, estimate: Bitrate) -> bool {
        // Don't interfere with initial probing phase.
        if self.is_during_initial(now) {
            return false;
        }

        // Periodic probes only fire in ALR (application-limited region).
        if !self.in_alr() {
            return false;
        }

        // Respect minimum interval between ALR probes.
        if self
            .periodic_alr_deadline()
            .is_none_or(|deadline| now < deadline)
        {
            return false;
        }

        let target = estimate * self.config.further_exponential_probe_scale;
        self.queue_probe(target, ProbeKind::PeriodicAlr, desired, now);
        true
    }

    pub fn request_recovery(&mut self, now: Instant) {
        let (Some(drop), Some(desired), Some(estimate)) =
            (&self.large_drop, self.desired_bitrate, self.last_estimate)
        else {
            return;
        };
        let target = drop.bitrate_before * PROBE_FRACTION_AFTER_DROP;
        if !self.enabled
            || self.waiting_for_result(now)
            || !(self.in_alr() || self.alr_ended_recently(now))
            || now.saturating_duration_since(drop.when) >= BITRATE_DROP_TIMEOUT
            || target * (1.0 - PROBE_UNCERTAINTY) <= estimate
            || self
                .last_recovery_request
                .is_some_and(|t| now.saturating_duration_since(t) <= MIN_TIME_BETWEEN_ALR_PROBES)
        {
            return;
        }
        self.last_recovery_request = Some(now);
        if self.can_probe(estimate) {
            self.queue_probe(target, ProbeKind::LargeDrop, desired, now);
            self.request_immediate();
        }
    }

    fn waiting_for_result(&self, now: Instant) -> bool {
        self.last_probe.is_some_and(|p| {
            p.allow_further
                && now.saturating_duration_since(p.when) <= MAX_WAITING_TIME_FOR_PROBING_RESULT
        })
    }

    fn queue_probe(&mut self, bitrate: Bitrate, kind: ProbeKind, desired: Bitrate, now: Instant) {
        // Cap at 2× desired bitrate.
        let max = desired * MAX_PROBE_BITRATE_FACTOR;
        let bitrate = bitrate.min(max);

        // No probe at too small values.
        if bitrate < Bitrate::kbps(5) {
            return;
        }

        let cluster_id = self.next_cluster_id.inc();

        let config = ProbeClusterConfig::new(cluster_id, bitrate, kind)
            .with_min_packet_count(self.config.min_probe_packets_sent)
            .with_duration(self.config.min_probe_duration)
            .with_min_probe_delta(self.config.min_probe_delta);

        // Threshold for further exponential probing (probe_bitrate * 0.7).
        let probe_further = bitrate * self.config.further_probe_threshold;

        self.pending.push_back(config);
        self.last_probe = Some(LastProbe {
            when: now,
            kind,
            further: probe_further,
            was_estimate: self.last_estimate,
            allow_further: bitrate < max,
        });
    }

    fn stagnation_deadline(&self) -> Option<Instant> {
        let (_, since) = self.stagnation_baseline?;
        if self.in_alr() || self.desired_bitrate? <= self.last_estimate? {
            return None;
        }
        let mut deadline =
            self.last_stagnation_probe.unwrap_or(since).max(since) + STAGNATION_INTERVAL;
        if let Some(last) = self.last_probe {
            if matches!(last.kind, ProbeKind::Initial | ProbeKind::Exponential) {
                deadline = deadline
                    .max(last.when + MAX_WAITING_TIME_FOR_PROBING_RESULT + Duration::from_nanos(1));
            }
        }
        Some(deadline)
    }

    fn maybe_stagnant(&mut self, now: Instant, desired: Bitrate, estimate: Bitrate) -> bool {
        if self
            .stagnation_deadline()
            .is_none_or(|deadline| now < deadline)
        {
            return false;
        }
        self.queue_probe(estimate * 2.0, ProbeKind::Stagnant, desired, now);
        self.last_stagnation_probe = Some(now);
        true
    }

    fn periodic_alr_deadline(&self) -> Option<Instant> {
        self.alr_start
            .map(|start| self.last_when().unwrap_or(start).max(start) + MIN_TIME_BETWEEN_ALR_PROBES)
    }

    fn process_tick_after(first: Instant, now: Instant) -> Instant {
        const INTERVAL_NS: u32 = 25_000_000;
        let phase = (now.duration_since(first).as_nanos() % u128::from(INTERVAL_NS)) as u32;
        now + Duration::from_nanos(u64::from(INTERVAL_NS - phase))
    }

    fn compute_next_timeout(&self, now: Instant) -> Instant {
        if let Some(deadline) = self.periodic_alr_deadline() {
            let tick = self.next_process_tick.unwrap_or(now);
            if deadline <= tick {
                return tick;
            }
            return Self::process_tick_after(tick, deadline - Duration::from_nanos(1));
        }

        self.stagnation_deadline().unwrap_or_else(not_happening)
    }

    fn can_probe(&self, estimate: Bitrate) -> bool {
        // Infinite estimate indicates no valid measurement yet.
        if estimate == Bitrate::INFINITY {
            return false;
        }

        // Only probe when delay-limited or loss-limited-but-increasing.
        // Don't probe during active congestion (loss-limited, delay-increased).
        matches!(
            self.last_cause,
            BandwidthLimitedCause::LossLimitedBweIncreasing
                | BandwidthLimitedCause::DelayBasedLimited
        )
    }

    fn in_alr(&self) -> bool {
        self.alr_start.is_some() && self.alr_stop.is_none()
    }

    fn alr_ended_recently(&self, now: Instant) -> bool {
        self.alr_stop
            .map(|stop| now.saturating_duration_since(stop) < ALR_ENDED_TIMEOUT)
            .unwrap_or(false)
    }

    fn is_during_initial(&self, now: Instant) -> bool {
        let is_initial = matches!(
            self.last_probe.map(|p| p.kind),
            Some(ProbeKind::Initial) | Some(ProbeKind::Exponential)
        );
        is_initial && self.time_since_last_probe(now) <= MAX_WAITING_TIME_FOR_PROBING_RESULT
    }

    fn last_when(&self) -> Option<Instant> {
        self.last_probe.map(|p| p.when)
    }

    fn time_since_last_probe(&self, now: Instant) -> Duration {
        self.last_when()
            .map(|t| now.saturating_duration_since(t))
            .unwrap_or(Duration::MAX)
    }
}

/// Configuration using WebRTC default constants (no field-trial plumbing).
#[derive(Debug, Clone, Copy)]
struct Config {
    // Initial/exponential probing
    first_exponential_probe_scale: f64,   // p1 = 3.0
    second_exponential_probe_scale: f64,  // p2 = 6.0
    further_exponential_probe_scale: f64, // step_size = 2.0
    further_probe_threshold: f64,         // 0.7

    // Allocation probing
    first_allocation_probe_scale: f64,            // 1.0
    second_allocation_probe_scale: f64,           // 2.0
    allocation_probe_limit_by_current_scale: f64, // 2.0

    // Probe cluster config defaults
    min_probe_packets_sent: usize, // 5
    min_probe_duration: Duration,  // 15ms
    min_probe_delta: Duration,     // 2ms

    // Gating / limits
    loss_limited_probe_scale: f64, // 1.5
}

impl Default for Config {
    fn default() -> Self {
        Self {
            first_exponential_probe_scale: 3.0,
            second_exponential_probe_scale: 6.0,
            further_exponential_probe_scale: 2.0,
            further_probe_threshold: 0.7,

            first_allocation_probe_scale: 1.0,
            second_allocation_probe_scale: 2.0,
            allocation_probe_limit_by_current_scale: 2.0,

            min_probe_packets_sent: 5,
            min_probe_duration: Duration::from_millis(15),
            min_probe_delta: Duration::from_millis(2),

            loss_limited_probe_scale: 1.5,
        }
    }
}

impl BandwidthLimitedCause {
    /// Probe scale factor for exponential probing.
    ///
    /// When loss-limited but increasing, use a more conservative 1.575× (1.5 * 1.05).
    /// Otherwise use the standard 2× scale.
    fn probe_scale(&self, config: &Config) -> f64 {
        match self {
            BandwidthLimitedCause::LossLimitedBweIncreasing => {
                config.loss_limited_probe_scale * (1.0 + PROBE_UNCERTAINTY)
            }
            _ => config.further_exponential_probe_scale,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn leaving_alr_refreshes_probe_cause_at_an_unchanged_rate() {
        use crate::bwe_::SendSideBandwidthEstimator;
        use crate::rtp_::DataSize;

        let start = Instant::now();
        let rate = Bitrate::kbps(300);
        let mut bwe = SendSideBandwidthEstimator::new(rate);
        bwe.propagate_estimate(start);
        bwe.alr_detector.handle_timeout(start);
        let now = start + Duration::from_secs(1);
        bwe.alr_detector.handle_timeout(now);
        assert!(bwe.alr_detector.alr_start_time().is_some());
        bwe.propagate_estimate(now);

        // A different limiting cause occurring at the same target rate.
        bwe.rtt_backoff.target = Some(rate);
        bwe.propagate_estimate(now);
        assert_eq!(
            bwe.probe_control.last_cause,
            BandwidthLimitedCause::DelayBasedLimited
        );

        bwe.alr_detector
            .on_bytes_sent(DataSize::bytes(100_000), now);
        assert!(bwe.alr_detector.alr_start_time().is_none());
        bwe.propagate_estimate(now);
        assert_eq!(bwe.last_estimate(), Some(rate));
        assert_eq!(
            bwe.probe_control.last_cause,
            BandwidthLimitedCause::RttBasedBackoff
        );
    }

    #[test]
    fn initial_exponential_probes_are_queued_and_emitted_one_per_tick() {
        let mut pc = ProbeControl::new();
        pc.enable(true);
        let now = Instant::now();

        pc.set_desired_bitrate(Bitrate::mbps(50));
        pc.set_estimated_bitrate(
            now,
            Bitrate::kbps(300),
            BandwidthLimitedCause::DelayBasedLimited,
        );

        // First handle_timeout triggers initial probing and returns first probe.
        let p1 = pc.handle_timeout(now).unwrap();

        // poll_timeout returns already_happened while there are pending probes.
        assert_eq!(pc.poll_timeout(), already_happened());

        // Second handle_timeout returns the second queued probe.
        let p2 = pc.handle_timeout(now).unwrap();

        assert_eq!(p1.target_bitrate(), Bitrate::kbps(900));
        assert_eq!(p2.target_bitrate(), Bitrate::kbps(1800));
        assert_eq!(p1.min_packet_count(), 5);
        assert_eq!(p1.min_probe_delta(), Duration::from_millis(2));
        assert!(!p1.is_alr_probe());

        // Queue drained - no more probes.
        assert!(pc.handle_timeout(now).is_none());
    }

    #[test]
    fn further_probe_is_triggered_when_probe_result_is_high_enough() {
        let mut pc = ProbeControl::new();
        pc.enable(true);
        let now = Instant::now();

        pc.enable(true);
        pc.set_desired_bitrate(Bitrate::mbps(50));
        pc.set_estimated_bitrate(
            now,
            Bitrate::mbps(1),
            BandwidthLimitedCause::DelayBasedLimited,
        );

        // Drain initial two probes.
        let _ = pc.handle_timeout(now).unwrap();
        let _ = pc.handle_timeout(now).unwrap();

        // WebRTC rule: if measured bitrate > min_bitrate_to_probe_further, probe at 2x measured.
        // min_bitrate_to_probe_further is 0.7 * last_probe_rate (6x start) = 4.2 Mbps.
        pc.set_estimated_bitrate(
            now,
            Bitrate::mbps(5),
            BandwidthLimitedCause::DelayBasedLimited,
        );

        let p = pc.handle_timeout(now + Duration::from_millis(10)).unwrap();
        assert_eq!(p.target_bitrate(), Bitrate::mbps(10));
    }

    #[test]
    fn allocation_probe_is_triggered_in_alr_when_allocation_increases() {
        let mut pc = ProbeControl::new();
        pc.enable(true);
        let now = Instant::now();

        pc.set_desired_bitrate(Bitrate::mbps(1));
        pc.set_estimated_bitrate(
            now,
            Bitrate::mbps(1),
            BandwidthLimitedCause::DelayBasedLimited,
        );

        // Drain initial probes.
        let _ = pc.handle_timeout(now).unwrap();
        let _ = pc.handle_timeout(now).unwrap();

        // Time out waiting for probing result -> probing complete.
        assert!(pc.handle_timeout(now + Duration::from_secs(2)).is_none());

        // Enter ALR
        pc.set_alr_start_time(now + Duration::from_secs(2));

        // No probe yet - desired hasn't increased
        assert!(pc.handle_timeout(now + Duration::from_secs(2)).is_none());

        // Increase desired bitrate while in ALR (desired > prev AND desired > estimate)
        pc.set_desired_bitrate(Bitrate::mbps(4));

        // Should trigger allocation probe: p1 = 4 Mbps * 1.0 = 4 Mbps, capped by 2× estimate = 2 Mbps
        let p = pc.handle_timeout(now + Duration::from_secs(2)).unwrap();
        assert_eq!(p.target_bitrate(), Bitrate::mbps(2));
    }

    #[test]
    fn handles_bitrate_infinity_without_panic() {
        let mut pc = ProbeControl::new();
        pc.enable(true);
        let now = Instant::now();

        pc.set_desired_bitrate(Bitrate::mbps(50));

        // Should not panic with Infinity
        pc.set_estimated_bitrate(
            now,
            Bitrate::INFINITY,
            BandwidthLimitedCause::DelayBasedLimited,
        );

        // Verify behavior is reasonable (no probing with infinite estimate)
        assert!(pc.handle_timeout(now).is_none());
    }

    #[test]
    fn handles_clock_skew_gracefully() {
        let mut pc = ProbeControl::new();
        pc.enable(true);
        let now = Instant::now();

        pc.set_desired_bitrate(Bitrate::mbps(50));
        pc.set_estimated_bitrate(
            now,
            Bitrate::kbps(300),
            BandwidthLimitedCause::DelayBasedLimited,
        );

        // Drain initial probes
        let _ = pc.handle_timeout(now);
        let _ = pc.handle_timeout(now);

        // Simulate time going backwards (clock skew)
        let earlier = now - Duration::from_secs(5);

        // Should handle gracefully with saturating_duration_since
        let _ = pc.handle_timeout(earlier);

        // Should still be able to continue normally
        let _ = pc.handle_timeout(now + Duration::from_secs(1));
    }

    #[test]
    fn handles_max_bitrate_zero() {
        let mut pc = ProbeControl::new();
        pc.enable(true);
        let now = Instant::now();

        // Set max_bitrate to zero - this is rejected as first value to avoid
        // creating probes with zero cap.
        pc.set_desired_bitrate(Bitrate::ZERO);
        pc.set_estimated_bitrate(
            now,
            Bitrate::kbps(300),
            BandwidthLimitedCause::DelayBasedLimited,
        );

        // No probes should be created since desired was rejected.
        let p1 = pc.handle_timeout(now);
        assert!(p1.is_none(), "Should not create probes with zero desired");
    }

    fn allocation_probe_fixture(in_alr: bool) -> (ProbeControl, Instant) {
        let now = Instant::now();
        let mut pc = ProbeControl::new();
        pc.enable(true);
        pc.set_desired_bitrate(Bitrate::kbps(500));
        pc.set_estimated_bitrate(
            now,
            Bitrate::kbps(500),
            BandwidthLimitedCause::DelayBasedLimited,
        );
        assert!(pc.handle_timeout(now).is_some());
        assert!(pc.handle_timeout(now).is_some());
        let now = now + Duration::from_secs(2);
        assert!(pc.handle_timeout(now).is_none());
        if in_alr {
            pc.set_alr_start_time(now);
            assert!(pc.handle_timeout(now).is_none());
        }
        (pc, now)
    }

    #[test]
    fn allocation_probe_on_increase_with_or_without_alr() {
        for in_alr in [false, true] {
            let (mut pc, now) = allocation_probe_fixture(in_alr);
            pc.set_desired_bitrate(Bitrate::mbps(4));
            assert!(pc.poll_timeout() <= now);
            let probe = pc
                .handle_timeout(now)
                .expect("increased demand should probe");
            assert_eq!(probe.target_bitrate(), Bitrate::mbps(1));
            assert_eq!(probe.is_alr_probe(), in_alr);
            assert!(pc.handle_timeout(now).is_none(), "only one capped probe");
        }
    }

    #[test]
    fn second_allocation_probe_is_capped_instead_of_dropped() {
        for in_alr in [false, true] {
            let (mut pc, now) = allocation_probe_fixture(in_alr);
            pc.set_desired_bitrate(Bitrate::kbps(750));
            let first = pc.handle_timeout(now).unwrap();
            assert_eq!(first.target_bitrate(), Bitrate::kbps(750));
            assert_eq!(first.is_alr_probe(), in_alr);
            let second = pc.handle_timeout(now).expect("capped second probe");
            assert_eq!(second.target_bitrate(), Bitrate::mbps(1));
            assert_eq!(second.is_alr_probe(), in_alr);
            assert!(pc.handle_timeout(now).is_none());
        }
    }

    #[test]
    fn allocation_probe_requires_increase_from_latest_desired() {
        for in_alr in [false, true] {
            let (mut pc, now) = allocation_probe_fixture(in_alr);
            // Raise demand without a probe while congestion prevents discovery.
            pc.set_estimated_bitrate(
                now,
                Bitrate::kbps(500),
                BandwidthLimitedCause::LossLimitedBwe,
            );
            pc.set_desired_bitrate(Bitrate::mbps(4));
            assert!(pc.handle_timeout(now).is_none());
            pc.set_estimated_bitrate(
                now,
                Bitrate::kbps(500),
                BandwidthLimitedCause::DelayBasedLimited,
            );
            assert!(
                pc.handle_timeout(now).is_none(),
                "do not replay blocked increases"
            );
            for desired in [Bitrate::mbps(4), Bitrate::mbps(2), Bitrate::mbps(2)] {
                pc.set_desired_bitrate(desired);
                assert!(
                    pc.handle_timeout(now).is_none(),
                    "unchanged/decreased demand"
                );
            }
            // Below the old high-water mark, but above the latest allocation.
            pc.set_desired_bitrate(Bitrate::mbps(3));
            assert!(pc.handle_timeout(now).is_some());
        }
    }

    #[test]
    fn allocation_increase_during_initial_probing_is_not_replayed() {
        let now = Instant::now();
        let mut pc = ProbeControl::new();
        pc.enable(true);
        pc.set_desired_bitrate(Bitrate::kbps(500));
        pc.set_estimated_bitrate(
            now,
            Bitrate::kbps(500),
            BandwidthLimitedCause::DelayBasedLimited,
        );
        assert!(pc.handle_timeout(now).is_some());
        assert!(pc.handle_timeout(now).is_some());

        pc.set_desired_bitrate(Bitrate::mbps(2));
        assert!(
            pc.handle_timeout(now + Duration::from_millis(500))
                .is_none()
        );
        assert!(pc.handle_timeout(now + Duration::from_secs(2)).is_none());

        pc.set_desired_bitrate(Bitrate::mbps(3));
        let probe = pc.handle_timeout(now + Duration::from_secs(2)).unwrap();
        assert_eq!(probe.target_bitrate(), Bitrate::mbps(1));
        assert!(!probe.is_alr_probe());
    }

    #[test]
    fn allocation_probe_respects_congestion_and_estimate_gates() {
        for cause in [
            BandwidthLimitedCause::LossLimitedBwe,
            BandwidthLimitedCause::DelayBasedLimitedDelayIncreased,
        ] {
            let (mut pc, now) = allocation_probe_fixture(false);
            pc.set_estimated_bitrate(now, Bitrate::kbps(500), cause);
            pc.set_desired_bitrate(Bitrate::mbps(4));
            assert!(pc.handle_timeout(now).is_none());
        }
        let (mut pc, now) = allocation_probe_fixture(false);
        pc.set_desired_bitrate(Bitrate::kbps(200));
        assert!(pc.handle_timeout(now).is_none());
        pc.set_desired_bitrate(Bitrate::kbps(400));
        assert!(
            pc.handle_timeout(now).is_none(),
            "estimate already covers demand"
        );
    }

    #[test]
    fn allocation_probe_fires_when_desired_increases_in_alr() {
        let mut pc = ProbeControl::new();
        pc.enable(true);
        let now = Instant::now();

        pc.set_desired_bitrate(Bitrate::kbps(500));
        pc.set_estimated_bitrate(
            now,
            Bitrate::kbps(500),
            BandwidthLimitedCause::DelayBasedLimited,
        );

        // Drain initial probes
        let _ = pc.handle_timeout(now);
        let _ = pc.handle_timeout(now);

        // Timeout to reach probing complete
        assert!(pc.handle_timeout(now + Duration::from_secs(2)).is_none());

        // Enter ALR
        pc.set_alr_start_time(now + Duration::from_secs(3));

        // No probe on ALR entry alone
        assert!(pc.handle_timeout(now + Duration::from_secs(3)).is_none());

        // Increase desired while in ALR (desired > prev AND desired > estimate)
        pc.set_desired_bitrate(Bitrate::mbps(4));

        // Should trigger allocation probe
        let probe = pc.handle_timeout(now + Duration::from_secs(3));
        assert!(
            probe.is_some(),
            "Allocation probe should trigger when desired increases in ALR"
        );
    }

    #[test]
    fn recovery_uses_the_cause_published_by_the_same_feedback() {
        use crate::bwe_::SendSideBandwidthEstimator;
        let now = Instant::now();
        let mut bwe = SendSideBandwidthEstimator::new(Bitrate::kbps(250));
        let pc = &mut bwe.probe_control;
        pc.enable(true);
        pc.set_desired_bitrate(Bitrate::mbps(3));
        pc.set_estimated_bitrate(
            now,
            Bitrate::mbps(1),
            BandwidthLimitedCause::DelayBasedLimited,
        );
        pc.handle_timeout(now).unwrap();
        pc.handle_timeout(now).unwrap();
        let drop_time = now + Duration::from_secs(2);
        pc.set_alr_start_time(drop_time);
        pc.set_estimated_bitrate(
            drop_time,
            Bitrate::kbps(250),
            BandwidthLimitedCause::DelayBasedLimitedDelayIncreased,
        );

        // The network target is unchanged. An encoder target notification on
        // recovery propagates the detector's normal state before RequestProbe.
        let recovery = drop_time + Duration::from_millis(50);
        bwe.finish_feedback(recovery, true);
        let probe = bwe.probe_control.handle_timeout(recovery).unwrap();
        assert_eq!(probe.target_bitrate(), Bitrate::kbps(850));
    }

    #[test]
    fn large_drop_probing_after_alr_ended() {
        let mut pc = ProbeControl::new();
        pc.enable(true);
        let now = Instant::now();

        pc.set_desired_bitrate(Bitrate::mbps(5));
        pc.set_estimated_bitrate(
            now,
            Bitrate::mbps(5),
            BandwidthLimitedCause::DelayBasedLimited,
        );

        // Drain initial probes
        let _ = pc.handle_timeout(now);
        let _ = pc.handle_timeout(now);

        // Timeout to probing complete
        assert!(pc.handle_timeout(now + Duration::from_secs(2)).is_none());

        // Enter and exit ALR (large-drop works when ALR ended recently)
        pc.set_alr_start_time(now + Duration::from_secs(2));
        pc.set_alr_stop_time(now + Duration::from_secs(3));

        // Simulate large drop (to 60% of original = 3 Mbps, below 66% threshold)
        pc.set_estimated_bitrate(
            now + Duration::from_secs(3),
            Bitrate::mbps(3),
            BandwidthLimitedCause::DelayBasedLimited,
        );

        // Check at now+5s (within 3s of ALR ending, so alr_ended_recently is true)
        let later = now + Duration::from_secs(5);

        // Should trigger large-drop recovery probe at 85% of pre-drop rate (4.25 Mbps)
        pc.request_recovery(later);
        let p = pc.handle_timeout(later);
        assert!(p.is_some(), "Large-drop recovery should schedule probe");
        if let Some(probe) = p {
            // 85% of 5 Mbps = 4.25 Mbps
            assert!(probe.target_bitrate() >= Bitrate::mbps(4));
            assert!(probe.target_bitrate() <= Bitrate::mbps(5));
        }
    }

    #[test]
    fn allocation_probe_requires_desired_increase_in_alr() {
        let mut pc = ProbeControl::new();
        pc.enable(true);
        let now = Instant::now();

        pc.set_desired_bitrate(Bitrate::mbps(5));
        pc.set_estimated_bitrate(
            now,
            Bitrate::mbps(1),
            BandwidthLimitedCause::DelayBasedLimited,
        );

        // Drain initial probes
        let _ = pc.handle_timeout(now);
        let _ = pc.handle_timeout(now);

        // Timeout to probing complete
        assert!(pc.handle_timeout(now + Duration::from_secs(2)).is_none());

        // Enter ALR with estimate < max_bitrate
        pc.set_alr_start_time(now + Duration::from_secs(2));

        // No allocation probe on ALR entry - need desired to increase
        let probe = pc.handle_timeout(now + Duration::from_secs(2));
        assert!(
            probe.is_none(),
            "Should NOT trigger allocation probe on ALR entry alone"
        );

        // Increase desired while in ALR
        pc.set_desired_bitrate(Bitrate::mbps(10));

        // Now should trigger allocation probe
        let probe = pc.handle_timeout(now + Duration::from_secs(2));
        assert!(
            probe.is_some(),
            "Should trigger allocation probe when desired increases in ALR"
        );
    }

    #[test]
    fn stable_estimate_outside_alr_probes_every_fifteen_seconds() {
        let start = Instant::now();
        let mut pc = ProbeControl::new();
        pc.enable(true);
        pc.set_desired_bitrate(Bitrate::mbps(3));
        pc.set_estimated_bitrate(
            start,
            Bitrate::kbps(396),
            BandwidthLimitedCause::DelayBasedLimited,
        );
        pc.handle_timeout(start).unwrap();
        pc.handle_timeout(start).unwrap();
        assert!(pc.handle_timeout(start + Duration::from_secs(2)).is_none());
        for seconds in [15, 30] {
            let due = start + Duration::from_secs(seconds);
            assert_eq!(pc.poll_timeout(), due);
            assert!(pc.handle_timeout(due - Duration::from_millis(1)).is_none());
            let probe = pc.handle_timeout(due).unwrap();
            assert_eq!(pc.last_probe.unwrap().kind, ProbeKind::Stagnant);
            assert_eq!(probe.target_bitrate(), Bitrate::kbps(792));
            assert!(pc.handle_timeout(due).is_none());
        }
    }

    #[test]
    fn periodic_alr_probing() {
        let mut pc = ProbeControl::new();
        pc.enable(true);
        let now = Instant::now();

        pc.set_desired_bitrate(Bitrate::mbps(5));
        pc.set_estimated_bitrate(
            now,
            Bitrate::mbps(1),
            BandwidthLimitedCause::DelayBasedLimited,
        );

        // Drain initial probes
        let _ = pc.handle_timeout(now);
        let _ = pc.handle_timeout(now);

        // Timeout to probing complete
        assert!(pc.handle_timeout(now + Duration::from_secs(2)).is_none());

        // Enter ALR
        pc.set_alr_start_time(now + Duration::from_secs(2));

        // No immediate probe on ALR entry
        assert!(pc.handle_timeout(now + Duration::from_secs(2)).is_none());

        // Wait 5 seconds for periodic probe (2s to complete initial + 5s = 7s)
        let probe = pc.handle_timeout(now + Duration::from_secs(7));
        assert!(
            probe.is_some(),
            "Should trigger periodic ALR probe after 5 seconds in ALR"
        );
        let probe = probe.unwrap();
        assert!(probe.is_alr_probe());
        assert_eq!(probe.target_bitrate(), Bitrate::mbps(2));
    }

    #[test]
    fn feedback_unlocking_an_overdue_alr_probe_waits_for_the_next_process_tick() {
        let mut pc = ProbeControl::new();
        let start = Instant::now();
        let at = |ms| start + Duration::from_millis(ms);
        let rate = Bitrate::mbps(1);
        pc.enable(true);
        pc.set_desired_bitrate(Bitrate::mbps(5));
        pc.set_estimated_bitrate(start, rate, BandwidthLimitedCause::DelayBasedLimited);
        pc.handle_timeout(start).unwrap();
        pc.handle_timeout(start).unwrap();
        pc.set_alr_start_time(at(2000));
        pc.set_estimated_bitrate(
            at(7000),
            rate,
            BandwidthLimitedCause::DelayBasedLimitedDelayIncreased,
        );
        assert!(pc.handle_timeout(at(7000)).is_none());
        pc.set_estimated_bitrate(at(7001), rate, BandwidthLimitedCause::DelayBasedLimited);
        assert!(pc.handle_timeout(at(7001)).is_none());
        assert_eq!(pc.poll_timeout(), at(7025));
        assert!(pc.handle_timeout(at(7024)).is_none());
        assert!(pc.handle_timeout(at(7025)).unwrap().is_alr_probe());
    }

    #[test]
    fn periodic_alr_probing_continues_even_when_estimate_reaches_max() {
        let mut pc = ProbeControl::new();
        pc.enable(true);
        let now = Instant::now();

        pc.set_desired_bitrate(Bitrate::mbps(2));
        pc.set_estimated_bitrate(
            now,
            Bitrate::mbps(1),
            BandwidthLimitedCause::DelayBasedLimited,
        );

        // Drain initial probes
        let _ = pc.handle_timeout(now);
        let _ = pc.handle_timeout(now);

        // Timeout to probing complete
        assert!(pc.handle_timeout(now + Duration::from_secs(2)).is_none());

        // Enter ALR
        pc.set_alr_start_time(now + Duration::from_secs(2));

        // No immediate probe on ALR entry
        assert!(pc.handle_timeout(now + Duration::from_secs(2)).is_none());

        // Now increase estimate to match max_bitrate
        pc.set_estimated_bitrate(
            now,
            Bitrate::mbps(2),
            BandwidthLimitedCause::DelayBasedLimited,
        );

        // Wait 5 seconds - should still trigger periodic probe in ALR
        // even though estimate >= max_bitrate, to maintain confidence in the estimate
        let probe = pc.handle_timeout(now + Duration::from_secs(7));
        assert!(
            probe.is_some(),
            "Should continue periodic probing in ALR even when estimate >= max_bitrate"
        );
    }
}
