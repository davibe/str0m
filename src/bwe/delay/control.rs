use std::collections::VecDeque;
use std::time::{Duration, Instant};

use super::super::macros::{log_bitrate_estimate, log_delay_variation};
use super::super::{AckedPacket, BandwidthUsage};
use super::arrival_group::ArrivalGroupAccumulator;
use super::rate_control::RateControl;
use super::trendline::TrendlineEstimator;
use crate::rtp_::Bitrate;
use crate::util::{MovingAverage, already_happened};

const MAX_RTT_HISTORY_WINDOW: usize = 32;
const UPDATE_INTERVAL: Duration = Duration::from_millis(25);
/// RFC 6298: Exponentially Weighted Moving Average smoothing factor for RTT (alpha = 1/8)
const RTT_SMOOTHING_FACTOR: f64 = 0.125;

/// Delay controller for googcc inspired BWE.
///
/// This controller attempts to estimate the available send bandwidth by looking at the variations
/// in packet arrival times for groups of packets sent together. Broadly, if the delay variation is
/// increasing this indicates overuse.
pub struct DelayController {
    arrival_group_accumulator: ArrivalGroupAccumulator,
    trendline_estimator: TrendlineEstimator,
    rate_control: RateControl,
    /// Last estimate produced, unlike [`next_estimate`] this will always have a value after the
    /// first estimate.
    last_estimate: Option<Bitrate>,
    /// Smoothed RTT using EWMA (RFC 6298, alpha = 1/8).
    smoothed_rtt: MovingAverage,
    /// History of the max RTT derived for each TWCC report (kept for fallback).
    max_rtt_history: VecDeque<Duration>,

    /// The next time we should poll.
    next_timeout: Instant,
}

impl DelayController {
    pub fn new(initial_bitrate: Bitrate) -> Self {
        Self {
            arrival_group_accumulator: ArrivalGroupAccumulator::default(),
            trendline_estimator: TrendlineEstimator::new(20),
            rate_control: RateControl::new(initial_bitrate, Bitrate::kbps(40), Bitrate::gbps(10)),
            last_estimate: Some(initial_bitrate),
            smoothed_rtt: MovingAverage::new(RTT_SMOOTHING_FACTOR),
            max_rtt_history: VecDeque::default(),
            next_timeout: already_happened(),
        }
    }

    /// Record a packet from a TWCC report.
    pub fn update(
        &mut self,
        acked: &[AckedPacket],
        acked_bitrate: Option<Bitrate>,
        probe_bitrate: Option<Bitrate>,
        now: Instant,
    ) -> Option<Bitrate> {
        let mut max_rtt = None;

        for acked_packet in acked {
            max_rtt = max_rtt.max(Some(acked_packet.rtt()));
            if let Some(delay_variation) = self
                .arrival_group_accumulator
                .accumulate_packet(acked_packet)
            {
                log_delay_variation!(delay_variation.arrival_delta);

                // Got a new delay variation, add it to the trendline.
                //
                // IMPORTANT: Match WebRTC's TrendlineEstimator time base.
                // WebRTC calls Detect/UpdateThreshold with `arrival_time_ms` (remote receive time),
                // not the local "time we processed this feedback". Using the remote receive time
                // avoids threshold adaptation artifacts when many deltas are processed in one
                // feedback batch (e.g. TWCC reports).
                //
                // Note: We use remote timestamps for relative timing only (computing time deltas
                // between packets). Clock skew doesn't matter since we're measuring trends in
                // delay variations, not absolute times.
                self.trendline_estimator
                    .add_delay_observation(delay_variation, delay_variation.remote_recv_time);
            }
        }

        if let Some(rtt) = max_rtt {
            self.update_rtt(rtt);
        }

        let new_hypothesis = self.trendline_estimator.hypothesis();

        self.update_estimate(
            new_hypothesis,
            acked_bitrate,
            probe_bitrate,
            self.get_smoothed_rtt(),
            now,
        );

        self.last_estimate
    }

    pub fn poll_timeout(&self) -> Instant {
        self.next_timeout
    }

    pub fn handle_timeout(&mut self, now: Instant) {
        // Keep BWE housekeeping scheduled; rate updates require transport feedback.
        self.next_timeout = now + UPDATE_INTERVAL;
    }

    /// Get the latest estimate.
    pub fn last_estimate(&self) -> Option<Bitrate> {
        self.last_estimate
    }

    /// Whether the delay-based detector currently signals overuse.
    ///
    /// This is useful for gating behaviors (like probing) that would otherwise
    /// re-excite the system while we're already congested.
    pub fn is_overusing(&self) -> bool {
        self.trendline_estimator.hypothesis() == BandwidthUsage::Overuse
    }

    /// Update smoothed RTT using EWMA (RFC 6298, alpha = 1/8).
    fn update_rtt(&mut self, rtt: Duration) {
        // Keep history as fallback in case smoothed RTT is not yet available
        while self.max_rtt_history.len() >= MAX_RTT_HISTORY_WINDOW {
            self.max_rtt_history.pop_front();
        }
        self.max_rtt_history.push_back(rtt);

        // Update smoothed RTT using EWMA: smoothed = (7/8) * smoothed + (1/8) * sample
        self.smoothed_rtt.update(rtt.as_secs_f64());
    }

    /// Get the current smoothed RTT, with fallback to mean of history if not yet available.
    fn get_smoothed_rtt(&self) -> Option<Duration> {
        // Try smoothed RTT first (EWMA)
        if let Some(avg_secs) = self.smoothed_rtt.get() {
            return Some(Duration::from_secs_f64(avg_secs));
        }

        // Fallback to mean of history during initialization
        if self.max_rtt_history.is_empty() {
            return None;
        }

        let sum = self
            .max_rtt_history
            .iter()
            .fold(Duration::ZERO, |acc, rtt| acc + *rtt);
        Some(sum / self.max_rtt_history.len() as u32)
    }

    fn update_estimate(
        &mut self,
        hypothesis: BandwidthUsage,
        observed_bitrate: Option<Bitrate>,
        probe_bitrate: Option<Bitrate>,
        mean_max_rtt: Option<Duration>,
        now: Instant,
    ) {
        // WebRTC's logic from delay_based_bwe.cc MaybeUpdateEstimate():
        // - If we have a probe result, apply it directly and skip delay-based updates
        // - Otherwise, apply normal delay-based rate control
        //
        // This prevents probe results from being immediately overridden by delay-based
        // decreases caused by the probe itself (probes cause temporary queuing delay).

        if let Some(probe_rate) = probe_bitrate {
            // Apply probe result directly, bypassing delay-based updates
            self.rate_control.set_probe_result(probe_rate, now);
            let estimated_rate = self.rate_control.estimated_bitrate();
            log_bitrate_estimate!(estimated_rate.as_f64());
            self.last_estimate = Some(estimated_rate);
        } else if let Some(observed_bitrate) = observed_bitrate {
            // No probe result, apply normal delay-based rate control
            self.rate_control
                .update(hypothesis.into(), observed_bitrate, mean_max_rtt, now);
            let estimated_rate = self.rate_control.estimated_bitrate();

            log_bitrate_estimate!(estimated_rate.as_f64());
            self.last_estimate = Some(estimated_rate);
        }

        // Set this even if we didn't update, otherwise we get stuck in a poll -> handle loop
        // that starves the run loop.
        self.next_timeout = now + UPDATE_INTERVAL;
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn rate_updates_require_feedback() {
        let now = Instant::now();
        let mut controller = DelayController::new(Bitrate::kbps(1500));
        let observed = Some(Bitrate::mbps(2));
        let packet = AckedPacket {
            seq_no: 0.into(),
            size: Default::default(),
            local_send_time: now,
            remote_recv_time: now + Duration::from_millis(10),
            local_recv_time: now + Duration::from_millis(20),
        };
        controller.update(&[packet], observed, None, packet.local_recv_time);
        let estimate = controller.last_estimate().unwrap();

        for offset in 21..=100 {
            let at = now + Duration::from_millis(offset);
            controller.handle_timeout(at);
            assert_eq!(controller.last_estimate(), Some(estimate));
            assert_eq!(controller.poll_timeout(), at + UPDATE_INTERVAL);
        }

        let next_packet = AckedPacket {
            seq_no: 1.into(),
            local_send_time: now + Duration::from_millis(90),
            remote_recv_time: now + Duration::from_millis(100),
            local_recv_time: now + Duration::from_millis(110),
            ..packet
        };
        controller.update(&[next_packet], observed, None, next_packet.local_recv_time);
        assert!(controller.last_estimate().unwrap() > estimate);
    }
}
