//! Google Congestion Control (GoogCC) Bandwidth Estimation based on TWCC feedback.
//!
//! This implementation is ported from libWebRTC's GoogCC and goes beyond the simplified
//! IETF draft (<https://datatracker.ietf.org/doc/html/draft-ietf-rmcat-gcc-02>) to include
//! WebRTC's production features:
//!
//! - Delay-based control (trendline estimator with AIMD rate control)
//! - Loss-based control (with inherent loss rate estimation)
//! - Probe controller with state machine and multi-stage probing strategy
//! - ALR (Application Limited Region) detection and periodic probing
//! - Link capacity estimation from ALR probes
//!
//! The probe controller in particular closely matches WebRTC's `ProbeController` behavior
//! and default constants, enabling compatible bandwidth discovery with WebRTC endpoints.

use std::cmp::Ordering;
use std::fmt;
use std::time::{Duration, Instant};

use crate::Reason;
use crate::rtp_::{Bitrate, DataSize, TwccClusterId, TwccSendRecord, TwccSeq};
use crate::util::Soonest;

mod alr_detector;
pub(crate) mod api;
mod congestion_window;
mod delay;
mod loss_controller;
mod macros;
mod probe;
mod robust_throughput_estimator;
mod smoother;
mod time;

use alr_detector::AlrDetector;
use delay::DelayController;
use loss_controller::{LossController, LossControllerState};
use macros::log_loss;
use robust_throughput_estimator::RobustThroughputEstimator;
use smoother::EstimateSmoother;

pub(crate) use macros::{log_pacer_media_debt, log_pacer_padding_debt};
#[cfg(test)]
pub(crate) use probe::ProbeKind;
pub(crate) use probe::{BandwidthLimitedCause, ProbeEstimator};
pub(crate) use probe::{ProbeClusterState, ProbeControl};

#[cfg(feature = "_internal_test_exports")]
pub use probe::ProbeClusterConfig;
#[cfg(not(feature = "_internal_test_exports"))]
pub(crate) use probe::ProbeClusterConfig;

const MIN_BITRATE: Bitrate = Bitrate::kbps(40);

pub struct Bwe {
    bwe: SendSideBandwidthEstimator,
    desired_bitrate: Bitrate,
    minimum_bitrate: Bitrate,
    smoother: EstimateSmoother,
}

impl Bwe {
    pub fn new(initial: Bitrate) -> Self {
        let send_side_bwe = SendSideBandwidthEstimator::new(initial);
        Bwe {
            bwe: send_side_bwe,
            desired_bitrate: Bitrate::ZERO,
            minimum_bitrate: Bitrate::ZERO,
            smoother: EstimateSmoother::new(),
        }
    }

    pub fn handle_timeout(&mut self, now: Instant, do_probe: bool) -> Option<ProbeClusterConfig> {
        let result = self.bwe.handle_timeout(self.desired_bitrate, do_probe, now);
        if let Some(estimate) = self.bwe.last_estimate() {
            self.smoother.record(now, estimate);
        }
        result
    }

    pub fn start_probe(&mut self, config: ProbeClusterConfig, now: Instant) -> bool {
        self.bwe.start_probe(config, now)
    }

    pub fn end_probe(&mut self, now: Instant, cluster_id: TwccClusterId) {
        self.bwe.end_probe(now, cluster_id);
    }

    pub fn reset(&mut self, init_bitrate: Bitrate) {
        self.bwe.reset(init_bitrate);
    }

    pub fn update<'t>(
        &mut self,
        records: impl Iterator<Item = &'t crate::rtp_::TwccSendRecord>,
        now: Instant,
    ) {
        self.bwe.update(records, now);
    }

    pub fn poll_estimate(&mut self, smoothing: bool) -> Option<Bitrate> {
        self.smoother.poll(smoothing)
    }

    pub fn poll_timeout(&self) -> (Option<Instant>, Reason) {
        self.bwe.poll_timeout()
    }

    pub fn last_estimate(&self) -> Option<Bitrate> {
        self.bwe.last_estimate()
    }

    pub fn update_rtt(&mut self, rtt: Duration) {
        self.bwe.delay_controller.update_rtt(rtt);
    }

    pub(crate) fn set_outstanding_bytes(&mut self, bytes: usize) {
        self.bwe.window.outstanding = bytes;
    }

    pub fn on_media_sent(&mut self, payload_size: DataSize, is_padding: bool, now: Instant) {
        if !is_padding {
            self.bwe.alr_detector.on_bytes_sent(payload_size, now);
        }
    }

    pub fn on_twcc_packet_sent(&mut self, now: Instant) {
        self.bwe.update_encoder_target(now);
        self.bwe.rtt_backoff.on_packet_sent(now);
    }

    pub fn has_transport_feedback(&self) -> bool {
        self.bwe.started_at.is_some()
    }

    pub fn is_overusing(&self) -> bool {
        self.bwe.is_overusing()
    }

    pub fn set_bitrate(&mut self, minimum: Bitrate, desired: Bitrate) {
        self.minimum_bitrate = minimum.min(desired);
        self.desired_bitrate = desired;
    }

    pub fn minimum_bitrate(&self) -> Bitrate {
        self.minimum_bitrate
    }
}

struct SendSideBandwidthEstimator {
    rtt_backoff: RttBasedBackoff,
    delay_controller: DelayController,
    loss_controller: LossController,
    acked_bitrate_estimator: RobustThroughputEstimator,
    probe_control: ProbeControl,
    probe_estimator: ProbeEstimator,
    // First nonempty transport feedback; starts loss estimation and enables ALR probing.
    started_at: Option<Instant>,
    alr_detector: AlrDetector,
    window: congestion_window::CongestionWindow,
    encoder_target: Option<Bitrate>,
    last_propagated: Option<(Bitrate, bool, Option<Bitrate>)>,
}

#[derive(Default)]
struct RttBasedBackoff {
    // For each acknowledged packet, send time plus time pending at the receiver.
    // The latest such instant gives the minimum propagation RTT in the report.
    propagation_origin: Option<Instant>,
    last_feedback: Option<Instant>,
    last_sent: Option<Instant>,
    last_decrease: Option<Instant>,
    target: Option<Bitrate>,
}

impl RttBasedBackoff {
    fn on_packet_sent(&mut self, now: Instant) {
        self.propagation_origin.get_or_insert(now);
        self.last_sent = Some(now);
    }

    fn on_feedback(&mut self, sorted_packets: &[AckedPacket], now: Instant) {
        let Some(last) = sorted_packets.last() else {
            return;
        };

        self.propagation_origin = sorted_packets
            .iter()
            .map(|packet| {
                let pending = last.remote_recv_time - packet.remote_recv_time;
                packet.local_send_time + pending
            })
            .max();
        self.last_feedback = Some(now);
    }

    fn update(
        &mut self,
        now: Instant,
        current_target: Option<Bitrate>,
        delay_limit: Option<Bitrate>,
    ) {
        // Feedback silence contributes only through the time of the last send.
        let corrected_rtt = self
            .last_feedback
            .max(self.last_sent)
            .zip(self.propagation_origin)
            .map(|(end, origin)| end.saturating_duration_since(origin));
        if corrected_rtt.unwrap_or_default() <= Duration::from_secs(3) {
            self.target = None;
            return;
        }

        let Some(mut target) = current_target else {
            return;
        };
        let floor = Bitrate::kbps(5);
        let interval_elapsed = self
            .last_decrease
            .is_none_or(|last| now - last >= Duration::from_secs(1));
        if target > floor && interval_elapsed {
            target = (target * 0.8).max(floor);
            self.last_decrease = Some(now);
        }
        self.target = Some(
            delay_limit
                .map_or(target, |limit| target.min(limit))
                .max(MIN_BITRATE),
        );
    }
}

impl SendSideBandwidthEstimator {
    pub fn new(initial_bitrate: Bitrate) -> Self {
        let mut alr_detector = AlrDetector::new();
        alr_detector.set_estimated_bitrate(initial_bitrate);

        let loss_controller = LossController::new();

        Self {
            rtt_backoff: RttBasedBackoff::default(),
            delay_controller: DelayController::new(initial_bitrate),
            loss_controller,
            acked_bitrate_estimator: RobustThroughputEstimator::default(),
            probe_control: ProbeControl::new(),
            probe_estimator: ProbeEstimator::new(),
            started_at: None,
            alr_detector,
            window: Default::default(),
            encoder_target: None,
            last_propagated: None,
        }
    }

    /// Whether the delay-based detector currently signals overuse.
    ///
    /// This is useful for gating behaviors (like padding/probing) that would otherwise
    /// re-excite the system while we're already congested.
    pub fn is_overusing(&self) -> bool {
        self.delay_controller.is_overusing()
    }

    /// Record a packet from a TWCC report.
    pub fn update<'t>(&mut self, records: impl Iterator<Item = &'t TwccSendRecord>, now: Instant) {
        let send_records: Vec<_> = records.collect();
        if send_records.is_empty() {
            return;
        }
        let current_target = self.last_estimate();
        let _ = self.started_at.get_or_insert(now);

        let latest_probe_result = self
            .probe_estimator
            .update(send_records.iter().copied())
            .last()
            .map(|(_, rate)| rate);

        let mut acked_packets = vec![];

        for record in send_records.iter() {
            if let Ok(packet) = (*record).try_into() {
                acked_packets.push(packet);
            }
        }
        log_loss!(if send_records.is_empty() {
            0.0
        } else {
            (send_records.len() - acked_packets.len()) as f64 / send_records.len() as f64
        });
        acked_packets.sort_by(AckedPacket::order_by_receive_time);
        if let Some(rtt) = acked_packets
            .iter()
            .map(|packet| now.duration_since(packet.local_send_time))
            .max()
        {
            self.window.record_rtt(rtt);
        }
        self.rtt_backoff.on_feedback(&acked_packets, now);

        self.acked_bitrate_estimator.update(&acked_packets);
        let acked_bitrate = self.acked_bitrate_estimator.current_estimate();

        // Use the latest probe result from this update, if any
        let probe_result = latest_probe_result;

        // Update delay controller with the latest probe result
        let (maybe_estimate, recovered) =
            self.delay_controller
                .update(&acked_packets, acked_bitrate, probe_result, now);

        let is_probe_result = probe_result.is_some() && !self.delay_controller.is_overusing();
        let Some(delay_estimate) = maybe_estimate else {
            if recovered {
                self.probe_control.request_recovery(now);
            }
            return;
        };

        // GoogCC applies a new delay limit (or probe target) before the RTT decrease.
        let current_target = if is_probe_result {
            Some(delay_estimate)
        } else {
            current_target.map(|rate| rate.min(delay_estimate))
        };
        self.rtt_backoff
            .update(now, current_target, Some(delay_estimate));

        if let Some(acked_bitrate) = acked_bitrate {
            self.loss_controller.set_acknowledged_bitrate(acked_bitrate);
        }

        // This corresponds to UpdateLossBasedEstimator + UpdateEstimate
        self.loss_controller
            .update_bandwidth_estimate(&send_records, delay_estimate);

        self.finish_feedback(now, recovered);
    }

    fn finish_feedback(&mut self, now: Instant, recovered: bool) {
        self.update_encoder_target(now);
        // Evaluate recovery with the limitation cause propagated by this feedback.
        if recovered {
            self.probe_control.request_recovery(now);
        }
        if let Some(rate) = self.last_estimate() {
            self.window.resize(rate);
        }
    }

    pub fn poll_timeout(&self) -> (Option<Instant>, Reason) {
        let probe_timeout = Some(self.probe_control.poll_timeout());
        let probe_estimator_timeout = Some(self.probe_estimator.poll_timeout());
        (probe_timeout, Reason::BweProbeControl)
            .soonest((probe_estimator_timeout, Reason::BweProbeEstimator))
    }

    /// Handle periodic timeout for BWE components.
    pub fn handle_timeout(
        &mut self,
        desired_bitrate: Bitrate,
        do_probe: bool,
        now: Instant,
    ) -> Option<ProbeClusterConfig> {
        self.rtt_backoff.update(
            now,
            self.last_estimate(),
            self.delay_controller.last_estimate(),
        );

        if self.window.process_due(now) {
            if let Some(rate) = self.last_estimate() {
                self.window.resize(rate);
            }
            self.update_encoder_target(now);
        }
        self.delay_controller.start_clock(now);
        // Update probe control with desired bitrate.
        self.probe_control.set_desired_bitrate(desired_bitrate);

        // Empty media queues are application-limited too. Advance the budget
        // without charging probe/padding bytes, including before the first media.
        if do_probe {
            self.alr_detector.handle_timeout(now);
        }

        // Forward ALR state to probe control
        let alr_start_time = self.alr_detector.alr_start_time();
        // ALR probing requires feedback for at least one sent packet.
        if let Some(t) = alr_start_time.filter(|_| self.started_at.is_some()) {
            self.probe_control.set_alr_start_time(t);
        } else {
            self.probe_control.set_alr_stop_time(now);
        }

        // Clean up expired probe cluster state
        self.probe_estimator.handle_timeout(now);

        // Feed the current estimate into subcontrollers, if it changed.
        self.propagate_estimate(now);

        // If we can't probe, clear any pending/active probes
        if !do_probe {
            self.probe_estimator.clear_probes();
        }

        self.probe_control.enable(do_probe);

        // Timeout-driven probe logic (WebRTC `Process()` equivalent).
        self.probe_control.handle_timeout(now)
    }

    fn update_encoder_target(&mut self, now: Instant) {
        if let Some(rate) = self.last_estimate() {
            self.encoder_target = Some(self.window.encoder_target(rate));
        }
        self.propagate_estimate(now);
    }

    fn propagate_estimate(&mut self, now: Instant) {
        // Do we have a value?
        let Some(estimate) = self.last_estimate() else {
            return;
        };
        // GoogCC also refreshes the probe controller's stored cause on ALR transitions.
        let rate_and_alr = (
            estimate,
            self.alr_detector.alr_start_time().is_some(),
            self.encoder_target,
        );
        if self.last_propagated == Some(rate_and_alr) {
            return;
        }

        let cause = self.bandwidth_limited_cause();

        self.probe_control
            .set_estimated_bitrate(now, estimate, cause);
        self.alr_detector.set_estimated_bitrate(estimate);

        self.last_propagated = Some(rate_and_alr);
    }

    fn bandwidth_limited_cause(&self) -> BandwidthLimitedCause {
        if self.delay_controller.usage() != BandwidthUsage::Normal {
            return BandwidthLimitedCause::DelayBasedLimitedDelayIncreased;
        }

        if self.rtt_backoff.target.is_some() {
            return BandwidthLimitedCause::RttBasedBackoff;
        }

        match self.loss_controller.loss_based_result().state {
            LossControllerState::DelayBased => BandwidthLimitedCause::DelayBasedLimited,
            LossControllerState::Increasing => BandwidthLimitedCause::LossLimitedBweIncreasing,
            LossControllerState::Decreasing => BandwidthLimitedCause::LossLimitedBwe,
        }
    }

    /// Get the latest estimate.
    pub fn last_estimate(&self) -> Option<Bitrate> {
        if let Some(target) = self.rtt_backoff.target {
            return Some(target);
        }

        let delay_estimate = self.delay_controller.last_estimate();

        let loss_result = self.loss_controller.loss_based_result();

        if self.loss_controller.is_ready() {
            loss_result
                .bandwidth_estimate
                .map(|rate| delay_estimate.map_or(rate, |delay| delay.min(rate)))
        } else {
            delay_estimate
        }
    }

    /// Start analyzing a probe cluster.
    ///
    /// This should be called when the pacer starts sending a probe cluster,
    /// to tell the estimator which cluster to watch for in TWCC feedback.
    /// Returns `true` if the probe was started, `false` if rejected.
    pub fn start_probe(&mut self, config: ProbeClusterConfig, now: Instant) -> bool {
        self.probe_estimator.probe_start(config, now)
    }

    /// End a probe cluster and mark it for cleanup.
    ///
    /// This should be called when the pacer finishes sending a probe cluster.
    /// The estimator will continue collecting feedback for a cluster history period
    /// to allow late-arriving TWCC reports to refine the estimate.
    pub fn end_probe(&mut self, now: Instant, cluster_id: TwccClusterId) {
        self.probe_estimator.end_probe(now, cluster_id);
    }

    pub fn reset(&mut self, init_bitrate: Bitrate) {
        *self = Self::new(init_bitrate);
    }
}

/// A RTP packet that has been sent and acknowledged by the receiver in a TWCC report.
#[derive(Debug, Copy, Clone)]
pub struct AckedPacket {
    /// The TWCC sequence number
    seq_no: TwccSeq,
    /// The size of the packets in bytes.
    size: DataSize,
    /// When we sent the packet
    local_send_time: Instant,
    /// When the packet was received at the remote, note this Instant is only usable with other
    /// instants of the same type i.e. those that represent a TWCC reported receive time for this
    /// session.
    remote_recv_time: Instant,
}

impl AckedPacket {
    fn order_by_receive_time(lhs: &Self, rhs: &Self) -> Ordering {
        if lhs.remote_recv_time != rhs.remote_recv_time {
            lhs.remote_recv_time.cmp(&rhs.remote_recv_time)
        } else if lhs.local_send_time != rhs.local_send_time {
            lhs.local_send_time.cmp(&rhs.local_send_time)
        } else {
            lhs.seq_no.cmp(&rhs.seq_no)
        }
    }
}

impl TryFrom<&TwccSendRecord> for AckedPacket {
    type Error = ();

    fn try_from(value: &TwccSendRecord) -> Result<Self, Self::Error> {
        let Some(remote_recv_time) = value.remote_recv_time() else {
            return Err(());
        };
        Ok(Self {
            seq_no: value.seq(),
            size: value.size().into(),
            local_send_time: value.local_send_time(),
            remote_recv_time,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BandwidthUsage {
    Overuse,
    Normal,
    Underuse,
}

impl fmt::Display for BandwidthUsage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BandwidthUsage::Overuse => write!(f, "overuse"),
            BandwidthUsage::Normal => write!(f, "normal"),
            BandwidthUsage::Underuse => write!(f, "underuse"),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::rtp_::TwccPacketId;

    #[test]
    fn rtt_backoff_tracks_sends_during_feedback_silence_and_recovers() {
        let start = Instant::now();
        let at = |ms| start + Duration::from_millis(ms);
        let mut bwe = Bwe::new(Bitrate::kbps(100));
        bwe.on_twcc_packet_sent(start);
        bwe.on_twcc_packet_sent(at(3000));
        bwe.handle_timeout(at(3500), false);
        assert_eq!(bwe.last_estimate(), Some(Bitrate::kbps(100)));

        bwe.on_twcc_packet_sent(at(3501));
        bwe.handle_timeout(at(3501), false);
        assert_eq!(bwe.last_estimate(), Some(Bitrate::kbps(80)));
        let lost = TwccSendRecord::test_new(TwccPacketId::new(1u64), start, 240, at(4500), None);
        bwe.update([&lost].into_iter(), at(4500));
        bwe.handle_timeout(at(4500), false);
        assert_eq!(bwe.last_estimate(), Some(Bitrate::kbps(80)));
        bwe.handle_timeout(at(4501), false);
        assert_eq!(bwe.last_estimate(), Some(Bitrate::kbps(64)));

        bwe.on_twcc_packet_sent(at(4502));
        let ack = TwccSendRecord::test_new(
            TwccPacketId::new(2u64),
            at(4502),
            240,
            at(4550),
            Some(at(4510)),
        );
        bwe.update([&ack].into_iter(), at(4550));
        assert!(bwe.last_estimate().unwrap() > Bitrate::kbps(64));
    }

    #[test]
    fn rtt_backoff_subtracts_receiver_wait_and_applies_target_limits() {
        let start = Instant::now();
        let at = |ms| start + Duration::from_millis(ms);
        let mut bwe = Bwe::new(Bitrate::kbps(100));
        let ack = |id, sent, received| {
            TwccSendRecord::test_new(
                TwccPacketId::new(id),
                at(sent),
                240,
                at(5000),
                Some(at(received)),
            )
        };
        // The reordered packet waits 2 s at the receiver. Its corrected RTT is 2.9 s.
        let early = ack(2u64, 100, 1000);
        let late = ack(1u64, 0, 3000);
        bwe.update([&late, &early].into_iter(), at(5000));
        assert!(bwe.bwe.rtt_backoff.target.is_none());

        let backoff = &mut bwe.bwe.rtt_backoff;
        backoff.on_packet_sent(at(5101));
        backoff.update(at(5101), Some(Bitrate::kbps(100)), Some(Bitrate::kbps(70)));
        assert_eq!(backoff.target, Some(Bitrate::kbps(70)));
        backoff.update(at(5102), backoff.target, Some(Bitrate::kbps(6)));
        assert_eq!(backoff.target, Some(MIN_BITRATE));
        backoff.update(at(6101), backoff.target, None);
        assert_eq!(backoff.target, Some(MIN_BITRATE));
    }

    #[test]
    fn alr_probing_waits_for_nonempty_transport_feedback() {
        let start = Instant::now();
        let desired = Bitrate::mbps(3);
        let mut bwe = SendSideBandwidthEstimator::new(Bitrate::kbps(300));

        // Initial discovery must work before feedback or media exists.
        assert!(bwe.handle_timeout(desired, true, start).is_some());
        assert!(bwe.handle_timeout(desired, true, start).is_some());
        for second in 1..=7 {
            let now = start + Duration::from_secs(second);
            bwe.update(std::iter::empty(), now);
            assert!(
                bwe.handle_timeout(desired, true, now).is_none(),
                "empty feedback must not authorize periodic ALR probes"
            );
        }
        assert!(bwe.alr_detector.alr_start_time().is_some());
        assert!(bwe.started_at.is_none());

        // Feedback for an actual sent packet authorizes ALR discovery.
        let now = start + Duration::from_secs(8);
        let record = TwccSendRecord::test_new(
            TwccPacketId::new(1u64),
            now - Duration::from_millis(20),
            240,
            now,
            Some(now - Duration::from_millis(10)),
        );
        bwe.update(std::iter::once(&record), now);
        let probe = bwe.handle_timeout(desired, true, now).unwrap();
        assert!(probe.is_alr_probe());

        // A reset starts discovery afresh, including the feedback requirement.
        bwe.reset(Bitrate::kbps(300));
        assert!(bwe.handle_timeout(desired, true, now).is_some());
        assert!(bwe.handle_timeout(desired, true, now).is_some());
        for second in 1..=7 {
            assert!(
                bwe.handle_timeout(desired, true, now + Duration::from_secs(second))
                    .is_none()
            );
        }
    }

    #[test]
    fn bitrate_targets_survive_estimator_reset() {
        let mut bwe = Bwe::new(Bitrate::kbps(300));
        bwe.set_bitrate(Bitrate::kbps(800), Bitrate::mbps(3));
        bwe.reset(Bitrate::kbps(200));
        assert_eq!(bwe.minimum_bitrate(), Bitrate::kbps(800));
        assert_eq!(bwe.desired_bitrate, Bitrate::mbps(3));
        assert_eq!(bwe.last_estimate(), Some(Bitrate::kbps(200)));
    }

    #[test]
    fn minimum_is_clamped_to_desired_and_can_be_cleared() {
        let mut bwe = Bwe::new(Bitrate::kbps(300));
        bwe.set_bitrate(Bitrate::mbps(2), Bitrate::mbps(1));
        assert_eq!(bwe.minimum_bitrate(), Bitrate::mbps(1));
        assert_eq!(bwe.desired_bitrate, Bitrate::mbps(1));
        bwe.set_bitrate(Bitrate::ZERO, Bitrate::mbps(1));
        assert_eq!(bwe.minimum_bitrate(), Bitrate::ZERO);
        assert_eq!(bwe.desired_bitrate, Bitrate::mbps(1));
    }
}
