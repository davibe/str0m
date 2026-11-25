//! Probe cluster data structures for bandwidth estimation.
//!
//! Probe clusters are short bursts of packets sent at specific bitrates to test
//! network capacity.

use std::time::{Duration, Instant};

use crate::rtp_::{Bitrate, DataSize, TwccClusterId};
use crate::util::{already_happened, not_happening};

/// Configuration for a probe cluster (the plan).
///
/// This represents the immutable blueprint for a bandwidth probe: what bitrate
/// to test, for how long, and with what constraints.
#[derive(Debug, Clone, Copy)]
pub struct ProbeClusterConfig {
    /// Unique identifier for this probe cluster
    cluster: TwccClusterId,

    /// Target bitrate to probe at (e.g., 3 Mbps)
    target_bitrate: Bitrate,

    /// How long to sustain the target bitrate (e.g., 15ms)
    target_duration: Duration,

    /// Minimum number of send bursts in the cluster (e.g., 5)
    /// This ensures statistical validity even for short bursts.
    min_packet_count: usize,

    /// Delta time between sent bursts of packets during probe.
    ///
    /// Mirrors WebRTC's `ProbeClusterConfig.min_probe_delta`. The pacer/probe sender must not
    /// schedule probe packets more frequently than this.
    min_probe_delta: Duration,

    /// The kind of probe this is.
    kind: ProbeKind,
}

/// Kind of probe
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProbeKind {
    Initial,
    Exponential,
    Allocation {
        in_alr: bool,
    },
    PeriodicAlr,
    LargeDrop,
    /// Legacy probe kind. The controller no longer probes solely on a stable estimate.
    Stagnant,
}

impl ProbeKind {
    pub(crate) fn is_alr(&self) -> bool {
        matches!(
            self,
            ProbeKind::PeriodicAlr | ProbeKind::Allocation { in_alr: true }
        )
    }
}

impl ProbeClusterConfig {
    /// Create a new probe cluster configuration with standard defaults:
    /// - 15ms duration (enough to get meaningful feedback without excessive delay)
    /// - 5 minimum packets (statistical significance for BWE analysis)
    pub fn new(cluster: TwccClusterId, target_bitrate: Bitrate, kind: ProbeKind) -> Self {
        Self {
            cluster,
            target_bitrate,
            // WebRTC defaults
            target_duration: Duration::from_millis(15),
            min_packet_count: 5,
            // WebRTC default for general probing (not initial/network-state): 2ms.
            min_probe_delta: Duration::from_millis(2),
            kind,
        }
    }

    /// Set a custom target duration for this probe.
    /// WebRTC uses 100ms for initial probes to allow time for media to start.
    pub fn with_duration(mut self, duration: Duration) -> Self {
        self.target_duration = duration;
        self
    }

    /// Set a custom minimum packet count for this probe.
    pub fn with_min_packet_count(mut self, min_packet_count: usize) -> Self {
        self.min_packet_count = min_packet_count;
        self
    }

    /// Set a custom minimum probe delta (spacing constraint) for this probe.
    pub fn with_min_probe_delta(mut self, min_probe_delta: Duration) -> Self {
        self.min_probe_delta = min_probe_delta;
        self
    }

    /// Check if this probe was created during ALR.
    pub fn is_alr_probe(&self) -> bool {
        self.kind.is_alr()
    }

    /// Get the probe cluster ID.
    pub fn cluster(&self) -> TwccClusterId {
        self.cluster
    }

    /// Get the target bitrate.
    pub fn target_bitrate(&self) -> Bitrate {
        self.target_bitrate
    }

    /// Get the minimum packet count required for a valid probe.
    pub fn min_packet_count(&self) -> usize {
        self.min_packet_count
    }

    /// Get the minimum probe delta (spacing constraint).
    pub fn min_probe_delta(&self) -> Duration {
        self.min_probe_delta
    }

    /// Calculate the target bytes for this probe.
    /// This is how much data we expect to send at target_bitrate for target_duration.
    pub fn target_bytes(&self) -> DataSize {
        self.target_bitrate * self.target_duration
    }
}

/// Runtime state of an active probe cluster (the execution).
///
/// This tracks what's actually happening as we send probe packets: how much
/// we've sent, how many packets, and when we started.
#[derive(Debug)]
pub struct ProbeClusterState {
    /// The immutable plan
    config: ProbeClusterConfig,

    /// Total bytes sent so far in this probe
    bytes_sent: DataSize,

    /// Completed send bursts in this cluster.
    bursts_sent: usize,

    /// Earliest burst time inherited from the preceding queued cluster.
    earliest_start: Instant,

    /// When the first packet was sent
    /// None = probe hasn't started yet (still queued)
    started_at: Option<Instant>,

    /// Bytes sent toward the current burst, across RTP packet boundaries.
    burst_bytes: DataSize,

    /// When we last created a padding request
    /// Used to prevent creating multiple padding packets for the same instant
    last_padding_at: Instant,
}

impl ProbeClusterState {
    /// Create a new probe cluster state from a config.
    pub fn new(config: ProbeClusterConfig) -> Self {
        Self {
            config,
            bytes_sent: DataSize::ZERO,
            bursts_sent: 0,
            started_at: None,
            earliest_start: already_happened(),
            burst_bytes: DataSize::ZERO,
            last_padding_at: already_happened(),
        }
    }

    pub(crate) fn defer_start_until(&mut self, deadline: Instant) {
        self.earliest_start = deadline;
    }

    /// Get the probe configuration.
    pub fn config(&self) -> &ProbeClusterConfig {
        &self.config
    }

    /// Calculates the next probe time based on total bytes sent and target bitrate.
    /// Finish an open burst immediately. Schedule the next burst from the first
    /// send and the total number of bytes transmitted at the target bitrate.
    pub fn next_probe_time(&self) -> Instant {
        let Some(started_at) = self.started_at else {
            return self.earliest_start;
        };

        if self.config.target_bitrate == Bitrate::ZERO {
            return not_happening();
        }

        if self.burst_in_progress() {
            return already_happened();
        }
        // BitrateProber::CalculateNextProbeTime uses whole microseconds.
        let elapsed = self.bytes_sent / self.config.target_bitrate;
        started_at + Duration::from_micros(elapsed.as_micros() as u64)
    }

    /// Check if the probe cluster is complete.
    ///
    /// A probe is complete when BOTH conditions are met (matching WebRTC):
    /// 1. Sent bytes >= target_bytes (target_bitrate * target_duration)
    /// 2. Completed bursts >= min_packet_count
    ///
    /// Note: WebRTC does NOT check duration for completion. Duration is only used
    /// to calculate the target bytes threshold. This ensures probes complete even
    /// when all packets are sent at the same instant (e.g., in tests or when the
    /// pacer generates bursts faster than wall-clock time advances).
    pub fn is_complete(&self, _now: Instant) -> bool {
        if self.started_at.is_none() {
            return false; // Not started yet
        }

        // Match WebRTC's BitrateProber::ProbeSent() logic:
        // if (sent_bytes >= probe_cluster_min_bytes && sent_probes >= probe_cluster_min_probes)
        let bytes_met = self.bytes_sent >= self.config.target_bytes();
        let bursts_met = self.bursts_sent >= self.config.min_packet_count;

        self.burst_bytes == DataSize::ZERO && bytes_met && bursts_met
    }

    /// Check if it's time to send the next probe packet.
    ///
    /// Returns `true` if `now >= next_probe_time()`, meaning we should send a packet now.
    pub fn should_send_now(&self, now: Instant) -> bool {
        now >= self.next_probe_time() && self.last_padding_at < now
    }

    /// Calculate how much padding should be generated for the next probe packet.
    ///
    /// WebRTC probing uses **bursts** of packets, with a minimum delta between bursts
    /// (`min_probe_delta`). In str0m, a `PaddingRequest` is expressed as a number of bytes
    /// to queue (which may result in multiple RTP padding packets), so we request a burst
    /// sized approximately as:
    ///
    /// `burst_bytes = target_bitrate * min_probe_delta`
    ///
    /// This avoids unintentionally capping probe throughput at `MAX_PADDING_PACKET_SIZE /
    /// min_probe_delta` (e.g. 240 bytes / 2ms = 960 kbit/s), which would be far below the
    /// intended probe bitrate.
    ///
    /// Returns `None` if it's not time to send yet, or if we've already created
    /// a padding packet for this instant.
    pub fn next_packet(&mut self, now: Instant) -> Option<DataSize> {
        if !self.should_send_now(now) {
            return None;
        }

        self.last_padding_at = now;
        Some(self.burst_size() - self.burst_bytes)
    }

    pub(crate) fn burst_in_progress(&self) -> bool {
        self.burst_bytes > DataSize::ZERO
    }

    fn burst_size(&self) -> DataSize {
        (self.config.target_bitrate * self.config.min_probe_delta()).max(DataSize::bytes(1))
    }

    /// Record a packet that was sent as part of this probe (media or padding).
    ///
    /// This updates the probe's tracking state so that `next_probe_time()` correctly
    /// calculates when the next packet should be sent based on the target bitrate.
    ///
    /// Should be called by the pacer whenever ANY packet is sent during an active probe,
    /// not just padding packets generated by `next_packet()`.
    pub fn record_packet(&mut self, now: Instant, size: DataSize) {
        // Media and padding both contribute to the current burst.
        if self.started_at.is_none() {
            self.started_at = Some(now);
        }

        self.last_padding_at = already_happened();
        self.bytes_sent += size;
        self.burst_bytes += size;
        if self.burst_bytes >= self.burst_size() {
            self.bursts_sent += 1;
            self.burst_bytes = DataSize::ZERO;
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn low_rate_padding_reaches_minimum_packet_count() {
        let now = Instant::now();
        let config = ProbeClusterConfig::new(0.into(), Bitrate::kbps(10), ProbeKind::Initial);
        let mut state = ProbeClusterState::new(config);
        let burst_size = config.target_bitrate() * config.min_probe_delta();
        let bursts = config
            .target_bytes()
            .as_bytes_usize()
            .div_ceil(burst_size.as_bytes_usize())
            .max(config.min_packet_count());
        for i in 0..bursts {
            let at = if i == 0 { now } else { state.next_probe_time() };
            let size = state.next_packet(at).expect("minimum packets still needed");
            assert_eq!(size, burst_size);
            state.record_packet(at, size);
        }
        assert!(state.is_complete(state.next_probe_time()));
    }

    #[test]
    fn several_rtp_packets_complete_one_burst() {
        let now = Instant::now();
        let config = ProbeClusterConfig::new(1.into(), Bitrate::mbps(4), ProbeKind::Initial)
            .with_duration(Duration::from_millis(1))
            .with_min_packet_count(2);
        let mut state = ProbeClusterState::new(config);
        for _ in 0..4 {
            state.record_packet(now, DataSize::bytes(240));
        }
        assert_eq!(state.next_packet(now), Some(DataSize::bytes(40)));
        state.record_packet(now, DataSize::bytes(40));
        assert!(!state.is_complete(now));
        let next = state.next_probe_time();
        assert_eq!(next, now + Duration::from_millis(2));
        state.record_packet(next, DataSize::bytes(1150));
        assert!(state.is_complete(next));
    }

    #[test]
    fn probe_deadline_truncates_fractional_microseconds() {
        let start = Instant::now();
        let config = ProbeClusterConfig::new(1.into(), Bitrate::mbps(5), ProbeKind::PeriodicAlr);
        let mut probe = ProbeClusterState::new(config);
        probe.record_packet(start, DataSize::bytes(8313));
        assert_eq!(
            probe.next_probe_time(),
            start + Duration::from_micros(13_300)
        );
    }

    #[test]
    fn partial_burst_can_continue_on_the_same_clock_tick() {
        let now = Instant::now();
        let config = ProbeClusterConfig::new(1.into(), Bitrate::mbps(4), ProbeKind::Initial);
        let mut state = ProbeClusterState::new(config);
        assert_eq!(state.next_packet(now), Some(DataSize::bytes(1000)));
        assert_eq!(state.next_packet(now), None);
        state.record_packet(now, DataSize::bytes(600));
        assert_eq!(state.next_packet(now), Some(DataSize::bytes(400)));
        state.record_packet(now, DataSize::bytes(400));
        assert_eq!(state.next_packet(now), None);
    }

    #[test]
    fn finish_the_last_burst_when_the_byte_target_is_crossed() {
        let now = Instant::now();
        let config = ProbeClusterConfig::new(1.into(), Bitrate::mbps(4), ProbeKind::Initial)
            .with_duration(Duration::from_millis(11));
        let mut state = ProbeClusterState::new(config);
        for i in 0..5 {
            state.record_packet(now + Duration::from_millis(i * 2), DataSize::bytes(1000));
        }
        let at = state.next_probe_time();
        state.record_packet(at, DataSize::bytes(600));
        assert!(!state.is_complete(at));
        state.record_packet(at, DataSize::bytes(400));
        assert!(state.is_complete(at));
    }

    // Test helper to directly set state for testing
    impl ProbeClusterState {
        fn test_set_state(&mut self, bytes_sent: DataSize, bursts_sent: usize, now: Instant) {
            self.bytes_sent = bytes_sent;
            self.bursts_sent = bursts_sent;
            if self.started_at.is_none() {
                self.started_at = Some(now);
            }
        }
    }

    #[test]
    fn probe_cluster_not_complete_before_start() {
        let now = Instant::now();
        let config = ProbeClusterConfig::new(1.into(), Bitrate::mbps(3), ProbeKind::Initial);
        let state = ProbeClusterState::new(config);

        assert!(!state.is_complete(now));
    }

    #[test]
    fn probe_cluster_not_complete_after_packets_but_not_bytes() {
        let now = Instant::now();
        let config = ProbeClusterConfig::new(1.into(), Bitrate::mbps(3), ProbeKind::Initial);
        // target_bytes = 3 Mbps * 15ms = 45,000 bits = 5,625 bytes
        let mut state = ProbeClusterState::new(config);

        // Send 5 packets (meets packet count) but only small packets (doesn't meet bytes)
        // 5 * 100 = 500 bytes, which is < 5,625 bytes
        state.test_set_state(DataSize::bytes(500), 5, now);

        // Not complete: packets met but bytes not met
        assert!(!state.is_complete(now));
    }

    #[test]
    fn probe_cluster_not_complete_after_bytes_but_not_packets() {
        let now = Instant::now();
        let config = ProbeClusterConfig::new(1.into(), Bitrate::mbps(3), ProbeKind::Initial);
        // target_bytes = 3 Mbps * 15ms = 45,000 bits = 5,625 bytes
        let mut state = ProbeClusterState::new(config);

        // Send 2 large packets (meets bytes) but not enough packets
        // 2 * 3000 = 6000 bytes > 5,625 bytes, but only 2 packets < 5 packets
        state.test_set_state(DataSize::bytes(6000), 2, now);

        // Not complete: bytes met but packets not met
        assert!(!state.is_complete(now));
    }

    #[test]
    fn probe_cluster_complete_when_both_criteria_met() {
        let now = Instant::now();
        let config = ProbeClusterConfig::new(1.into(), Bitrate::mbps(3), ProbeKind::Initial);
        // target_bytes = 3 Mbps * 15ms = 45,000 bits = 5,625 bytes
        let mut state = ProbeClusterState::new(config);

        // Send 5 packets of 1200 bytes each = 6000 bytes
        // Meets both: 6000 >= 5625 bytes AND 5 >= 5 packets
        state.test_set_state(DataSize::bytes(6000), 5, now);

        // Complete: both bytes and packets met, even at same instant
        assert!(state.is_complete(now));
    }

    #[test]
    fn probe_cluster_complete_even_with_zero_duration() {
        let now = Instant::now();
        let config = ProbeClusterConfig::new(1.into(), Bitrate::mbps(3), ProbeKind::Initial);
        let mut state = ProbeClusterState::new(config);

        // Send all packets at exactly the same instant (duration = 0)
        state.test_set_state(DataSize::bytes(6000), 5, now);

        // Should still complete (this is the bug fix - no duration requirement)
        assert!(state.is_complete(now));
    }

    #[test]
    fn probe_cluster_tracks_bytes_and_packets() {
        let now = Instant::now();
        let config = ProbeClusterConfig::new(1.into(), Bitrate::mbps(3), ProbeKind::Initial);
        let mut state = ProbeClusterState::new(config);

        state.test_set_state(DataSize::bytes(1200), 1, now);
        assert_eq!(state.bytes_sent, DataSize::bytes(1200));
        assert_eq!(state.bursts_sent, 1);

        state.test_set_state(DataSize::bytes(2200), 2, now + Duration::from_millis(1));
        assert_eq!(state.bytes_sent, DataSize::bytes(2200));
        assert_eq!(state.bursts_sent, 2);
    }

    #[test]
    fn min_probe_delta_is_enforced_in_next_probe_time() {
        let now = Instant::now();
        let config = ProbeClusterConfig::new(1.into(), Bitrate::mbps(3), ProbeKind::Initial)
            .with_min_probe_delta(Duration::from_millis(20));
        let mut state = ProbeClusterState::new(config);
        assert_eq!(state.config().min_probe_delta(), Duration::from_millis(20));

        // Start a burst at `now`, then verify that a second burst is blocked until >= now+20ms.
        let size = state.next_packet(now).unwrap();
        state.record_packet(now, size);
        assert!(state.next_packet(now + Duration::from_millis(19)).is_none());
        assert!(state.next_packet(now + Duration::from_millis(20)).is_some());
        let next = state.last_padding_at;
        assert!(
            next >= now + Duration::from_millis(20),
            "next_probe_time {next:?} must be >= now + min_probe_delta"
        );
    }
}
