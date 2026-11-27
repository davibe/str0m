use crate::rtp_::Bitrate;

/// AIMD's capacity estimate from throughput observed during congestion.
pub(super) struct LinkCapacityEstimator {
    estimate_kbps: Option<f64>,
    // Normalized variance, as in libwebrtc's LinkCapacityEstimator.
    deviation: f64,
}

impl Default for LinkCapacityEstimator {
    fn default() -> Self {
        Self {
            estimate_kbps: None,
            deviation: 0.4,
        }
    }
}

impl LinkCapacityEstimator {
    pub(super) fn estimate_kbps(&self) -> Option<f64> {
        self.estimate_kbps
    }

    pub(super) fn reset_if_exceeded(&mut self, observed_bitrate: Bitrate) {
        if self
            .estimate_kbps
            .is_some_and(|c| observed_bitrate.as_f64() > 1000.0 * (c + self.capacity_margin(c)))
        {
            self.estimate_kbps = None;
        }
    }

    fn capacity_margin(&self, estimate_kbps: f64) -> f64 {
        3.0 * (self.deviation * estimate_kbps).sqrt()
    }

    pub(super) fn on_overuse(&mut self, throughput: Bitrate) {
        let sample = (throughput.as_f64() / 1000.0).round();
        let capacity = self
            .estimate_kbps
            .filter(|&c| sample >= c - self.capacity_margin(c));
        let estimate = capacity.map_or(sample, |c| c * 0.95 + sample * 0.05);
        self.estimate_kbps = Some(estimate);
        self.deviation = (0.95 * self.deviation
            + 0.05 * (estimate - sample).powi(2) / estimate.max(1.0))
        .clamp(0.4, 2.5);
    }
}
