use crate::rtp_::Bitrate;

const INITIAL_PACING_FACTOR: f64 = 2.5;
const PACING_FACTOR: f64 = 1.1;

/// Automatic padding target when media is active. This maintains NAT bindings, RTX state,
/// and allows ALR periodic probes to discover higher bandwidth.
const PADDING_TARGET: Bitrate = Bitrate::bps(50_000);

pub(crate) struct PacingResult {
    /// The bitrate at which the pacer may emit padding **when there is no media queued**.
    ///
    /// This value is intentionally an *absolute* target used by the pacer, not a “delta to add
    /// on top of current media”. In practice the **effective padding** over time is the
    /// difference between this target and the media actually sent, because padding is only used
    /// to fill gaps (empty queues), not to continuously top-up while media is flowing.
    pub padding_rate: Bitrate,
    pub pacing_rate: Bitrate,
}

/// Controls the pacing and padding rates.
pub(crate) struct PacerControl {}

impl PacerControl {
    pub fn new() -> Self {
        Self {}
    }

    pub fn calculate(
        &self,
        has_active_media: bool,
        estimate: Bitrate,
        is_overuse: bool,
        minimum: Bitrate,
        has_transport_feedback: bool,
    ) -> PacingResult {
        let padding_rate = if is_overuse {
            // No padding during overuse
            Bitrate::ZERO
        } else if has_active_media {
            // Sustain the requested minimum without exceeding estimated capacity.
            // Keep the automatic target for NAT bindings and RTX state.
            PADDING_TARGET.max(minimum).min(estimate)
        } else {
            // No padding when no media is being sent
            Bitrate::ZERO
        };

        // Set pacing rate to smooth out media transmission (burst avoidance).
        // Must be at least the current BWE estimate * factor, but also high enough
        // to allow the padding we want to send.
        let factor = if has_transport_feedback {
            PACING_FACTOR
        } else {
            INITIAL_PACING_FACTOR
        };
        let min_pacing_rate = estimate * factor;
        let pacing_rate = min_pacing_rate.max(padding_rate);

        PacingResult {
            padding_rate,
            pacing_rate,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn first_feedback_changes_the_media_pacing_factor() {
        let c = PacerControl::new();
        let estimate = Bitrate::kbps(300);
        let before = c.calculate(true, estimate, false, Bitrate::ZERO, false);
        let after = c.calculate(true, estimate, false, Bitrate::ZERO, true);
        assert_eq!(before.pacing_rate, Bitrate::kbps(750));
        assert_eq!(after.pacing_rate.as_u64(), 330000);
    }

    #[test]
    fn padding_enabled_with_active_media() {
        let c = PacerControl::new();
        let estimate = Bitrate::kbps(1_000);

        let r = c.calculate(true, estimate, false, Bitrate::ZERO, true);

        assert_eq!(r.padding_rate, PADDING_TARGET);
    }

    #[test]
    fn no_padding_without_active_media() {
        let c = PacerControl::new();
        let estimate = Bitrate::kbps(1_000);

        let r = c.calculate(false, estimate, false, Bitrate::mbps(2), true);

        assert_eq!(r.padding_rate, Bitrate::ZERO);
    }

    #[test]
    fn overuse_suppresses_padding() {
        let c = PacerControl::new();
        let estimate = Bitrate::mbps(40);

        let r = c.calculate(true, estimate, true, Bitrate::mbps(2), true);
        assert_eq!(r.padding_rate, Bitrate::ZERO);
    }

    #[test]
    fn minimum_tracks_estimate_without_exceeding_target() {
        let c = PacerControl::new();
        let minimum = Bitrate::kbps(800);
        // Both increasing and decreasing estimates must immediately change the cap.
        for (estimate, expected) in [(450, 450), (700, 700), (1000, 800), (300, 300)] {
            let result = c.calculate(true, Bitrate::kbps(estimate), false, minimum, true);
            assert_eq!(result.padding_rate, Bitrate::kbps(expected));
            assert_eq!(result.pacing_rate, Bitrate::kbps(estimate) * PACING_FACTOR);
        }
    }

    #[test]
    fn automatic_padding_is_also_capped_by_estimate() {
        let c = PacerControl::new();
        for estimate in [Bitrate::ZERO, Bitrate::kbps(20)] {
            let result = c.calculate(true, estimate, false, Bitrate::ZERO, true);
            assert_eq!(result.padding_rate, estimate);
        }
    }
}
