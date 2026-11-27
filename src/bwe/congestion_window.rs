//! CongestionWindowPushbackController in GoogCC's drop-frame-only mode.
//! A change to the encoder target refreshes the probe controller's stored
//! limitation cause even when the published network estimate stays constant.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use crate::rtp_::Bitrate;

use super::MIN_BITRATE;

#[derive(Default)]
pub(super) struct CongestionWindow {
    feedback_rtts_ms: VecDeque<u64>,
    bytes: Option<u64>,
    pub(super) outstanding: usize,
    encoding_ratio: Option<f64>,
    last_process: Option<Instant>,
}

impl CongestionWindow {
    pub(super) fn record_rtt(&mut self, rtt: Duration) {
        if self.feedback_rtts_ms.len() == 32 {
            self.feedback_rtts_ms.pop_front();
        }
        self.feedback_rtts_ms
            .push_back(((rtt.as_micros() + 500) / 1000) as u64);
    }

    pub(super) fn resize(&mut self, rate: Bitrate) {
        let Some(min_rtt) = self.feedback_rtts_ms.iter().min() else {
            return;
        };
        let window = (rate.as_f64() * (*min_rtt as f64 + 350.0) / 8000.0).round() as u64;
        self.bytes = Some(
            self.bytes
                .map_or(window, |old| old.midpoint(window))
                .max(3000),
        );
    }

    pub(super) fn process_due(&mut self, now: Instant) -> bool {
        if self
            .last_process
            .is_some_and(|last| now.duration_since(last) < Duration::from_millis(25))
        {
            return false;
        }
        self.last_process = Some(now);
        true
    }

    pub(super) fn encoder_target(&mut self, rate: Bitrate) -> Bitrate {
        let Some(window) = self.bytes else {
            return rate;
        };
        let fill = self.outstanding as f64 / window as f64;
        let ratio = self.encoding_ratio.get_or_insert(1.0);
        if fill > 1.5 {
            *ratio *= 0.90;
        } else if fill > 1.0 {
            *ratio *= 0.95;
        } else if fill < 0.1 {
            *ratio = 1.0;
        } else {
            *ratio = (*ratio * 1.05).min(1.0);
        }
        Bitrate::bps((rate.as_f64() * *ratio) as u64)
            .max(MIN_BITRATE)
            .min(rate)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn draining_a_full_window_changes_encoder_target_at_constant_network_rate() {
        let mut window = CongestionWindow::default();
        let rate = Bitrate::kbps(800);
        window.record_rtt(Duration::from_millis(50));
        window.resize(rate);
        window.outstanding = 64_000;
        assert_eq!(window.encoder_target(rate), Bitrate::kbps(720));
        window.outstanding = 1_000;
        assert_eq!(window.encoder_target(rate), rate);
    }
}
