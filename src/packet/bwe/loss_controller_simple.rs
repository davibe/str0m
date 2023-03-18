#![allow(dead_code)]
// ^- TODO: remove

// inspired by: https://datatracker.ietf.org/doc/html/draft-ietf-rmcat-gcc-02#section-6

use crate::rtp::Bitrate;

use super::{
    loss_controller::{DelayDetectorBandwidthUsage, PacketResult},
    rate_control::MovingAverage,
};

const LOSS_CONTROL_STARTING_BITRATE: f64 = 100_000.0; // 100kbps
const MIN_OBSERVATIONS: usize = 2;

pub struct NaiveLossController {
    packet_loss: MovingAverage,
    num_observations: usize,
    estimated_bitrate: Bitrate,
    min_bitrate: Bitrate,
    max_bitrate: Bitrate,
}

impl NaiveLossController {
    pub fn new(starting_bitrate: Option<Bitrate>) -> NaiveLossController {
        let estimated_bitrate =
            starting_bitrate.unwrap_or_else(|| Bitrate::from(LOSS_CONTROL_STARTING_BITRATE));

        NaiveLossController {
            packet_loss: MovingAverage::new(0.5),
            num_observations: 0,
            estimated_bitrate,
            min_bitrate: Bitrate::ZERO,
            max_bitrate: Bitrate::MAX,
        }
    }

    pub fn update(
        &mut self,
        packet_results: &Vec<PacketResult>,
        delay_state: DelayDetectorBandwidthUsage,
    ) {
        let num_lost = packet_results
            .iter()
            .filter(|p| p.receive_time.is_none())
            .count() as f64;
        let num_received = packet_results.len() as f64;
        let loss = num_lost / num_received;

        self.packet_loss.update(loss);

        self.num_observations += 1;

        let Some(loss) = self.packet_loss.get_average() else {
            return
        };

        let max_bitrate = if delay_state == DelayDetectorBandwidthUsage::Overusing {
            // the system already knows we are over using,
            // so our estimate does not need to evolve upwards
            self.estimated_bitrate
        } else {
            self.max_bitrate
        };

        let ratio = ratio_with_loss(loss);
        self.estimated_bitrate = Bitrate::from(self.estimated_bitrate.as_f64() * ratio)
            .clamp(self.min_bitrate, max_bitrate);
    }

    pub fn get_estimated_bitrate(&self) -> Option<Bitrate> {
        if self.num_observations < MIN_OBSERVATIONS {
            return None;
        }
        Some(self.estimated_bitrate)
    }

    pub fn set_min_bitrate(&mut self, min_bitrate: Bitrate) {
        self.min_bitrate = min_bitrate;
    }

    pub fn set_max_bitrate(&mut self, max_bitrate: Bitrate) {
        self.max_bitrate = max_bitrate;
    }
}

fn ratio_with_loss(loss: f64) -> f64 {
    if loss < 0.2 {
        1.05
    } else if loss > 10.0 {
        1.0 - 0.5 * loss
    } else {
        1.0
    }
}
