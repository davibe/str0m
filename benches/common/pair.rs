use std::net::Ipv4Addr;
use str0m::format::Codec;
use str0m::media::*;
use str0m::*;
use tracing::*;
use super::*;

#[derive(Debug, Clone)]
pub struct LtoR {
    codec: Codec,
    input_data: PcapData,
}

impl LtoR {
    pub fn with_vp8_input() -> Self {
        Self::new(Codec::Vp8, vp8_data())
    }

    pub fn with_vp9_input() -> Self {
        Self::new(Codec::Vp9, vp9_contiguous_data())
    }

    pub fn new(codec: Codec, input_data: PcapData) -> Self {
        Self {
            codec,
            input_data,
        }
    }

    pub fn run(&self) -> Result<(), RtcError> {
        let mut l = TestRtc::new(info_span!("L"));

        let rtc_r = Rtc::builder().build();

        let mut r = TestRtc::new_with_rtc(info_span!("R"), rtc_r);

        let host1 = Candidate::host((Ipv4Addr::new(1, 1, 1, 1), 1000).into(), "udp")?;
        let host2 = Candidate::host((Ipv4Addr::new(2, 2, 2, 2), 2000).into(), "udp")?;
        l.add_local_candidate(host1);
        r.add_local_candidate(host2);

        // The change is on the L (sending side) with Direction::SendRecv.
        let mut change = l.sdp_api();
        let mid = change.add_media(MediaKind::Video, Direction::SendOnly, None, None);
        let (offer, pending) = change.apply().unwrap();

        let answer = r.rtc.sdp_api().accept_offer(offer)?;
        l.rtc.sdp_api().accept_answer(pending, answer)?;

        loop {
            if l.is_connected() || r.is_connected() {
                break;
            }
            progress(&mut l, &mut r)?;
        }

        let max = l.last.max(r.last);
        l.last = max;
        r.last = max;

        let params = match self.codec {
            Codec::Vp8 => l.params_vp8(),
            Codec::Vp9 => l.params_vp9(),
            _ => unimplemented!(),
        };
        assert_eq!(params.spec().codec, self.codec);

        let pt = params.pt();

        let data = &self.input_data;

        for _ in 0..1000 {
            for (relative, header, payload) in data {
                // Drop a random packet in the middle.

                // Keep RTC time progressed to be "in sync" with the test data.
                while (l.last - max) < *relative {
                    progress(&mut l, &mut r)?;
                }

                let absolute = max + *relative;

                let mut direct = l.direct_api();
                let tx = direct.stream_tx_by_mid(mid, None).unwrap();
                tx.write_rtp(
                    pt,
                    header.sequence_number(None),
                    header.timestamp,
                    absolute,
                    header.marker,
                    header.ext_vals.clone(),
                    true,
                    payload.clone(),
                )
                .unwrap();

                progress(&mut l, &mut r)?;
            }
        }

        Ok(())
    }
}
