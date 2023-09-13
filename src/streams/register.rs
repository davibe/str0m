use std::{ops::Range, time::Instant};

use crate::rtp_::{Nack, NackEntry, ReceptionReport, ReportList, SeqNo};

/// How many sequence numbers we keep track of
const MAX_DROPOUT: u64 = 3000;

/// Number of out of order packets we keep track of for reports
/// A suggested maximum value min is MAX_DROPOUT / 2
const MAX_MISORDER: u64 = 100;

/// Limits the reporting of missing packet up to max_seq - MISORDER_DELAY.
/// This is to avoid reporting packets that are likely to arrive soon because of very small jitter.
const MISORDER_DELAY: u64 = 1;

/// The max number of NACKs we perform for a single packet
const MAX_NACKS: u8 = 5;

const U16_MAX: u64 = u16::MAX as u64 + 1_u64;

#[derive(Debug)]
pub struct ReceiverRegister2 {
    /// Status of packets indexed by wrapping SeqNo.
    packets: Vec<PacketStatus>,

    /// Range of seq numbers considered NACK reporting.
    nack: Option<Range<SeqNo>>,
}

impl ReceiverRegister2 {
    pub fn new() -> Self {
        ReceiverRegister2 {
            packets: vec![PacketStatus::default(); MAX_DROPOUT as usize],
            nack: None,
        }
    }

    pub fn update(&mut self, seq: SeqNo) -> bool {
        let Some(nack) = self.nack.clone() else {
            // automatically pick up the first seq number
            self.nack = Some(seq..seq);
            self.packet(seq).mark_received();
            return true;
        };

        if seq < nack.start {
            // skip old seq numbers, report as not new
            return false;
        }

        let mut next_nack = nack.start..nack.end.max(seq);

        let new = self.packet(seq).mark_received();

        next_nack.start = {
            let min = next_nack.end.saturating_sub(MAX_MISORDER);
            let mut start = (*next_nack.start).max(min);
            while start < *next_nack.end {
                if !self.packet(start.into()).received {
                    break;
                }
                start += 1;
            }
            start.into()
        };

        // reset packets that are rolling our of the nack window
        for s in *nack.start..*next_nack.start {
            let p = self.packet(s.into());
            if !p.received {
                debug!("Seq no {} missing after {} attempts", seq, p.nack_count);
            }
            self.packet(s.into()).reset();
        }

        self.nack = Some(next_nack);

        new
    }

    pub fn nack_report(&mut self) -> Option<Vec<Nack>> {
        let nack = self.nack.as_ref()?;

        if nack.is_empty() {
            return None;
        }

        let mut nacks = vec![];
        let mut last_seq_added = 0;

        for seq in *nack.start..*nack.end {
            let packet = self.packet(seq.into());

            if !packet.should_nack() {
                continue;
            }

            let distance = seq - last_seq_added;

            let update_last = nacks.last().is_some() && distance <= 16;

            if update_last {
                let last: &mut NackEntry = nacks.last_mut().expect("last");
                let pos = (distance - 1) as u16;
                last.blp |= 1 << pos;
            } else {
                nacks.push(NackEntry {
                    pid: (seq % U16_MAX) as u16,
                    blp: 0,
                });
                last_seq_added = seq;
            }

            self.packet(seq.into()).nack_count += 1;
        }

        if nacks.is_empty() {
            return None;
        }

        let reports = ReportList::lists_from_iter(nacks).into_iter();

        Some(
            reports
                .map(|reports| {
                    Nack {
                        sender_ssrc: 0.into(),
                        ssrc: 0.into(), // changed when sending
                        reports,
                    }
                })
                .collect(),
        )
    }

    fn as_index(&self, seq: SeqNo) -> usize {
        (*seq % self.packets.len() as u64) as usize
    }

    fn packet(&mut self, seq: SeqNo) -> &mut PacketStatus {
        let index = self.as_index(seq);
        &mut self.packets[index]
    }
}

#[cfg(test)]
mod nack_test {
    use std::ops::Range;

    use crate::streams::register::{ReceiverRegister2, MAX_MISORDER, MISORDER_DELAY};

    fn assert_update(
        reg: &mut ReceiverRegister2,
        seq: u64,
        expect_new: bool,
        expect_received: bool,
        expect_nack: Range<u64>,
    ) {
        assert_eq!(
            reg.update(seq.into()),
            expect_new,
            "seq {} was expected to{} be new",
            seq,
            if expect_new { "" } else { " NOT" }
        );
        let nack = reg.nack.clone().expect("nack range");
        assert_eq!(
            reg.packet(seq.into()).received,
            expect_received,
            "seq {} expected to{} be received in {:?}",
            seq,
            if expect_received { "" } else { " NOT" },
            nack
        );
        assert_eq!(nack, expect_nack.start.into()..expect_nack.end.into());
        assert_not_dirty(reg);
    }

    fn assert_not_dirty(reg: &ReceiverRegister2) {
        // we should leave no dirty state outside of the nack window
        let nack = reg.nack.clone().expect("nack range");
        let nack = (*nack.start..=*nack.end)
            .map(|seq| reg.as_index(seq.into()))
            .collect::<Vec<_>>();

        for i in 0..reg.packets.len() {
            if nack.contains(&i) {
                continue;
            }
            assert_eq!(
                reg.packets[i].received || reg.packets[i].nack_count != 0,
                false,
                "dirty state at index {} outside of nack window {:?}",
                i,
                nack,
            );
        }
    }

    #[test]
    fn nack_window_sliding() {
        let mut reg = ReceiverRegister2::new();

        assert_update(&mut reg, 10, true, true, 10..10);

        // packet before window start is ignored
        assert_update(&mut reg, 9, false, false, 10..10);

        // duped packet
        assert_update(&mut reg, 10, false, true, 10..10);

        // future packets accepted, window not sliding
        let next = 10 + MAX_MISORDER;
        assert_update(&mut reg, next, true, true, 11..next);
        let next = 11 + MAX_MISORDER;
        assert_update(&mut reg, next, true, true, 11..next);

        // future packet accepted, sliding window
        let next = 12 + MAX_MISORDER;
        assert_update(&mut reg, next, true, true, 12..next);
        assert_eq!(reg.packet(11.into()).received, false);

        // older packet received within window
        let next = 13;
        assert_update(&mut reg, next, true, true, 12..(12 + MAX_MISORDER));

        // future packet accepted, sliding window start skips over received
        let next = 13 + MAX_MISORDER;
        assert_update(&mut reg, next, true, true, 14..next);
        assert_eq!(reg.packet(11.into()).received, false);

        // older packet accepted, window star moves ahead
        let next = 14;
        assert_update(&mut reg, next, true, false, 15..(13 + MAX_MISORDER));
    }

    #[test]
    fn nack_report_none() {
        let mut reg = ReceiverRegister2::new();
        assert!(reg.nack_report().is_none());

        reg.update(110.into());
        assert!(reg.nack_report().is_none());

        reg.update(111.into());
        assert!(reg.nack_report().is_none());
    }

    #[test]
    fn nack_report_one() {
        let mut reg = ReceiverRegister2::new();
        assert!(reg.nack_report().is_none());

        reg.update(110.into());
        assert!(reg.nack_report().is_none());

        reg.update(112.into());
        let report = reg.nack_report().expect("some report");
        assert!(report.len() == 1);
        assert_eq!(report[0].reports.len(), 1);
        assert_eq!(report[0].reports[0].pid, 111);
        assert_eq!(report[0].reports[0].blp, 0);
    }

    #[test]
    fn nack_report_two() {
        let mut reg = ReceiverRegister2::new();
        assert!(reg.nack_report().is_none());

        reg.update(110.into());
        assert!(reg.nack_report().is_none());

        reg.update(113.into());
        let report = reg.nack_report().expect("some report");
        assert!(report.len() == 1);
        assert_eq!(report[0].reports.len(), 1);
        assert_eq!(report[0].reports[0].pid, 111);
        assert_eq!(report[0].reports[0].blp, 0b1);
    }

    #[test]
    fn nack_report_with_hole() {
        let mut reg = ReceiverRegister2::new();

        for i in &[100, 101, 103, 105, 106, 107, 108, 109, 110] {
            reg.update((*i).into());
        }

        let report = reg.nack_report().expect("some report");
        assert!(report.len() == 1);
        assert_eq!(report[0].reports.len(), 1);
        assert_eq!(report[0].reports[0].pid, 102);
        assert_eq!(report[0].reports[0].blp, 0b10);
    }

    #[test]
    fn nack_report_stop_at_17() {
        let mut reg = ReceiverRegister2::new();

        let seq = &[
            100, 101, 103, 104, 105, 106, 107, 108, 109, 110, //
            111, 112, 113, 114, 115, 116, 117, 118, 119, 120, //
            121, 122, 123, 125,
        ];

        for i in seq {
            reg.update((*i).into());
        }

        let report = reg.nack_report().expect("some report");
        assert_eq!(report.len(), 1);
        assert_eq!(report[0].reports.len(), 2);
        assert_eq!(report[0].reports[0].pid, 102);
        assert_eq!(report[0].reports[0].blp, 0);
    }

    #[test]
    fn nack_report_hole_at_17() {
        let mut reg = ReceiverRegister2::new();

        let seq = &[
            100, 101, 103, 104, 105, 106, 107, 108, 109, 110, //
            111, 112, 113, 114, 115, 116, 117, 119, 120, 121, //
            122, 123, 124, 125, 126, 127, 128, 129,
        ];

        for i in seq {
            reg.update((*i).into());
        }

        let report = reg.nack_report().expect("some report");
        assert_eq!(report.len(), 1);
        assert_eq!(report[0].reports.len(), 1);
        assert_eq!(report[0].reports[0].pid, 102);
        assert_eq!(report[0].reports[0].blp, 0b1000_0000_0000_0000);
    }

    #[test]
    fn nack_report_no_stop_all_there() {
        let mut reg = ReceiverRegister2::new();

        let seq = &[
            100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, //
            111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, //
            122, 123, 124, 125, 126, 127, 128, 129,
        ];

        for i in seq {
            reg.update((*i).into());
        }

        assert_eq!(reg.nack_report(), None);
    }

    #[test]
    fn nack_report_rtx() {
        let mut reg = ReceiverRegister2::new();
        for i in &[
            100, 101, 102, 103, 104, 105, //
        ] {
            reg.update((*i).into());
        }
        assert!(reg.nack_report().is_none());
        let nack = reg.nack.clone().expect("nack range");
        assert_eq!(*nack.start, 105);

        for i in &[
            106, 108, 109, 110, 111, 112, 113, 114, 115, //
        ] {
            reg.update((*i).into());
        }
        assert!(reg.nack_report().is_some());
        let nack = reg.nack.clone().expect("nack range");
        assert_eq!(*nack.start, 107);

        reg.update(107.into()); // Got 107 via RTX

        let nacks = reg.nack_report();
        assert_eq!(
            reg.nack_report(),
            None,
            "Expected no NACKs to be generated after repairing the stream, got {nacks:?}"
        );
        let nack = reg.nack.clone().expect("nack range");
        assert_eq!(*nack.start, 115);
    }

    #[test]
    fn nack_report_rollover_rtx() {
        // This test is checking that after rollover nacks are not skipped because of
        // packet position that would remain marked as received from before the rollover
        let mut reg = ReceiverRegister2::new();
        for i in &[
            100, 101, 102, 103, 104, 105, 106, 108, 109, 110, 111, 112, 113, 114, 115,
        ] {
            reg.update((*i).into());
        }

        reg.update(107.into()); // Got 107 via RTX
        let nack = reg.nack.clone().expect("nack range");
        assert_eq!(*nack.start, 115);

        for i in 116..3106 {
            reg.update(i.into());
        }
        let nack = reg.nack.clone().expect("nack range");
        assert_eq!(*nack.start, 3105);

        for i in &[3106, 3108, 3109, 3110, 3111, 3112, 3113, 3114, 3115] {
            reg.update((*i).into()); // Missing at postion 107 again
        }

        let nack = reg.nack.clone().expect("nack range");
        assert_eq!(*nack.start, 3107);
    }

    #[test]
    fn nack_report_rollover_rtx_with_seq_jump() {
        let mut reg = ReceiverRegister2::new();

        // 2999 is missing
        for i in 0..2999 {
            reg.update(i.into());
        }

        // 3002 is missing
        reg.update(3003.into());
        reg.update(3004.into());
        reg.update(3000.into());
        reg.update(3001.into());

        let reports = reg.nack_report().expect("some report");
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].reports[0].pid, 2999);
        assert_eq!(reports[0].reports[0].blp, 4);
    }

    #[test]
    fn out_of_order_and_rollover() {
        let mut reg = ReceiverRegister2::new();

        reg.update(2998.into());
        reg.update(2999.into());

        // receive older packet
        reg.update(2995.into());

        // wrap
        for i in 3000..5995 {
            reg.update(i.into());
        }

        // 5995 is missing

        reg.update(5996.into());
        reg.update(5997.into());

        let reports = reg.nack_report().expect("some report");
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].reports[0].pid, 5995);
    }

    #[test]
    fn nack_check_on_seq_rollover() {
        let range = 65530..65541;
        let missing = [65535_u64, 65536_u64, 65537_u64];
        let expected = [65535_u16, 0_u16, 1_u16];

        for (missing, expected) in missing.iter().zip(expected.iter()) {
            let mut seqs: Vec<_> = range.clone().collect();
            let mut reg = ReceiverRegister2::new();

            seqs.retain(|x| *x != *missing);
            for i in seqs.as_slice() {
                reg.update((*i).into());
            }

            let reports = reg.nack_report().expect("some report");
            let pid = reports[0].reports[0].pid;
            assert_eq!(pid, *expected);
        }
    }

    #[test]
    fn nack_check_forward_at_boundary() {
        let mut reg = ReceiverRegister2::new();
        for i in 2996..=3003 {
            reg.update(i.into());
        }

        assert!(reg.nack_report().is_none());
        let nack = reg.nack.clone().expect("nack range");
        assert_eq!(*nack.start, 3003);

        for i in 3004..=3008 {
            reg.update(i.into());
        }

        let report = reg.nack_report();
        assert!(report.is_none(), "Expected empty NACKs got {:?}", report);
        let nack = reg.nack.clone().expect("nack range");
        assert_eq!(*nack.start, 3008);
    }

    #[test]
    fn nack_check_forward_at_u16_boundary() {
        let mut reg = ReceiverRegister2::new();
        for i in 65500..=65534 {
            reg.update(i.into());
        }
        assert!(reg.nack_report().is_none());
        let nack = reg.nack.clone().expect("nack range");
        assert_eq!(*nack.start, 65534);

        for i in 65536..=65566 {
            reg.update(i.into());
        }

        assert!(!reg.nack_report().is_none());
        let nack = reg.nack.clone().expect("nack range");
        assert_eq!(*nack.start, 65535);

        for i in 65567..=65666 {
            reg.update(i.into());
        }

        reg.update(65535.into());

        assert!(reg.nack_report().is_none());
        let nack = reg.nack.clone().expect("nack range");
        assert_eq!(*nack.start, 65666);
    }
}

const MIN_SEQUENTIAL: u64 = 2;

#[derive(Debug)]
pub struct ReceiverRegister {
    /// Keep track of packet status.
    packet_status: Vec<PacketStatus>,

    /// First ever sequence number observed.
    base_seq: SeqNo,

    /// Max ever observed sequence number.
    max_seq: SeqNo,

    /// last 'bad' seq number + 1.
    ///
    /// This is set when we observe a large jump in sequence numbers (MAX_DROPOUT) that we
    /// assume could indicate a restart of the sender sequence numbers.
    bad_seq: Option<SeqNo>,

    /// Sequential packets remaining until source is valid.
    ///
    /// This is not really useful in the presence of SRTP, since that cryptographically checks
    /// the packets are from the origin, and not misaddressed.
    ///
    /// The value stay here, because that's the original algorithm in the RFC, but it has very
    /// limited use.
    probation: u64,

    /// Counter of received packets.
    received: i64,

    /// Expected at last reception report generation.
    expected_prior: i64,

    /// Received at last reception report generation.
    received_prior: i64,

    /// Estimated jitter. This is in the media time base, so divided by
    /// 90_000 or 48_000 to normalize.
    jitter: f32,

    /// Check nacks from this point.
    ///
    /// We've reported nack to here already.
    nack_check_from: SeqNo,

    /// Previously received time point.
    time_point_prior: Option<TimePoint>,
}

impl ReceiverRegister {
    pub fn new(base_seq: SeqNo) -> Self {
        ReceiverRegister {
            packet_status: vec![PacketStatus::default(); MAX_DROPOUT as usize],
            base_seq,
            // ensure first update_seq considers the first packet sequential
            max_seq: base_seq.wrapping_sub(1).into(),
            bad_seq: None,
            probation: MIN_SEQUENTIAL,
            received: 1,
            expected_prior: 0,
            received_prior: 0,
            jitter: 0.0,
            nack_check_from: base_seq,
            time_point_prior: None,
        }
    }

    fn init_seq(&mut self, seq: SeqNo) {
        self.base_seq = seq;
        self.max_seq = seq;
        self.bad_seq = None;
        self.received = 0;
        self.received_prior = 0;
        self.expected_prior = 0;
        self.jitter = 0.0;
        self.packet_status.fill(PacketStatus::default());
        self.record_received(seq);
        self.nack_check_from = seq;
        self.time_point_prior = None;
    }

    /// Set a bit indicating we've received a packet.
    ///
    /// Returns true if the packet received wasn't received before.
    fn record_received(&mut self, seq: SeqNo) -> bool {
        if seq < self.nack_check_from {
            return false;
        }

        let pos = self.packet_index(*seq);
        let was_set = self.packet_status[pos].received;
        self.packet_status[pos].received = true;

        if self.packet_status[pos].nack_count > 0 {
            debug!(
                "Received packet {} after {} NACKs",
                seq, self.packet_status[pos].nack_count
            );
        }

        // Move nack_check_from forward
        let check_up_to = (*self.max_seq).saturating_sub(MISORDER_DELAY);
        let new_nack_check_from: Option<SeqNo> = {
            // Check if we can move forward because we have a consecutive run of packets
            let consecutive_unil = (*self.nack_check_from..=check_up_to)
                .take_while(|seq| self.packet_status[self.packet_index(*seq)].received)
                .last()
                .map(Into::into);

            match consecutive_unil {
                Some(new) if new != self.nack_check_from => {
                    trace!(
                        "Moving nack_check_from forward from {} to {} on consecutive packet run",
                        self.nack_check_from,
                        new
                    );

                    Some(new)
                }
                _ => {
                    // No consecutive run, make sure we don't let nack_check_from fall too far
                    if check_up_to.saturating_sub(*self.nack_check_from) > MAX_MISORDER {
                        // If nack_check_from is falling too far behind bring it forward by discarding
                        // older packets.
                        let forced_nack_check_from = check_up_to - MAX_MISORDER;
                        trace!(
                        "Forcing nack_check_from forward from {} to {} on non-consecutive packet run",
                        self.nack_check_from,forced_nack_check_from
                    );

                        Some(forced_nack_check_from.into())
                    } else {
                        None
                    }
                }
            }
        };

        if let Some(new_nack_check_from) = new_nack_check_from {
            self.reset_receceived(self.nack_check_from, new_nack_check_from);
            self.nack_check_from = new_nack_check_from;
        }

        // if a bit flips from false -> true, we have received a new packet. dupe packets are
        // not counted (i.e. true -> true) that can happen due to resends.
        if !was_set {
            self.received += 1;
        }

        !was_set
    }

    fn reset_receceived(&mut self, start: SeqNo, end: SeqNo) {
        for seq in *start..*end {
            let index = self.packet_index(seq);

            let status = self.packet_status[index];

            if status.nack_count > 0 && !status.received {
                debug!("Seq no was nacked but not resent {}", seq);
            }

            // Reset state
            self.packet_status[index] = PacketStatus::default();
        }
    }

    /// Update a received sequence number.
    ///
    /// Returns true if we have not seen this sequence number before.
    pub fn update_seq(&mut self, seq: SeqNo) -> bool {
        if self.probation > 0 {
            // Source is not valid until MIN_SEQUENTIAL packets with
            // sequential sequence numbers have been received.
            if *seq == self.max_seq.wrapping_add(1) {
                self.probation -= 1;
                self.max_seq = seq;
                if self.probation == 0 {
                    self.init_seq(seq);
                }
            } else {
                self.probation = MIN_SEQUENTIAL - 1;
                self.max_seq = seq;
            }

            // During probation, consider all packets as "recorded".
            true
        } else if *self.max_seq < *seq {
            // Incoming seq is larger than we've seen before. This
            // is the normal case, where we receive packets sequentially.
            let udelta = *seq - *self.max_seq;

            if udelta < MAX_DROPOUT {
                // in order, with permissible gap
                self.max_seq = seq;
                self.bad_seq = None;
                self.record_received(seq)
            } else {
                // the sequence number made a very large jump
                self.maybe_seq_jump(seq);

                // Optimistically assume the remote side seq jumped.
                true
            }
        } else {
            // duplicate or out of order packet
            let udelta = *self.max_seq - *seq;

            if udelta < MAX_MISORDER {
                self.record_received(seq)
            } else {
                // the sequence number is too far in the past
                self.maybe_seq_jump(seq);

                // Optimistically assume the remote side seq jumped.
                true
            }
        }
    }

    fn maybe_seq_jump(&mut self, seq: SeqNo) {
        if self.bad_seq == Some(seq) {
            // Two sequential packets -- assume that the other side
            // restarted without telling us so just re-sync
            // (i.e., pretend this was the first packet).
            self.init_seq(seq);
        } else {
            self.bad_seq = Some((*seq + 1).into());
        }
    }

    pub fn max_seq(&self) -> SeqNo {
        self.max_seq
    }

    pub fn update_time(&mut self, arrival: Instant, rtp_time: u32, clock_rate: u32) {
        let tp = TimePoint {
            arrival,
            rtp_time,
            clock_rate,
        };

        if let Some(prior) = self.time_point_prior {
            if tp.is_same(prior) {
                // rtp_time didn't move forward. this is quite normal
                // when multiple rtp packets are needed for one keyframe.

                // https://www.cs.columbia.edu/~hgs/rtp/faq.html#jitter
                //
                // If several packets, say, within a video frame, bear the
                // same timestamp, it is advisable to only use the first
                // packet in a frame to compute the jitter. (This issue may
                // be addressed in a future version of the specification.)
                // Jitter is computed in timestamp units. For example, for
                // an audio stream sampled at 8,000 Hz, the arrival time
                // measured with the local clock is converted by multiplying
                // the seconds by 8,000.
                //
                // Steve Casner wrote:
                //
                // For encodings such as MPEG that transmit data in a
                // different order than it was sampled, this adds noise
                // into the jitter calculation. I have heard handwavy
                // arguments that this factor can be calculated out given
                // that you know the shape of the noise, but my math
                // isn't strong enough for that.
                //
                // In many of the cases that we care about, the jitter
                // introduced by MPEG will be small enough that when the
                // network jitter is of the same order we don't have a
                // problem anyway.
                //
                // There is another problem for video in that all of the
                // packets of a frame have the same timestamp because the
                // whole frame is sampled at once. However, the
                // dispersion in time of those packets really is all part
                // of the network transfer process that the receiver must
                // accommodate with its buffer.
                //
                // It has been suggested that jitter be calculated only
                // on the first packet of a video frame, or only on "I"
                // frames for MPEG. However, that may color the results
                // also because those packets may see transit delays
                // different than the following packets see.
                //
                // The main point to remember is that the primary
                // function of the RTP timestamp is to represent the
                // inherent notion of real time associated with the
                // media. It also turns out to be useful for the jitter
                // measure, but that is a secondary function.
                //
                // The jitter value is not expected to be useful as an
                // absolute value. It is more useful as a means of
                // comparing the reception quality at two receiver or
                // comparing the reception quality 5 minutes ago to now.

                return;
            }

            // update jitter.
            let d = tp.delta(prior);

            self.jitter += (1.0 / 16.0) * (d - self.jitter);
        }

        self.time_point_prior = Some(tp);
    }

    pub fn has_nack_report(&mut self) -> bool {
        // No nack report during probation.
        if self.probation > 0 {
            return false;
        }

        // nack_check_from tracks where we create the next nack report from.
        let start = *self.nack_check_from;
        // MISORDER_DELAY gives us a "grace period" of receiving packets out of
        // order without reporting it as a NACK straight away.
        let stop = (*self.max_seq).saturating_sub(MISORDER_DELAY);

        if stop < start {
            return false;
        }

        (start..stop).any(|seq| self.packet_status[self.packet_index(seq)].should_nack())
    }

    pub fn nack_reports(&mut self) -> Vec<Nack> {
        self.create_nack_reports()
    }

    fn create_nack_reports(&mut self) -> Vec<Nack> {
        // No nack report during probation.
        if self.probation > 0 {
            return vec![];
        }

        // nack_check_from tracks where we create the next nack report from.
        let start = *self.nack_check_from;
        // MISORDER_DELAY gives us a "grace period" of receiving packets out of
        // order without reporting it as a NACK straight away.
        let stop = (*self.max_seq).saturating_sub(MISORDER_DELAY);
        let u16max = u16::MAX as u64 + 1_u64;

        if stop < start {
            return vec![];
        }

        let mut nacks = vec![];
        let mut first_missing = None;
        let mut bitmask = 0;

        for i in start..stop {
            let j = self.packet_index(i);

            let should_nack = self.packet_status[j].should_nack();

            if let Some(first) = first_missing {
                if should_nack {
                    let o = (i - (first + 1)) as u16;
                    bitmask |= 1 << o;
                    self.packet_status[j].nack_count += 1;
                }

                if i - first == 16 {
                    nacks.push(NackEntry {
                        pid: (first % u16max) as u16,
                        blp: bitmask,
                    });
                    bitmask = 0;
                    first_missing = None;
                }
            } else if should_nack {
                self.packet_status[j].nack_count += 1;
                first_missing = Some(i);
            }
        }

        if let Some(first) = first_missing {
            nacks.push(NackEntry {
                pid: (first % u16max) as u16,
                blp: bitmask,
            });
        }

        let reports = ReportList::lists_from_iter(nacks).into_iter();

        reports
            .map(|reports| {
                Nack {
                    sender_ssrc: 0.into(),
                    ssrc: 0.into(), // changed when sending
                    reports,
                }
            })
            .collect()
    }

    /// Create a new reception report.
    ///
    /// This modifies the state since fraction_lost is calculated
    /// since the last call to this function.
    pub fn reception_report(&mut self) -> ReceptionReport {
        ReceptionReport {
            ssrc: 0.into(),
            fraction_lost: self.fraction_lost(),
            packets_lost: self.packets_lost(),
            max_seq: (*self.max_seq % ((u32::MAX as u64) + 1_u64)) as u32,
            jitter: self.jitter as u32,
            last_sr_time: 0,
            last_sr_delay: 0,
        }
    }

    // Calculations from here
    // https://www.rfc-editor.org/rfc/rfc3550#appendix-A.3

    /// Fraction lost since last call.
    fn fraction_lost(&mut self) -> u8 {
        let expected = self.expected();
        let expected_interval = expected - self.expected_prior;
        self.expected_prior = expected;

        let received = self.received;
        let received_interval = received - self.received_prior;
        self.received_prior = received;

        let lost_interval = expected_interval - received_interval;

        let lost = if expected_interval == 0 || lost_interval == 0 {
            0
        } else {
            (lost_interval << 8) / expected_interval
        } as u8;

        trace!("Reception fraction lost: {}", lost);

        lost
    }

    /// Absolute number of lost packets.
    fn packets_lost(&self) -> u32 {
        // Since this signed number is carried in 24 bits, it should be clamped
        // at 0x7fffff for positive loss or 0x800000 for negative loss rather
        // than wrapping around.
        let lost_t = self.expected() - self.received;
        if lost_t > 0x7fffff {
            0x7fffff_u32
        } else if lost_t < -0x7fffff {
            0x8000000_u32
        } else {
            lost_t as u32
        }
    }

    fn expected(&self) -> i64 {
        *self.max_seq as i64 - *self.base_seq as i64 + 1
    }

    fn packet_index(&self, seq: u64) -> usize {
        (seq % self.packet_status.len() as u64) as usize
    }

    pub(crate) fn clear(&mut self) {
        self.packet_status.clear();
        self.nack_check_from = self.max_seq;
    }
}

/// Helper to keep a time point for jitter calculation.
#[derive(Debug, Clone, Copy)]
struct TimePoint {
    arrival: Instant,
    rtp_time: u32,
    clock_rate: u32,
}

impl TimePoint {
    fn is_same(&self, other: TimePoint) -> bool {
        self.rtp_time == other.rtp_time
    }

    fn delta(&self, other: TimePoint) -> f32 {
        // See
        // https://www.rfc-editor.org/rfc/rfc3550#appendix-A.8
        //
        // rdur is often i 90kHz (for video) or 48kHz (for audio). we need
        // a time unit of Duration, that is likely to give us an increase between
        // 1 in rdur. milliseconds is thus "too coarse"
        let rdur =
            ((self.rtp_time as f32 - other.rtp_time as f32) * 1_000_000.0) / self.clock_rate as f32;

        let tdur = (self.arrival - other.arrival).as_micros() as f32;

        let d = (tdur - rdur).abs();

        trace!("Timepoint delta: {}", d);

        d
    }
}

#[derive(Debug, Default, Clone, Copy)]
struct PacketStatus {
    received: bool,
    nack_count: u8,
}

impl PacketStatus {
    fn should_nack(&self) -> bool {
        !self.received && self.nack_count < MAX_NACKS
    }

    fn mark_received(&mut self) -> bool {
        let new = !self.received;
        self.received = true;
        new
    }

    fn reset(&mut self) {
        self.received = false;
        self.nack_count = 0;
    }
}

#[cfg(test)]
mod test {
    use std::time::Duration;

    use super::*;


    #[test]
    fn jitter_at_0() {
        let mut reg = ReceiverRegister::new(14.into());
        // reg.update_seq(14.into());
        // reg.update_seq(15.into());

        // 100 fps in clock rate 90kHz => 90_000/100 = 900 per frame
        // 1/100 * 1_000_000 = 10_000 microseconds per frame.

        let start = Instant::now();
        let dur = Duration::from_micros(10_000);

        reg.update_time(start + 4 * dur, 1234 + 4 * 900, 90_000);
        reg.update_time(start + 5 * dur, 1234 + 5 * 900, 90_000);
        reg.update_time(start + 6 * dur, 1234 + 6 * 900, 90_000);
        reg.update_time(start + 7 * dur, 1234 + 7 * 900, 90_000);
        assert_eq!(reg.jitter, 0.0);

        //
    }

    // TODO
    #[test]
    fn jitter_at_20() {
        let mut reg = ReceiverRegister::new(14.into());
        reg.update_seq(14.into());
        reg.update_seq(15.into());

        // 100 fps in clock rate 90kHz => 90_000/100 = 900 per frame
        // 1/100 * 1_000_000 = 10_000 microseconds per frame.

        let start = Instant::now();
        let dur = Duration::from_micros(10_000);
        let off = Duration::from_micros(10);

        for i in 4..1000 {
            let arrival = if i % 2 == 0 {
                start + (i * dur).checked_sub(off).unwrap()
            } else {
                start + i * dur + off
            };
            reg.update_time(arrival, 1234 + i * 900, 90_000);
        }


    // TODO
    #[test]
    fn expected_received_no_loss() {
        let mut reg = ReceiverRegister::new(14.into());
        reg.update_seq(14.into());
        reg.update_seq(15.into());
        reg.update_seq(16.into());
        reg.update_seq(17.into());
        // MIN_SEQUENTIAL=2, 14, 15 resets base_seq.
        assert_eq!(reg.base_seq, 15.into());
        assert_eq!(reg.max_seq, 17.into());
        assert_eq!(reg.expected(), 3);
        assert_eq!(reg.received, 3);
        assert_eq!(reg.packets_lost(), 0);
    }

    // TODO
    #[test]
    fn expected_received_with_loss() {
        let mut reg = ReceiverRegister::new(14.into());
        reg.update_seq(14.into());
        reg.update_seq(15.into());
        reg.update_seq(17.into());
        // MIN_SEQUENTIAL=2, 14, 15 resets base_seq.
        assert_eq!(reg.base_seq, 15.into());
        assert_eq!(reg.max_seq, 17.into());
        assert_eq!(reg.expected(), 3);
        assert_eq!(reg.received, 2);
        assert_eq!(reg.packets_lost(), 1);
    }

    #[test]
    fn low_seq_no_dont_panic() {
        let mut reg = ReceiverRegister::new(1.into());
        reg.update_seq(2.into());
        reg.update_seq(3.into());
        // Don't panic.
        let _ = reg.has_nack_report();
        let _ = reg.create_nack_reports();
    }
}
