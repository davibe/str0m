use std::ops::Deref;

use crate::io::Id;
use crate::rtp::{ChannelId, Direction, Extensions, Mid, Ssrc};
use crate::sctp::{DcepOpen, ReliabilityType};
use crate::sdp::{MediaLine, Msid, Offer};

use crate::media::{CodecConfig, MLine, MediaKind, PayloadParams};
use crate::session::MLineOrApp;
use crate::Rtc;

pub(crate) struct Changes(pub Vec<Change>);

#[derive(Debug)]
pub(crate) enum Change {
    AddMedia(AddMedia),
    AddApp(Mid),
    AddChannel(ChannelId, DcepOpen),
    Direction(Mid, Direction),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddMedia {
    pub mid: Mid,
    pub cname: String,
    pub msid: Msid,
    pub kind: MediaKind,
    pub dir: Direction,
    pub ssrcs: Vec<(Ssrc, Option<Ssrc>)>,

    // These are filled in when creating a Media from AddMedia
    pub params: Vec<PayloadParams>,
    pub index: usize,
}

/// Changes to apply to the m-lines of the WebRTC session.
///
/// Get this by calling [`Rtc::create_change_set`][crate::Rtc::create_change_set()].
///
/// No changes are made without calling [`ChangeSet::apply()`], followed by sending
/// the offer to the remote peer, receiving an answer and completing the changes using
/// [`Rtc::pending_changes()`][crate::Rtc::pending_changes()].
pub struct ChangeSet<'a> {
    rtc: &'a mut Rtc,
    changes: Changes,
}

impl<'a> ChangeSet<'a> {
    pub(crate) fn new(rtc: &'a mut Rtc) -> Self {
        ChangeSet {
            rtc,
            changes: Changes(vec![]),
        }
    }

    /// Test if this change set has any changes.
    ///
    /// ```
    /// # use str0m::{Rtc, media::MediaKind, media::Direction};
    /// let mut rtc = Rtc::new();
    ///
    /// let mut changes = rtc.create_change_set();
    /// assert!(!changes.has_changes());
    ///
    /// let mid = changes.add_media(MediaKind::Audio, Direction::SendRecv, None);
    /// assert!(changes.has_changes());
    /// ```
    pub fn has_changes(&self) -> bool {
        !self.changes.is_empty()
    }

    /// Add audio or video media and get the `mid` that will be used.
    ///
    /// Each call will result in a new m-line in the offer identifed by the [`Mid`].
    ///
    /// The mid is not valid to use until the SDP offer-answer dance is complete and
    /// the mid been advertised via [`Event::MediaAdded`][crate::Event::MediaAdded].
    ///
    /// ```
    /// # use str0m::{Rtc, media::MediaKind, media::Direction};
    /// let mut rtc = Rtc::new();
    ///
    /// let mut changes = rtc.create_change_set();
    ///
    /// let mid = changes.add_media(MediaKind::Audio, Direction::SendRecv, None);
    /// ```
    pub fn add_media(&mut self, kind: MediaKind, dir: Direction, cname: Option<String>) -> Mid {
        let mid = self.rtc.new_mid();

        let cname = if let Some(cname) = cname {
            fn is_token_char(c: &char) -> bool {
                // token-char = %x21 / %x23-27 / %x2A-2B / %x2D-2E / %x30-39
                // / %x41-5A / %x5E-7E
                let u = *c as u32;
                u == 0x21
                    || (0x23..=0x27).contains(&u)
                    || (0x2a..=0x2b).contains(&u)
                    || (0x2d..=0x2e).contains(&u)
                    || (0x30..=0x39).contains(&u)
                    || (0x41..=0x5a).contains(&u)
                    || (0x5e..0x7e).contains(&u)
            }
            // https://www.rfc-editor.org/rfc/rfc8830
            // msid-id = 1*64token-char
            cname.chars().filter(is_token_char).take(64).collect()
        } else {
            Id::<20>::random().to_string()
        };

        let ssrcs = {
            // For video we do RTX channels.
            let has_rtx = kind == MediaKind::Video;

            let ssrc_base = if has_rtx { 2 } else { 1 };

            // TODO: allow configuring simulcast
            let simulcast_count = 1;

            let ssrc_count = ssrc_base * simulcast_count;
            let mut v = Vec::with_capacity(ssrc_count);

            let mut prev = 0.into();
            for i in 0..ssrc_count {
                // Allocate SSRC that are not in use in the session already.
                let new_ssrc = self.rtc.new_ssrc();
                let is_rtx = has_rtx && i % 2 == 1;
                let repairs = if is_rtx { Some(prev) } else { None };
                v.push((new_ssrc, repairs));
                prev = new_ssrc;
            }

            v
        };

        // TODO: let user configure stream/track name.
        let msid = Msid {
            stream_id: cname.clone(),
            track_id: Id::<30>::random().to_string(),
        };

        let add = AddMedia {
            mid,
            cname,
            msid,
            kind,
            dir,
            ssrcs,

            // Added later
            params: vec![],
            index: 0,
        };

        self.changes.0.push(Change::AddMedia(add));
        mid
    }

    /// Change the direction of an already existing m-line.
    ///
    /// All media m-line have a direction. The media can be added by this side via
    /// [`ChangeSet::add_media()`] or by the remote peer. Either way, the direction
    /// of the line can be changed at any time.
    ///
    /// It's possible to set the direction [`Direction::Inactive`] for media that
    /// will not be used by the session anymore.
    ///
    /// If the direction is set for media that doesn't exist, or if the direction is
    /// the same that's already set [`ChangeSet::apply()`] not require a negotiation.
    pub fn set_direction(&mut self, mid: Mid, dir: Direction) {
        let Some(media) = self.rtc.session.m_line_by_mid_mut(mid) else {
            return;
        };

        if media.direction() == dir {
            return;
        }

        self.changes.0.push(Change::Direction(mid, dir));
    }

    /// Add a new data channel and get the `id` that will be used.
    ///
    /// The first ever data channel added to a WebRTC session results in an m-line of a
    /// special "application" type in the SDP. The m-line is for a SCTP association over
    /// DTLS, and all data channels are multiplexed over this single association.
    ///
    /// That means only the first ever `add_channel` will result in an [`Offer`].
    /// Consecutive channels will be opened without needing a negotiation.
    ///
    /// The label is used to identify the data channel to the remote peer. This is mostly
    /// useful whe multiple channels are in use at the same time.
    ///
    /// ```
    /// # use str0m::Rtc;
    /// let mut rtc = Rtc::new();
    ///
    /// let mut changes = rtc.create_change_set();
    ///
    /// let cid = changes.add_channel("my special channel".to_string());
    /// ```
    pub fn add_channel(&mut self, label: String) -> ChannelId {
        let has_m_line = self.rtc.session.app().is_some();

        if !has_m_line {
            let mid = self.rtc.new_mid();
            self.changes.0.push(Change::AddApp(mid));
        }

        let id = self.rtc.new_sctp_channel();

        let dcep = DcepOpen {
            unordered: false,
            channel_type: ReliabilityType::Reliable,
            reliability_parameter: 0,
            label,
            priority: 0,
            protocol: String::new(),
        };

        self.changes.0.push(Change::AddChannel(id, dcep));

        id
    }

    /// Attempt to apply the changes made in the change set. If this returns [`Offer`], the caller
    /// the changes are not happening straight away, and the caller is expected to do a negotiation
    /// with the remote peer and apply the answer using
    /// [`Rtc::pending_changes()`][crate::Rtc::pending_changes()].
    ///
    /// In case this returns `None`, there either were no changes, or the changes could be applied
    /// without doing a negotiation. Specifically for additional [`ChangeSet::add_channel()`]
    /// after the first, there is no negotiation needed.
    ///
    /// ```
    /// # use str0m::Rtc;
    /// let mut rtc = Rtc::new();
    ///
    /// let changes = rtc.create_change_set();
    /// assert_eq!(changes.apply(), None);
    /// ```
    pub fn apply(self) -> Option<Offer> {
        let requires_negotiation = self.changes.iter().any(|c| c.requires_negotiation());

        if requires_negotiation {
            Some(self.rtc.set_pending(self.changes))
        } else {
            self.rtc.apply_direct_changes(self.changes);
            None
        }
    }
}

impl Changes {
    pub fn take_new_channels(&mut self) -> Vec<(ChannelId, DcepOpen)> {
        let mut v = vec![];

        if self.0.is_empty() {
            return v;
        }

        for i in (0..self.0.len()).rev() {
            if matches!(&self.0[i], Change::AddChannel(_, _)) {
                if let Change::AddChannel(id, dcep) = self.0.remove(i) {
                    v.push((id, dcep));
                }
            }
        }

        v
    }

    /// Tests the given lines (from answer) corresponds to changes.
    pub fn ensure_correct_answer(&self, lines: &[&MediaLine]) -> Option<String> {
        if self.count_new_m_lines() != lines.len() {
            return Some(format!(
                "Differing m-line count in offer vs answer: {} != {}",
                self.count_new_m_lines(),
                lines.len()
            ));
        }

        'next: for l in lines {
            let mid = l.mid();

            for m in &self.0 {
                use Change::*;
                match m {
                    AddMedia(v) if v.mid == mid => {
                        if !l.typ.is_media() {
                            return Some(format!(
                                "Answer m-line for mid ({}) is not of media type: {:?}",
                                mid, l.typ
                            ));
                        }
                        continue 'next;
                    }
                    AddApp(v) if *v == mid => {
                        if !l.typ.is_channel() {
                            return Some(format!(
                                "Answer m-line for mid ({}) is not a data channel: {:?}",
                                mid, l.typ
                            ));
                        }
                        continue 'next;
                    }
                    _ => {}
                }
            }

            return Some(format!("Mid in answer is not in offer: {mid}"));
        }

        None
    }

    fn count_new_m_lines(&self) -> usize {
        self.0
            .iter()
            .filter(|c| matches!(c, Change::AddMedia(_) | Change::AddApp(_)))
            .count()
    }

    pub fn as_new_m_lines<'a, 'b: 'a>(
        &'a self,
        index_start: usize,
        config: &'b CodecConfig,
        exts: &'b Extensions,
    ) -> impl Iterator<Item = MLineOrApp> + '_ {
        self.0
            .iter()
            .enumerate()
            .filter_map(move |(idx, c)| c.as_new_m_line(index_start + idx, config, exts))
    }

    pub(crate) fn apply_to(&self, lines: &mut [MediaLine]) {
        for change in &self.0 {
            if let Change::Direction(mid, dir) = change {
                if let Some(line) = lines.iter_mut().find(|l| l.mid() == *mid) {
                    if let Some(dir_pos) = line.attrs.iter().position(|a| a.is_direction()) {
                        line.attrs[dir_pos] = (*dir).into();
                    }
                }
            }
        }
    }
}

impl Change {
    fn as_new_m_line(
        &self,
        index: usize,
        config: &CodecConfig,
        exts: &Extensions,
    ) -> Option<MLineOrApp> {
        use Change::*;
        match self {
            AddMedia(v) => {
                // TODO can we avoid all this cloning?
                let mut add = v.clone();
                add.params = config.all_for_kind(v.kind).copied().collect();
                add.index = index;

                let m_line = MLine::from_add_media(add, *exts);
                Some(MLineOrApp::MLine(m_line))
            }
            AddApp(mid) => {
                let channel = (*mid, index).into();
                Some(MLineOrApp::App(channel))
            }
            _ => None,
        }
    }

    fn requires_negotiation(&self) -> bool {
        match self {
            Change::AddMedia(_) => true,
            Change::AddApp(_) => true,
            Change::AddChannel(_, _) => false,
            Change::Direction(_, _) => true,
        }
    }
}

impl Deref for Changes {
    type Target = [Change];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
