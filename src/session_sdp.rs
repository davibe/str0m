use crate::change::{Change, Changes};
use crate::dtls::Fingerprint;
use crate::ice::{Candidate, IceCreds};
use crate::media::{App, MediaKind, Source};
use crate::rtp::{Extension, Mid};
use crate::sdp;
use crate::sdp::{Answer, MediaAttribute, MediaLine, MediaType, SimulcastGroups, SimulcastOption};
use crate::sdp::{Offer, Proto, Sdp, SessionAttribute, Setup};
use crate::session::{only_m_line_mut, MLineOrApp};
use crate::RtcError;

use super::{MLine, Session};

pub(crate) struct AsSdpParams<'a> {
    pub candidates: &'a [Candidate],
    pub creds: &'a IceCreds,
    pub fingerprint: &'a Fingerprint,
    pub setup: Setup,
    pub pending: &'a Option<Changes>,
}

impl<'a> AsSdpParams<'a> {
    fn media_attributes(&self, include_candidates: bool) -> Vec<MediaAttribute> {
        use MediaAttribute::*;

        let mut v = if include_candidates {
            self.candidates
                .iter()
                .map(|c| Candidate(c.clone()))
                .collect()
        } else {
            vec![]
        };

        v.push(IceUfrag(self.creds.ufrag.clone()));
        v.push(IcePwd(self.creds.pass.clone()));
        v.push(IceOptions("trickle".into()));
        v.push(Fingerprint(self.fingerprint.clone()));
        v.push(Setup(self.setup));

        v
    }
}

impl Session {
    pub fn as_sdp(&self, params: AsSdpParams) -> Sdp {
        let (media_lines, mids) = {
            let mut v = self.as_media_lines().collect::<Vec<_>>();

            let mut new_lines = vec![];

            // When creating new m-lines from the pending changes, the m-line index starts from this.
            let new_index_start = v.len();

            // If there are additions in the pending changes, prepend them now.
            if let Some(pending) = params.pending {
                let exts = self.exts();
                new_lines = pending
                    .as_new_m_lines(new_index_start, self.codec_config(), exts)
                    .collect();
            }

            // Add potentially new m-lines to the existing ones.
            v.extend(new_lines.iter().map(|n| n as &dyn AsMediaLine));

            // Turn into sdp::MediaLine (m-line).
            let mut lines = v
                .iter()
                .map(|m| {
                    // Candidates should only be in the first BUNDLE mid
                    let include_candidates = m.index() == 0;

                    let attrs = params.media_attributes(include_candidates);

                    m.as_media_line(attrs)
                })
                .collect::<Vec<_>>();

            if let Some(pending) = params.pending {
                pending.apply_to(&mut lines);
            }

            // Mids go into the session part of the SDP.
            let mids = v.iter().map(|m| m.mid()).collect();

            (lines, mids)
        };

        let mut attrs = vec![
            SessionAttribute::Group {
                typ: "BUNDLE".into(),
                mids,
            },
            // a=msid-semantic: WMS
        ];

        if self.ice_lite {
            attrs.push(SessionAttribute::IceLite);
        }

        Sdp {
            session: sdp::Session {
                id: self.id(),
                bw: None,
                attrs,
            },
            media_lines,
        }
    }

    pub fn apply_offer(&mut self, offer: Offer) -> Result<(), RtcError> {
        offer.assert_consistency()?;

        self.update_session(&offer);

        let new_lines = self.sync_m_lines(&offer).map_err(RtcError::RemoteSdp)?;

        self.add_new_lines(&new_lines, true)
            .map_err(RtcError::RemoteSdp)?;

        self.equalize_sources();

        Ok(())
    }

    pub fn apply_answer(&mut self, pending: Changes, answer: Answer) -> Result<(), RtcError> {
        answer.assert_consistency()?;

        self.update_session(&answer);

        let new_lines = self.sync_m_lines(&answer).map_err(RtcError::RemoteSdp)?;

        // The new_lines from the answer must correspond to what we sent in the offer.
        if let Some(err) = pending.ensure_correct_answer(&new_lines) {
            return Err(RtcError::RemoteSdp(err));
        }

        self.add_new_lines(&new_lines, false)
            .map_err(RtcError::RemoteSdp)?;

        // Add all pending changes (since we pre-allocated SSRC communicated in the Offer).
        self.add_pending_changes(pending);

        self.equalize_sources();

        Ok(())
    }

    fn add_pending_changes(&mut self, pending: Changes) {
        // For pending AddMedia, we have outgoing SSRC communicated that needs to be added.
        for change in pending.0 {
            let add_media = match change {
                Change::AddMedia(v) => v,
                _ => continue,
            };

            for (ssrc, repairs) in &add_media.ssrcs {
                if repairs.is_none() {
                    self.set_first_ssrc_local(*ssrc);
                }
            }

            let media = self
                .m_line_by_mid_mut(add_media.mid)
                .expect("Media to be added for pending mid");

            // the cname/msid has already been communicated in the offer, we need to kep
            // it the same once the m-line is created.
            media.set_cname(add_media.cname);
            media.set_msid(add_media.msid);

            for (ssrc, repairs) in add_media.ssrcs {
                let tx = media.get_or_create_source_tx(ssrc);
                if let Some(repairs) = repairs {
                    if tx.set_repairs(repairs) {
                        media.set_equalize_sources();
                    }
                }
            }
        }
    }

    /// Compares m-lines in Sdp with that already in the session.
    ///
    /// * Existing m-lines can apply changes (such as direction change).
    /// * New m-lines are returned to the caller.
    fn sync_m_lines<'a>(&mut self, sdp: &'a Sdp) -> Result<Vec<&'a MediaLine>, String> {
        let mut new_lines = Vec::with_capacity(sdp.media_lines.len());

        let config = self.codec_config().clone();
        let session_exts = *self.exts();

        for (idx, m) in sdp.media_lines.iter().enumerate() {
            // First, match existing m-lines.
            match m.typ {
                MediaType::Application => {
                    if let Some(app) = self.app() {
                        if idx != app.index() {
                            return index_err(m.mid());
                        }

                        app.apply_changes(m);
                        continue;
                    }
                }
                MediaType::Audio | MediaType::Video => {
                    if let Some(media) = self.m_line_by_mid_mut(m.mid()) {
                        if idx != media.index() {
                            return index_err(m.mid());
                        }

                        media.apply_changes(m, &config, &session_exts);
                        continue;
                    }
                }
                _ => {
                    continue;
                }
            }

            // Second, discover new m-lines.
            new_lines.push(m);
        }

        fn index_err<T>(mid: Mid) -> Result<T, String> {
            Err(format!("Changed order for m-line with mid: {mid}"))
        }

        Ok(new_lines)
    }

    /// Adds new m-lines as found in an offer or answer.
    fn add_new_lines(
        &mut self,
        new_lines: &[&MediaLine],
        need_open_event: bool,
    ) -> Result<(), String> {
        for m in new_lines {
            let idx = self.m_lines.len();

            if m.typ.is_media() {
                let mut exts = *self.exts();
                exts.keep_same(&self.exts);

                // Update the PTs to match that of the remote.
                self.codec_config.update_pts(m);

                let media = MLine::from_remote_media_line(m, idx, exts);
                self.m_lines.push(MLineOrApp::MLine(media));

                let media = only_m_line_mut(&mut self.m_lines).last().unwrap();
                media.need_open_event = need_open_event;
                media.apply_changes(m, &self.codec_config, &self.exts)
            } else if m.typ.is_channel() {
                let app = (m.mid(), idx).into();
                self.m_lines.push(MLineOrApp::App(app));

                let chan = self.app().unwrap();
                chan.apply_changes(m);
            } else {
                return Err(format!(
                    "New m-line is neither media nor channel: {}",
                    m.mid()
                ));
            }
        }

        Ok(())
    }

    /// Update session level properties like
    /// Extensions from offer or answer.
    fn update_session(&mut self, sdp: &Sdp) {
        let old = self.exts;

        let extmaps = sdp.media_lines.iter().flat_map(|m| m.extmaps());

        for x in extmaps {
            self.exts.apply_mapping(&x);
        }

        if old != self.exts {
            info!("Updated session extensions: {:?}", self.exts);
        }

        // Does any m-line contain a a=rtcp-fb:xx transport-cc?
        let has_transport_cc = sdp
            .media_lines
            .iter()
            .any(|m| m.rtp_params().iter().any(|p| p.fb_transport_cc));

        // Is the session level sequence number enabled?
        let has_twcc_header = self
            .exts
            .id_of(Extension::TransportSequenceNumber)
            .is_some();

        // Since twcc feedback is session wide and not per m-line or pt, we enable it if
        // there are _any_ m-line with a a=rtcp-fb transport-cc parameter and the sequence
        // number header is enabled.
        if has_transport_cc && has_twcc_header {
            self.enable_twcc_feedback();
        }
    }

    /// Returns all media/channels as `AsMediaLine` trait.
    pub fn as_media_lines(&self) -> impl Iterator<Item = &dyn AsMediaLine> {
        self.m_lines.iter().map(|m| m as &dyn AsMediaLine)
    }
}

pub trait AsMediaLine {
    fn mid(&self) -> Mid;
    fn index(&self) -> usize;
    fn as_media_line(&self, attrs: Vec<MediaAttribute>) -> MediaLine;
}

impl AsMediaLine for App {
    fn mid(&self) -> Mid {
        self.mid()
    }
    fn index(&self) -> usize {
        self.index()
    }
    fn as_media_line(&self, mut attrs: Vec<MediaAttribute>) -> MediaLine {
        attrs.push(MediaAttribute::Mid(self.mid()));
        attrs.push(MediaAttribute::SctpPort(5000));
        attrs.push(MediaAttribute::MaxMessageSize(262144));

        MediaLine {
            typ: sdp::MediaType::Application,
            proto: Proto::Sctp,
            pts: vec![],
            bw: None,
            attrs,
        }
    }
}

impl AsMediaLine for MLine {
    fn mid(&self) -> Mid {
        self.mid()
    }
    fn index(&self) -> usize {
        self.index()
    }
    fn as_media_line(&self, mut attrs: Vec<MediaAttribute>) -> MediaLine {
        attrs.push(MediaAttribute::Mid(self.mid()));

        let audio = self.kind() == MediaKind::Audio;
        for e in self.exts().as_extmap(audio) {
            attrs.push(MediaAttribute::ExtMap(e));
        }

        attrs.push(self.direction().into());
        attrs.push(MediaAttribute::Msid(self.msid().clone()));
        attrs.push(MediaAttribute::RtcpMux);

        for p in self.payload_params() {
            p.inner().as_media_attrs(&mut attrs);
        }

        // The advertised payload types.
        let pts = self
            .payload_params()
            .iter()
            .flat_map(|c| [Some(c.pt()), c.pt_rtx()].into_iter())
            .flatten()
            .collect();

        if let Some(s) = self.simulcast() {
            fn to_rids<'a>(
                gs: &'a SimulcastGroups,
                direction: &'static str,
            ) -> impl Iterator<Item = MediaAttribute> + 'a {
                gs.iter().flat_map(|g| g.iter()).filter_map(move |o| {
                    if let SimulcastOption::Rid(id) = o {
                        Some(MediaAttribute::Rid {
                            id: id.clone(),
                            direction,
                            pt: vec![],
                            restriction: vec![],
                        })
                    } else {
                        None
                    }
                })
            }
            attrs.extend(to_rids(&s.recv, "recv"));
            attrs.extend(to_rids(&s.send, "send"));
            attrs.push(MediaAttribute::Simulcast(s.clone()));
        }

        // Outgoing SSRCs
        let msid = format!("{} {}", self.msid().stream_id, self.msid().track_id);
        for ssrc in self.source_tx_ssrcs() {
            attrs.push(MediaAttribute::Ssrc {
                ssrc,
                attr: "cname".to_string(),
                value: self.cname().to_string(),
            });
            attrs.push(MediaAttribute::Ssrc {
                ssrc,
                attr: "msid".to_string(),
                value: msid.clone(),
            });
        }

        let count = self.source_tx_ssrcs().count();
        #[allow(clippy::comparison_chain)]
        if count == 2 {
            attrs.push(MediaAttribute::SsrcGroup {
                semantics: "FID".to_string(),
                ssrcs: self.source_tx_ssrcs().collect(),
            });
        } else if count > 2 {
            // TODO: handle simulcast
        }

        MediaLine {
            typ: self.kind().into(),
            proto: Proto::Srtp,
            pts,
            bw: None,
            attrs,
        }
    }
}

impl AsMediaLine for MLineOrApp {
    fn mid(&self) -> Mid {
        use MLineOrApp::*;
        match self {
            MLine(v) => v.mid(),
            App(v) => v.mid(),
        }
    }
    fn index(&self) -> usize {
        use MLineOrApp::*;
        match self {
            MLine(v) => v.index(),
            App(v) => v.index(),
        }
    }
    fn as_media_line(&self, attrs: Vec<sdp::MediaAttribute>) -> MediaLine {
        use MLineOrApp::*;
        match self {
            MLine(v) => v.as_media_line(attrs),
            App(v) => v.as_media_line(attrs),
        }
    }
}

impl From<MediaKind> for MediaType {
    fn from(value: MediaKind) -> Self {
        match value {
            MediaKind::Audio => MediaType::Audio,
            MediaKind::Video => MediaType::Video,
        }
    }
}
