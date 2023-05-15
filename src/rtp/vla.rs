/// Video Layer Allocation RTP Header Extension
///  ref. https://webrtc.googlesource.com/src/+/refs/heads/main/docs/native-code/rtp-hdrext/video-layers-allocation00

const MAX_TARGET_BITRATES: usize = 64;
const MAX_RESOLUTIONS: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VideoLayers {
    rtp_stream_index: u8,

    /// the number of rtp streams
    num_rtp_streams: u8,

    /// bitmask of active spatial layers (up to 4), one per rtp stream
    spatial_layer_bitmasks: [u8; 4],

    /// one value per spatial layer (assuming all streams are the same)
    num_temporal_layers: [u8; 4],

    /// Vector of stream, spatial, temporal, bitrate sorted by bitrate ASC
    target_bitrates: [(u8, u8, u8, u64); MAX_TARGET_BITRATES],

    /// Vector of stream, spatial, (width, height, framerate) sorted by
    /// resolution ASC, optional
    resolutions: Option<[(u8, u8, (u16, u16, u8)); MAX_RESOLUTIONS]>,
}

impl VideoLayers {
    #[allow(dead_code)]
    pub fn write_to(&self, buf: &mut [u8]) -> usize {
        let mut p = 0;

        // compose a byte where
        // - the first 2 bits are the RID
        // - the next 2 bits are the number of rtp streams
        // - the next 4 bits are the bitmask of active spatial layers
        //   (up to 4) one per rtp stream
        //   or 0 if the bitmask is different for each stream
        let mut v = 0_u8;
        v |= self.rtp_stream_index << 6;
        v |= ((self.num_rtp_streams - 1) & 0b00000011) << 4;

        let collapse_bitmaps = self.spatial_layer_bitmasks[0] == self.spatial_layer_bitmasks[1]
            && self.spatial_layer_bitmasks[0] == self.spatial_layer_bitmasks[2]
            && self.spatial_layer_bitmasks[0] == self.spatial_layer_bitmasks[3];

        if collapse_bitmaps {
            v |= self.spatial_layer_bitmasks[0] & 0b00001111;
        }

        // write byte to buf and advance position
        buf[0] = v;
        p += 1;

        // write the expanded layer bitmaps for each stream when they are different
        if !collapse_bitmaps {
            let mut bm = 0_u8;
            bm |= (self.spatial_layer_bitmasks[0] & 0b00001111) << 4;
            bm |= self.spatial_layer_bitmasks[1] & 0b00001111;
            buf[p] = bm;
            p += 1;
            if (self.num_rtp_streams) > 2 {
                bm = (self.spatial_layer_bitmasks[0] & 0b00001111) << 4;
                bm |= self.spatial_layer_bitmasks[1] & 0b00001111;
                buf[p] = bm;
                p += 1;
            }
        }

        // write the number of temporal layers for each spatial layer
        let mut v = 0_u8;
        for i in 0..4 {
            let j = 3 - i;
            v |= ((self.num_temporal_layers[i] - 1) & 0b00000011) << (j * 2);
        }
        buf[p] = v;
        p += 1;

        // write the target bitrates for each stream, spatial, temporal layer

        let num_spatial_layers = {
            let mut num_spatial_layers: [u8; 4] = [0; 4];
            for i in 0..4 {
                num_spatial_layers[i] = if i < self.num_rtp_streams as usize {
                    count_layers_from_bitmask(self.spatial_layer_bitmasks[i])
                } else {
                    0
                };
            }
            num_spatial_layers
        };

        let mut i = 0;
        for s in 0..self.num_rtp_streams {
            for sl in 0..num_spatial_layers[s as usize] {
                for _tl in 0..self.num_temporal_layers[sl as usize] {
                    let (_stream, _spatial, _temporal, bitrate) = self.target_bitrates[i as usize];
                    i += 1;
                    p += write_leb128_unsigned(&mut buf[p..], bitrate);
                }
            }
        }

        // Write resolutions

        if let Some(resolutions) = &self.resolutions {
            for (stream, spatial, (width, height, framerate)) in resolutions {
                buf[p] = (stream & 0b00000011) << 6;
                buf[p] |= (spatial & 0b00000011) << 4;
                p += 1;
                buf[p..p + 2].copy_from_slice(&(*width - 1).to_be_bytes());
                p += 2;
                buf[p..p + 2].copy_from_slice(&(*height - 1).to_be_bytes());
                p += 2;
                buf[p] = (*framerate - 1).to_be_bytes()[0];
                p += 1;
            }
        }

        p
    }
}

impl From<&[u8]> for VideoLayers {
    fn from(buf: &[u8]) -> Self {
        let mut p = 0;

        let v = u8::from_be_bytes(buf[p..p + 1].try_into().unwrap());
        p += 1;

        // RID: RTP stream index this allocation is sent on, numbered from 0. 2 bits.

        let rid = v >> 6;

        // NS: Number of RTP streams minus one. 2 bits, thus allowing up-to 4 RTP streams.

        let num_rtp_streams = 1 + (v >> 4) & 0b11;

        // sl_bm: BitMask of the active Spatial Layers when same for all RTP
        // streams or 0 otherwise. 4 bits, thus allows up to 4 spatial layers
        // per RTP streams.

        let spatial_layer_bitmasks = {
            let mut bitmasks: [u8; 4] = [0; 4];
            // bitmask of active spatial layers  (up to 4)
            // this is common to all rtp streams,
            let bitmask = v & 0b1111;
            if bitmask != 0 {
                for i in 0..4 {
                    bitmasks[i as usize] = bitmask;
                }
            } else {
                // when it's 0, means we have a different bitmask for each stream
                if num_rtp_streams <= 2 {
                    let v = u8::from_be_bytes(buf[p..p + 1].try_into().unwrap());
                    p += 1;
                    for i in 0..2 {
                        let pos = 1 - i;
                        bitmasks[i as usize] = (v >> (pos * 4)) & 0b1111;
                    }
                } else {
                    let v = u16::from_be_bytes(buf[p..p + 1].try_into().unwrap());
                    p += 2;
                    for i in 0..4 {
                        let pos = 3 - i;
                        bitmasks[i as usize] = (v >> (pos * 4)) as u8 & 0b1111;
                    }
                }
            }
            bitmasks
        };

        let num_spatial_layers = {
            let mut num_spatial_layers: [u8; 4] = [0; 4];
            for i in 0..4 {
                num_spatial_layers[i] = if i < num_rtp_streams as usize {
                    count_layers_from_bitmask(spatial_layer_bitmasks[i])
                } else {
                    0
                };
            }
            num_spatial_layers
        };

        // #tl: 2-bit value of number of temporal layers-1, thus allowing up-to
        // 4 temporal layers. Values are stored in ascending order of spatial
        // id. Zero-padded to byte alignment.

        let v = u8::from_be_bytes(buf[p..p + 1].try_into().unwrap());
        p += 1;
        let mut num_temporal_layers: [u8; 4] = [0; 4];
        // for i in 0..num_spatial_layers.iter().sum() {
        for i in 0..4 {
            let i = i as usize;
            let shift = 6 - (i * 2);
            num_temporal_layers[i] = 1 + (v >> shift & 0b00000011);
        }

        // Target bitrate in kbps. Values are stored using leb128 encoding [1].
        // One value per temporal layer. Values are stored in (RTP stream id,
        // spatial id, temporal id) ascending order. All bitrates are total
        // required bitrate to receive the corresponding layer, i.e. in
        // simulcast mode they include only corresponding spatial layers, in
        // full-svc all lower spatial layers are included. All lower temporal
        // layers are also included.

        let mut target_bitrates: [(u8, u8, u8, u64); MAX_TARGET_BITRATES] =
            [(0, 0, 0, 0); MAX_TARGET_BITRATES];

        let mut i = 0;
        for s in 0..num_rtp_streams {
            for sl in 0..num_spatial_layers[s as usize] {
                for tl in 0..num_temporal_layers[sl as usize] {
                    let (bitrate, size) = read_leb128_unsigned(&buf[p..]);
                    trace!("VLA: stream: {} spatial layer: {} temporal layer: {} -> bitrate: {}, size: {}, p: {}", s, sl, tl, bitrate, size, p);
                    p += size;
                    target_bitrates[i] = (s, sl, tl, bitrate);
                    i += 1;
                }
            }
        }

        // Resolution and framerate. Optional.
        // Presence is inferred from the rtp header extension size.
        // Encoded (width - 1), 16-bit, (height - 1), 16-bit,
        // max frame rate 8-bit per spatial layer per RTP stream. Values are
        // stored in (RTP stream id, spatial id) ascending order.

        let resolutions: Option<[(u8, u8, (u16, u16, u8)); MAX_RESOLUTIONS]> = if buf.len() - p > 0
        {
            let mut v = [(0, 0, (0, 0, 0)); MAX_RESOLUTIONS];
            let mut i = 0;
            for s in 0..num_rtp_streams {
                let num_spatial_layers =
                    count_layers_from_bitmask(spatial_layer_bitmasks[s as usize]);
                for sl in 0..num_spatial_layers {
                    let width = 1 + u16::from_be_bytes(buf[p..p + 2].try_into().unwrap());
                    p += 2;
                    let height = 1 + u16::from_be_bytes(buf[p..p + 2].try_into().unwrap());
                    p += 2;
                    let max_framerate = 1 + u8::from_be_bytes(buf[p..p + 1].try_into().unwrap());
                    p += 1;

                    v[i] = (s, sl, (width, height, max_framerate));
                    i += 1;
                }
            }
            Some(v)
        } else {
            None
        };

        Self {
            rtp_stream_index: rid,
            num_rtp_streams,
            spatial_layer_bitmasks,
            num_temporal_layers,
            target_bitrates,
            resolutions,
        }
    }
}

// read a leb128 encoded unsigned integer from a slice of bytes
// return both the value and the number of bytes read
fn read_leb128_unsigned(buf: &[u8]) -> (u64, usize) {
    let mut p = 0;
    let mut value = 0;
    let mut shift = 0;
    loop {
        let byte = buf[p];
        p += 1;
        value |= ((byte & 0x7f) as u64) << shift;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
    }
    (value, p)
}

// write a leb128 encoded unsigned integer to a slice of bytes
// return the number of bytes written
fn write_leb128_unsigned(buf: &mut [u8], value: u64) -> usize {
    let mut p = 0;
    let mut v = value;
    loop {
        let mut byte = (v & 0x7f) as u8;
        v >>= 7;
        if v != 0 {
            byte |= 0x80;
        }
        buf[p] = byte;
        p += 1;
        if v == 0 {
            break;
        }
    }
    p
}

#[test]
fn test_write_leb128_unsigned() {
    let mut buf = [0; 8];
    let value = 300;

    let bytes_written = write_leb128_unsigned(&mut buf, value);

    assert_eq!(bytes_written, 2);
    assert_eq!(buf[0], 0xAC);
    assert_eq!(buf[1], 0x02);
}

#[test]
fn test_write_leb128_unsigned_zero() {
    let mut buf = [0; 8];
    let value = 0;

    let bytes_written = write_leb128_unsigned(&mut buf, value);

    assert_eq!(bytes_written, 1);
    assert_eq!(buf[0], 0x00);
}

/// given a layer bitmask, count the number of layers
/// i.e. 0b1011 -> 3
fn count_layers_from_bitmask(bitmask: u8) -> u8 {
    let mut count = 0;
    for i in 0..4 {
        if bitmask & (1 << i) != 0 {
            count += 1;
        }
    }
    count
}

#[cfg(test)]
mod vla_tests {
    use super::*;

    #[test]
    fn test_read_leb128_unsigned() {
        let buf = [0b00000000];
        let (value, size) = read_leb128_unsigned(&buf);
        assert_eq!(value, 0);
        assert_eq!(size, 1);

        let buf = [0b00000001];
        let (value, size) = read_leb128_unsigned(&buf);
        assert_eq!(value, 1);
        assert_eq!(size, 1);

        let buf = [0b10000000, 0b00000001];
        let (value, size) = read_leb128_unsigned(&buf);
        assert_eq!(value, 128);
        assert_eq!(size, 2);

        let buf = [0b10000000, 0b10000000, 0b00000001];
        let (value, size) = read_leb128_unsigned(&buf);
        assert_eq!(value, 16384);
        assert_eq!(size, 3);

        let buf = [0b10000000, 0b10000000, 0b10000000, 0b00000001];
        let (value, size) = read_leb128_unsigned(&buf);
        assert_eq!(value, 2097152);
        assert_eq!(size, 4);
    }

    #[test]
    fn test_vla_rw_1_stream() {
        let video_layers = VideoLayers {
            rtp_stream_index: 1,
            num_rtp_streams: 1,
            spatial_layer_bitmasks: [0b1010, 0b0000, 0b0000, 0b0000],
            num_temporal_layers: [2, 1, 3, 1],
            target_bitrates: {
                let mut bitrates = [(0, 0, 0, 0); MAX_TARGET_BITRATES];
                bitrates[..3].copy_from_slice(&[
                    // stream 1
                    (0, 0, 0, 100),
                    (0, 0, 1, 100),
                    (0, 1, 0, 100),
                ]);
                bitrates
            },
            resolutions: None, // Some(vec![(0, 0, (640, 480, 30)), (1, 1, (1280, 720, 60))]),
        };

        let mut buffer = [0u8; 50];
        let bytes_written = video_layers.write_to(&mut buffer);

        let parsed_video_layers = VideoLayers::from(&buffer[..bytes_written]);

        assert_eq!(video_layers, parsed_video_layers);
    }

    #[test]
    fn test_vla_rw_1_stream_collapsed() {
        let video_layers = VideoLayers {
            rtp_stream_index: 1,
            num_rtp_streams: 1,
            spatial_layer_bitmasks: [0b1010, 0b1010, 0b1010, 0b1010],
            num_temporal_layers: [2, 1, 3, 1],
            target_bitrates: {
                let mut bitrates = [(0, 0, 0, 0); MAX_TARGET_BITRATES];
                bitrates[..3].copy_from_slice(&[
                    // stream 1
                    (0, 0, 0, 100),
                    (0, 0, 1, 200),
                    (0, 1, 0, 400),
                ]);
                bitrates
            },
            resolutions: None, // Some(vec![(0, 0, (640, 480, 30)), (1, 1, (1280, 720, 60))]),
        };

        let mut buffer = [0u8; 50];
        let bytes_written = video_layers.write_to(&mut buffer);

        let parsed_video_layers = VideoLayers::from(&buffer[..bytes_written]);

        assert_eq!(video_layers, parsed_video_layers);
    }

    #[test]
    fn test_vla_rw_2_streams() {
        let video_layers = VideoLayers {
            rtp_stream_index: 1,
            num_rtp_streams: 2,
            spatial_layer_bitmasks: [0b1010, 0b0001, 0b0000, 0b0000],
            num_temporal_layers: [2, 1, 3, 1],
            target_bitrates: {
                let mut bitrates = [(0, 0, 0, 0); MAX_TARGET_BITRATES];
                bitrates[..5].copy_from_slice(&[
                    // stream 1
                    (0, 0, 0, 100),
                    (0, 0, 1, 200),
                    (0, 1, 0, 400),
                    (1, 0, 0, 800),
                    (1, 0, 1, 1600),
                ]);
                bitrates
            },
            resolutions: None, // Some(vec![(0, 0, (640, 480, 30)), (1, 1, (1280, 720, 60))]),
        };

        let mut buffer = [0u8; 50];
        let bytes_written = video_layers.write_to(&mut buffer);

        let parsed_video_layers = VideoLayers::from(&buffer[..bytes_written]);

        assert_eq!(video_layers, parsed_video_layers);
    }

    #[test]
    fn test_parse_and_write_chrome() {
        // this is from Chrome
        let src = string_to_buffer(
            "
            00100001
            01010100
            01110000
            10111011
            00000001
            11010001
            00000010
            10110010
            00000100
            10000100
            00000111
            11011100
            00001011
            ",
        );

        let vla = VideoLayers::from(&src[..]);

        let mut buffer = [0u8; 50];
        let size = vla.write_to(&mut buffer);
        let dst = &buffer[..size];

        assert_eq!(src, dst);
    }

    fn string_to_buffer(input: &str) -> Vec<u8> {
        input
            .trim()
            .split('\n')
            .map(|line| u8::from_str_radix(line.trim(), 2).expect("Invalid binary character"))
            .collect()
    }

    fn _buffer_to_string(bytes: &[u8]) {
        for (_, &byte) in bytes.iter().enumerate() {
            println!("{:08b}", byte);
        }
    }
}
