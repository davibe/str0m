use openssl::asn1::{Asn1Integer, Asn1Time};
use openssl::bn::BigNum;
use openssl::ec::EcKey;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::ssl::{HandshakeError, MidHandshakeSslStream, Ssl, SslStream};
use openssl::ssl::{SslContext, SslContextBuilder, SslMethod, SslOptions, SslVerifyMode};
use openssl::x509::X509;
use std::io;
use std::mem;
use std::ops::Deref;

use crate::sdp::Fingerprint;
use crate::util::unix_time;
use crate::{Error, UDP_MTU};

const RSA_F4: u32 = 0x10001;
const DTLS_CIPHERS: &str = "EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH";
const DTLS_SRTP: &str = "SRTP_AES128_CM_SHA1_80";
const DTLS_EC_CURVE: Nid = Nid::X9_62_PRIME256V1;
const DTLS_KEY_LABEL: &str = "EXTRACTOR-dtls_srtp";

extern "C" {
    pub fn DTLSv1_2_method() -> *const openssl_sys::SSL_METHOD;
}

pub fn dtls_create_ctx() -> Result<(SslContext, Fingerprint), Error> {
    let method = unsafe { SslMethod::from_ptr(DTLSv1_2_method()) };
    let mut ctx = SslContextBuilder::new(method)?;

    ctx.set_cipher_list(DTLS_CIPHERS)?;
    ctx.set_tlsext_use_srtp(DTLS_SRTP)?;

    let mut mode = SslVerifyMode::empty();
    mode.insert(SslVerifyMode::PEER);
    mode.insert(SslVerifyMode::FAIL_IF_NO_PEER_CERT);
    ctx.set_verify_callback(mode, |_ok, _ctx| true);

    let f4 = BigNum::from_u32(RSA_F4).unwrap();
    let key = Rsa::generate_with_e(2048, &f4)?;
    let pkey = PKey::from_rsa(key)?;
    ctx.set_private_key(&pkey)?;

    let mut x509 = X509::builder()?;
    let serial_bn = BigNum::from_u32(1)?;
    let serial = Asn1Integer::from_bn(&serial_bn)?;
    x509.set_serial_number(&serial)?;
    let before = Asn1Time::from_unix(unix_time() - 3600)?;
    x509.set_not_before(&before)?;
    let after = Asn1Time::days_from_now(7)?;
    x509.set_not_after(&after)?;
    x509.set_pubkey(&pkey)?;

    x509.sign(&pkey, MessageDigest::sha1())?;
    let cert = x509.build();

    ctx.set_certificate(&cert)?;

    let mut options = SslOptions::empty();
    options.insert(SslOptions::SINGLE_ECDH_USE);
    options.insert(SslOptions::NO_DTLSV1);
    ctx.set_options(options);

    let ctx = ctx.build();

    let digest: &[u8] = &cert.digest(MessageDigest::sha256())?;
    let fp = Fingerprint {
        hash_func: "sha-256".into(),
        bytes: digest.to_vec(),
    };

    Ok((ctx, fp))
}

pub fn dtls_ssl_create(ctx: &SslContext) -> Result<Ssl, Error> {
    let mut ssl = Ssl::new(ctx)?;
    ssl.set_mtu(UDP_MTU as u32)?;

    let eckey = EcKey::from_curve_name(DTLS_EC_CURVE)?;
    ssl.set_tmp_ecdh(&eckey)?;

    Ok(ssl)
}

pub struct SrtpKeyMaterial([u8; 60]);

impl Deref for SrtpKeyMaterial {
    type Target = [u8; 60];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::fmt::Debug for SrtpKeyMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SrtpKeyMaterial")
    }
}

pub struct Dtls<S> {
    state: State<S>,
    key_mat: Option<(SrtpKeyMaterial, Fingerprint)>,
    exported: bool,
}

pub enum State<S> {
    Init(Ssl, S, bool),
    Handshaking(MidHandshakeSslStream<S>),
    Established(SslStream<S>),
    Empty,
}

impl<S> Dtls<S>
where
    S: io::Read + io::Write,
{
    pub fn new(ssl: Ssl, stream: S, active: bool) -> Self {
        Dtls {
            state: State::Init(ssl, stream, active),
            key_mat: None,
            exported: false,
        }
    }

    pub fn complete_handshake_until_block(&mut self) -> Result<bool, Error> {
        if let Err(e) = self.handshaken() {
            if e.kind() != io::ErrorKind::WouldBlock {
                Ok(false)
            } else {
                Err(e.into())
            }
        } else {
            Ok(true)
        }
    }

    fn handshaken(&mut self) -> Result<&mut SslStream<S>, io::Error> {
        let v = self.state.handshaken()?;

        // first time we complete the handshake, we extract the keying material for SRTP.
        if !self.exported {
            let key_mat = extract_srtp_key_material(v)?;
            self.exported = true;
            self.key_mat = Some(key_mat);
        }

        Ok(v)
    }

    pub fn take_srtp_key_material(&mut self) -> Option<(SrtpKeyMaterial, Fingerprint)> {
        self.key_mat.take()
    }

    pub fn inner_mut(&mut self) -> Result<&mut S, Error> {
        Ok(self.handshaken()?.get_mut())
    }
}

impl<S> State<S>
where
    S: io::Read + io::Write,
{
    fn handshaken(&mut self) -> Result<&mut SslStream<S>, io::Error> {
        if let State::Established(v) = self {
            return Ok(v);
        }

        let taken = mem::replace(self, State::Empty);

        let result = match taken {
            State::Empty | State::Established(_) => unreachable!(),
            State::Init(ssl, stream, active) => {
                if active {
                    ssl.connect(stream)
                } else {
                    ssl.accept(stream)
                }
            }
            State::Handshaking(mid) => mid.handshake(),
        };

        match result {
            Ok(v) => {
                let _ = mem::replace(self, State::Established(v));

                // recursively return the &mut SslStream.
                self.handshaken()
            }
            Err(e) => Err(match e {
                HandshakeError::WouldBlock(e) => {
                    let _ = mem::replace(self, State::Handshaking(e));
                    io::Error::new(io::ErrorKind::WouldBlock, "WouldBlock")
                }
                HandshakeError::SetupFailure(e) => {
                    //
                    io::Error::new(io::ErrorKind::InvalidInput, e)
                }
                HandshakeError::Failure(e) => {
                    io::Error::new(io::ErrorKind::InvalidData, e.into_error())
                }
            }),
        }
    }
}

fn extract_srtp_key_material<S>(
    stream: &mut SslStream<S>,
) -> Result<(SrtpKeyMaterial, Fingerprint), io::Error> {
    let ssl = stream.ssl();

    // remote peer certificate fingerprint
    let x509 = ssl
        .peer_certificate()
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "No remote X509 cert"))?;
    let digest: &[u8] = &x509.digest(MessageDigest::sha256())?.to_vec();

    let fp = Fingerprint {
        hash_func: "sha-256".into(),
        bytes: digest.to_vec(),
    };

    // extract SRTP keying material
    let mut buf = [0_u8; 60];
    ssl.export_keying_material(&mut buf, DTLS_KEY_LABEL, None)?;

    let mat = SrtpKeyMaterial(buf);

    Ok((mat, fp))
}

impl<S> io::Read for Dtls<S>
where
    S: io::Read + io::Write,
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.handshaken()?.read(buf)
    }
}

impl<S> io::Write for Dtls<S>
where
    S: io::Read + io::Write,
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.handshaken()?.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.handshaken()?.flush()
    }
}