use std::borrow::BorrowMut;

use openssl::cipher;
use openssl::cipher_ctx::CipherCtx;
use openssl::symm::{Cipher, Crypter, Mode};
use ring::aead::{self, Algorithm, Tag, AES_128_GCM};

use crate::crypto::srtp::SrtpCryptoImpl;
use crate::crypto::srtp::{aead_aes_128_gcm, aes_128_cm_sha1_80};
use crate::crypto::CryptoError;

pub struct OsslSrtpCryptoImpl;

impl SrtpCryptoImpl for OsslSrtpCryptoImpl {
    type Aes128CmSha1_80 = OsslAes128CmSha1_80;
    type AeadAes128Gcm = OsslAeadAes128Gcm;

    fn srtp_aes_128_ecb_round(key: &[u8], input: &[u8], output: &mut [u8]) {
        let mut aes =
            Crypter::new(Cipher::aes_128_ecb(), Mode::Encrypt, key, None).expect("AES deriver");

        // Run AES
        let count = aes.update(input, output).expect("AES update");
        let rest = aes.finalize(&mut output[count..]).expect("AES finalize");

        assert_eq!(count + rest, 16 + 16); // input len + block size
    }
}

pub struct OsslAes128CmSha1_80(CipherCtx);

impl aes_128_cm_sha1_80::CipherCtx for OsslAes128CmSha1_80 {
    fn new(key: aes_128_cm_sha1_80::AesKey, encrypt: bool) -> Self
    where
        Self: Sized,
    {
        let t = cipher::Cipher::aes_128_ctr();
        let mut ctx = CipherCtx::new().expect("a reusable cipher context");

        if encrypt {
            ctx.encrypt_init(Some(t), Some(&key[..]), None)
                .expect("enc init");
        } else {
            ctx.decrypt_init(Some(t), Some(&key[..]), None)
                .expect("enc init");
        }

        OsslAes128CmSha1_80(ctx)
    }

    fn encrypt(
        &mut self,
        iv: &aes_128_cm_sha1_80::RtpIv,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), CryptoError> {
        self.0.encrypt_init(None, None, Some(iv))?;
        let count = self.0.cipher_update(input, Some(output))?;
        self.0.cipher_final(&mut output[count..])?;
        Ok(())
    }

    fn decrypt(
        &mut self,
        iv: &aes_128_cm_sha1_80::RtpIv,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), CryptoError> {
        self.0.decrypt_init(None, None, Some(iv))?;
        let count = self.0.cipher_update(input, Some(output))?;
        self.0.cipher_final(&mut output[count..])?;
        Ok(())
    }
}

pub struct OsslAeadAes128Gcm(aead::LessSafeKey);

impl aead_aes_128_gcm::CipherCtx for OsslAeadAes128Gcm {
    fn new(key: aead_aes_128_gcm::AeadKey, encrypt: bool) -> Self
    where
        Self: Sized,
    {
        
        let unbound_key = aead::UnboundKey::new(&AES_128_GCM, &key).unwrap();
        let key = aead::LessSafeKey::new(unbound_key);

        let t = cipher::Cipher::aes_128_gcm();
        let mut ctx = CipherCtx::new().expect("a reusable cipher context");
        
        return OsslAeadAes128Gcm(key);
    }

    fn encrypt(
        &mut self,
        iv: &[u8; aead_aes_128_gcm::IV_LEN],
        aad: &[u8],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), CryptoError> {
        assert!(
            aad.len() >= 12,
            "Associated data length MUST be at least 12 octets"
        );

        let nonce = aead::Nonce::assume_unique_for_key(*iv);
        let aad = aead::Aad::from(aad);
        output[..input.len()].copy_from_slice(input);
        let tag = self.0.seal_in_place_separate_tag(nonce, aad, &mut output[..input.len()]).unwrap();
        output[input.len()..].copy_from_slice(tag.as_ref());

        return Ok(());

    }

    fn decrypt(
        &mut self,
        iv: &[u8; aead_aes_128_gcm::IV_LEN],
        aads: &[&[u8]],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, CryptoError> {
        // This needs to be converted to an error maybe
        assert!(input.len() >= aead_aes_128_gcm::TAG_LEN);

        let nonce = aead::Nonce::assume_unique_for_key(*iv);

        let mut aad: Vec<u8> = Vec::new();
        for a in aads {
            aad.extend_from_slice(a);
        }
        let aad = aead::Aad::from(aad);
        let (input, tag) = input.split_at(input.len() - aead_aes_128_gcm::TAG_LEN);
        let tag = Tag::try_from(tag).unwrap();
        output[..input.len()].copy_from_slice(input);
        let output = self.0.open_in_place_separate_tag(nonce, aad, tag, output, std::ops::RangeFrom { start: 0 }).unwrap();
        return Ok(output.len());

    }
}
