//! Web Push (RFC 8291 encryption, RFC 8292 VAPID) built on ring. One request, no state.

use crate::notify::{Body, Req};
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine;
use ring::{aead, agreement, hkdf, rand::SystemRandom, signature};
use serde_json::{json, Value};

struct Len(usize);
impl hkdf::KeyType for Len {
    fn len(&self) -> usize {
        self.0
    }
}

fn expand(prk: &hkdf::Prk, info: &[u8], n: usize) -> Result<Vec<u8>, String> {
    let mut out = vec![0u8; n];
    prk.expand(&[info], Len(n))
        .and_then(|o| o.fill(&mut out))
        .map_err(|_| "key derivation failed".to_string())?;
    Ok(out)
}

fn b64(s: &str, what: &str) -> Result<Vec<u8>, String> {
    B64.decode(s.trim().trim_end_matches('='))
        .map_err(|_| format!("{what} is not base64url."))
}

/// Encrypts `plain` for the browser's key (`ua_public`, 65 bytes) and auth secret.
pub fn encrypt(plain: &[u8], ua_public: &[u8], auth: &[u8]) -> Result<Vec<u8>, String> {
    if plain.len() > 3800 {
        return Err("Message too long".into());
    }
    let rng = SystemRandom::new();
    let eph = agreement::EphemeralPrivateKey::generate(&agreement::ECDH_P256, &rng)
        .map_err(|_| "no randomness".to_string())?;
    let as_public = eph
        .compute_public_key()
        .map_err(|_| "key error".to_string())?
        .as_ref()
        .to_vec();
    let ikm_secret = agreement::agree_ephemeral(
        eph,
        &agreement::UnparsedPublicKey::new(&agreement::ECDH_P256, ua_public),
        |s| s.to_vec(),
    )
    .map_err(|_| "The subscription key is not a valid P-256 point.".to_string())?;
    let mut salt = [0u8; 16];
    ring::rand::SecureRandom::fill(&rng, &mut salt).map_err(|_| "no randomness".to_string())?;
    let prk_key = hkdf::Salt::new(hkdf::HKDF_SHA256, auth).extract(&ikm_secret);
    let mut key_info = b"WebPush: info\0".to_vec();
    key_info.extend_from_slice(ua_public);
    key_info.extend_from_slice(&as_public);
    let ikm = expand(&prk_key, &key_info, 32)?;
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, &salt).extract(&ikm);
    let cek = expand(&prk, b"Content-Encoding: aes128gcm\0", 16)?;
    let nonce = expand(&prk, b"Content-Encoding: nonce\0", 12)?;
    let mut data = plain.to_vec();
    data.push(2); // last record
    let key = aead::LessSafeKey::new(
        aead::UnboundKey::new(&aead::AES_128_GCM, &cek).map_err(|_| "key error".to_string())?,
    );
    let n =
        aead::Nonce::try_assume_unique_for_key(&nonce).map_err(|_| "nonce error".to_string())?;
    key.seal_in_place_append_tag(n, aead::Aad::empty(), &mut data)
        .map_err(|_| "encryption failed".to_string())?;
    let mut body = salt.to_vec();
    body.extend_from_slice(&4096u32.to_be_bytes());
    body.push(as_public.len() as u8);
    body.extend_from_slice(&as_public);
    body.extend_from_slice(&data);
    Ok(body)
}

fn vapid(endpoint: &str, public: &[u8], private: &[u8], subject: &str) -> Result<String, String> {
    let u = reqwest::Url::parse(endpoint).map_err(|_| "Invalid endpoint".to_string())?;
    let aud = u.origin().ascii_serialization();
    let exp = crate::db::now() + 12 * 3600;
    let head = B64.encode(r#"{"typ":"JWT","alg":"ES256"}"#);
    let claims = B64.encode(json!({"aud": aud, "exp": exp, "sub": subject}).to_string());
    let input = format!("{head}.{claims}");
    let pair = signature::EcdsaKeyPair::from_private_key_and_public_key(
        &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
        private,
        public,
        &SystemRandom::new(),
    )
    .map_err(|_| "The VAPID key pair does not match.".to_string())?;
    let sig = pair
        .sign(&SystemRandom::new(), input.as_bytes())
        .map_err(|_| "Signing failed".to_string())?;
    Ok(format!(
        "vapid t={input}.{}, k={}",
        B64.encode(sig.as_ref()),
        B64.encode(public)
    ))
}

/// `sub` is the JSON a browser returns from `pushManager.subscribe()`.
pub fn request(
    sub: &str,
    vpub: &str,
    vpriv: &str,
    subject: &str,
    title: &str,
    text: &str,
) -> Result<Req, String> {
    let v: Value = serde_json::from_str(sub).map_err(|_| "Subscription is not valid JSON.")?;
    let endpoint = v["endpoint"]
        .as_str()
        .ok_or("Subscription has no endpoint.")?;
    let ok = reqwest::Url::parse(endpoint)
        .map(|u| u.scheme() == "https" && u.host_str().is_some())
        .unwrap_or(false);
    if !ok {
        return Err("The endpoint must be an https:// address.".into());
    }
    let ua = b64(v["keys"]["p256dh"].as_str().unwrap_or(""), "p256dh")?;
    let auth = b64(v["keys"]["auth"].as_str().unwrap_or(""), "auth")?;
    let public = b64(vpub, "VAPID public key")?;
    let private = b64(vpriv, "VAPID private key")?;
    let subject = if subject.is_empty() {
        "mailto:admin@example.com"
    } else {
        subject
    };
    let body = encrypt(
        json!({"title": title, "body": text}).to_string().as_bytes(),
        &ua,
        &auth,
    )?;
    Ok(Req {
        method: "POST",
        url: endpoint.to_string(),
        headers: vec![
            ("content-encoding".into(), "aes128gcm".into()),
            ("ttl".into(), "3600".into()),
            ("urgency".into(), "high".into()),
            (
                "authorization".into(),
                vapid(endpoint, &public, &private, subject)?,
            ),
        ],
        body: Body::Bytes(body),
        basic: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The receiver side of RFC 8291, so the sender can be checked against it.
    fn decrypt(
        body: &[u8],
        recv_priv: agreement::EphemeralPrivateKey,
        recv_pub: &[u8],
        auth: &[u8],
    ) -> Vec<u8> {
        let salt = &body[..16];
        let idlen = body[20] as usize;
        let as_public = &body[21..21 + idlen];
        let cipher = &body[21 + idlen..];
        let secret = agreement::agree_ephemeral(
            recv_priv,
            &agreement::UnparsedPublicKey::new(&agreement::ECDH_P256, as_public),
            |s| s.to_vec(),
        )
        .unwrap();
        let prk_key = hkdf::Salt::new(hkdf::HKDF_SHA256, auth).extract(&secret);
        let mut info = b"WebPush: info\0".to_vec();
        info.extend_from_slice(recv_pub);
        info.extend_from_slice(as_public);
        let ikm = expand(&prk_key, &info, 32).unwrap();
        let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, salt).extract(&ikm);
        let cek = expand(&prk, b"Content-Encoding: aes128gcm\0", 16).unwrap();
        let nonce = expand(&prk, b"Content-Encoding: nonce\0", 12).unwrap();
        let key = aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_128_GCM, &cek).unwrap());
        let mut data = cipher.to_vec();
        let plain = key
            .open_in_place(
                aead::Nonce::try_assume_unique_for_key(&nonce).unwrap(),
                aead::Aad::empty(),
                &mut data,
            )
            .unwrap();
        let end = plain.iter().rposition(|b| *b != 0).unwrap();
        assert_eq!(plain[end], 2);
        plain[..end].to_vec()
    }

    #[test]
    fn message_round_trips_and_signature_header_is_well_formed() {
        let rng = SystemRandom::new();
        let recv = agreement::EphemeralPrivateKey::generate(&agreement::ECDH_P256, &rng).unwrap();
        let recv_pub = recv.compute_public_key().unwrap().as_ref().to_vec();
        let auth = [7u8; 16];
        let body = encrypt(b"hello push", &recv_pub, &auth).unwrap();
        assert_eq!(decrypt(&body, recv, &recv_pub, &auth), b"hello push");

        let pkcs8 = signature::EcdsaKeyPair::generate_pkcs8(
            &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            &rng,
        )
        .unwrap();
        let pair = signature::EcdsaKeyPair::from_pkcs8(
            &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            pkcs8.as_ref(),
            &rng,
        )
        .unwrap();
        use signature::KeyPair;
        let public = pair.public_key().as_ref().to_vec();
        // ring's PKCS#8 layout for P-256: 36 bytes of prefix, the 32-byte scalar, then the point
        let private = &pkcs8.as_ref()[36..68];
        let h = vapid(
            "https://push.example.com/x",
            &public,
            private,
            "mailto:a@b.c",
        )
        .unwrap();
        let (t, k) = h
            .strip_prefix("vapid t=")
            .unwrap()
            .split_once(", k=")
            .unwrap();
        assert_eq!(k, B64.encode(&public));
        let (input, sig) = t.rsplit_once('.').unwrap();
        signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, &public)
            .verify(input.as_bytes(), &B64.decode(sig).unwrap())
            .unwrap();
        assert!(vapid(
            "https://push.example.com/x",
            &public,
            &[1u8; 32],
            "mailto:a@b.c"
        )
        .is_err());
    }
}
