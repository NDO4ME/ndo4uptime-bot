//! Nostr direct messages (NIP-17 gift wraps with NIP-44 encryption) published to wss relays.
//! Curve arithmetic comes from the audited k256 crate; nothing here touches raw field math.

use crate::notify::{C, M};
use base64::Engine;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use hmac::{Hmac, Mac};
use k256::schnorr::SigningKey;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

type HmacSha = Hmac<Sha256>;
const STEP: Duration = Duration::from_secs(10);

// ---------------------------------------------------------------- bech32 (nsec / npub)
const CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

fn polymod(values: &[u8]) -> u32 {
    const G: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    let mut chk = 1u32;
    for v in values {
        let b = chk >> 25;
        chk = ((chk & 0x1ffffff) << 5) ^ u32::from(*v);
        for (i, g) in G.iter().enumerate() {
            if (b >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

/// Decodes `nsec1…` / `npub1…` into (prefix, 32 bytes).
pub fn bech32(s: &str) -> Result<(String, [u8; 32]), String> {
    let s = s.trim().to_ascii_lowercase();
    let bad = || "Not a valid nsec/npub key.".to_string();
    let (hrp, data) = s.rsplit_once('1').ok_or_else(bad)?;
    if data.len() < 7 || s.len() > 120 {
        return Err(bad());
    }
    let vals: Vec<u8> = data
        .bytes()
        .map(|c| CHARSET.iter().position(|x| *x == c).map(|p| p as u8))
        .collect::<Option<_>>()
        .ok_or_else(bad)?;
    let mut chk: Vec<u8> = hrp.bytes().map(|b| b >> 5).collect();
    chk.push(0);
    chk.extend(hrp.bytes().map(|b| b & 31));
    chk.extend(&vals);
    if polymod(&chk) != 1 {
        return Err(bad());
    }
    let payload = &vals[..vals.len() - 6];
    let (mut acc, mut bits, mut out) = (0u32, 0u32, Vec::new());
    for v in payload {
        acc = (acc << 5) | u32::from(*v);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    let key: [u8; 32] = out.try_into().map_err(|_| bad())?;
    Ok((hrp.to_string(), key))
}

// ---------------------------------------------------------------- NIP-44 v2
fn hkdf_expand(prk: &[u8], info: &[u8], n: usize) -> Vec<u8> {
    let (mut out, mut t) = (Vec::new(), Vec::new());
    let mut i = 1u8;
    while out.len() < n {
        let mut m = HmacSha::new_from_slice(prk).expect("any key length");
        m.update(&t);
        m.update(info);
        m.update(&[i]);
        t = m.finalize().into_bytes().to_vec();
        out.extend_from_slice(&t);
        i += 1;
    }
    out.truncate(n);
    out
}

fn padded_len(n: usize) -> usize {
    if n <= 32 {
        return 32;
    }
    let next = 1usize << (usize::BITS - (n - 1).leading_zeros());
    let chunk = if next <= 256 { 32 } else { next / 8 };
    chunk * ((n - 1) / chunk + 1)
}

fn shared_x(sk: &[u8; 32], peer_x: &[u8; 32]) -> Result<[u8; 32], String> {
    let secret = k256::SecretKey::from_slice(sk).map_err(|_| "Invalid private key.".to_string())?;
    let mut sec1 = vec![2u8];
    sec1.extend_from_slice(peer_x);
    let public = k256::PublicKey::from_sec1_bytes(&sec1)
        .map_err(|_| "Invalid recipient key.".to_string())?;
    let shared = k256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), public.as_affine());
    let mut out = [0u8; 32];
    out.copy_from_slice(shared.raw_secret_bytes());
    Ok(out)
}

fn conversation_key(sk: &[u8; 32], peer_x: &[u8; 32]) -> Result<Vec<u8>, String> {
    let x = shared_x(sk, peer_x)?;
    let mut m = HmacSha::new_from_slice(b"nip44-v2").expect("any key length");
    m.update(&x);
    Ok(m.finalize().into_bytes().to_vec())
}

fn nip44_encrypt(plain: &str, ck: &[u8], nonce: &[u8; 32]) -> Result<String, String> {
    let n = plain.len();
    if n == 0 || n > 65535 {
        return Err("Message length out of range.".into());
    }
    let keys = hkdf_expand(ck, nonce, 76);
    let mut buf = Vec::with_capacity(2 + padded_len(n));
    buf.extend_from_slice(&(n as u16).to_be_bytes());
    buf.extend_from_slice(plain.as_bytes());
    buf.resize(2 + padded_len(n), 0);
    let mut c = chacha20::ChaCha20::new(keys[..32].into(), keys[32..44].into());
    c.apply_keystream(&mut buf);
    let mut m = HmacSha::new_from_slice(&keys[44..76]).expect("any key length");
    m.update(nonce);
    m.update(&buf);
    let mac = m.finalize().into_bytes();
    let mut out = vec![2u8];
    out.extend_from_slice(nonce);
    out.extend_from_slice(&buf);
    out.extend_from_slice(&mac);
    Ok(base64::engine::general_purpose::STANDARD.encode(out))
}

// ---------------------------------------------------------------- events
fn event(sk: &SigningKey, created: i64, kind: u32, tags: Value, content: &str) -> Value {
    let pubkey = hex::encode(sk.verifying_key().to_bytes());
    let ser = json!([0, pubkey, created, kind, tags, content]).to_string();
    let id = Sha256::digest(ser.as_bytes());
    let mut aux = [0u8; 32];
    for b in aux.iter_mut() {
        *b = rand::random();
    }
    let sig = sk
        .sign_raw(&id, &aux)
        .map(|s| s.to_bytes())
        .unwrap_or([0u8; 64]);
    json!({"id": hex::encode(id), "pubkey": pubkey, "created_at": created, "kind": kind,
           "tags": tags, "content": content, "sig": hex::encode(sig)})
}

fn random_sk() -> ([u8; 32], SigningKey) {
    loop {
        let mut b = [0u8; 32];
        for x in b.iter_mut() {
            *x = rand::random();
        }
        if let Ok(k) = SigningKey::from_bytes(&b.into()) {
            return (b, k);
        }
    }
}

fn nonce() -> [u8; 32] {
    let mut n = [0u8; 32];
    for x in n.iter_mut() {
        *x = rand::random();
    }
    n
}

/// A kind 1059 gift wrap carrying `text` for one recipient.
fn wrap(sender: &[u8; 32], recipient: &[u8; 32], text: &str, now: i64) -> Result<Value, String> {
    let me = SigningKey::from_bytes(&(*sender).into())
        .map_err(|_| "Invalid private key.".to_string())?;
    let rumor = {
        let pubkey = hex::encode(me.verifying_key().to_bytes());
        let tags = json!([["p", hex::encode(recipient)]]);
        let ser = json!([0, pubkey, now, 14, tags, text]).to_string();
        json!({"id": hex::encode(Sha256::digest(ser.as_bytes())), "pubkey": pubkey,
               "created_at": now, "kind": 14, "tags": tags, "content": text})
    };
    let jitter = |t: i64| t - i64::from(rand::random::<u32>() % 172_800);
    let seal = event(
        &me,
        jitter(now),
        13,
        json!([]),
        &nip44_encrypt(
            &rumor.to_string(),
            &conversation_key(sender, recipient)?,
            &nonce(),
        )?,
    );
    let (esk, eph) = random_sk();
    Ok(event(
        &eph,
        jitter(now),
        1059,
        json!([["p", hex::encode(recipient)]]),
        &nip44_encrypt(
            &seal.to_string(),
            &conversation_key(&esk, recipient)?,
            &nonce(),
        )?,
    ))
}

// ---------------------------------------------------------------- relay (minimal websocket client)
async fn publish(relay: &str, ev: &Value) -> Result<(), String> {
    let u = reqwest::Url::parse(relay).map_err(|_| "Invalid relay address".to_string())?;
    if u.scheme() != "wss" {
        return Err("Relays must use wss://".into());
    }
    let host = u.host_str().ok_or("Invalid relay address")?.to_string();
    let port = u.port().unwrap_or(443);
    let path = match u.query() {
        Some(q) => format!("{}?{q}", u.path()),
        None => u.path().to_string(),
    };
    let tcp = timeout(STEP, TcpStream::connect((host.as_str(), port)))
        .await
        .map_err(|_| "Relay timed out".to_string())?
        .map_err(|_| "Relay unreachable".to_string())?;
    let name = rustls::pki_types::ServerName::try_from(host.clone())
        .map_err(|_| "Invalid relay name".to_string())?;
    let mut s = timeout(STEP, crate::mail::connector().connect(name, tcp))
        .await
        .map_err(|_| "TLS timed out".to_string())?
        .map_err(|_| "TLS failed".to_string())?;
    let key = base64::engine::general_purpose::STANDARD.encode(&nonce()[..16]);
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
    );
    s.write_all(req.as_bytes())
        .await
        .map_err(|_| "Relay write failed".to_string())?;
    // handshake answer, up to the blank line
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() > 4096 {
            return Err("Relay handshake too long".into());
        }
        timeout(STEP, s.read_exact(&mut b))
            .await
            .map_err(|_| "Relay timed out".to_string())?
            .map_err(|_| "Relay closed".to_string())?;
        head.push(b[0]);
    }
    let head = String::from_utf8_lossy(&head).to_string();
    if !head.starts_with("HTTP/1.1 101") {
        return Err("Relay refused the connection".into());
    }
    let mut accept_src = key.into_bytes();
    accept_src.extend_from_slice(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    let want = base64::engine::general_purpose::STANDARD.encode(ring::digest::digest(
        &ring::digest::SHA1_FOR_LEGACY_USE_ONLY,
        &accept_src,
    ));
    if !head.to_ascii_lowercase().contains(&format!(
        "sec-websocket-accept: {}",
        want.to_ascii_lowercase()
    )) {
        return Err("Relay handshake mismatch".into());
    }
    // one masked text frame: ["EVENT", {...}]
    let payload = json!(["EVENT", ev]).to_string().into_bytes();
    let mask: [u8; 4] = rand::random();
    let mut frame = vec![0x81u8];
    match payload.len() {
        n if n < 126 => frame.push(0x80 | n as u8),
        n if n < 65536 => {
            frame.push(0x80 | 126);
            frame.extend_from_slice(&(n as u16).to_be_bytes());
        }
        n => {
            frame.push(0x80 | 127);
            frame.extend_from_slice(&(n as u64).to_be_bytes());
        }
    }
    frame.extend_from_slice(&mask);
    frame.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
    s.write_all(&frame)
        .await
        .map_err(|_| "Relay write failed".to_string())?;
    // wait for ["OK", id, accepted, reason]
    let id = ev["id"].as_str().unwrap_or("").to_string();
    for _ in 0..8 {
        let mut h = [0u8; 2];
        timeout(STEP, s.read_exact(&mut h))
            .await
            .map_err(|_| "Relay did not answer".to_string())?
            .map_err(|_| "Relay closed".to_string())?;
        let op = h[0] & 0x0f;
        let mut len = u64::from(h[1] & 0x7f);
        if len == 126 {
            let mut x = [0u8; 2];
            s.read_exact(&mut x)
                .await
                .map_err(|_| "Relay closed".to_string())?;
            len = u64::from(u16::from_be_bytes(x));
        } else if len == 127 {
            let mut x = [0u8; 8];
            s.read_exact(&mut x)
                .await
                .map_err(|_| "Relay closed".to_string())?;
            len = u64::from_be_bytes(x);
        }
        if len > 65536 {
            return Err("Relay answer too large".into());
        }
        let mut data = vec![0u8; len as usize];
        s.read_exact(&mut data)
            .await
            .map_err(|_| "Relay closed".to_string())?;
        if op == 8 {
            return Err("Relay closed".into());
        }
        if op != 1 {
            continue;
        }
        if let Ok(v) = serde_json::from_slice::<Value>(&data) {
            if v[0] == "OK" && v[1] == id.as_str() {
                let _ = s.write_all(&[0x88, 0x80, 0, 0, 0, 0]).await;
                return if v[2] == true {
                    Ok(())
                } else {
                    Err(format!(
                        "Relay said: {}",
                        v[3].as_str().unwrap_or("rejected")
                    ))
                };
            }
        }
    }
    Err("Relay sent no confirmation".into())
}

pub async fn send(c: &C, m: &M) -> Result<String, String> {
    let (hrp, sender) = bech32(c.g("sender"))?;
    if hrp != "nsec" {
        return Err("The sender key must be an nsec.".into());
    }
    let mut recipients = vec![];
    for r in c
        .g("recipients")
        .split([',', '\n', ' '])
        .filter(|x| !x.is_empty())
    {
        let (hrp, k) = bech32(r)?;
        if hrp != "npub" {
            return Err("Recipients must be npub keys.".into());
        }
        recipients.push(k);
    }
    let relays: Vec<&str> = c
        .g("relays")
        .split([',', '\n', ' '])
        .filter(|x| !x.is_empty())
        .collect();
    if recipients.is_empty() || relays.is_empty() || recipients.len() > 5 || relays.len() > 5 {
        return Err("Give 1 to 5 recipients and 1 to 5 relays.".into());
    }
    let now = crate::db::now();
    let events: Vec<Value> = recipients
        .iter()
        .map(|r| wrap(&sender, r, &m.text, now))
        .collect::<Result<_, _>>()?;
    let mut ok = 0;
    let mut last = String::new();
    for r in &relays {
        let mut all = true;
        for e in &events {
            if let Err(e) = publish(r, e).await {
                all = false;
                last = e;
                break;
            }
        }
        ok += usize::from(all);
    }
    if ok == 0 {
        return Err(last);
    }
    Ok(format!("{ok}/{} relays accepted", relays.len()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode(hrp: &str, data: &[u8]) -> String {
        let (mut acc, mut bits, mut v) = (0u32, 0u32, Vec::new());
        for b in data {
            acc = (acc << 8) | u32::from(*b);
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                v.push(((acc >> bits) & 31) as u8);
            }
        }
        if bits > 0 {
            v.push(((acc << (5 - bits)) & 31) as u8);
        }
        let mut chk: Vec<u8> = hrp.bytes().map(|b| b >> 5).collect();
        chk.push(0);
        chk.extend(hrp.bytes().map(|b| b & 31));
        chk.extend(&v);
        chk.extend([0u8; 6]);
        let p = polymod(&chk) ^ 1;
        for i in 0..6 {
            v.push(((p >> (5 * (5 - i))) & 31) as u8);
        }
        format!(
            "{hrp}1{}",
            v.iter()
                .map(|x| CHARSET[*x as usize] as char)
                .collect::<String>()
        )
    }

    #[test]
    fn keys_decode_and_bad_checksums_fail() {
        let key = [0x5au8; 32];
        let s = encode("npub", &key);
        assert_eq!(bech32(&s).unwrap(), ("npub".to_string(), key));
        let mut bad = s.clone();
        bad.pop();
        bad.push('q');
        assert!(bech32(&bad).is_err());
        // NIP-19 example
        let (h, k) =
            bech32("npub10elfcs4fr0l0r8af98jlmgdh9c8tcxjvz9qkw038js35mp4dma8qzvjptg").unwrap();
        assert_eq!(h, "npub");
        assert_eq!(
            hex::encode(k),
            "7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e"
        );
    }

    #[test]
    fn padding_matches_the_spec_table() {
        for (n, p) in [
            (1, 32),
            (32, 32),
            (33, 64),
            (37, 64),
            (65, 96),
            (257, 320),
            (1000, 1024),
            (65535, 65536),
        ] {
            assert_eq!(padded_len(n), p, "{n}");
        }
    }

    #[test]
    fn conversation_key_is_symmetric_and_wrap_is_signed() {
        let (a_sk, a) = random_sk();
        let (b_sk, b) = random_sk();
        let ax: [u8; 32] = a.verifying_key().to_bytes().into();
        let bx: [u8; 32] = b.verifying_key().to_bytes().into();
        assert_eq!(
            conversation_key(&a_sk, &bx).unwrap(),
            conversation_key(&b_sk, &ax).unwrap()
        );
        let w = wrap(&a_sk, &bx, "hello", 1_800_000_000).unwrap();
        assert_eq!(w["kind"], 1059);
        let id = hex::decode(w["id"].as_str().unwrap()).unwrap();
        let sig = k256::schnorr::Signature::try_from(
            hex::decode(w["sig"].as_str().unwrap()).unwrap().as_slice(),
        )
        .unwrap();
        let pk = k256::schnorr::VerifyingKey::from_bytes(
            &<[u8; 32]>::try_from(hex::decode(w["pubkey"].as_str().unwrap()).unwrap())
                .unwrap()
                .into(),
        )
        .unwrap();
        pk.verify_raw(&id, &sig).unwrap();

        // the recipient can open wrap -> seal -> rumor
        let open = |payload: &str, sk: &[u8; 32], peer: &[u8; 32]| -> String {
            let raw = base64::engine::general_purpose::STANDARD
                .decode(payload)
                .unwrap();
            assert_eq!(raw[0], 2);
            let (nonce, rest) = raw[1..].split_at(32);
            let (cipher, mac) = rest.split_at(rest.len() - 32);
            let keys = hkdf_expand(&conversation_key(sk, peer).unwrap(), nonce, 76);
            let mut m = HmacSha::new_from_slice(&keys[44..76]).unwrap();
            m.update(nonce);
            m.update(cipher);
            m.verify_slice(mac).unwrap();
            let mut buf = cipher.to_vec();
            chacha20::ChaCha20::new(keys[..32].into(), keys[32..44].into())
                .apply_keystream(&mut buf);
            let n = u16::from_be_bytes([buf[0], buf[1]]) as usize;
            String::from_utf8(buf[2..2 + n].to_vec()).unwrap()
        };
        let wpk: [u8; 32] = hex::decode(w["pubkey"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let seal: Value =
            serde_json::from_str(&open(w["content"].as_str().unwrap(), &b_sk, &wpk)).unwrap();
        assert_eq!(seal["kind"], 13);
        let rumor: Value =
            serde_json::from_str(&open(seal["content"].as_str().unwrap(), &b_sk, &ax)).unwrap();
        assert_eq!(rumor["content"], "hello");
        assert_eq!(rumor["kind"], 14);
    }
}
