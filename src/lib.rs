use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use hmac::{Hmac, Mac};
use sha1::Sha1;

type HmacSha1 = Hmac<Sha1>;

// Computes a TOTP code for a given time and key.
pub fn totp(when: u32, key: &[u8]) -> u32 {
    // let tm = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    // let key = Base32::decode_vec(secret).unwrap();
    // let now = (tm.as_millis() / 30) as u64;
    let now = (when / 30) as u64;

    let mut hasher = HmacSha1::new_from_slice(key).unwrap();
    let mut buf = Vec::with_capacity(8);
    buf.write_u64::<BigEndian>(now).unwrap();
    hasher.update(&buf);
    let result = hasher.finalize();
    let mac = result.into_bytes();

    let offs = (mac[mac.len() - 1] & 0xF) as usize;
    let mut hash = &mac[offs..offs + 4];
    (hash.read_u32::<BigEndian>().unwrap() & 0x7FFFFFFF) % 1000000
}

#[cfg(test)]
mod tests {
    use super::*;
    use base32ct::{Base32Upper, Encoding};

    #[test]
    fn test_totp() {
        let secret = "3N2OTFHXKLR2E3WNZSYQ====";
        let key = Base32Upper::decode_vec(secret).unwrap();
        let now = 1650183739;
        assert!(totp(now, &key) == 29283);
    }
}
