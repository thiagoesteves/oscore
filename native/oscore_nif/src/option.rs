//! RFC 8613 §6.1: compact encoding of the OSCORE option value (not CBOR).

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OscoreOption {
    pub partial_iv: Vec<u8>,
    pub kid_context: Option<Vec<u8>>,
    pub kid: Option<Vec<u8>>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum DecodeError {
    ReservedBitsSet,
    ReservedPartialIvLength,
    Truncated,
    TrailingBytes,
}

pub fn encode(opt: &OscoreOption) -> Vec<u8> {
    let n = opt.partial_iv.len();
    assert!(n <= 5, "Partial IV longer than 5 bytes");

    let h = opt.kid_context.is_some();
    let k = opt.kid.is_some();

    if n == 0 && !h && !k {
        return vec![];
    }

    let flag = ((h as u8) << 4) | ((k as u8) << 3) | (n as u8);

    let mut out = vec![flag];
    out.extend_from_slice(&opt.partial_iv);
    if let Some(kid_context) = &opt.kid_context {
        out.push(kid_context.len() as u8);
        out.extend_from_slice(kid_context);
    }
    if let Some(kid) = &opt.kid {
        out.extend_from_slice(kid);
    }
    out
}

pub fn decode(bytes: &[u8]) -> Result<OscoreOption, DecodeError> {
    if bytes.is_empty() {
        return Ok(OscoreOption::default());
    }

    let flag = bytes[0];
    if flag & 0b1110_0000 != 0 {
        return Err(DecodeError::ReservedBitsSet);
    }

    let n = (flag & 0x07) as usize;
    if n == 6 || n == 7 {
        return Err(DecodeError::ReservedPartialIvLength);
    }
    let h = flag & 0x10 != 0;
    let k = flag & 0x08 != 0;

    let mut pos = 1usize;
    if bytes.len() < pos + n {
        return Err(DecodeError::Truncated);
    }
    let partial_iv = bytes[pos..pos + n].to_vec();
    pos += n;

    let kid_context = if h {
        if bytes.len() < pos + 1 {
            return Err(DecodeError::Truncated);
        }
        let s = bytes[pos] as usize;
        pos += 1;
        if bytes.len() < pos + s {
            return Err(DecodeError::Truncated);
        }
        let v = bytes[pos..pos + s].to_vec();
        pos += s;
        Some(v)
    } else {
        None
    };

    let kid = if k {
        Some(bytes[pos..].to_vec())
    } else {
        if pos != bytes.len() {
            return Err(DecodeError::TrailingBytes);
        }
        None
    };

    Ok(OscoreOption {
        partial_iv,
        kid_context,
        kid,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// RFC 8613 §6.3, example 1.
    #[test]
    fn example_1_kid_and_partial_iv() {
        let opt = OscoreOption {
            partial_iv: hex("05"),
            kid_context: None,
            kid: Some(hex("25")),
        };
        assert_eq!(encode(&opt), hex("090525"));
        assert_eq!(decode(&hex("090525")).unwrap(), opt);
    }

    /// RFC 8613 §6.3, example 2.
    #[test]
    fn example_2_empty_kid() {
        let opt = OscoreOption {
            partial_iv: hex("00"),
            kid_context: None,
            kid: Some(vec![]),
        };
        assert_eq!(encode(&opt), hex("0900"));
        assert_eq!(decode(&hex("0900")).unwrap(), opt);
    }

    /// RFC 8613 §6.3, example 3.
    #[test]
    fn example_3_kid_context() {
        let opt = OscoreOption {
            partial_iv: hex("05"),
            kid_context: Some(hex("44616c656b")),
            kid: Some(vec![]),
        };
        assert_eq!(encode(&opt), hex("19050544616c656b"));
        assert_eq!(decode(&hex("19050544616c656b")).unwrap(), opt);
    }

    /// RFC 8613 §6.3, example 4.
    #[test]
    fn example_4_response_no_partial_iv() {
        let opt = OscoreOption::default();
        assert_eq!(encode(&opt), Vec::<u8>::new());
        assert_eq!(decode(&[]).unwrap(), opt);
    }

    /// RFC 8613 §6.3, example 5.
    #[test]
    fn example_5_response_with_partial_iv() {
        let opt = OscoreOption {
            partial_iv: hex("07"),
            kid_context: None,
            kid: None,
        };
        assert_eq!(encode(&opt), hex("0107"));
        assert_eq!(decode(&hex("0107")).unwrap(), opt);
    }

    #[test]
    fn rejects_reserved_partial_iv_length() {
        assert_eq!(decode(&[0x06]), Err(DecodeError::ReservedPartialIvLength));
        assert_eq!(decode(&[0x07]), Err(DecodeError::ReservedPartialIvLength));
    }

    #[test]
    fn rejects_reserved_bits() {
        assert_eq!(decode(&[0b0010_0000]), Err(DecodeError::ReservedBitsSet));
    }
}
