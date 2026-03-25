//! Negentropy wire-protocol parser for diagnostic / debug logging.
//!
//! Decodes the binary negentropy reconciliation payloads into a structured
//! summary (`NegPayloadSummary`) that the sync-run capture layer can persist
//! as JSON.  Nothing here mutates sync state — it is purely read-only
//! introspection of the on-wire format.

use serde::Serialize;

pub(crate) const NEG_FINGERPRINT_SIZE: usize = 16;
pub(crate) const NEG_ID_SIZE: usize = 32;
pub(crate) const MAX_CAPTURE_IDS: usize = 32;

#[derive(Serialize)]
pub(crate) struct NegEntry {
    pub bound_ts: String,
    pub bound_id_prefix: String,
    pub mode: String,
    pub fingerprint_hex: Option<String>,
    pub id_count: Option<usize>,
    pub ids: Option<Vec<String>>,
    pub ids_truncated: bool,
}

#[derive(Serialize)]
pub(crate) struct NegPayloadSummary {
    pub protocol: Option<u64>,
    pub entry_count: usize,
    pub skip_count: usize,
    pub fingerprint_count: usize,
    pub idlist_count: usize,
    pub entries: Vec<NegEntry>,
    pub parse_error: Option<String>,
}

fn decode_var_int(encoded: &mut &[u8]) -> Result<u64, String> {
    if encoded.is_empty() {
        return Err("unexpected EOF while decoding varint".to_string());
    }

    let mut res = 0u64;
    let mut consumed = 0usize;
    for byte in encoded.iter() {
        consumed += 1;
        res = (res << 7) | (*byte as u64 & 0b0111_1111);
        if (byte & 0b1000_0000) == 0 {
            *encoded = &encoded[consumed..];
            return Ok(res);
        }
        if consumed >= 10 {
            return Err("varint too long".to_string());
        }
    }

    Err("unterminated varint".to_string())
}

fn take_bytes<'a>(encoded: &'a mut &[u8], n: usize) -> Result<&'a [u8], String> {
    if encoded.len() < n {
        return Err(format!(
            "unexpected EOF while decoding payload (need {}, have {})",
            n,
            encoded.len()
        ));
    }
    let out = &encoded[..n];
    *encoded = &encoded[n..];
    Ok(out)
}

pub(crate) fn parse_neg_payload(msg: &[u8], capture_full_ids: bool) -> NegPayloadSummary {
    let mut payload = msg;
    let mut entries = Vec::new();
    let mut skip_count = 0usize;
    let mut fingerprint_count = 0usize;
    let mut idlist_count = 0usize;
    let mut parse_error = None;
    let mut protocol = None;

    if !payload.is_empty() {
        protocol = Some(payload[0] as u64);
        payload = &payload[1..];
    } else {
        parse_error = Some("empty negentropy payload".to_string());
    }

    let mut last_ts = 0u64;

    while parse_error.is_none() && !payload.is_empty() {
        let ts_enc = match decode_var_int(&mut payload) {
            Ok(v) => v,
            Err(e) => {
                parse_error = Some(e);
                break;
            }
        };
        let mut ts = if ts_enc == 0 { u64::MAX } else { ts_enc - 1 };
        ts = ts.saturating_add(last_ts);
        last_ts = ts;

        let id_len = match decode_var_int(&mut payload) {
            Ok(v) => v as usize,
            Err(e) => {
                parse_error = Some(e);
                break;
            }
        };
        let id_prefix = match take_bytes(&mut payload, id_len) {
            Ok(v) => hex::encode(v),
            Err(e) => {
                parse_error = Some(e);
                break;
            }
        };

        let mode = match decode_var_int(&mut payload) {
            Ok(v) => v,
            Err(e) => {
                parse_error = Some(e);
                break;
            }
        };

        match mode {
            0 => {
                skip_count += 1;
                entries.push(NegEntry {
                    bound_ts: if ts == u64::MAX {
                        "MAX".to_string()
                    } else {
                        ts.to_string()
                    },
                    bound_id_prefix: id_prefix,
                    mode: "Skip".to_string(),
                    fingerprint_hex: None,
                    id_count: None,
                    ids: None,
                    ids_truncated: false,
                });
            }
            1 => {
                let fp = match take_bytes(&mut payload, NEG_FINGERPRINT_SIZE) {
                    Ok(v) => hex::encode(v),
                    Err(e) => {
                        parse_error = Some(e);
                        break;
                    }
                };
                fingerprint_count += 1;
                entries.push(NegEntry {
                    bound_ts: if ts == u64::MAX {
                        "MAX".to_string()
                    } else {
                        ts.to_string()
                    },
                    bound_id_prefix: id_prefix,
                    mode: "Fingerprint".to_string(),
                    fingerprint_hex: Some(fp),
                    id_count: None,
                    ids: None,
                    ids_truncated: false,
                });
            }
            2 => {
                let total = match decode_var_int(&mut payload) {
                    Ok(v) => v as usize,
                    Err(e) => {
                        parse_error = Some(e);
                        break;
                    }
                };
                let mut ids = Vec::new();
                let keep = if capture_full_ids {
                    total
                } else {
                    total.min(MAX_CAPTURE_IDS)
                };
                for idx in 0..total {
                    let id = match take_bytes(&mut payload, NEG_ID_SIZE) {
                        Ok(v) => v,
                        Err(e) => {
                            parse_error = Some(e);
                            break;
                        }
                    };
                    if idx < keep {
                        ids.push(hex::encode(id));
                    }
                }
                if parse_error.is_some() {
                    break;
                }
                idlist_count += 1;
                entries.push(NegEntry {
                    bound_ts: if ts == u64::MAX {
                        "MAX".to_string()
                    } else {
                        ts.to_string()
                    },
                    bound_id_prefix: id_prefix,
                    mode: "IdList".to_string(),
                    fingerprint_hex: None,
                    id_count: Some(total),
                    ids: Some(ids),
                    ids_truncated: !capture_full_ids && total > MAX_CAPTURE_IDS,
                });
            }
            other => {
                parse_error = Some(format!("unexpected mode {}", other));
            }
        }
    }

    NegPayloadSummary {
        protocol,
        entry_count: entries.len(),
        skip_count,
        fingerprint_count,
        idlist_count,
        entries,
        parse_error,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_payload_reports_error() {
        let summary = parse_neg_payload(&[], false);
        assert!(summary.parse_error.is_some());
        assert_eq!(summary.entry_count, 0);
    }

    #[test]
    fn protocol_only_payload() {
        let summary = parse_neg_payload(&[1], false);
        assert!(summary.parse_error.is_none());
        assert_eq!(summary.protocol, Some(1));
        assert_eq!(summary.entry_count, 0);
    }

    #[test]
    fn single_skip_entry() {
        // protocol=1, then a skip entry:
        //   ts_enc=0 (varint 0x00 => ts=MAX), id_len=0 (varint 0x00), mode=0 (varint 0x00 => Skip)
        let payload = vec![1, 0x00, 0x00, 0x00];
        let summary = parse_neg_payload(&payload, false);
        assert!(summary.parse_error.is_none(), "{:?}", summary.parse_error);
        assert_eq!(summary.entry_count, 1);
        assert_eq!(summary.skip_count, 1);
        assert_eq!(summary.entries[0].mode, "Skip");
        assert_eq!(summary.entries[0].bound_ts, "MAX");
    }

    #[test]
    fn decode_var_int_simple() {
        let mut data: &[u8] = &[0x05];
        assert_eq!(decode_var_int(&mut data).unwrap(), 5);
        assert!(data.is_empty());
    }

    #[test]
    fn decode_var_int_multibyte() {
        // 300 = 0b100101100 => two 7-bit groups: 0b10 (high), 0b0101100 (low)
        // encoded: 0x82, 0x2C
        let mut data: &[u8] = &[0x82, 0x2C];
        assert_eq!(decode_var_int(&mut data).unwrap(), 300);
        assert!(data.is_empty());
    }

    #[test]
    fn decode_var_int_empty() {
        let mut data: &[u8] = &[];
        assert!(decode_var_int(&mut data).is_err());
    }

    #[test]
    fn take_bytes_basic() {
        let mut data: &[u8] = &[0xAA, 0xBB, 0xCC];
        let out = take_bytes(&mut data, 2).unwrap();
        assert_eq!(out, &[0xAA, 0xBB]);
        assert_eq!(data, &[0xCC]);
    }

    #[test]
    fn take_bytes_insufficient() {
        let mut data: &[u8] = &[0xAA];
        assert!(take_bytes(&mut data, 2).is_err());
    }
}
