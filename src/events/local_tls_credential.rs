use super::registry::{EventTypeMeta, ShareScope};
use super::{EventError, ParsedEvent, EVENT_TYPE_LOCAL_TLS_CREDENTIAL};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalTlsCredentialEvent {
    pub created_at_ms: u64,
    pub cert_der: Vec<u8>,
    pub key_der: Vec<u8>,
}

/// Wire format (variable length, min 13 bytes):
/// [0]           type_code = 27
/// [1..9]        created_at_ms (u64 LE)
/// [9..11]       cert_len (u16 LE)
/// [11..11+C]    cert_der (C bytes)
/// [11+C..13+C]  key_len (u16 LE)
/// [13+C..13+C+K] key_der (K bytes)
/// No signature trailer.
pub fn parse_local_tls_credential(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    if blob.len() < 13 {
        return Err(EventError::TooShort {
            expected: 13,
            actual: blob.len(),
        });
    }
    if blob[0] != EVENT_TYPE_LOCAL_TLS_CREDENTIAL {
        return Err(EventError::WrongType {
            expected: EVENT_TYPE_LOCAL_TLS_CREDENTIAL,
            actual: blob[0],
        });
    }

    let created_at_ms = u64::from_le_bytes(blob[1..9].try_into().unwrap());

    let cert_len = u16::from_le_bytes(blob[9..11].try_into().unwrap()) as usize;
    let cert_end = 11 + cert_len;
    if blob.len() < cert_end + 2 {
        return Err(EventError::TooShort {
            expected: cert_end + 2,
            actual: blob.len(),
        });
    }

    let cert_der = blob[11..cert_end].to_vec();

    let key_len =
        u16::from_le_bytes(blob[cert_end..cert_end + 2].try_into().unwrap()) as usize;
    let key_end = cert_end + 2 + key_len;
    if blob.len() < key_end {
        return Err(EventError::TooShort {
            expected: key_end,
            actual: blob.len(),
        });
    }
    if blob.len() > key_end {
        return Err(EventError::TooShort {
            expected: key_end,
            actual: blob.len(),
        });
    }

    let key_der = blob[cert_end + 2..key_end].to_vec();

    Ok(ParsedEvent::LocalTlsCredential(LocalTlsCredentialEvent {
        created_at_ms,
        cert_der,
        key_der,
    }))
}

pub fn encode_local_tls_credential(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let cred = match event {
        ParsedEvent::LocalTlsCredential(c) => c,
        _ => return Err(EventError::WrongVariant),
    };

    if cred.cert_der.len() > u16::MAX as usize {
        return Err(EventError::ContentTooLong(cred.cert_der.len()));
    }
    if cred.key_der.len() > u16::MAX as usize {
        return Err(EventError::ContentTooLong(cred.key_der.len()));
    }

    let total = 1 + 8 + 2 + cred.cert_der.len() + 2 + cred.key_der.len();
    let mut buf = Vec::with_capacity(total);
    buf.push(EVENT_TYPE_LOCAL_TLS_CREDENTIAL);
    buf.extend_from_slice(&cred.created_at_ms.to_le_bytes());
    buf.extend_from_slice(&(cred.cert_der.len() as u16).to_le_bytes());
    buf.extend_from_slice(&cred.cert_der);
    buf.extend_from_slice(&(cred.key_der.len() as u16).to_le_bytes());
    buf.extend_from_slice(&cred.key_der);
    Ok(buf)
}

pub static LOCAL_TLS_CREDENTIAL_META: EventTypeMeta = EventTypeMeta {
    type_code: EVENT_TYPE_LOCAL_TLS_CREDENTIAL,
    type_name: "local_tls_credential",
    projection_table: "local_tls_credentials",
    share_scope: ShareScope::Local,
    dep_fields: &[],
    dep_field_type_codes: &[],
    signer_required: false,
    signature_byte_len: 0,
    parse: parse_local_tls_credential,
    encode: encode_local_tls_credential,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{encode_event, parse_event, registry};

    #[test]
    fn test_roundtrip() {
        // Use realistic-ish cert/key DER blobs
        let cert_der = vec![0x30; 256];
        let key_der = vec![0x82; 128];

        let event = ParsedEvent::LocalTlsCredential(LocalTlsCredentialEvent {
            created_at_ms: 1700000000000,
            cert_der: cert_der.clone(),
            key_der: key_der.clone(),
        });

        let blob = encode_event(&event).unwrap();
        let parsed = parse_event(&blob).unwrap();
        assert_eq!(parsed, event);

        if let ParsedEvent::LocalTlsCredential(cred) = &parsed {
            assert_eq!(cred.created_at_ms, 1700000000000);
            assert_eq!(cred.cert_der, cert_der);
            assert_eq!(cred.key_der, key_der);
        } else {
            panic!("expected LocalTlsCredential variant");
        }
    }

    #[test]
    fn test_trailing_data_rejected() {
        let event = ParsedEvent::LocalTlsCredential(LocalTlsCredentialEvent {
            created_at_ms: 100,
            cert_der: vec![1, 2, 3],
            key_der: vec![4, 5],
        });
        let mut blob = encode_event(&event).unwrap();
        blob.push(0xFF); // trailing byte
        let result = parse_event(&blob);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_cert_and_key() {
        let event = ParsedEvent::LocalTlsCredential(LocalTlsCredentialEvent {
            created_at_ms: 42,
            cert_der: vec![],
            key_der: vec![],
        });
        let blob = encode_event(&event).unwrap();
        assert_eq!(blob.len(), 13); // 1 + 8 + 2 + 0 + 2 + 0
        let parsed = parse_event(&blob).unwrap();
        assert_eq!(parsed, event);
    }

    #[test]
    fn test_registry_lookup() {
        let reg = registry();
        let meta = reg.lookup(EVENT_TYPE_LOCAL_TLS_CREDENTIAL).unwrap();
        assert_eq!(meta.type_name, "local_tls_credential");
        assert_eq!(meta.projection_table, "local_tls_credentials");
        assert_eq!(meta.share_scope, ShareScope::Local);
        assert!(!meta.signer_required);
        assert_eq!(meta.signature_byte_len, 0);
        assert_eq!(meta.dep_fields.len(), 0);
    }
}
