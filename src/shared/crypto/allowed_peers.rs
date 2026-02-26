use std::collections::HashSet;

/// Set of allowed peer SPKI fingerprints (BLAKE2b-256).
#[derive(Debug, Clone)]
pub struct AllowedPeers {
    fingerprints: HashSet<[u8; 32]>,
}

impl AllowedPeers {
    /// Build from a list of hex-encoded fingerprints.
    pub fn from_hex_strings(
        hexes: &[String],
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let mut fingerprints = HashSet::new();
        for h in hexes {
            let bytes = hex::decode(h)?;
            if bytes.len() != 32 {
                return Err(format!("fingerprint must be 32 bytes, got {}", bytes.len()).into());
            }
            let mut fp = [0u8; 32];
            fp.copy_from_slice(&bytes);
            fingerprints.insert(fp);
        }
        Ok(Self { fingerprints })
    }

    /// Build from raw fingerprints.
    pub fn from_fingerprints(fps: Vec<[u8; 32]>) -> Self {
        Self {
            fingerprints: fps.into_iter().collect(),
        }
    }

    pub fn contains(&self, fp: &[u8; 32]) -> bool {
        self.fingerprints.contains(fp)
    }

    /// Return a new AllowedPeers that is the union of self and other.
    pub fn union(&self, other: &AllowedPeers) -> AllowedPeers {
        let mut combined = self.fingerprints.clone();
        for fp in &other.fingerprints {
            combined.insert(*fp);
        }
        AllowedPeers {
            fingerprints: combined,
        }
    }

    pub fn len(&self) -> usize {
        self.fingerprints.len()
    }

    pub fn is_empty(&self) -> bool {
        self.fingerprints.is_empty()
    }

    /// Return a copy of all fingerprints as a Vec.
    pub fn fingerprints(&self) -> Vec<[u8; 32]> {
        self.fingerprints.iter().copied().collect()
    }
}

