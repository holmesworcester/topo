use alloc::collections::BTreeSet;
use alloc::vec::Vec;
use core::convert::{TryFrom, TryInto};

use crate::storage::Storage;
use crate::types::{Bound, Fingerprint, Item};
use crate::{Error, Id};

const DEP_RECONCILE_PROTOCOL_VERSION: u8 = 1;
const BUCKETS: usize = 16;
const DOUBLE_BUCKETS: usize = BUCKETS * 2;
const MODE_FINGERPRINT: u8 = 1;
const MODE_EXACT: u8 = 2;

/// Exact dep-aware diff accumulated across reconciliation rounds.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DepReconcileDiff {
    /// Root IDs present locally but missing remotely.
    pub have_root_ids: Vec<Id>,
    /// Root IDs present remotely but missing locally.
    pub need_root_ids: Vec<Id>,
    /// Local roots from exact mismatched slices whose dependency closures
    /// should be probed in phase 2.
    pub dep_probe_root_ids: Vec<Id>,
}

/// Range-bounded storage for dep-aware reconciliation.
pub trait DepReconcileRangeStorage {
    /// Number of root items in timestamp order.
    fn root_size(&self) -> Result<usize, Error>;
    /// Root item at the given index.
    fn get_root_item(&self, i: usize) -> Result<Option<Item>, Error>;
    /// Binary-search lower bound by negentropy bound.
    fn find_lower_bound(&self, first: usize, last: usize, value: &Bound) -> usize;
    /// Fingerprint of the requested root slice, including the roots
    /// themselves plus their recursive dependency contribution.
    fn combined_fingerprint(&self, begin: usize, end: usize) -> Result<Fingerprint, Error>;
    /// Exact root IDs for the requested slice.
    fn root_ids(&self, begin: usize, end: usize) -> Result<Vec<Id>, Error>;
}

/// Two-mode dep-aware reconciler over root ranges plus dependency closures.
#[derive(Debug)]
pub struct DepReconciler<'a, T> {
    storage: Storage<'a, T>,
    is_initiator: bool,
}

impl<'a, T> DepReconciler<'a, T>
where
    T: DepReconcileRangeStorage,
{
    /// Create a reconciler from owned or borrowed storage.
    pub fn new(storage: Storage<'a, T>) -> Self {
        Self {
            storage,
            is_initiator: false,
        }
    }

    /// Create a reconciler that owns its storage.
    pub fn owned(storage: T) -> Self {
        Self::new(Storage::Owned(storage))
    }

    /// Create a reconciler borrowing external storage.
    pub fn borrowed(storage: &'a T) -> Self {
        Self::new(Storage::Borrowed(storage))
    }

    /// Build the initial initiator query.
    pub fn initiate(&mut self) -> Result<Vec<u8>, Error> {
        if self.is_initiator {
            return Err(Error::AlreadyBuiltInitialMessage);
        }
        self.is_initiator = true;

        let mut output = Vec::new();
        output.push(DEP_RECONCILE_PROTOCOL_VERSION);
        output.extend(self.split_range(
            0,
            self.storage.root_size()?,
            Bound::with_timestamp(u64::MAX),
        )?);
        Ok(output)
    }

    /// Reconcile a responder message on the initiator side.
    pub fn reconcile_with_ids(
        &mut self,
        query: &[u8],
        diff: &mut DepReconcileDiff,
    ) -> Result<Option<Vec<u8>>, Error> {
        if !self.is_initiator {
            return Err(Error::NonInitiator);
        }

        let output = self.reconcile_aux(query, diff)?;
        if output.len() == 1 {
            return Ok(None);
        }
        Ok(Some(output))
    }

    /// Reconcile an initiator message on the responder side.
    pub fn reconcile_with_diff(
        &mut self,
        query: &[u8],
        diff: &mut DepReconcileDiff,
    ) -> Result<Vec<u8>, Error> {
        if self.is_initiator {
            return Err(Error::Initiator);
        }
        self.reconcile_aux(query, diff)
    }

    fn reconcile_aux(
        &mut self,
        mut query: &[u8],
        diff: &mut DepReconcileDiff,
    ) -> Result<Vec<u8>, Error> {
        let Some(protocol_version) = query.first().copied() else {
            return Err(Error::ProtocolVersionNotFound);
        };
        if protocol_version != DEP_RECONCILE_PROTOCOL_VERSION {
            return Err(Error::InvalidProtocolVersion);
        }
        query = &query[1..];

        let storage_size = self.storage.root_size()?;
        let mut prev_index = 0usize;
        let mut full_output = vec![DEP_RECONCILE_PROTOCOL_VERSION];

        while !query.is_empty() {
            let curr_bound = decode_bound(&mut query)?;
            let mode = take_u8(&mut query)?;
            let lower = prev_index;
            let upper = self
                .storage
                .find_lower_bound(prev_index, storage_size, &curr_bound);

            match mode {
                MODE_FINGERPRINT => {
                    let their_combined_fp = decode_fingerprint(&mut query)?;
                    let our_combined_fp = self.storage.combined_fingerprint(lower, upper)?;

                    if their_combined_fp != our_combined_fp.to_bytes() {
                        full_output.extend(self.split_range(lower, upper, curr_bound)?);
                    } else if !self.is_initiator {
                        full_output.extend(encode_fingerprint_entry(&curr_bound, &our_combined_fp));
                    }
                }
                MODE_EXACT => {
                    let their_combined_fp = decode_fingerprint(&mut query)?;
                    let their_root_ids = decode_id_vec(&mut query)?;
                    let our_root_ids = self.storage.root_ids(lower, upper)?;
                    let our_combined_fp = self.storage.combined_fingerprint(lower, upper)?;

                    diff_exact_ids(
                        &our_root_ids,
                        &their_root_ids,
                        &mut diff.have_root_ids,
                        &mut diff.need_root_ids,
                    );
                    if their_combined_fp != our_combined_fp.to_bytes() {
                        diff.dep_probe_root_ids.extend(our_root_ids.iter().copied());
                    }

                    if !self.is_initiator {
                        full_output.extend(encode_exact_entry(
                            &curr_bound,
                            &our_combined_fp,
                            &our_root_ids,
                        )?);
                    }
                }
                other => return Err(Error::UnexpectedMode(other as u64)),
            }

            prev_index = upper;
        }

        Ok(full_output)
    }

    fn split_range(
        &self,
        lower: usize,
        upper: usize,
        upper_bound: Bound,
    ) -> Result<Vec<u8>, Error> {
        let num_roots = upper.saturating_sub(lower);
        if num_roots == 0 {
            let combined_fp = self.storage.combined_fingerprint(lower, upper)?;
            return Ok(encode_exact_entry(&upper_bound, &combined_fp, &[])?);
        }
        if num_roots < DOUBLE_BUCKETS {
            let root_ids = self.storage.root_ids(lower, upper)?;
            let combined_fp = self.storage.combined_fingerprint(lower, upper)?;
            return encode_exact_entry(&upper_bound, &combined_fp, &root_ids);
        }

        let mut output = Vec::new();
        let items_per_bucket = num_roots / BUCKETS;
        let buckets_with_extra = num_roots % BUCKETS;
        let mut curr = lower;
        for i in 0..BUCKETS {
            let bucket_size = items_per_bucket + usize::from(i < buckets_with_extra);
            if bucket_size == 0 {
                continue;
            }
            let bucket_upper = curr + bucket_size;
            let combined_fp = self.storage.combined_fingerprint(curr, bucket_upper)?;
            let next_bound = if bucket_upper == upper {
                upper_bound
            } else {
                let Some(item) = self.storage.get_root_item(bucket_upper)? else {
                    return Err(Error::BadRange);
                };
                Bound::from_item(&item)
            };
            output.extend(encode_fingerprint_entry(&next_bound, &combined_fp));
            curr = bucket_upper;
        }
        Ok(output)
    }
}

fn diff_exact_ids(ours: &[Id], theirs: &[Id], have_out: &mut Vec<Id>, need_out: &mut Vec<Id>) {
    let mut their_ids = BTreeSet::new();
    for id in theirs {
        their_ids.insert(*id);
    }

    for id in ours {
        if !their_ids.remove(id) {
            have_out.push(*id);
        }
    }

    for id in their_ids {
        need_out.push(id);
    }
}

fn encode_fingerprint_entry(bound: &Bound, combined_fp: &Fingerprint) -> Vec<u8> {
    let mut output = encode_bound(bound);
    output.push(MODE_FINGERPRINT);
    output.extend(combined_fp.to_bytes());
    output
}

fn encode_exact_entry(
    bound: &Bound,
    combined_fp: &Fingerprint,
    root_ids: &[Id],
) -> Result<Vec<u8>, Error> {
    let mut output = encode_bound(bound);
    output.push(MODE_EXACT);
    output.extend(combined_fp.to_bytes());
    output.extend(encode_id_vec(root_ids)?);
    Ok(output)
}

fn encode_id_vec(ids: &[Id]) -> Result<Vec<u8>, Error> {
    let mut output = Vec::new();
    output.extend(
        u32::try_from(ids.len())
            .map_err(|_| Error::BadRange)?
            .to_le_bytes(),
    );
    for id in ids {
        output.extend(id.iter());
    }
    Ok(output)
}

fn decode_id_vec(input: &mut &[u8]) -> Result<Vec<Id>, Error> {
    let count = decode_u32(input)? as usize;
    let mut ids = Vec::with_capacity(count);
    for _ in 0..count {
        let id_bytes: [u8; 32] = take_bytes(input, 32)?.try_into()?;
        ids.push(Id::from_byte_array(id_bytes));
    }
    Ok(ids)
}

fn encode_bound(bound: &Bound) -> Vec<u8> {
    let mut output = Vec::with_capacity(8 + 1 + bound.id_len);
    output.extend(bound.item.timestamp.to_le_bytes());
    output.push(bound.id_len as u8);
    output.extend(&bound.item.id[..bound.id_len]);
    output
}

fn decode_bound(input: &mut &[u8]) -> Result<Bound, Error> {
    let timestamp = u64::from_le_bytes(take_bytes(input, 8)?.try_into()?);
    let id_len = take_u8(input)? as usize;
    let id = take_bytes(input, id_len)?;
    Bound::with_timestamp_and_id(timestamp, id)
}

fn decode_fingerprint(input: &mut &[u8]) -> Result<[u8; 16], Error> {
    take_bytes(input, 16)?.try_into().map_err(Into::into)
}

fn decode_u32(input: &mut &[u8]) -> Result<u32, Error> {
    Ok(u32::from_le_bytes(take_bytes(input, 4)?.try_into()?))
}

fn take_u8(input: &mut &[u8]) -> Result<u8, Error> {
    Ok(take_bytes(input, 1)?[0])
}

fn take_bytes<'a>(input: &mut &'a [u8], len: usize) -> Result<&'a [u8], Error> {
    if input.len() < len {
        return Err(Error::ParseEndsPrematurely);
    }
    let out = &input[..len];
    *input = &input[len..];
    Ok(out)
}
