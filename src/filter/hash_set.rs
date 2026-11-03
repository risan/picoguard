//! A set of 64-bit name hashes in about 6.2 bytes per hash instead of 8.
//!
//! The hashes are uniformly spread, so sorted neighbours share their top bits. A directory of
//! buckets holds those bits once (a hash belongs to the bucket its top bits name), and each
//! hash keeps only the 48 bits that follow them. A lookup reads one directory slot and
//! compares the few residuals of that bucket, which lie in one or two cache lines.
//!
//! A name that is not in the set matches a residual of its bucket with a chance of about 16 in
//! 2^48 (7e-14), as small as the 64-bit arrays this replaces had (n in 2^64 for a list of
//! 600,000 names).
//!
//! A set can carry a small `TAG` with each hash, in the low `TAG_BITS` bits of the 64-bit value
//! and of the 48-bit residual: the group of a host rule. The hash then has 48 - `TAG_BITS`
//! bits after its bucket.

/// Bits kept of each hash after its bucket bits, tag included.
const RESIDUAL_BITS: u32 = 48;

pub(super) const RESIDUAL_BYTES: usize = 6;

/// The residuals are taken from the bits right after the bucket bits; with at most this many
/// bucket bits they never reach the tag in the low bits of a value.
pub(super) const MAX_BUCKET_BITS: u32 = 16;

/// About this many hashes share a bucket.
const HASHES_PER_BUCKET: usize = 16;

pub(super) type Residual = [u8; RESIDUAL_BYTES];

#[derive(Debug, PartialEq, Eq)]
pub(super) struct HashSet48<const TAG_BITS: u32> {
    bucket_bits: u32,
    /// Where each bucket starts in `residuals`, and the end of the last: `2^bucket_bits + 1`
    /// entries. Empty for an empty set.
    starts: Vec<u32>,
    residuals: Vec<Residual>,
}

impl<const TAG_BITS: u32> Default for HashSet48<TAG_BITS> {
    fn default() -> Self {
        HashSet48 {
            bucket_bits: 0,
            starts: Vec::new(),
            residuals: Vec::new(),
        }
    }
}

impl<const TAG_BITS: u32> HashSet48<TAG_BITS> {
    const HASH_BITS: u32 = RESIDUAL_BITS - TAG_BITS;
    const TAG_MASK: u64 = (1 << TAG_BITS) - 1;

    /// `sorted` is in ascending order, without duplicates. The `TAG_BITS` low bits of a value
    /// are its tag, the rest its hash.
    pub(super) fn from_sorted(sorted: &[u64]) -> Self {
        if sorted.is_empty() {
            return HashSet48::default();
        }

        let bucket_bits = (sorted.len() / HASHES_PER_BUCKET)
            .max(2)
            .ilog2()
            .min(MAX_BUCKET_BITS);
        let mut starts = vec![0u32; (1 << bucket_bits) + 1];
        for &value in sorted {
            starts[Self::bucket_index(bucket_bits, value) + 1] += 1;
        }

        for slot in 1..starts.len() {
            starts[slot] += starts[slot - 1];
        }

        let residuals = sorted
            .iter()
            .map(|&value| Self::residual(bucket_bits, value))
            .collect();

        HashSet48 {
            bucket_bits,
            starts,
            residuals,
        }
    }

    /// The set a snapshot holds, or `None` when the parts cannot be one: a directory that does
    /// not start at zero, decreases, or does not end at the last residual.
    pub(super) fn from_parts(
        bucket_bits: u32,
        starts: Vec<u32>,
        residuals: Vec<Residual>,
    ) -> Option<Self> {
        if residuals.is_empty() {
            return (starts.is_empty() && bucket_bits == 0).then(HashSet48::default);
        }

        let well_formed = (1..=MAX_BUCKET_BITS).contains(&bucket_bits)
            && starts.len() == (1 << bucket_bits) + 1
            && starts.first() == Some(&0)
            && starts.last().map(|&end| end as usize) == Some(residuals.len())
            && starts.windows(2).all(|pair| pair[0] <= pair[1]);

        well_formed.then_some(HashSet48 {
            bucket_bits,
            starts,
            residuals,
        })
    }

    pub(super) fn len(&self) -> usize {
        self.residuals.len()
    }

    pub(super) fn is_empty(&self) -> bool {
        self.residuals.is_empty()
    }

    pub(super) fn bucket_bits(&self) -> u32 {
        self.bucket_bits
    }

    pub(super) fn starts(&self) -> &[u32] {
        &self.starts
    }

    pub(super) fn residuals(&self) -> &[Residual] {
        &self.residuals
    }

    pub(super) fn heap_bytes(&self) -> usize {
        self.starts.capacity() * size_of::<u32>() + self.residuals.capacity() * RESIDUAL_BYTES
    }

    /// True when some value has the hash of `value`, whatever its tag.
    pub(super) fn contains(&self, value: u64) -> bool {
        let wanted = self.hash_part(value);

        self.bucket(value)
            .iter()
            .any(|&residual| Self::decode(residual) >> TAG_BITS == wanted)
    }

    /// The tags of the values that have the hash of `value`, in the order they were stored.
    pub(super) fn tags_of(&self, value: u64) -> impl Iterator<Item = u64> + '_ {
        let wanted = self.hash_part(value);

        self.bucket(value).iter().filter_map(move |&residual| {
            let residual = Self::decode(residual);

            (residual >> TAG_BITS == wanted).then_some(residual & Self::TAG_MASK)
        })
    }

    /// The tag of every value.
    pub(super) fn all_tags(&self) -> impl Iterator<Item = u64> + '_ {
        self.residuals
            .iter()
            .map(|&residual| Self::decode(residual) & Self::TAG_MASK)
    }

    fn bucket(&self, value: u64) -> &[Residual] {
        if self.residuals.is_empty() {
            return &[];
        }

        let slot = Self::bucket_index(self.bucket_bits, value);

        &self.residuals[self.starts[slot] as usize..self.starts[slot + 1] as usize]
    }

    fn bucket_index(bucket_bits: u32, value: u64) -> usize {
        (value >> (64 - bucket_bits)) as usize
    }

    /// The hash bits right after the bucket bits.
    fn hash_part(&self, value: u64) -> u64 {
        (value << self.bucket_bits) >> (64 - Self::HASH_BITS)
    }

    fn residual(bucket_bits: u32, value: u64) -> Residual {
        let hash_part = (value << bucket_bits) >> (64 - Self::HASH_BITS);
        let bytes = ((hash_part << TAG_BITS) | (value & Self::TAG_MASK)).to_le_bytes();

        [bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]]
    }

    fn decode(residual: Residual) -> u64 {
        u64::from_le_bytes([
            residual[0],
            residual[1],
            residual[2],
            residual[3],
            residual[4],
            residual[5],
            0,
            0,
        ])
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn splitmix(state: &mut u64) -> u64 {
        *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = *state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);

        z ^ (z >> 31)
    }

    fn sorted_distinct(mut values: Vec<u64>) -> Vec<u64> {
        values.sort_unstable();
        values.dedup();

        values
    }

    /// The set agrees with a binary search on every member and on unrelated probes. A probe
    /// that shares a member's hash bits but not its low ones is a legitimate false match, so
    /// only independent random probes are compared.
    fn assert_agrees_with_binary_search(sorted: &[u64], state: &mut u64) {
        let set = HashSet48::<0>::from_sorted(sorted);

        assert_eq!(set.len(), sorted.len());
        for value in sorted {
            assert!(set.contains(*value), "member {value:x} of {}", sorted.len());
        }

        for _ in 0..2000 {
            let probe = splitmix(state);

            assert_eq!(
                set.contains(probe),
                sorted.binary_search(&probe).is_ok(),
                "probe {probe:x} on {} members",
                sorted.len()
            );
        }
    }

    #[test]
    fn sets_of_every_size_agree_with_a_binary_search() {
        let mut state = 7;
        for size in [0, 1, 2, 3, 31, 32, 33, 100, 1000, 100_000] {
            let sorted = sorted_distinct((0..size).map(|_| splitmix(&mut state)).collect());

            assert_agrees_with_binary_search(&sorted, &mut state);
        }
    }

    #[test]
    fn a_set_whose_values_all_share_a_bucket_still_finds_them() {
        let mut state = 11;
        let sorted = sorted_distinct(
            (0..5000)
                .map(|_| splitmix(&mut state) & 0x0000_ffff_ffff_ffff)
                .collect(),
        );
        let set = HashSet48::<0>::from_sorted(&sorted);

        assert_eq!(set.starts()[1], sorted.len() as u32);
        assert_agrees_with_binary_search(&sorted, &mut state);
    }

    #[test]
    fn a_set_with_the_most_buckets_stays_in_bounds() {
        let mut state = 13;
        let sorted = sorted_distinct((0..1_200_000).map(|_| splitmix(&mut state)).collect());
        let set = HashSet48::<0>::from_sorted(&sorted);

        assert_eq!(set.bucket_bits(), MAX_BUCKET_BITS);
        assert_agrees_with_binary_search(&sorted, &mut state);
    }

    #[test]
    fn extreme_values_are_found() {
        let sorted = vec![0, 1, u64::MAX >> 1, u64::MAX - 1, u64::MAX];
        let set = HashSet48::<0>::from_sorted(&sorted);

        for value in &sorted {
            assert!(set.contains(*value));
        }

        assert!(!set.contains(1 << 40));
    }

    #[test]
    fn a_set_is_about_six_bytes_a_hash() {
        let mut state = 17;
        let sorted = sorted_distinct((0..620_000).map(|_| splitmix(&mut state)).collect());
        let set = HashSet48::<0>::from_sorted(&sorted);
        let per_hash = set.heap_bytes() as f64 / sorted.len() as f64;

        assert!(per_hash < 6.5, "{per_hash} bytes a hash");
    }

    #[test]
    fn tagged_values_give_back_their_tags_in_order() {
        const GROUP_BITS: u32 = 10;
        let mut state = 19;
        let mut values = Vec::new();
        let mut hashes = Vec::new();
        for _ in 0..3000 {
            let hash = splitmix(&mut state) & !((1 << GROUP_BITS) - 1);
            hashes.push(hash);
            let groups = splitmix(&mut state) % 4;
            for group in 0..=groups {
                values.push(hash | (group * 255 + 3));
            }
        }

        let values = sorted_distinct(values);
        let set = HashSet48::<GROUP_BITS>::from_sorted(&values);

        for hash in hashes {
            let expected: Vec<u64> = values
                .iter()
                .filter(|&&value| value & !((1 << GROUP_BITS) - 1) == hash)
                .map(|&value| value & ((1 << GROUP_BITS) - 1))
                .collect();

            assert_eq!(set.tags_of(hash | 5).collect::<Vec<_>>(), expected);
            assert!(set.contains(hash));
        }

        assert_eq!(set.tags_of(splitmix(&mut state)).count(), 0);
        assert_eq!(set.all_tags().count(), values.len());
    }

    #[test]
    fn parts_that_cannot_be_a_set_are_refused() {
        let mut state = 23;
        let sorted = sorted_distinct((0..500).map(|_| splitmix(&mut state)).collect());
        let set = HashSet48::<0>::from_sorted(&sorted);
        let parts = |starts: Vec<u32>, bits| {
            HashSet48::<0>::from_parts(bits, starts, set.residuals().to_vec())
        };

        assert_eq!(
            parts(set.starts().to_vec(), set.bucket_bits()).as_ref(),
            Some(&set)
        );
        assert!(parts(set.starts().to_vec(), set.bucket_bits() + 1).is_none());
        assert!(parts(set.starts()[1..].to_vec(), set.bucket_bits()).is_none());

        let mut starts = set.starts().to_vec();
        starts[2] = starts[1].saturating_sub(1);
        starts[1] = starts[3];
        assert!(parts(starts, set.bucket_bits()).is_none());

        let mut starts = set.starts().to_vec();
        *starts.last_mut().unwrap() += 1;
        assert!(parts(starts, set.bucket_bits()).is_none());

        assert_eq!(
            HashSet48::<0>::from_parts(0, Vec::new(), Vec::new()),
            Some(HashSet48::default())
        );
        assert!(HashSet48::<0>::from_parts(3, vec![0; 9], Vec::new()).is_none());
    }

    proptest! {
        #[test]
        fn small_sets_agree_with_a_binary_search(
            values in proptest::collection::vec(any::<u64>(), 0..300),
            seed in any::<u64>(),
        ) {
            let sorted = sorted_distinct(values);
            let mut state = seed;

            assert_agrees_with_binary_search(&sorted, &mut state);
        }

        #[test]
        fn small_sets_that_share_their_top_bits_agree_with_a_binary_search(
            values in proptest::collection::vec(any::<u64>(), 0..300),
            top_bits in 0u32..40,
            seed in any::<u64>(),
        ) {
            let sorted = sorted_distinct(values.into_iter().map(|value| value >> top_bits).collect());
            let mut state = seed;

            assert_agrees_with_binary_search(&sorted, &mut state);
        }
    }
}
