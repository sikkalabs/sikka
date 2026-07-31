//! Sparse Merkle Tree over the 256-bit address space.
//!
//! The state root is what consensus secures, so this tree has to satisfy three
//! properties at once:
//!
//! * **Canonical** — the root depends only on the set of leaves, never on the
//!   order they were inserted or removed in. Two nodes that reach the same
//!   state must compute the same root, or the chain halts.
//! * **Cheap to update** — a transaction touches two accounts, and updating a
//!   leaf costs one hash per level of *actual* depth (≈ log₂(accounts)), not 256.
//! * **Provable** — a stateless wallet can be handed a leaf plus a sibling path
//!   and check it against a signed checkpoint.
//!
//! Empty subtrees collapse rather than being padded down to depth 256 (the
//! structure a naive SMT would build), which is what keeps updates logarithmic.
//! A leaf commits to its own key, so its position cannot be forged even though
//! its depth is not fixed.

use sikka_common::bytes::Hash;
use sikka_common::codec::{Decode, Encode, Reader, Writer};
use sikka_common::error::{Error, Result};

/// Domain tag for leaf hashes.
pub const SMT_LEAF_TAG: &[u8] = b"SIKKA/smt-leaf/v1";
/// Domain tag for internal node hashes.
pub const SMT_NODE_TAG: &[u8] = b"SIKKA/smt-node/v1";

/// The hash of an empty subtree.
pub const EMPTY_HASH: Hash = Hash([0u8; 32]);

/// Maximum tree depth: keys are 256-bit.
pub const MAX_DEPTH: usize = 256;

/// A 256-bit tree key (an address).
pub type Key = [u8; 32];

/// Bit `index` of `key`, most significant first.
fn bit(key: &Key, index: usize) -> bool {
    (key[index / 8] >> (7 - (index % 8))) & 1 == 1
}

/// Leaf hash: `SHA3-256(tag || key || value)`.
pub fn leaf_hash(key: &Key, value: &Hash) -> Hash {
    Hash::digest(&[SMT_LEAF_TAG, key, value.as_bytes()])
}

/// Internal node hash: `SHA3-256(tag || left || right)`.
pub fn node_hash(left: &Hash, right: &Hash) -> Hash {
    Hash::digest(&[SMT_NODE_TAG, left.as_bytes(), right.as_bytes()])
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
enum Node {
    #[default]
    Empty,
    Leaf {
        key: Key,
        value: Hash,
        hash: Hash,
    },
    Internal {
        left: Box<Node>,
        right: Box<Node>,
        hash: Hash,
    },
}

impl Node {
    fn leaf(key: Key, value: Hash) -> Self {
        let hash = leaf_hash(&key, &value);
        Node::Leaf { key, value, hash }
    }

    fn internal(left: Node, right: Node) -> Self {
        let hash = node_hash(&left.hash(), &right.hash());
        Node::Internal {
            left: Box::new(left),
            right: Box::new(right),
            hash,
        }
    }

    fn hash(&self) -> Hash {
        match self {
            Node::Empty => EMPTY_HASH,
            Node::Leaf { hash, .. } => *hash,
            Node::Internal { hash, .. } => *hash,
        }
    }

    /// Rebuild an internal node, collapsing it if it no longer needs to exist.
    ///
    /// This is what keeps the tree canonical: an internal node with a single
    /// leaf below it is indistinguishable from that leaf, so it must not be
    /// kept, or removing a leaf would leave a different shape (and root) than
    /// never having inserted it.
    fn join(left: Node, right: Node) -> Self {
        match (&left, &right) {
            (Node::Empty, Node::Empty) => Node::Empty,
            (Node::Leaf { .. }, Node::Empty) => left,
            (Node::Empty, Node::Leaf { .. }) => right,
            _ => Node::internal(left, right),
        }
    }
}

/// Split two distinct keys into the shallowest subtree that separates them.
fn split(depth: usize, a: (Key, Hash), b: (Key, Hash)) -> Node {
    debug_assert!(
        depth < MAX_DEPTH,
        "distinct 256-bit keys must differ within 256 bits"
    );
    let a_bit = bit(&a.0, depth);
    let b_bit = bit(&b.0, depth);
    if a_bit != b_bit {
        let (left, right) = if a_bit {
            (Node::leaf(b.0, b.1), Node::leaf(a.0, a.1))
        } else {
            (Node::leaf(a.0, a.1), Node::leaf(b.0, b.1))
        };
        Node::internal(left, right)
    } else {
        let child = split(depth + 1, a, b);
        if a_bit {
            Node::internal(Node::Empty, child)
        } else {
            Node::internal(child, Node::Empty)
        }
    }
}

/// A Sparse Merkle Tree held in memory.
///
/// Persistence lives in the account store; the tree is rebuilt from leaves on
/// startup, which is fast because it is a pure hash computation and needs no
/// signature checks.
#[derive(Debug, Clone, Default)]
pub struct Smt {
    root: Node,
    len: usize,
}

impl Smt {
    pub fn new() -> Self {
        Self {
            root: Node::Empty,
            len: 0,
        }
    }

    /// Build a tree from an iterator of leaves.
    pub fn from_leaves<I: IntoIterator<Item = (Key, Hash)>>(leaves: I) -> Self {
        let mut smt = Smt::new();
        for (key, value) in leaves {
            smt.insert(key, value);
        }
        smt
    }

    /// The state root. An empty tree hashes to all zeroes.
    pub fn root(&self) -> Hash {
        self.root.hash()
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn get(&self, key: &Key) -> Option<Hash> {
        let mut node = &self.root;
        let mut depth = 0;
        loop {
            match node {
                Node::Empty => return None,
                Node::Leaf { key: k, value, .. } => {
                    return if k == key { Some(*value) } else { None }
                }
                Node::Internal { left, right, .. } => {
                    node = if bit(key, depth) { right } else { left };
                    depth += 1;
                }
            }
        }
    }

    /// Insert or overwrite a leaf, returning the previous value.
    pub fn insert(&mut self, key: Key, value: Hash) -> Option<Hash> {
        let root = std::mem::take(&mut self.root);
        let (root, previous) = Self::insert_at(root, 0, key, value);
        self.root = root;
        if previous.is_none() {
            self.len += 1;
        }
        previous
    }

    fn insert_at(node: Node, depth: usize, key: Key, value: Hash) -> (Node, Option<Hash>) {
        match node {
            Node::Empty => (Node::leaf(key, value), None),
            Node::Leaf {
                key: existing_key,
                value: existing_value,
                ..
            } => {
                if existing_key == key {
                    (Node::leaf(key, value), Some(existing_value))
                } else {
                    (
                        split(depth, (existing_key, existing_value), (key, value)),
                        None,
                    )
                }
            }
            Node::Internal { left, right, .. } => {
                if bit(&key, depth) {
                    let (right, previous) = Self::insert_at(*right, depth + 1, key, value);
                    (Node::join(*left, right), previous)
                } else {
                    let (left, previous) = Self::insert_at(*left, depth + 1, key, value);
                    (Node::join(left, *right), previous)
                }
            }
        }
    }

    /// Remove a leaf, returning its previous value.
    pub fn remove(&mut self, key: &Key) -> Option<Hash> {
        let root = std::mem::take(&mut self.root);
        let (root, previous) = Self::remove_at(root, 0, key);
        self.root = root;
        if previous.is_some() {
            self.len -= 1;
        }
        previous
    }

    fn remove_at(node: Node, depth: usize, key: &Key) -> (Node, Option<Hash>) {
        match node {
            Node::Empty => (Node::Empty, None),
            Node::Leaf {
                key: existing_key,
                value,
                hash,
            } => {
                if &existing_key == key {
                    (Node::Empty, Some(value))
                } else {
                    (
                        Node::Leaf {
                            key: existing_key,
                            value,
                            hash,
                        },
                        None,
                    )
                }
            }
            Node::Internal { left, right, .. } => {
                if bit(key, depth) {
                    let (right, previous) = Self::remove_at(*right, depth + 1, key);
                    (Node::join(*left, right), previous)
                } else {
                    let (left, previous) = Self::remove_at(*left, depth + 1, key);
                    (Node::join(left, *right), previous)
                }
            }
        }
    }

    /// Apply a batch of updates, returning an undo log.
    ///
    /// `None` removes the leaf. The undo log restores the exact previous tree
    /// (and therefore the exact previous root), which is what lets a validator
    /// speculatively execute a proposed checkpoint, compare roots, and back the
    /// change out if it disagrees.
    pub fn apply(&mut self, updates: &[(Key, Option<Hash>)]) -> UndoLog {
        let mut undo = Vec::with_capacity(updates.len());
        for (key, value) in updates {
            let previous = match value {
                Some(value) => self.insert(*key, *value),
                None => self.remove(key),
            };
            undo.push((*key, previous));
        }
        UndoLog(undo)
    }

    /// Roll back a batch applied with [`Smt::apply`].
    pub fn revert(&mut self, undo: UndoLog) {
        for (key, previous) in undo.0.into_iter().rev() {
            match previous {
                Some(value) => {
                    self.insert(key, value);
                }
                None => {
                    self.remove(&key);
                }
            }
        }
    }

    /// All leaves, in tree order (which is ascending key order).
    pub fn leaves(&self) -> Vec<(Key, Hash)> {
        let mut out = Vec::with_capacity(self.len);
        collect(&self.root, &mut out);
        out
    }

    /// Build an inclusion (or absence) proof for `key`.
    pub fn proof(&self, key: &Key) -> Proof {
        let mut siblings = Vec::new();
        let mut node = &self.root;
        let mut depth = 0;
        loop {
            match node {
                Node::Empty => {
                    return Proof {
                        siblings,
                        leaf: None,
                    }
                }
                Node::Leaf { key: k, value, .. } => {
                    return Proof {
                        siblings,
                        leaf: Some(ProofLeaf {
                            key: *k,
                            value: *value,
                        }),
                    }
                }
                Node::Internal { left, right, .. } => {
                    if bit(key, depth) {
                        siblings.push(left.hash());
                        node = right;
                    } else {
                        siblings.push(right.hash());
                        node = left;
                    }
                    depth += 1;
                }
            }
        }
    }
}

fn collect(node: &Node, out: &mut Vec<(Key, Hash)>) {
    match node {
        Node::Empty => {}
        Node::Leaf { key, value, .. } => out.push((*key, *value)),
        Node::Internal { left, right, .. } => {
            collect(left, out);
            collect(right, out);
        }
    }
}

/// Undo information produced by [`Smt::apply`].
#[derive(Debug, Clone, Default)]
pub struct UndoLog(Vec<(Key, Option<Hash>)>);

impl UndoLog {
    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// The leaf a proof terminates at.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ProofLeaf {
    #[serde(with = "key_hex")]
    pub key: Key,
    pub value: Hash,
}

/// A Merkle path from a leaf position up to the root.
///
/// `siblings` is ordered root-first. `leaf` is the leaf actually found at the
/// end of the path: it is the queried key for an inclusion proof, a *different*
/// key for an absence proof that ran into an unrelated leaf, and `None` for an
/// absence proof that ran into an empty subtree.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Proof {
    pub siblings: Vec<Hash>,
    pub leaf: Option<ProofLeaf>,
}

mod key_hex {
    use super::Key;
    use serde::de::Error as _;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(key: &Key, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&format!("0x{}", hex::encode(key)))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Key, D::Error> {
        let s = String::deserialize(d)?;
        let bytes = hex::decode(s.strip_prefix("0x").unwrap_or(&s)).map_err(D::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| D::Error::custom("expected 32 bytes"))
    }
}

impl Proof {
    /// Fold the sibling path back up to a root, starting from `start`.
    fn fold(&self, key: &Key, start: Hash) -> Hash {
        let mut current = start;
        for depth in (0..self.siblings.len()).rev() {
            let sibling = self.siblings[depth];
            current = if bit(key, depth) {
                node_hash(&sibling, &current)
            } else {
                node_hash(&current, &sibling)
            };
        }
        current
    }

    /// Verify that `key` maps to `value` under `root`.
    pub fn verify(&self, root: &Hash, key: &Key, value: &Hash) -> bool {
        if self.siblings.len() > MAX_DEPTH {
            return false;
        }
        match &self.leaf {
            Some(leaf) if &leaf.key == key && &leaf.value == value => {
                self.fold(key, leaf_hash(key, value)) == *root
            }
            _ => false,
        }
    }

    /// Verify that `key` has no leaf under `root`.
    pub fn verify_absent(&self, root: &Hash, key: &Key) -> bool {
        if self.siblings.len() > MAX_DEPTH {
            return false;
        }
        match &self.leaf {
            None => self.fold(key, EMPTY_HASH) == *root,
            Some(leaf) => {
                if &leaf.key == key {
                    return false;
                }
                // The leaf that blocks the path must genuinely sit on it,
                // otherwise any leaf could be presented as proof of absence.
                let shares_prefix =
                    (0..self.siblings.len()).all(|depth| bit(&leaf.key, depth) == bit(key, depth));
                shares_prefix && self.fold(key, leaf_hash(&leaf.key, &leaf.value)) == *root
            }
        }
    }
}

impl Encode for Proof {
    fn encode(&self, w: &mut Writer) {
        self.siblings.encode(w);
        match &self.leaf {
            Some(leaf) => {
                w.u8(1).raw(&leaf.key).raw(leaf.value.as_bytes());
            }
            None => {
                w.u8(0);
            }
        }
    }
}

impl Decode for Proof {
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        let siblings = Vec::<Hash>::decode(r)?;
        let leaf = match r.u8()? {
            0 => None,
            1 => Some(ProofLeaf {
                key: r.array::<32>()?,
                value: Hash::decode(r)?,
            }),
            tag => {
                return Err(Error::InvalidTag {
                    kind: "ProofLeaf",
                    tag,
                })
            }
        };
        Ok(Proof { siblings, leaf })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u8) -> Key {
        let mut k = [0u8; 32];
        k[0] = seed;
        k[31] = seed.wrapping_mul(7);
        k
    }

    fn value(seed: u8) -> Hash {
        Hash([seed; 32])
    }

    #[test]
    fn empty_tree_has_zero_root() {
        let smt = Smt::new();
        assert_eq!(smt.root(), EMPTY_HASH);
        assert!(smt.is_empty());
    }

    #[test]
    fn insert_get_remove() {
        let mut smt = Smt::new();
        assert_eq!(smt.insert(key(1), value(1)), None);
        assert_eq!(smt.get(&key(1)), Some(value(1)));
        assert_eq!(smt.len(), 1);

        assert_eq!(smt.insert(key(1), value(2)), Some(value(1)));
        assert_eq!(smt.get(&key(1)), Some(value(2)));
        assert_eq!(smt.len(), 1);

        assert_eq!(smt.remove(&key(1)), Some(value(2)));
        assert_eq!(smt.get(&key(1)), None);
        assert_eq!(smt.root(), EMPTY_HASH);
    }

    #[test]
    fn single_leaf_root_is_the_leaf_hash() {
        let mut smt = Smt::new();
        smt.insert(key(1), value(1));
        assert_eq!(smt.root(), leaf_hash(&key(1), &value(1)));
    }

    #[test]
    fn root_is_independent_of_insertion_order() {
        let leaves: Vec<(Key, Hash)> = (1..=40).map(|i| (key(i), value(i))).collect();

        let forward = Smt::from_leaves(leaves.clone());
        let mut reversed = leaves.clone();
        reversed.reverse();
        let backward = Smt::from_leaves(reversed);

        let mut shuffled = leaves.clone();
        // Deterministic shuffle: interleave from both ends.
        let mut interleaved = Vec::new();
        while !shuffled.is_empty() {
            interleaved.push(shuffled.remove(0));
            if !shuffled.is_empty() {
                interleaved.push(shuffled.pop().unwrap());
            }
        }
        let mixed = Smt::from_leaves(interleaved);

        assert_eq!(forward.root(), backward.root());
        assert_eq!(forward.root(), mixed.root());
        assert_eq!(forward.len(), 40);
    }

    #[test]
    fn removal_restores_the_previous_root() {
        let mut smt = Smt::from_leaves((1..=20).map(|i| (key(i), value(i))));
        let before = smt.root();

        smt.insert(key(99), value(99));
        assert_ne!(smt.root(), before);
        smt.remove(&key(99));
        assert_eq!(smt.root(), before);
    }

    #[test]
    fn tree_shape_is_canonical_after_churn() {
        // Insert 30 leaves, delete 10, and compare against building the final
        // leaf set directly. A non-collapsing tree fails this.
        let mut churned = Smt::from_leaves((1..=30).map(|i| (key(i), value(i))));
        for i in 1..=10 {
            churned.remove(&key(i));
        }
        let direct = Smt::from_leaves((11..=30).map(|i| (key(i), value(i))));
        assert_eq!(churned.root(), direct.root());
        assert_eq!(churned.len(), direct.len());
        assert_eq!(churned.leaves(), direct.leaves());
    }

    #[test]
    fn value_changes_change_the_root() {
        let mut smt = Smt::from_leaves((1..=10).map(|i| (key(i), value(i))));
        let before = smt.root();
        smt.insert(key(5), value(200));
        assert_ne!(smt.root(), before);
        smt.insert(key(5), value(5));
        assert_eq!(smt.root(), before);
    }

    #[test]
    fn deep_keys_sharing_long_prefixes() {
        // Two keys differing only in the last bit force a 256-deep path.
        let mut a = [0xffu8; 32];
        let mut b = [0xffu8; 32];
        a[31] = 0xfe;
        b[31] = 0xff;

        let mut smt = Smt::new();
        smt.insert(a, value(1));
        smt.insert(b, value(2));
        assert_eq!(smt.get(&a), Some(value(1)));
        assert_eq!(smt.get(&b), Some(value(2)));

        let proof = smt.proof(&a);
        assert_eq!(proof.siblings.len(), 256);
        assert!(proof.verify(&smt.root(), &a, &value(1)));
    }

    #[test]
    fn inclusion_proofs_verify() {
        let smt = Smt::from_leaves((1..=64).map(|i| (key(i), value(i))));
        let root = smt.root();
        for i in 1..=64u8 {
            let proof = smt.proof(&key(i));
            assert!(proof.verify(&root, &key(i), &value(i)), "leaf {i}");
        }
    }

    #[test]
    fn proofs_reject_wrong_values_roots_and_keys() {
        let smt = Smt::from_leaves((1..=32).map(|i| (key(i), value(i))));
        let root = smt.root();
        let proof = smt.proof(&key(7));

        assert!(proof.verify(&root, &key(7), &value(7)));
        assert!(!proof.verify(&root, &key(7), &value(8)));
        assert!(!proof.verify(&Hash([9u8; 32]), &key(7), &value(7)));
        assert!(!proof.verify(&root, &key(8), &value(7)));

        let mut tampered = proof.clone();
        if let Some(first) = tampered.siblings.first_mut() {
            *first = Hash([1u8; 32]);
        }
        assert!(!tampered.verify(&root, &key(7), &value(7)));
    }

    #[test]
    fn absence_proofs_verify() {
        let smt = Smt::from_leaves((1..=32).map(|i| (key(i), value(i))));
        let root = smt.root();

        let missing = key(200);
        let proof = smt.proof(&missing);
        assert!(proof.verify_absent(&root, &missing));
        assert!(!proof.verify(&root, &missing, &value(200)));

        // An inclusion proof must not double as an absence proof.
        let present = smt.proof(&key(7));
        assert!(!present.verify_absent(&root, &key(7)));
    }

    #[test]
    fn absence_proof_from_empty_tree() {
        let smt = Smt::new();
        let proof = smt.proof(&key(1));
        assert!(proof.leaf.is_none());
        assert!(proof.verify_absent(&EMPTY_HASH, &key(1)));
    }

    #[test]
    fn absence_proof_cannot_borrow_an_unrelated_leaf() {
        let smt = Smt::from_leaves((1..=32).map(|i| (key(i), value(i))));
        let root = smt.root();

        // Take a real proof for one key and claim it proves another key absent.
        let proof = smt.proof(&key(7));
        let other = key(200);
        // key(200) does not follow the same path as key(7) all the way down, so
        // the prefix check must reject the substitution.
        assert!(
            !proof.siblings.is_empty(),
            "a 32-leaf tree has interior nodes"
        );
        assert!(!proof.verify_absent(&root, &other));
    }

    #[test]
    fn undo_log_restores_the_root_exactly() {
        let mut smt = Smt::from_leaves((1..=25).map(|i| (key(i), value(i))));
        let before = smt.root();
        let leaves_before = smt.leaves();

        let updates = vec![
            (key(3), Some(value(99))),
            (key(100), Some(value(100))),
            (key(4), None),
            (key(101), Some(value(101))),
        ];
        let undo = smt.apply(&updates);
        assert_ne!(smt.root(), before);

        smt.revert(undo);
        assert_eq!(smt.root(), before);
        assert_eq!(smt.leaves(), leaves_before);
        assert_eq!(smt.len(), 25);
    }

    #[test]
    fn leaves_are_returned_in_key_order() {
        let smt = Smt::from_leaves((1..=50).map(|i| (key(i), value(i))));
        let leaves = smt.leaves();
        let mut sorted = leaves.clone();
        sorted.sort_by_key(|a| a.0);
        assert_eq!(leaves, sorted);
    }

    #[test]
    fn rebuilding_from_leaves_reproduces_the_root() {
        let smt = Smt::from_leaves((1..=100).map(|i| (key(i), value(i))));
        let rebuilt = Smt::from_leaves(smt.leaves());
        assert_eq!(smt.root(), rebuilt.root());
    }

    #[test]
    fn proof_encoding_roundtrips() {
        let smt = Smt::from_leaves((1..=16).map(|i| (key(i), value(i))));
        let proof = smt.proof(&key(3));
        assert_eq!(Proof::from_bytes(&proof.to_bytes()).unwrap(), proof);
        let json = serde_json::to_string(&proof).unwrap();
        assert_eq!(serde_json::from_str::<Proof>(&json).unwrap(), proof);

        let absent = smt.proof(&key(250));
        assert_eq!(Proof::from_bytes(&absent.to_bytes()).unwrap(), absent);
    }

    #[test]
    fn oversized_proofs_are_rejected() {
        let smt = Smt::from_leaves([(key(1), value(1))]);
        let mut proof = smt.proof(&key(1));
        proof.siblings = vec![EMPTY_HASH; MAX_DEPTH + 1];
        assert!(!proof.verify(&smt.root(), &key(1), &value(1)));
        assert!(!proof.verify_absent(&smt.root(), &key(1)));
    }

    #[test]
    fn distinct_leaf_sets_have_distinct_roots() {
        let a = Smt::from_leaves((1..=10).map(|i| (key(i), value(i))));
        let b = Smt::from_leaves((1..=11).map(|i| (key(i), value(i))));
        assert_ne!(a.root(), b.root());
    }
}
