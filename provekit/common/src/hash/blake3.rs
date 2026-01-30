use {
    crate::FieldElement,
    ark_crypto_primitives::{
        crh::{CRHScheme, TwoToOneCRHScheme},
        merkle_tree::{Config, IdentityDigestConverter},
        Error,
    },
    ark_ff::{PrimeField, BigInteger},
    rand08::Rng,
    serde::{Deserialize, Serialize},
    spongefish::duplex_sponge::{DuplexSponge, Permutation},
    spongefish::{
        codecs::arkworks_algebra::{
            FieldDomainSeparator, FieldToUnitDeserialize, FieldToUnitSerialize,
        },
        DomainSeparator, ProofResult, ProverState, VerifierState,
    },
    std::borrow::Borrow,
    spongefish_pow::PowStrategy,
    blake3,
    zeroize::Zeroize,
};

//
// ----------------------------
// Transcript (Fiat–Shamir)
// ----------------------------
//

#[derive(Clone, Default, Zeroize)]
pub struct Blake3Permutation {
    state: [FieldElement; 2],
}

impl AsRef<[FieldElement]> for Blake3Permutation {
    fn as_ref(&self) -> &[FieldElement] {
        &self.state
    }
}

impl AsMut<[FieldElement]> for Blake3Permutation {
    fn as_mut(&mut self) -> &mut [FieldElement] {
        &mut self.state
    }
}

impl Permutation for Blake3Permutation {
    type U = FieldElement;
    const N: usize = 2;
    const R: usize = 1;

    fn new(iv: [u8; 32]) -> Self {
        let felt = FieldElement::from_le_bytes_mod_order(&iv);
        Self {
            state: [0.into(), felt],
        }
    }


 fn permute(&mut self) {
    let mut hasher = blake3::Hasher::new();

    // Domain separation for transcript permutation
    hasher.update(b"PROVEKIT_BLAKE3_PERM");

    for x in &self.state {
        hasher.update(&x.into_bigint().to_bytes_le());
    }

    let mut reader = hasher.finalize_xof();
    let mut out = [0u8; 32];
    reader.fill(&mut out);

    let left = FieldElement::from_le_bytes_mod_order(&out[..16]);
    let right = FieldElement::from_le_bytes_mod_order(&out[16..]);

    self.state = [left, right];
}
}

pub type Blake3Sponge = DuplexSponge<Blake3Permutation>;

//
// ----------------------------
// Merkle hashing
// ----------------------------
//

fn hash_pair(l: FieldElement, r: FieldElement) -> FieldElement {
    let mut hasher = blake3::Hasher::new();

    // Domain separation for Merkle tree nodes
    hasher.update(b"PROVEKIT_BLAKE3_NODE");
    hasher.update(&l.into_bigint().to_bytes_le());
    hasher.update(&r.into_bigint().to_bytes_le());

    let mut out = [0u8; 32];
    hasher.finalize_xof().fill(&mut out);

    FieldElement::from_le_bytes_mod_order(&out)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Blake3CRH;

impl CRHScheme for Blake3CRH {
    type Input = [FieldElement];
    type Output = FieldElement;
    type Parameters = ();

    fn setup<R: Rng>(_r: &mut R) -> Result<Self::Parameters, Error> {
        Ok(())
    }

    fn evaluate<T: Borrow<Self::Input>>(
        _: &Self::Parameters,
        input: T,
    ) -> Result<Self::Output, Error> {
        input
            .borrow()
            .iter()
            .copied()
            .reduce(hash_pair)
            .ok_or(Error::IncorrectInputLength(0))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Blake3TwoToOne;

impl TwoToOneCRHScheme for Blake3TwoToOne {
    type Input = FieldElement;
    type Output = FieldElement;
    type Parameters = ();

    fn setup<R: Rng>(_r: &mut R) -> Result<Self::Parameters, Error> {
        Ok(())
    }

    fn evaluate<T: Borrow<Self::Input>>(
        _: &Self::Parameters,
        l: T,
        r: T,
    ) -> Result<Self::Output, Error> {
        Ok(hash_pair(*l.borrow(), *r.borrow()))
    }

    fn compress<T: Borrow<Self::Output>>(
        p: &Self::Parameters,
        l: T,
        r: T,
    ) -> Result<Self::Output, Error> {
        <Self as TwoToOneCRHScheme>::evaluate(p, l, r)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Blake3MerkleConfig;

impl Config for Blake3MerkleConfig {
    type Leaf = [FieldElement];
    type LeafDigest = FieldElement;
    type LeafInnerDigestConverter = IdentityDigestConverter<FieldElement>;
    type InnerDigest = FieldElement;
    type LeafHash = Blake3CRH;
    type TwoToOneHash = Blake3TwoToOne;
}

//
// ----------------------------
// WHIR glue 
// ----------------------------
//

impl whir::whir::domainsep::DigestDomainSeparator<Blake3MerkleConfig>
    for DomainSeparator<Blake3Sponge, FieldElement>
{
    fn add_digest(self, label: &str) -> Self {
        <Self as FieldDomainSeparator<FieldElement>>::add_scalars(self, 1, label)
    }
}

impl whir::whir::utils::DigestToUnitSerialize<Blake3MerkleConfig>
    for ProverState<Blake3Sponge, FieldElement>
{
    fn add_digest(&mut self, digest: FieldElement) -> ProofResult<()> {
        self.add_scalars(&[digest])
    }
}

impl whir::whir::utils::DigestToUnitDeserialize<Blake3MerkleConfig>
    for VerifierState<'_, Blake3Sponge, FieldElement>
{
    fn read_digest(&mut self) -> ProofResult<FieldElement> {
        let [r] = self.next_scalars()?;
        Ok(r)
    }
}

// POW (BLAKE3)
// ----------------------------

#[derive(Clone, Copy)]
pub struct Blake3PoW {
    challenge: [u8; 32],
    bits: f64,
}

impl PowStrategy for Blake3PoW {
    fn new(challenge: [u8; 32], bits: f64) -> Self {
        assert!((0.0..60.0).contains(&bits), "bits must be smaller than 60");
        Self { challenge, bits }
    }

    fn check(&mut self, nonce: u64) -> bool {
        let mut input = [0u8; 40];
        input[..32].copy_from_slice(&self.challenge);
        input[32..].copy_from_slice(&nonce.to_le_bytes());

        let hash = blake3::hash(&input);
        meets_difficulty(hash.as_bytes(), self.bits)
    }

    fn solve(&mut self) -> Option<u64> {
        let mut nonce = 0u64;
        loop {
            if self.check(nonce) {
                return Some(nonce);
            }
            nonce = nonce.wrapping_add(1);
        }
    }
}

fn meets_difficulty(hash: &[u8; 32], bits: f64) -> bool {
    let target_zero_bits = bits.floor() as usize;

    let mut count = 0;
    for byte in hash {
        if *byte == 0 {
            count += 8;
        } else {
            count += byte.leading_zeros() as usize;
            break;
        }
    }

    count >= target_zero_bits
}