use {
    crate::FieldElement,
    ark_crypto_primitives::{
        crh::{CRHScheme, TwoToOneCRHScheme},
        merkle_tree::{Config, IdentityDigestConverter},
        Error,
    },
    ark_ff::PrimeField,
    ark_serialize::CanonicalSerialize,
    rand08::Rng,
    serde::{Deserialize, Serialize},
    sha2::{Digest, Sha256},
    spongefish::duplex_sponge::{DuplexSponge, Permutation},
    spongefish::{
        codecs::arkworks_algebra::{
            FieldDomainSeparator, FieldToUnitDeserialize, FieldToUnitSerialize,
        },
        DomainSeparator, ProofResult, ProverState, VerifierState,
    },
    std::borrow::Borrow,
    spongefish_pow::PowStrategy,
    zeroize::Zeroize,
};

//
// ----------------------------
// Transcript (Fiat–Shamir)
// ----------------------------
//

#[derive(Clone, Default)]
pub struct Sha2Permutation {
    state: [FieldElement; 2],
}

impl AsRef<[FieldElement]> for Sha2Permutation {
    fn as_ref(&self) -> &[FieldElement] {
        &self.state
    }
}

impl AsMut<[FieldElement]> for Sha2Permutation {
    fn as_mut(&mut self) -> &mut [FieldElement] {
        &mut self.state
    }
}

impl Zeroize for Sha2Permutation {
    fn zeroize(&mut self) {
        self.state.iter_mut().for_each(|x| x.zeroize());
    }
}

impl Permutation for Sha2Permutation {
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
        // Serialize state → bytes
        let mut bytes = Vec::new();
        for x in &self.state {
            let mut buf = Vec::new();
            x.serialize_compressed(&mut buf).unwrap();
            bytes.extend_from_slice(&buf);
        }

        // Hash
        let digest = Sha256::digest(&bytes);

        // Map back into two field elements
        let left = FieldElement::from_le_bytes_mod_order(&digest[..16]);
        let right = FieldElement::from_le_bytes_mod_order(&digest[16..]);

        self.state = [left, right];
    }
}

pub type Sha2Sponge = DuplexSponge<Sha2Permutation>;

//
// ----------------------------
// Merkle hashing
// ----------------------------
//

fn hash_pair(l: FieldElement, r: FieldElement) -> FieldElement {
    let mut bytes = Vec::new();
    let mut buf = Vec::new();
    l.serialize_compressed(&mut buf).unwrap();
    bytes.extend_from_slice(&buf);

    buf.clear();
    r.serialize_compressed(&mut buf).unwrap();
    bytes.extend_from_slice(&buf);

    let digest = Sha256::digest(&bytes);
    FieldElement::from_le_bytes_mod_order(&digest)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sha2CRH;

impl CRHScheme for Sha2CRH {
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
pub struct Sha2TwoToOne;

impl TwoToOneCRHScheme for Sha2TwoToOne {
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
pub struct Sha2MerkleConfig;

impl Config for Sha2MerkleConfig {
    type Leaf = [FieldElement];
    type LeafDigest = FieldElement;
    type LeafInnerDigestConverter = IdentityDigestConverter<FieldElement>;
    type InnerDigest = FieldElement;
    type LeafHash = Sha2CRH;
    type TwoToOneHash = Sha2TwoToOne;
}

//
// ----------------------------
// WHIR glue (same as skyscraper)
// ----------------------------
//

impl whir::whir::domainsep::DigestDomainSeparator<Sha2MerkleConfig>
    for DomainSeparator<Sha2Sponge, FieldElement>
{
    fn add_digest(self, label: &str) -> Self {
        <Self as FieldDomainSeparator<FieldElement>>::add_scalars(self, 1, label)
    }
}

impl whir::whir::utils::DigestToUnitSerialize<Sha2MerkleConfig>
    for ProverState<Sha2Sponge, FieldElement>
{
    fn add_digest(&mut self, digest: FieldElement) -> ProofResult<()> {
        self.add_scalars(&[digest])
    }
}

impl whir::whir::utils::DigestToUnitDeserialize<Sha2MerkleConfig>
    for VerifierState<'_, Sha2Sponge, FieldElement>
{
    fn read_digest(&mut self) -> ProofResult<FieldElement> {
        let [r] = self.next_scalars()?;
        Ok(r)
    }
}

//
// ----------------------------
// Proof of Work (SHA2)
// ----------------------------
//

#[derive(Clone, Copy)]
pub struct Sha2PoW {
    challenge: [u8; 32],
    bits: f64,
}

impl PowStrategy for Sha2PoW {
    fn new(challenge: [u8; 32], bits: f64) -> Self {
        assert!((0.0..60.0).contains(&bits), "bits must be smaller than 60");
        Self { challenge, bits }
    }

    fn check(&mut self, nonce: u64) -> bool {
        let mut hasher = Sha256::new();
        hasher.update(self.challenge);
        hasher.update(nonce.to_le_bytes());
        let digest = hasher.finalize();

        leading_zero_bits(&digest) as f64 >= self.bits
    }

    fn solve(&mut self) -> Option<u64> {
        for nonce in 0u64.. {
            if self.check(nonce) {
                return Some(nonce);
            }
        }
        None
    }
}

fn leading_zero_bits(bytes: &[u8]) -> u32 {
    let mut count = 0;
    for &b in bytes {
        if b == 0 {
            count += 8;
        } else {
            count += b.leading_zeros();
            break;
        }
    }
    count
}