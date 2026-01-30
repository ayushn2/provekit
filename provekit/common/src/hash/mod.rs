pub mod skyscraper;
pub mod sha2;
pub mod sha3;
pub mod blake3;


#[cfg(feature = "sha2")]
pub type ActiveSponge = sha2::Sha2Sponge;
#[cfg(feature = "sha2")]
pub type ActiveMerkleConfig = sha2::Sha2MerkleConfig;
#[cfg(feature = "sha2")]
pub type ActivePoW = sha2::Sha2PoW;
#[cfg(feature = "sha2")]
pub type ActiveCRH = sha2::Sha2CRH;


#[cfg(feature = "sha3")]
pub type ActiveSponge = sha3::Sha3Sponge;
#[cfg(feature = "sha3")]
pub type ActiveMerkleConfig = sha3::Sha3MerkleConfig;
#[cfg(feature = "sha3")]
pub type ActivePoW = sha3::Sha3PoW;
#[cfg(feature = "sha3")]
pub type ActiveCRH = sha3::Sha3CRH;

#[cfg(feature = "blake3")]
pub type ActiveSponge = blake3::Blake3Sponge;
#[cfg(feature = "blake3")]
pub type ActiveMerkleConfig = blake3::Blake3MerkleConfig;
#[cfg(feature = "blake3")]
pub type ActivePoW = blake3::Blake3PoW;
#[cfg(feature = "blake3")]
pub type ActiveCRH = blake3::Blake3CRH;

#[cfg(all(
    feature = "skyscraper",
    not(any(feature = "sha2", feature = "sha3", feature = "blake3"))
))]
pub type ActiveSponge = skyscraper::SkyscraperSponge;

#[cfg(all(
    feature = "skyscraper",
    not(any(feature = "sha2", feature = "sha3", feature = "blake3"))
))]
pub type ActiveMerkleConfig = skyscraper::SkyscraperMerkleConfig;

#[cfg(all(
    feature = "skyscraper",
    not(any(feature = "sha2", feature = "sha3", feature = "blake3"))
))]
pub type ActivePoW = skyscraper::SkyscraperPoW;
#[cfg(all(
    feature = "skyscraper",
    not(any(feature = "sha2", feature = "sha3", feature = "blake3"))
))]
pub type ActiveCRH = skyscraper::SkyscraperCRH;

pub fn confirm_hash() {
    #[cfg(feature = "sha2")]
    {
        println!(">>> USING SHA2 <<<");
        return;
    }

    #[cfg(feature = "sha3")]
    {
        println!(">>> USING SHA3 <<<");
        return;
    }

    #[cfg(feature = "blake3")]
    {
        println!(">>> USING BLAKE3 <<<");
        return;
    }

    #[cfg(all(
        feature = "skyscraper",
        not(any(feature = "sha2", feature = "sha3", feature = "blake3"))
    ))]
    {
        println!(">>> USING SKYSCRAPER <<<");
        return;
    }

    #[cfg(not(any(
        feature = "sha2",
        feature = "sha3",
        feature = "blake3",
        feature = "skyscraper"
    )))]
    {
        panic!("No hash feature enabled");
    }
}