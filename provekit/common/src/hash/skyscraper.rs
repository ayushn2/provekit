//! Skyscraper backend re-exported under the `hash` namespace
//! so it can be compared cleanly with SHA2 / SHA3 / BLAKE3.

pub use crate::skyscraper::{
    SkyscraperSponge,
    SkyscraperCRH,
    SkyscraperMerkleConfig,
    SkyscraperPoW,
};