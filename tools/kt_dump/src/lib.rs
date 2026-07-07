//! Shim crate: compiles the VERBATIM eat-pass transparency.rs (which is
//! pomfrit-feature-gated upstream only because KeyLog::append takes an
//! IssuerPublicKey) against a stub IssuerPublicKey carrying a fixed
//! token_key_id. All chain/signing/verification logic is the reference
//! source file, byte for byte.
pub mod faest_sig {
    pub use eat_pass_core::faest_sig::*;
}

#[derive(Clone, Debug)]
pub struct IssuerPublicKey {
    pub key_version: u32,
    pub tkid: [u8; 32],
}

impl IssuerPublicKey {
    pub fn token_key_id(&self) -> Result<[u8; 32], ()> {
        Ok(self.tkid)
    }
}

#[path = "/Users/mac/tee-stack/eat-pass/core/src/transparency.rs"]
pub mod transparency;
