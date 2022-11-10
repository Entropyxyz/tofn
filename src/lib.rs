#![no_std]

// `traced_test`attribute depends on `std`, so we enable it in tests.
// TODO: probably can be fixed in `tracing`.
#[cfg(test)]
extern crate std;

extern crate alloc;

pub mod collections;
mod constants;
// todo(tk): made crypto tools public to use MessageDigest in cli; make private again
pub mod crypto_tools;
pub mod ecdsa;
pub mod gg20;
pub mod multisig;
pub mod sdk;
