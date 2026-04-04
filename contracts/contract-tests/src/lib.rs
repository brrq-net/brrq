//! Integration tests for Brrq system contracts.
//!
//! Tests compile the actual contracts to RISC-V, load the binaries into brrq-vm,
//! and exercise each contract function with simulated calldata.

#[cfg(test)]
mod harness;
#[cfg(test)]
mod proxy_tests;
#[cfg(test)]
mod treasury_tests;
#[cfg(test)]
mod wbrc_tests;
