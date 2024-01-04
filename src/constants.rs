use revm::primitives::{address, Address};

pub(crate) static STATEFUL_SPONGE_BYTECODE: &str = include_str!("../testdata/stateful_sponge");
/// The deployed address of the stateful sponge contract.
pub(crate) static STATEFUL_SPONGE_ADDR: Address =
    address!("dead00000000000000000000000000000000beef");
