use alloy_sol_types::{sol, SolCall};
use anyhow::{bail, Result};
use revm::{
    db::{CacheDB, EmptyDB},
    primitives::{ExecutionResult, Output},
    EVM,
};
use tiny_keccak::Hasher;

sol! {
    function absorb(bytes calldata input) external;
    function squeeze() external returns (bytes32 digest);
}

/// Hashes the input bytes using [tiny_keccak]'s Keccak256 implementation.
pub(crate) fn hash_input_tiny(input: &[u8], output: &mut [u8]) {
    let mut hasher = tiny_keccak::Keccak::v256();
    hasher.update(input);
    hasher.finalize(output);
}

/// Hashes the input bytes using the `StatefulSponge` contract.
pub(crate) fn hash_input_evm(evm: &mut EVM<CacheDB<EmptyDB>>, input: &[u8]) -> Result<[u8; 32]> {
    // Absorb the data into the sponge.
    let absorb_call = absorbCall {
        input: input.to_vec(),
    };
    evm.env.tx.data = absorb_call.abi_encode().into();
    match evm.transact_commit()? {
        ExecutionResult::Success { .. } => { /* continue */ }
        r => bail!("Absorb call failed: {r:?}"),
    }

    // Squeeze the sponge and retrieve the output digest.
    let squeeze_call = squeezeCall {};
    evm.env.tx.data = squeeze_call.abi_encode().into();
    match evm.transact_commit()? {
        ExecutionResult::Success {
            output: Output::Call(hash),
            ..
        } => {
            let return_data = squeezeCall::abi_decode_returns(hash.as_ref(), false)?;
            Ok(*return_data.digest)
        }
        r => bail!("Squeeze call failed: {r:?}"),
    }
}
