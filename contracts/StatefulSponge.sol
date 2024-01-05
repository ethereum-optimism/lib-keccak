// SPDX-License-Identifier: MIT
pragma solidity 0.8.15;

import { LibKeccak } from "contracts/lib/LibKeccak.sol";

/// @title StatefulSponge
/// @dev This is a test contract that allows for streaming bytes into the Keccak sponge over multiple transactions
///      and then squeezing the state matrix for the final keccak256 digest.
contract StatefulSponge {
    /// @notice The internal state matrix of the keccak sponge.
    LibKeccak.StateMatrix internal state;

    /// @notice Absorbs a stream of bytes into the sponge.
    function absorb(bytes calldata _data) external {
        bytes memory input = LibKeccak.pad(_data);

        // Pull the state into memory for the absorbtion.
        LibKeccak.StateMatrix memory state_ = state;

        // Absorb the data into the sponge.
        bytes memory blockBuffer = new bytes(136);
        for (uint256 i; i < input.length; i += LibKeccak.BLOCK_SIZE_BYTES) {
            // Pull the current block into the processing buffer.
            assembly {
                let dPtr := add(input, i)
                mstore(add(blockBuffer, 0x20), mload(add(dPtr, 0x20)))
                mstore(add(blockBuffer, 0x40), mload(add(dPtr, 0x40)))
                mstore(add(blockBuffer, 0x60), mload(add(dPtr, 0x60)))
                mstore(add(blockBuffer, 0x80), mload(add(dPtr, 0x80)))
                mstore(add(blockBuffer, 0xA0), and(mload(add(dPtr, 0xA0)), shl(192, 0xFFFFFFFFFFFFFFFF)))
            }

            LibKeccak.absorb(state_, blockBuffer);
            LibKeccak.permutation(state_);
        }

        // Persist the state matrix.
        state = state_;
    }

    /// @notice Squeezes the sponge and returns the resulting `keccak256` digest.
    function squeeze() external returns (bytes32 hash_) {
        // Squeeze the sponge.
        hash_ = LibKeccak.squeeze(state);

        // Reset the state matrix.
        delete state;
    }
}
