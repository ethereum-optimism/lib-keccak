// SPDX-License-Identifier: MIT
pragma solidity 0.8.15;

import { LibKeccak } from "contracts/lib/LibKeccak.sol";

/// @title StatefulSponge
/// @dev This is a test contract that allows for streaming bytes into the Keccak sponge over multiple transactions
///      and then squeezing the state matrix for the final keccak256 digest.
contract StatefulSponge {
    /// @notice The block size of the Keccak-f[1600] permutation, 1088 bits (136 bytes).
    uint256 internal constant BLOCK_SIZE_BYTES = 136;
    /// @notice The internal state matrix of the keccak sponge.
    LibKeccak.StateMatrix internal state;

    /// @notice Absorbs a stream of bytes into the sponge.
    function absorb(bytes calldata _data) external {
        bytes memory input = _pad(_data);

        // Pull the state into memory for the absorbtion.
        LibKeccak.StateMatrix memory state_ = state;

        // Absorb the data into the sponge.
        bytes memory blockBuffer = new bytes(136);
        for (uint256 i; i < input.length; i += BLOCK_SIZE_BYTES) {
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

    /// @notice Pads input data to an even multiple of the Keccak-f[1600] permutation block size, 1088 bits (136 bytes).
    /// @dev Can clobber memory after `_data` if `_data` is not already a multiple of 136 bytes.
    function _pad(bytes calldata _data) internal pure returns (bytes memory padded_) {
        assembly {
            padded_ := mload(0x40)

            // Grab the original length of `_data`
            let len := _data.length

            let dataPtr := add(padded_, 0x20)
            let endPtr := add(dataPtr, len)

            // Copy the data into memory.
            calldatacopy(dataPtr, _data.offset, len)

            let modBlockSize := mod(len, BLOCK_SIZE_BYTES)
            switch modBlockSize
            case false {
                // If the input is a perfect multiple of the block size, then we add a full extra block of padding.
                mstore8(endPtr, 0x01)
                mstore8(sub(add(endPtr, BLOCK_SIZE_BYTES), 0x01), 0x80)

                // Update the length of the data to include the padding.
                mstore(padded_, add(len, BLOCK_SIZE_BYTES))
            }
            default {
                // If the input is not a perfect multiple of the block size, then we add a partial block of padding.
                // This should entail a set bit after the input, followed by as many zero bits as necessary to fill
                // the block, followed by a single 1 bit in the lowest-order bit of the final block.

                let remaining := sub(BLOCK_SIZE_BYTES, modBlockSize)
                let newLen := add(len, remaining)

                // Store the padding bits.
                mstore8(add(dataPtr, sub(newLen, 0x01)), 0x80)
                mstore8(endPtr, or(byte(0, mload(endPtr)), 0x01))

                // Update the length of the data to include the padding. The length should be a multiple of the
                // block size after this.
                mstore(padded_, newLen)
            }

            // Update the free memory pointer.
            mstore(0x40, add(padded_, and(add(mload(padded_), 0x3F), not(0x1F))))
        }
    }
}
