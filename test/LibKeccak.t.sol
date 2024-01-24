// SPDX-License-Identifier: MIT
pragma solidity 0.8.15;

import { Test, console2 as console } from "forge-std/Test.sol";
import { TestPlus } from "@solady-test/utils/TestPlus.sol";
import { LibString } from "@solady/utils/LibString.sol";

import { LibKeccak } from "contracts/lib/LibKeccak.sol";
import { StatefulSponge } from "contracts/StatefulSponge.sol";

contract LibKeccak_Test is Test, TestPlus {
    function test_staticHash_success() public brutalizeMemory {
        // Init
        LibKeccak.StateMatrix memory state;

        // Absorb 136 bytes into the sponge
        bytes memory data = new bytes(136);
        LibKeccak.absorb(state, data);
        LibKeccak.permutation(state);

        // Absorb another 64 bytes into the sponge
        bytes memory padded = new bytes(136);
        padded[135] = 0x80;
        padded[64] |= 0x01;

        LibKeccak.absorb(state, padded);
        LibKeccak.permutation(state);

        assertEq(LibKeccak.squeeze(state), keccak256(new bytes(200)));
    }

    function test_staticHashModuloBlockSize_success() public brutalizeMemory {
        // Init
        LibKeccak.StateMatrix memory state;

        // Absorb 136 bytes into the sponge
        bytes memory data = new bytes(136);
        LibKeccak.absorb(state, data);
        LibKeccak.permutation(state);

        // Absorb another 136 bytes into the sponge
        LibKeccak.absorb(state, data);
        LibKeccak.permutation(state);

        // Absorb the padding into the sponge. Because the input is a perfect multiple of the block size, the padding
        // will be a full block.
        data[135] = 0x80;
        data[0] |= 0x01;
        LibKeccak.absorb(state, data);
        LibKeccak.permutation(state);

        assertEq(LibKeccak.squeeze(state), keccak256(new bytes(136 * 2)));
    }

    /// @notice Tests the permutation end-to-end with brutalized memory. This ensures that the permutation does not have
    ///         reliance on clean memory to function properly.
    function testFuzz_hash_success(uint256 _numBytes) public brutalizeMemory {
        _numBytes = bound(_numBytes, 0, 2 ** 10);

        // Generate a pseudo-random preimage.
        bytes memory data = new bytes(_numBytes);
        for (uint256 i = 0; i < data.length; i++) {
            data[i] = bytes1(uint8(_random()));
        }

        // Pad the data.
        bytes memory paddedData = LibKeccak.padMemory(data);

        // Hash the preimage.
        LibKeccak.StateMatrix memory state;
        for (uint256 i = 0; i < paddedData.length; i += LibKeccak.BLOCK_SIZE_BYTES) {
            bytes memory kBlock = bytes(LibString.slice(string(paddedData), i, i + LibKeccak.BLOCK_SIZE_BYTES));
            LibKeccak.absorb(state, kBlock);
            LibKeccak.permutation(state);
        }

        // Assert that the hash is correct.
        assertEq(LibKeccak.squeeze(state), keccak256(data));
    }

    /// @notice Tests that the `padCalldata` function does not write outside of the bounds of the input.
    function testFuzz_padCalldata_memorySafety_succeeds(bytes calldata _in) public {
        uint256 len = _in.length;
        uint256 paddedLen = len % LibKeccak.BLOCK_SIZE_BYTES == 0
            ? len + LibKeccak.BLOCK_SIZE_BYTES
            : len + (LibKeccak.BLOCK_SIZE_BYTES - (len % LibKeccak.BLOCK_SIZE_BYTES));
        uint64 freePtr;
        assembly {
            freePtr := mload(0x40)
        }

        // Pad memory should only write to memory in the range of [freePtr, freePtr + paddedLen + 0x20 (length word)]
        vm.expectSafeMemory(freePtr, freePtr + uint64(paddedLen) + 0x20);
        LibKeccak.pad(_in);
    }

    /// @notice Tests that the `padMemory` function does not write outside of the bounds of the input.
    function testFuzz_padMemory_memorySafety_succeeds(bytes memory _in) public {
        uint256 len = _in.length;
        uint256 paddedLen = len % LibKeccak.BLOCK_SIZE_BYTES == 0
            ? len + LibKeccak.BLOCK_SIZE_BYTES
            : len + (LibKeccak.BLOCK_SIZE_BYTES - (len % LibKeccak.BLOCK_SIZE_BYTES));
        uint64 freePtr;
        assembly {
            freePtr := mload(0x40)
        }

        // Pad memory should only write to memory in the range of [freePtr, freePtr + paddedLen + 0x20 (length word)]
        vm.expectSafeMemory(freePtr, freePtr + uint64(paddedLen) + 0x20);
        LibKeccak.padMemory(_in);
    }

    /// @dev Tests that the stateful sponge can absorb and squeeze an arbitrary amount of random data.
    function testFuzz_statefulSponge_success(bytes memory _data) public {
        vm.pauseGasMetering();
        StatefulSponge sponge = new StatefulSponge();
        vm.resumeGasMetering();

        sponge.absorb(_data);
        bytes32 res = sponge.squeeze();
        assertEq(res, keccak256(_data));
    }
}
