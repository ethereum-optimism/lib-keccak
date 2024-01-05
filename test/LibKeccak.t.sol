// SPDX-License-Identifier: MIT
pragma solidity 0.8.15;

import { Test, console2 as console } from "forge-std/Test.sol";

import { LibKeccak } from "contracts/lib/LibKeccak.sol";
import { StatefulSponge } from "contracts/StatefulSponge.sol";

contract LibKeccak_Test is Test {
    function test_staticHash_success() public {
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

    function test_staticHashModuloBlockSize_success() public {
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
