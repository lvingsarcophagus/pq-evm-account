// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;
import {Test} from "forge-std/Test.sol";
import {SphincsMinusVerifier} from "../src/verifiers/SphincsMinusVerifier.sol";

contract ProbeV9 is SphincsMinusVerifier {
    function probeFull(bytes32 pkSeed, bytes32 pkRoot, bytes32 message, bytes calldata sig)
        external returns (bool readable, bool optimized)
    {
        readable = this.verifyReadable(pkSeed, pkRoot, message, sig);
        optimized = this.verify(pkSeed, pkRoot, message, sig);

    }
}

contract ProbeT9 is Test {
    function test_P() public {
        string memory json = vm.readFile("test/vectors/c13.json");
        ProbeV9 p = new ProbeV9();
        bytes32 seed = vm.parseJsonBytes32(json, ".vectors[0].pkSeed");
        bytes32 root = vm.parseJsonBytes32(json, ".vectors[0].pkRoot");
        bytes32 msgHash = vm.parseJsonBytes32(json, ".vectors[0].message");
        bytes memory sig = vm.parseJsonBytes(json, ".vectors[0].sig");
        (bool r, bool o) = p.probeFull(seed, root, msgHash, sig);
        emit log_named_uint("readable", r ? 1 : 0);
        emit log_named_uint("optimized", o ? 1 : 0);
    }
}
