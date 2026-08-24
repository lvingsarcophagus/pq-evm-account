// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;
import {Test} from "forge-std/Test.sol";
import {SphincsMinusVerifier} from "../src/verifiers/SphincsMinusVerifier.sol";

contract ProbeTD2 is Test {
    function test_P() public {
        string memory json = vm.readFile("test/vectors/c13.json");
        SphincsMinusVerifier v = new SphincsMinusVerifier();
        bytes32 seed = vm.parseJsonBytes32(json, ".vectors[0].pkSeed");
        bytes32 root = vm.parseJsonBytes32(json, ".vectors[0].pkRoot");
        bytes32 msgHash = vm.parseJsonBytes32(json, ".vectors[0].message");
        bytes memory sig = vm.parseJsonBytes(json, ".vectors[0].sig");
        emit log_named_uint("readable", v.verifyReadable(seed, root, msgHash, sig) ? 1 : 0);
        emit log_named_uint("optimized", v.verify(seed, root, msgHash, sig) ? 1 : 0);
    }
}
