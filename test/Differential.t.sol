// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {SphincsMinusVerifier} from "../src/verifiers/SphincsMinusVerifier.sol";

/// Differential testing: the optimized assembly verify() and the readable
/// verifyReadable() must agree on every input — reference vectors, random
/// mutations, and adversarially structured near-valid signatures.
contract DifferentialTest is Test {
    SphincsMinusVerifier verifier;
    bytes32 seed;
    bytes32 pkRoot;
    bytes32 msgHash;
    bytes goodSig;

    function setUp() public {
        verifier = new SphincsMinusVerifier();
        string memory json = vm.readFile("test/vectors/c13.json");
        seed = vm.parseJsonBytes32(json, ".vectors[0].pkSeed");
        pkRoot = vm.parseJsonBytes32(json, ".vectors[0].pkRoot");
        msgHash = vm.parseJsonBytes32(json, ".vectors[0].message");
        goodSig = vm.parseJsonBytes(json, ".vectors[0].sig");
    }

    /// Both implementations must accept all valid vectors.
    function test_BothAcceptVector() public view {
        assertTrue(verifier.verify(seed, pkRoot, msgHash, goodSig));
        assertTrue(verifier.verifyReadable(seed, pkRoot, msgHash, goodSig));
    }

    /// On arbitrary mutations the two implementations must agree exactly.
    function testFuzz_ImplAgreement(uint256 x) public view {
        // Deterministic pseudo-random mutation pattern derived from x.
        bytes memory mutated = abi.encodePacked(goodSig);
        uint256 flips = 1 + (x % 8);
        for (uint256 f = 0; f < flips; ++f) {
            uint256 bit = uint256(keccak256(abi.encode(x, f))) % (mutated.length * 8);
            mutated[bit / 8] ^= bytes1(uint8(1 << (bit % 8)));
        }
        bool a = verifier.verify(seed, pkRoot, msgHash, mutated);
        bool b = verifier.verifyReadable(seed, pkRoot, msgHash, mutated);
        assertEq(a, b, "optimized vs readable disagreement");
    }

    /// Agreement on random messages with the untouched signature.
    function testFuzz_MessageAgreement(uint256 x) public view {
        bytes32 m = bytes32(keccak256(abi.encode("msg", x)));
        assertEq(
            verifier.verify(seed, pkRoot, m, goodSig),
            verifier.verifyReadable(seed, pkRoot, m, goodSig)
        );
    }

    /// Revert behaviour must match: bad length reverts in both.
    function test_BadLength_BothRevert() public {
        bytes memory shortSig = new bytes(3687);
        vm.expectRevert(SphincsMinusVerifier.InvalidSignatureLength.selector);
        verifier.verify(seed, pkRoot, msgHash, shortSig);
        vm.expectRevert(SphincsMinusVerifier.InvalidSignatureLength.selector);
        verifier.verifyReadable(seed, pkRoot, msgHash, shortSig);
    }
}
