// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {SphincsMinusVerifier} from "../src/verifiers/SphincsMinusVerifier.sol";

contract SphincsVerifierTest is Test {
    SphincsMinusVerifier verifier;
    string constant VECTORS = "test/vectors/c13.json";

    struct Vector {
        string message;
        bytes32 pkSeed;
        bytes32 pkRoot;
        bytes sig;
    }

    Vector[] vectors;

    function setUp() public {
        verifier = new SphincsMinusVerifier();
        string memory json = vm.readFile(VECTORS);
        uint256 count = vm.parseJsonUint(json, ".count");
        for (uint256 i = 0; i < count; ++i) {
            string memory root = string.concat(".vectors[", vm.toString(i), "]");
            vectors.push(
                Vector({
                    message: vm.parseJsonString(json, string.concat(root, ".message")),
                    pkSeed: vm.parseJsonBytes32(json, string.concat(root, ".pkSeed")),
                    pkRoot: vm.parseJsonBytes32(json, string.concat(root, ".pkRoot")),
                    sig: vm.parseJsonBytes(json, string.concat(root, ".sig"))
                })
            );
        }
        assertGt(vectors.length, 0, "no vectors loaded");
    }

    /// All reference-signer signatures must verify.
    function test_ReferenceVectors_Accept() public view {
        for (uint256 i = 0; i < vectors.length; ++i) {
            bytes32 msgHash = vm.parseBytes32(vectors[i].message);
            assertTrue(
                verifier.verify(vectors[i].pkSeed, vectors[i].pkRoot, msgHash, vectors[i].sig),
                string.concat("vector ", vm.toString(i), " must be valid")
            );
        }
    }

    /// Flipping any single bit anywhere in the signature must break it.
    function testFuzz_SigBitFlip_Reject(uint256 x) public view {
        Vector storage v = vectors[x % vectors.length];
        bytes memory mutated = v.sig;
        uint256 bit = x % (mutated.length * 8);
        mutated[bit / 8] ^= bytes1(uint8(1 << (bit % 8)));
        bytes32 msgHash = vm.parseBytes32(v.message);
        assertFalse(verifier.verify(v.pkSeed, v.pkRoot, msgHash, mutated), "bit-flipped sig must fail");
    }

    /// Wrong message must not verify.
    function test_WrongMessage_Reject() public view {
        Vector storage v = vectors[0];
        bytes32 wrong = vm.parseBytes32(v.message) ^ bytes32(uint256(1));
        assertFalse(verifier.verify(v.pkSeed, v.pkRoot, wrong, v.sig));
    }

    /// Swapped pkSeed/pkRoot must not verify.
    function test_SwappedKeyMaterial_Reject() public view {
        Vector storage v = vectors[0];
        bytes32 msgHash = vm.parseBytes32(v.message);
        assertFalse(verifier.verify(v.pkRoot, v.pkSeed, msgHash, v.sig));
    }

    /// Non-canonical keys (low bits set) revert instead of silently failing.
    function test_NonCanonicalKey_Reverts() public {
        Vector storage v = vectors[0];
        bytes32 badSeed = bytes32(uint256(v.pkSeed) + 1);
        bytes32 msgHash = vm.parseBytes32(v.message);
        vm.expectRevert(SphincsMinusVerifier.InvalidPublicKey.selector);
        verifier.verify(badSeed, v.pkRoot, msgHash, v.sig);
    }

    /// Wrong signature length reverts.
    function test_BadLength_Reverts() public {
        Vector storage v = vectors[0];
        bytes memory shortSig = new bytes(3687);
        vm.expectRevert(SphincsMinusVerifier.InvalidSignatureLength.selector);
        verifier.verify(v.pkSeed, v.pkRoot, bytes32(0), shortSig);
    }

    /// Independent gas measurement against reference vectors.
    /// Inputs are decoded from storage BEFORE the clock starts so we measure
    /// pure verification cost, not SLOADs.
    function test_GasBenchmark() public {
        for (uint256 i = 0; i < vectors.length; ++i) {
            bytes32 msgHash = vm.parseBytes32(vectors[i].message);
            bytes32 s = vectors[i].pkSeed;
            bytes32 r = vectors[i].pkRoot;
            bytes memory sig = vectors[i].sig;
            assertTrue(verifier.verify(s, r, msgHash, sig));
            uint256 start = gasleft();
            bool ok = verifier.verify(s, r, msgHash, sig);
            uint256 used = start - gasleft();
            assertTrue(ok);
            emit log_named_uint(string.concat("verify(vector ", vm.toString(i), ") gas"), used);
        }
    }
}
