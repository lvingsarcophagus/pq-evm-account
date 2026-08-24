// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {EntryPoint} from "account-abstraction/core/EntryPoint.sol";
import {HybridPQAccount} from "../src/account/HybridPQAccount.sol";

/// Phase 2 tests: hybrid (ECDSA + SPHINCS- C13) validation on an ERC-4337 account,
/// including a full handleOps execution through the real v0.8 EntryPoint.
contract HybridAccountTest is Test {
    // Packed gas-limit fields for the test UserOps.
    uint256 constant VERIFICATION_GAS = 600_000;
    uint256 constant CALL_GAS = 100_000;
    uint256 constant PRE_VERIFICATION_GAS = 100_000;
    uint256 constant MAX_FEE = 10 gwei;

    EntryPoint internal ep;
    HybridPQAccount internal account;

    uint256 internal ownerKey;
    address internal owner;
    address internal beneficiary;

    bytes32 internal pqSeed;
    bytes32 internal pqRoot;
    bytes internal pqSigForHash;

    function setUp() public {
        ownerKey = 0xA11CE;
        owner = vm.addr(ownerKey);
        beneficiary = makeAddr("beneficiary");

        ep = new EntryPoint();
        account = new HybridPQAccount(IEntryPoint(ep), owner, bytes32(0), bytes32(0));
        vm.deal(address(account), 10 ether);
    }

    /// Run the reference signer over `hash`; register its (seed, root) on the
    /// account and cache the resulting PQ signature. Skips the test when the
    /// signer binary is not available.
    function _signPQ(bytes32 hash) internal {
        string[] memory inputs = new string[](3);
        inputs[0] = "tools/signer-c13";
        inputs[1] = "c13";
        inputs[2] = vm.toString(hash);
        bytes memory result = vm.ffi(inputs);
        (bytes32 seed, bytes32 root, bytes memory sig) =
            abi.decode(result, (bytes32, bytes32, bytes));
        assertEq(sig.length, 3688, "C13 sig must be 3688 bytes");
        vm.prank(owner);
        account.setPQKeys(seed, root);
        pqSeed = seed;
        pqRoot = root;
        pqSigForHash = sig;
    }

    function _packGas(uint128 verificationGasLimit, uint128 callGasLimit)
        internal
        pure
        returns (bytes32)
    {
        return bytes32((uint256(verificationGasLimit) << 128) | callGasLimit);
    }

    function _buildUserOp(bytes memory callData, bytes memory signature)
        internal
        view
        returns (PackedUserOperation memory)
    {
        return PackedUserOperation({
            sender: address(account),
            nonce: ep.getNonce(address(account), 0),
            initCode: "",
            callData: callData,
            accountGasLimits: _packGas(uint128(VERIFICATION_GAS), uint128(CALL_GAS)),
            preVerificationGas: PRE_VERIFICATION_GAS,
            gasFees: bytes32((uint256(MAX_FEE) << 128) | MAX_FEE),
            paymasterAndData: "",
            signature: signature
        });
    }

    function _hybridSignature(bytes32 userOpHash, bool validECDSA, bool validPQ)
        internal returns (bytes memory)
    {
        bytes memory pqPart = pqSigForHash;
        if (!validPQ) {
            pqPart = abi.encodePacked(pqPart);
            pqPart[0] ^= 0x01; // flip one bit -> verifier must reject
        }
        // ECDSA over userOpHash; optionally corrupt r so ecrecover misses owner.
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, userOpHash);
        if (!validECDSA) {
            r = bytes32(uint256(r) ^ 0x01);
        }
        return abi.encodePacked(pqPart, r, s, v);
    }

    // ------------------------------------------------------------------
    // Validation matrix (spec section 6 Phase 2 integration tests)
    // ------------------------------------------------------------------

    function test_validateUserOp_validHybrid() public {
        bytes memory callData =
            abi.encodeWithSignature("execute(address,uint256,bytes)", beneficiary, 1 ether, "");
        PackedUserOperation memory op = _buildUserOp(callData, "");
        bytes32 hash = ep.getUserOpHash(op);
        _signPQ(hash);

        op.signature = _hybridSignature(hash, true, true);

        vm.prank(address(ep));
        uint256 validationData = account.validateUserOp(op, hash, 0);
        assertEq(validationData, 0, "both signatures valid -> success");
    }

    function test_validateUserOp_invalidPQ_validECDSA_fails() public {
        bytes memory callData =
            abi.encodeWithSignature("execute(address,uint256,bytes)", beneficiary, 1 ether, "");
        PackedUserOperation memory op = _buildUserOp(callData, "");
        bytes32 hash = ep.getUserOpHash(op);
        _signPQ(hash);

        op.signature = _hybridSignature(hash, true, false);

        vm.prank(address(ep));
        uint256 validationData = account.validateUserOp(op, hash, 0);
        assertEq(validationData, 1, "invalid PQ must fail even with valid ECDSA");
    }

    function test_validateUserOp_validPQ_invalidECDSA_fails() public {
        bytes memory callData =
            abi.encodeWithSignature("execute(address,uint256,bytes)", beneficiary, 1 ether, "");
        PackedUserOperation memory op = _buildUserOp(callData, "");
        bytes32 hash = ep.getUserOpHash(op);
        _signPQ(hash);

        op.signature = _hybridSignature(hash, false, true);

        vm.prank(address(ep));
        uint256 validationData = account.validateUserOp(op, hash, 0);
        assertEq(validationData, 1, "invalid ECDSA must fail even with valid PQ");
    }

    function test_validateUserOp_wrongHash_fails() public {
        bytes memory callData =
            abi.encodeWithSignature("execute(address,uint256,bytes)", beneficiary, 1 ether, "");
        PackedUserOperation memory op = _buildUserOp(callData, "");
        bytes32 hash = ep.getUserOpHash(op);
        _signPQ(hash);

        bytes32 wrongHash = bytes32(uint256(hash) ^ 1);
        op.signature = _hybridSignature(wrongHash, true, true);

        vm.prank(address(ep));
        uint256 validationData = account.validateUserOp(op, wrongHash, 0);
        assertEq(validationData, 1, "signature over different hash must fail");
    }

    function test_validateUserOp_badLength_reverts() public {
        vm.expectRevert(HybridPQAccount.BadSignatureLength.selector);
        vm.prank(address(ep));
        account.validateUserOp(
            PackedUserOperation({
                sender: address(account),
                nonce: 0,
                initCode: "",
                callData: "",
                accountGasLimits: bytes32(0),
                preVerificationGas: 0,
                gasFees: bytes32(0),
                paymasterAndData: "",
                signature: new bytes(100)
            }),
            bytes32(0),
            0
        );
    }

    function test_validateUserOp_notFromEntryPoint_reverts() public {
        vm.expectRevert("account: not from EntryPoint");
        account.validateUserOp(
            PackedUserOperation({
                sender: address(account),
                nonce: 0,
                initCode: "",
                callData: "",
                accountGasLimits: bytes32(0),
                preVerificationGas: 0,
                gasFees: bytes32(0),
                paymasterAndData: "",
                signature: ""
            }),
            bytes32(0),
            0
        );
    }

    // ------------------------------------------------------------------
    // End-to-end: real EntryPoint.handleOps execution
    // ------------------------------------------------------------------

    function test_handleOps_executesHybridSignedUserOp() public {
        bytes memory callData =
            abi.encodeWithSignature("execute(address,uint256,bytes)", beneficiary, 1 ether, "");

        // Build op without signature, derive hash, then attach hybrid sig.
        PackedUserOperation memory op = _buildUserOp(callData, "");
        bytes32 hash = ep.getUserOpHash(op);
        _signPQ(hash);
        op.signature = _hybridSignature(hash, true, true);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;

        uint256 balanceBefore = beneficiary.balance;
        address refundTo = makeAddr("refundTo");
        ep.handleOps(ops, payable(refundTo));
        assertGt(refundTo.balance, 0, "bundler must be compensated");
        assertEq(beneficiary.balance, balanceBefore + 1 ether, "execute() must transfer 1 ETH");
    }

    function test_handleOps_rejectsWhenOnlyECDSAValid() public {
        bytes memory callData =
            abi.encodeWithSignature("execute(address,uint256,bytes)", beneficiary, 1 ether, "");
        PackedUserOperation memory op = _buildUserOp(callData, "");
        bytes32 hash = ep.getUserOpHash(op);
        _signPQ(hash);
        op.signature = _hybridSignature(hash, true, false); // PQ broken

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;

        vm.expectRevert(); // EntryPoint reverts FailedOp on signature failure
        ep.handleOps(ops, payable(beneficiary));
    }
}
