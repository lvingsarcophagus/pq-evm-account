// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {EntryPoint} from "account-abstraction/core/EntryPoint.sol";
import {OptimisticThresholdAccount} from "../src/account/OptimisticThresholdAccount.sol";

/// Phase 5 tests: optimistic (naysayer) verification mode.
contract OptimisticAccountTest is Test {
    EntryPoint internal ep;
    OptimisticThresholdAccount internal account;

    uint256 internal ownerKey;
    address internal owner;
    address internal trustedTarget;
    address internal strangerTarget;

    function setUp() public {
        ownerKey = 0xA11CE;
        owner = vm.addr(ownerKey);
        trustedTarget = makeAddr("trustedTarget");
        strangerTarget = makeAddr("strangerTarget");

        ep = new EntryPoint();
        account = new OptimisticThresholdAccount(IEntryPoint(ep), owner);
        vm.deal(address(account), 10 ether);

        // bootstrap: trust target, 1 ETH threshold
        vm.startPrank(owner);
        account.setTrustedTarget(trustedTarget, true);
        account.setPolicy(false, 1 ether);
        vm.stopPrank();
    }

    // ---------- helpers ----------

    function _packGas() internal pure returns (bytes32) {
        return bytes32((uint256(600_000) << 128) | 100_000);
    }

    function _op(bytes memory callData, bytes memory signature)
        internal
        view
        returns (PackedUserOperation memory)
    {
        return PackedUserOperation({
            sender: address(account),
            nonce: ep.getNonce(address(account), 0),
            initCode: "",
            callData: callData,
            accountGasLimits: _packGas(),
            preVerificationGas: 100_000,
            gasFees: bytes32((uint256(10 gwei) << 128) | 2 gwei),
            paymasterAndData: "",
            signature: signature
        });
    }

    function _executeCall(address to, uint256 value) internal pure returns (bytes memory) {
        return abi.encodeWithSignature("execute(address,uint256,bytes)", to, value, "");
    }

    function _signPQ(bytes32 hash) internal returns (bytes memory) {
        string[] memory inputs = new string[](3);
        inputs[0] = "tools/signer-c13";
        inputs[1] = "c13";
        inputs[2] = vm.toString(hash);
        bytes memory result = vm.ffi(inputs);
        (bytes32 seed, bytes32 root, bytes memory sig) =
            abi.decode(result, (bytes32, bytes32, bytes));
        // rotate only when needed (direct rotation is bootstrap-only)
        bytes32 cur = account.pqSeed();
        if (cur != seed) {
            vm.startPrank(address(account));
            account.setPQKeys(seed, root);
            vm.stopPrank();
        }
        return sig;
    }

    function _ecdsaSig(bytes32 hash) internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, hash);
        return abi.encodePacked(r, s, v);
    }

    /// Enable optimistic mode through a hybrid-validated self-call.
    function _enableOptimistic(uint256 windowSeconds) internal {
        bytes memory inner =
            abi.encodeWithSignature("enableOptimistic(bool,uint256)", true, windowSeconds);
        bytes memory cd =
            abi.encodeWithSignature("execute(address,uint256,bytes)", address(account), 0, inner);
        PackedUserOperation memory op = _op(cd, "");
        bytes32 hash = ep.getUserOpHash(op);
        bytes memory pqSig = _signPQ(hash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, hash);
        op.signature = abi.encodePacked(pqSig, r, s, v);

        vm.prank(address(ep));
        assertEq(account.validateUserOp(op, hash, 0), 0, "enable op must validate hybrid");
        vm.prank(address(ep));
        account.execute(address(account), 0, inner); // performs the self-call
        assertTrue(account.optimisticEnabled(), "mode must be enabled");
    }

    // ---------- tests ----------

    function test_optimistic_disabled_by_default() public view {
        assertFalse(account.optimisticEnabled());
    }

    function test_enable_viaHybridSelfCall() public {
        _enableOptimistic(30 minutes);
        assertEq(account.challengeWindow(), 30 minutes);
    }

    function test_riskyOp_validatesECDSAOnly_whenOptimistic() public {
        _enableOptimistic(30 minutes);

        bytes memory cd = _executeCall(strangerTarget, 2 ether);
        PackedUserOperation memory op = _op(cd, "");
        bytes32 hash = ep.getUserOpHash(op);
        op.signature = _ecdsaSig(hash);

        vm.prank(address(ep));
        assertEq(
            account.validateUserOp(op, hash, 0),
            0,
            "risky op must pass ECDSA-only under optimism"
        );
    }

    function test_riskyOp_parksInsteadOfExecuting_and_claimAfterWindow() public {
        _enableOptimistic(30 minutes);

        bytes memory cd = _executeCall(strangerTarget, 2 ether);
        PackedUserOperation memory op = _op(cd, "");
        bytes32 hash = ep.getUserOpHash(op);
        op.signature = _ecdsaSig(hash);

        vm.deal(address(account), 10 ether);
        vm.prank(address(ep));
        account.validateUserOp(op, hash, 0);

        uint256 balBefore = strangerTarget.balance;
        vm.prank(address(ep));
        account.execute(strangerTarget, 2 ether, ""); // parks

        assertEq(strangerTarget.balance, balBefore, "must NOT fire immediately");
        (, , , , uint64 execAfter, bool active) = account.pendingOps(1);
        assertTrue(active);

        vm.expectRevert(OptimisticThresholdAccount.WindowStillActive.selector);
        account.claimPending(1);

        vm.warp(block.timestamp + 31 minutes);
        account.claimPending(1);
        assertEq(strangerTarget.balance, balBefore + 2 ether, "funds move after window");
    }

    function test_cancel_withInvalidPQProof_succeeds() public {
        _enableOptimistic(30 minutes);

        bytes memory cd = _executeCall(strangerTarget, 2 ether);
        PackedUserOperation memory op = _op(cd, "");
        bytes32 hash = ep.getUserOpHash(op);
        op.signature = _ecdsaSig(hash);

        vm.prank(address(ep));
        account.validateUserOp(op, hash, 0);
        vm.prank(address(ep));
        account.execute(strangerTarget, 2 ether, "");

        // challenger submits a garbage PQ signature -> verifier says invalid -> cancel
        bytes memory garbage = new bytes(3688);
        garbage[0] = bytes1(uint8(0x5A));
        account.cancelPending(1, garbage);

        (,,,, , bool active) = account.pendingOps(1);
        assertFalse(active, "forged pending must be cancelled");

        vm.warp(block.timestamp + 31 minutes);
        vm.expectRevert("unknown pending");
        account.claimPending(1);
    }

    function test_cancel_withValidPQ_rejected() public {
        _enableOptimistic(30 minutes);

        bytes memory cd = _executeCall(trustedTarget, 2 ether); // risky by value
        PackedUserOperation memory op = _op(cd, "");
        bytes32 hash = ep.getUserOpHash(op);
        bytes memory pqSig = _signPQ(hash); // VALID PQ sig over this hash

        // park via optimistic fast lane (ECDSA-only)
        op.signature = _ecdsaSig(hash);
        vm.prank(address(ep));
        account.validateUserOp(op, hash, 0);
        vm.prank(address(ep));
        account.execute(trustedTarget, 2 ether, "");

        // cancelling with the CORRECT PQ signature must be rejected
        vm.expectRevert(OptimisticThresholdAccount.SignatureWasValid.selector);
        account.cancelPending(1, pqSig);

        // and it still executes after the window
        vm.warp(block.timestamp + 31 minutes);
        account.claimPending(1);
        assertEq(trustedTarget.balance, 2 ether);
    }

    function test_gas_benchmark_optimistic_vs_hybrid_validation() public {
        // measure validation gas for a risky op in both modes
        bytes memory cd = _executeCall(strangerTarget, 2 ether);

        PackedUserOperation memory op = _op(cd, "");
        bytes32 hash = ep.getUserOpHash(op);
        bytes memory pqSig = _signPQ(hash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, hash);

        // hybrid validation (optimism off)
        op.signature = abi.encodePacked(pqSig, r, s, v);
        vm.prank(address(ep));
        uint256 g0 = gasleft();
        account.validateUserOp(op, hash, 0);
        uint256 hybridGas = g0 - gasleft();

        // optimistic validation (ECDSA-only fast lane)
        _enableOptimistic(30 minutes);
        op.nonce = ep.getNonce(address(account), 0);
        op.signature = _ecdsaSig(hash);
        vm.prank(address(ep));
        g0 = gasleft();
        account.validateUserOp(op, hash, 0);
        uint256 optimisticGas = g0 - gasleft();

        emit log_named_uint("validation gas HYBRID", hybridGas);
        emit log_named_uint("validation gas OPTIMISTIC", optimisticGas);
        assertLt(optimisticGas, hybridGas - 50_000, "optimism must save ~100K");
    }
}
