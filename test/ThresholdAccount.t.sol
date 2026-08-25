// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {EntryPoint} from "account-abstraction/core/EntryPoint.sol";
import {ThresholdHybridAccount} from "../src/account/ThresholdHybridAccount.sol";

/// Phase 2-v2 tests: risk-based hybrid validation.
/// Cheap ops (trusted target, small value) need ECDSA only; risky ops
/// (big value, untrusted target, self-admin) additionally demand the
/// SPHINCS- C13 post-quantum signature.
contract ThresholdAccountTest is Test {
    uint256 constant VERIFICATION_GAS = 600_000;
    uint256 constant CALL_GAS = 100_000;

    EntryPoint internal ep;
    ThresholdHybridAccount internal account;

    uint256 internal ownerKey;
    address internal owner;
    address internal trustedTarget;
    address internal strangerTarget;

    bytes32 internal pqSeed;
    bytes32 internal pqRoot;
    bytes internal pqSigForHash;

    function setUp() public {
        ownerKey = 0xA11CE;
        owner = vm.addr(ownerKey);
        trustedTarget = makeAddr("trustedTarget");
        strangerTarget = makeAddr("strangerTarget");

        ep = new EntryPoint();
        account = new ThresholdHybridAccount(IEntryPoint(ep), owner);
        vm.deal(address(account), 10 ether);

        vm.startPrank(owner);
        account.setTrustedTarget(trustedTarget, true); // bootstrap mode
        account.setPolicy(false, 1 ether); // transfers >= 1 ETH are risky
        vm.stopPrank();
    }

    // ---------- helpers ----------

    function _signPQ(bytes32 hash) internal {
        string[] memory inputs = new string[](3);
        inputs[0] = "tools/signer-c13";
        inputs[1] = "c13";
        inputs[2] = vm.toString(hash);
        bytes memory result = vm.ffi(inputs);
        (bytes32 seed, bytes32 root, bytes memory sig) =
            abi.decode(result, (bytes32, bytes32, bytes));
        vm.prank(owner);
        account.setPQKeys(seed, root);
        pqSeed = seed;
        pqRoot = root;
        pqSigForHash = sig;
    }

    function _packGas() internal pure returns (bytes32) {
        return bytes32((uint256(VERIFICATION_GAS) << 128) | CALL_GAS);
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

    function _executeCall(address to, uint256 value)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodeWithSignature("execute(address,uint256,bytes)", to, value, "");
    }

    function _validate(PackedUserOperation memory op, bytes32 hash)
        internal
        returns (uint256)
    {
        vm.prank(address(ep));
        return account.validateUserOp(op, hash, 0);
    }

    /// ECDSA-only signature over `hash` — with an optional tweak so it fails.
    function _ecdsaSig(bytes32 hash, bool valid) internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, hash);
        if (!valid) r = bytes32(uint256(r) ^ 1);
        return abi.encodePacked(r, s, v);
    }

    function _hybridSig(bytes32 hash, bool validECDSA, bool validPQ)
        internal
        view
        returns (bytes memory)
    {
        bytes memory pqPart = pqSigForHash;
        if (!validPQ) pqPart[0] ^= 0x01;
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, hash);
        if (!validECDSA) r = bytes32(uint256(r) ^ 1);
        return abi.encodePacked(pqPart, r, s, v);
    }

    // ---------- cheap path: ECDSA only ----------

    function test_cheapOp_ECDSAOnly_succeeds() public {
        bytes memory cd = _executeCall(trustedTarget, 0.5 ether); // below threshold
        PackedUserOperation memory op = _op(cd, "");
        bytes32 hash = ep.getUserOpHash(op);
        _signPQ(hash); // keys provisioned, but NOT required for this op

        op.signature = _ecdsaSig(hash, true);
        assertEq(_validate(op, hash), 0, "cheap op must pass with ECDSA alone");
    }

    function test_cheapOp_hybridAlsoAccepted() public {
        bytes memory cd = _executeCall(trustedTarget, 0.5 ether);
        PackedUserOperation memory op = _op(cd, "");
        bytes32 hash = ep.getUserOpHash(op);
        _signPQ(hash);

        op.signature = _hybridSig(hash, true, true);
        assertEq(_validate(op, hash), 0, "hybrid sig defensively accepted on cheap ops");
    }

    function test_fuzz_cheapPath_rejectsBadECDSA(bytes calldata noise) public {
        bytes memory cd = _executeCall(trustedTarget, 0.5 ether);
        PackedUserOperation memory op = _op(cd, "");
        bytes32 hash = ep.getUserOpHash(op);
        _signPQ(hash);

        if (noise.length < 3) return; // nothing meaningful to mutate
        bytes memory sig = abi.encodePacked(
            bytes32(uint256(keccak256("r")) ^ uint256(uint8(noise[0]))),
            bytes32(uint256(keccak256("s")) ^ uint256(uint8(noise[1]))),
            bytes1(uint8(27 + (uint8(noise[2]) % 2)))
        );
        op.signature = sig;
        assertEq(_validate(op, hash), 1);
    }

    // ---------- risky: value threshold ----------

    function test_bigValue_withoutPQ_fails() public {
        bytes memory cd = _executeCall(trustedTarget, 1 ether); // == threshold
        PackedUserOperation memory op = _op(cd, "");
        bytes32 hash = ep.getUserOpHash(op);
        _signPQ(hash);

        op.signature = _ecdsaSig(hash, true);
        assertEq(_validate(op, hash), 1, "value >= threshold must require PQ");
    }

    function test_bigValue_withHybrid_succeeds() public {
        bytes memory cd = _executeCall(trustedTarget, 1 ether);
        PackedUserOperation memory op = _op(cd, "");
        bytes32 hash = ep.getUserOpHash(op);
        _signPQ(hash);

        op.signature = _hybridSig(hash, true, true);
        assertEq(_validate(op, hash), 0);
    }

    // ---------- risky: untrusted target (fail-closed default) ----------

    function test_untrustedTarget_smallValue_requiresPQ() public {
        bytes memory cd = _executeCall(strangerTarget, 0.001 ether);
        PackedUserOperation memory op = _op(cd, "");
        bytes32 hash = ep.getUserOpHash(op);
        _signPQ(hash);

        op.signature = _ecdsaSig(hash, true);
        assertEq(_validate(op, hash), 1, "fail-closed: untrusted callee is risky");

        op.signature = _hybridSig(hash, true, true);
        assertEq(_validate(op, hash), 0, "hybrid passes for untrusted callee");
    }

    // ---------- risky: self-admin calls ----------

    function test_policyChange_viaSelfCall_hybridRequiredAndWorks() public {
        // UserOp: execute(self, 0, setPolicy(true, 0))
        bytes memory inner =
            abi.encodeWithSignature("setPolicy(bool,uint256)", false, 0);
        bytes memory cd = _executeCall(address(account), 0);
        // replace inner data properly: rebuild execute with real inner bytes
        cd = abi.encodeWithSignature(
            "execute(address,uint256,bytes)", address(account), 0, inner
        );
        PackedUserOperation memory op = _op(cd, "");
        bytes32 hash = ep.getUserOpHash(op);
        _signPQ(hash);

        op.signature = _ecdsaSig(hash, true);
        assertEq(_validate(op, hash), 1, "self-call must be hybrid-gated");

        op.signature = _hybridSig(hash, true, true);
        assertEq(_validate(op, hash), 0, "hybrid unlocks policy change");
    }

    function test_setPolicy_lockedAfterProvisioning() public {
        _signPQ(bytes32(uint256(999))); // provision PQ keys
        vm.prank(owner);
        vm.expectRevert("not authorized");
        account.setPolicy(false, 0); // no longer trusted to reconfigure alone
    }

    // ---------- PQ key provisioning rules ----------

    function test_bootstrapThenLock() public {
        // While keys are unprovisioned, the ECDSA owner bootstraps config:
        vm.prank(owner);
        account.setTrustedTarget(strangerTarget, true); // ok in bootstrap mode

        // One-time PQ provisioning by owner:
        string[] memory inputs = new string[](3);
        inputs[0] = "tools/signer-c13";
        inputs[1] = "c13";
        inputs[2] = vm.toString(bytes32(uint256(1234)));
        bytes memory result = vm.ffi(inputs);
        (bytes32 seed, bytes32 root, ) = abi.decode(result, (bytes32, bytes32, bytes));
        vm.prank(owner);
        account.setPQKeys(seed, root); // ok (keys were zero)

        // After provisioning, direct configuration is locked:
        vm.prank(owner);
        vm.expectRevert("not authorized");
        account.setTrustedTarget(strangerTarget, false);

        vm.prank(owner);
        vm.expectRevert(ThresholdHybridAccount.NotOwner.selector);
        account.setPQKeys(root, seed);
    }

    function test_trustedTarget_cheapOp_afterProvisioning_stillCheap() public {
        // proves trust relationships survive provisioning and stay cheap
        bytes memory cd = _executeCall(trustedTarget, 0.1 ether);
        PackedUserOperation memory op = _op(cd, "");
        bytes32 hash = ep.getUserOpHash(op);
        _signPQ(hash);
        op.signature = _ecdsaSig(hash, true);
        assertEq(_validate(op, hash), 0);
    }

    // ---------- malformed signatures ----------

    function test_badLength_reverts() public {
        bytes memory cd = _executeCall(trustedTarget, 0.5 ether);
        PackedUserOperation memory op = _op(cd, new bytes(100));
        bytes32 hash = ep.getUserOpHash(op);
        vm.prank(address(ep));
        vm.expectRevert(ThresholdHybridAccount.BadSignatureLength.selector);
        account.validateUserOp(op, hash, 0);
    }

    // ---------- E2E: cheap path through real EntryPoint ----------

    function test_handleOps_cheapPath_runsWithoutAnyPQCost() public {
        bytes memory cd = _executeCall(trustedTarget, 0.25 ether);
        PackedUserOperation memory op = _op(cd, "");
        bytes32 hash = ep.getUserOpHash(op);
        _signPQ(hash); // provision keys; op itself stays ECDSA-only
        op.signature = _ecdsaSig(hash, true);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;

        address refundTo = makeAddr("refundTo");
        uint256 before = trustedTarget.balance;
        ep.handleOps(ops, payable(refundTo));
        assertEq(trustedTarget.balance, before + 0.25 ether);
        assertGt(refundTo.balance, 0);
    }
}
