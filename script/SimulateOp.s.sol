// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script, console2} from "forge-std/Script.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {IAccount} from "account-abstraction/interfaces/IAccount.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";

/// Diagnose a pre-signed UserOp JSON against a forked chain.
/// Env: OP_JSON (path), ENTRYPOINT
contract SimulateOp is Script {
    function run() external {
        string memory json = vm.readFile(vm.envString("OP_JSON"));
        PackedUserOperation memory op;
        op.sender = vm.parseJsonAddress(json, ".[0].sender");
        op.nonce = vm.parseJsonUint(json, ".[0].nonce");
        op.initCode = vm.parseJsonBytes(json, ".[0].initCode");
        op.callData = vm.parseJsonBytes(json, ".[0].callData");
        op.accountGasLimits = vm.parseJsonBytes32(json, ".[0].accountGasLimits");
        op.preVerificationGas = vm.parseJsonUint(json, ".[0].preVerificationGas");
        op.gasFees = vm.parseJsonBytes32(json, ".[0].gasFees");
        op.paymasterAndData = vm.parseJsonBytes(json, ".[0].paymasterAndData");
        op.signature = vm.parseJsonBytes(json, ".[0].signature");

        IEntryPoint ep = IEntryPoint(vm.envAddress("ENTRYPOINT"));
        bytes32 hash = ep.getUserOpHash(op);
        console2.log("userOpHash:", vm.toString(hash));

        // 1. Direct validation, pranking the EntryPoint (bypasses guard).
        IAccount acct = IAccount(op.sender);
        vm.prank(address(ep));
        try acct.validateUserOp(op, hash, 0) returns (uint256 vd) {
            console2.log("validateUserOp returned:", vd);
        } catch (bytes memory reason) {
            console2.log("validateUserOp reverted:", vm.toString(reason));
        }

        // 2. Full handleOps simulation.
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;
        try ep.handleOps(ops, payable(0x90F79bf6EB2c4f870365E785982E1f101E93b906)) {
            console2.log("handleOps SUCCESS");
        } catch (bytes memory reason) {
            console2.log("handleOps reverted:", vm.toString(reason));
        }
    }
}
