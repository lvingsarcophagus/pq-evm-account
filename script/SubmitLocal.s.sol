// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script, console2} from "forge-std/Script.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";

/// Submit a pre-signed UserOp JSON file through handleOps (local smoke test).
/// Env: OP_JSON (path), PRIVATE_KEY (bundler key), ENTRYPOINT
contract SubmitLocal is Script {
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

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;

        uint256 bundlerKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(bundlerKey);
        IEntryPoint(vm.envAddress("ENTRYPOINT")).handleOps(ops, payable(vm.envOr("BENEFICIARY", address(0x90F79bf6EB2c4f870365E785982E1f101E93b906))));
        vm.stopBroadcast();
        console2.log("submitted ok");
    }
}
