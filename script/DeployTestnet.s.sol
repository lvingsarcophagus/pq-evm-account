// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script, console2} from "forge-std/Script.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {HybridPQAccount} from "../src/account/HybridPQAccount.sol";

/// Deploy a HybridPQAccount to a testnet.
///
/// Env:
///   PRIVATE_KEY      funded deployer (= ECDSA owner for simplicity)
///   ENTRYPOINT       EntryPoint address (v0.8 canonical: 0x4337084D9E255Ff0702461CF8895CE9E3b5FF108)
///   DEPOSIT_AMOUNT   optional, wei deposited into the EntryPoint for the account
///
/// The account starts with zeroed PQ keys; rotate them with setPQKeys() from
/// the owner key before any UserOp can validate (see scripts/send_userop.sh).
contract DeployTestnet is Script {
    function run() external {
        uint256 deployerKey = vm.envUint("PRIVATE_KEY");
        address entrypoint = vm.envAddress("ENTRYPOINT");
        uint256 deposit = vm.envOr("DEPOSIT_AMOUNT", uint256(0.05 ether));

        vm.startBroadcast(deployerKey);
        HybridPQAccount account = new HybridPQAccount(
            IEntryPoint(entrypoint),
            vm.addr(deployerKey), // ECDSA owner = deployer
            bytes32(0),
            bytes32(0)
        );
        if (deposit > 0) {
            (bool ok,) = entrypoint.call{value: deposit}(
                abi.encodeWithSignature("depositTo(address)", address(account))
            );
            require(ok, "deposit failed");
        }
        vm.stopBroadcast();

        console2.log("HybridPQAccount:", address(account));
        console2.log("EntryPoint:", entrypoint);
        console2.log("ECDSA owner:", vm.addr(deployerKey));
    }
}
