// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;
import {Script, console2} from "forge-std/Script.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {ThresholdHybridAccount} from "../src/account/ThresholdHybridAccount.sol";

contract DeployThreshold is Script {
    function run() external {
        uint256 key = vm.envUint("PRIVATE_KEY");
        IEntryPoint ep = IEntryPoint(vm.envAddress("ENTRYPOINT"));
        uint256 deposit = vm.envOr("DEPOSIT_AMOUNT", uint256(0.05 ether));
        address trusted = vm.envOr("TRUSTED_TARGET", vm.addr(key));
        uint256 threshold = vm.envOr("VALUE_THRESHOLD", uint256(1 ether));

        vm.startBroadcast(key);
        ThresholdHybridAccount acct = new ThresholdHybridAccount(ep, vm.addr(key));
        // bootstrap-mode configuration (keys still zeroed):
        acct.setTrustedTarget(trusted, true);
        acct.setPolicy(false, threshold);
        if (deposit > 0) {
            (bool ok,) = address(ep).call{value: deposit}(
                abi.encodeWithSignature("depositTo(address)", address(acct))
            );
            require(ok, "deposit failed");
        }
        vm.stopBroadcast();
        console2.log("ThresholdHybridAccount:", address(acct));
        console2.log("trusted target:", trusted);
    }
}
