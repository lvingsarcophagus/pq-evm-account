// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;
import {Script, console2} from "forge-std/Script.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {SimpleAccountFactory} from "account-abstraction/accounts/SimpleAccountFactory.sol";

/// Diagnostic control: deploy vanilla ECDSA-only SimpleAccount factory.
contract SimpleDiag is Script {
    function run() external {
        uint256 key = vm.envUint("PRIVATE_KEY");
        IEntryPoint ep = IEntryPoint(vm.envAddress("ENTRYPOINT"));
        vm.startBroadcast(key);
        SimpleAccountFactory f = new SimpleAccountFactory(ep);
        vm.stopBroadcast();
        console2.log("factory:", address(f));
        console2.log("account:", f.getAddress(vm.addr(key), 0));
    }
}
