// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script, console2} from "forge-std/Script.sol";
import {SphincsMinusVerifier} from "../src/verifiers/SphincsMinusVerifier.sol";

/// Phase 3 portability benchmark: measure pure verification gas for the same
/// vector on whatever chain this process is pointed at (--fork-url <RPC>).
///
/// Run per chain:
///   forge script script/BenchmarkChains.s.sol \
///     --rpc-url <chain RPC> [--fork-block-latest] --broadcast -vvv
///
/// No key needed: nothing is broadcast, the verifier deploys inside the local
/// fork VM and gas is measured around a staticcall-equivalent call.
contract BenchmarkChains is Script {
    function run() external {
        string memory json = vm.readFile("test/vectors/c13.json");
        bytes32 seed = vm.parseJsonBytes32(json, ".vectors[0].pkSeed");
        bytes32 root = vm.parseJsonBytes32(json, ".vectors[0].pkRoot");
        bytes32 msgHash = vm.parseJsonBytes32(json, ".vectors[0].message");
        bytes memory sig = vm.parseJsonBytes(json, ".vectors[0].sig");

        SphincsMinusVerifier v = new SphincsMinusVerifier();

        bool ok = v.verify(seed, root, msgHash, sig);
        require(ok, "vector must verify");

        // warm-up done; measure twice for determinism
        uint256 g0 = gasleft();
        bool ok1 = v.verify(seed, root, msgHash, sig);
        uint256 g1 = gasleft();
        bool ok2 = v.verify(seed, root, msgHash, sig);
        uint256 g2 = gasleft();

        console2.log("chainId:", block.chainid);
        console2.log("block:", block.number);
        console2.log("verify ok:", ok1 && ok2);
        console2.log("verify gas #1:", g0 - g1);
        console2.log("verify gas #2:", g1 - g2);
    }
}
