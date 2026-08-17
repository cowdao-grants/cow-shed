// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.25;

import {Script, console2} from "forge-std/Script.sol";

import {COWShedExecutorFactory} from "src/COWShedExecutorFactory.sol";
import {COWShedWithExecutorSigner} from "src/COWShedWithExecutorSigner.sol";
import {CowShedHooksWrapper} from "src/CowShedHooksWrapper.sol";
import {ICowSettlement} from "src/vendor/CowWrapper.sol";

/// @dev Deploys the enforceable-hooks stack with plain CREATE (no CREATE2 salt), so it works on
///      chains that lack the deterministic CREATE2 deployer (0x4e59...4956C) — e.g. a local node.
///      Deploys the executor-signer implementation, its factory, and the hooks wrapper.
///      Env: COW_SETTLEMENT (optional; defaults to the canonical GPv2Settlement).
contract DeployStackScript is Script {
    // Canonical GPv2Settlement address (same on all supported networks).
    address constant DEFAULT_SETTLEMENT = 0x9008D19f58AAbD9eD0D60971565AA8510560ab41;

    function run() external {
        address settlement = address(vm.envOr("COW_SETTLEMENT", address(DEFAULT_SETTLEMENT)));

        vm.startBroadcast();
        COWShedWithExecutorSigner impl = new COWShedWithExecutorSigner();
        COWShedExecutorFactory factory = new COWShedExecutorFactory(address(impl));
        CowShedHooksWrapper wrapper = new CowShedHooksWrapper(ICowSettlement(settlement), factory);
        vm.stopBroadcast();

        console2.log("COWShedWithExecutorSigner (impl):", address(impl));
        console2.log("COWShedExecutorFactory:          ", address(factory));
        console2.log("CowShedHooksWrapper:             ", address(wrapper));
    }
}
