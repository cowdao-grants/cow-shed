// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.25;

import {Script} from "forge-std/Script.sol";

import {COWShedExecutorFactory} from "src/COWShedExecutorFactory.sol";
import {CowShedHooksWrapper} from "src/CowShedHooksWrapper.sol";
import {ICowSettlement} from "src/CowWrapper.sol";

/// @dev Deploys the enforceable-hooks wrapper. Kept separate from `Deploy.s.sol` so the shared test
///      deployment (BaseTest) does not construct a wrapper against a settlement with no code.
///      NOTE: the wrapper must be allowlisted as a CoW solver by governance before it can settle,
///      and the executor-signer factory (from the preconfigured-executor deployment) must already
///      exist — pass it via the EXECUTOR_FACTORY env var.
contract DeployHooksWrapperScript is Script {
    // Canonical GPv2Settlement address (same on all supported networks).
    address constant DEFAULT_SETTLEMENT = 0x9008D19f58AAbD9eD0D60971565AA8510560ab41;

    function run() external returns (CowShedHooksWrapper wrapper) {
        address settlement = address(vm.envOr("COW_SETTLEMENT", address(DEFAULT_SETTLEMENT)));
        COWShedExecutorFactory factory = COWShedExecutorFactory(vm.envAddress("EXECUTOR_FACTORY"));

        vm.broadcast();
        wrapper = new CowShedHooksWrapper(ICowSettlement(settlement), factory);
    }
}
