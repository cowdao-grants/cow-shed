// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.25;

import {DeployScript} from "./Deploy.s.sol";

/// @dev This script deploys all necessary contracts and create a json file with
/// deployment information that will be used by the TS library in this
/// repository.
contract DeployAndRecordScript is DeployScript {
    function run() external override {
        Deployment memory deployment = deploy();
        bytes memory initCode = vm.getCode("src/COWShedProxy.sol:COWShedProxy");

        string memory addrJson = "deploymentAddresses.json";
        vm.serializeAddress(addrJson, "factory", address(deployment.factory));
        vm.serializeBytes(addrJson, "proxyInitCode", initCode);
        string memory serialized = vm.serializeAddress(addrJson, "implementation", address(deployment.cowShed));
        vm.writeJson(serialized, "deploymentAddresses.json");
    }
}
