// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.25;

import {DeployScript} from "./Deploy.s.sol";

contract DeployAndRecordScript is DeployScript {
    function run(string calldata baseEns) external override {
        Deployment memory deployment = deploy(baseEns);
        bytes memory initCode = vm.getCode("src/COWShedProxy.sol:COWShedProxy");

        string memory addrJson = "deploymentAddresses.json";
        vm.serializeAddress(addrJson, "factory", address(deployment.factory));
        vm.serializeBytes(addrJson, "proxyInitCode", initCode);
        string memory serialized = vm.serializeAddress(addrJson, "implementation", address(deployment.cowShed));
        vm.writeJson(serialized, "deploymentAddresses.json");
    }
}
