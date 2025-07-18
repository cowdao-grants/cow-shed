// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.25;

import {Script} from "forge-std/Script.sol";
import {LibString} from "solady/utils/LibString.sol";

import {COWShedFactory, COWShed} from "src/COWShedFactory.sol";

bytes32 constant SALT = bytes32(0);

contract DeployScript is Script {
    struct Deployment {
        COWShed cowShed;
        COWShedFactory factory;
    }

    function run(string calldata baseEns) external virtual {
        deploy(baseEns);
    }

    function deploy(string calldata baseEns) public returns (Deployment memory) {
        bytes32 bName = LibString.toSmallString(baseEns);
        bytes32 bNode = vm.ensNamehash(baseEns);

        vm.broadcast();
        COWShed cowShed = new COWShed{salt: SALT}();
        vm.broadcast();
        COWShedFactory factory = new COWShedFactory{salt: SALT}(address(cowShed), bName, bNode);
        return Deployment({cowShed: cowShed, factory: factory});
    }
}
