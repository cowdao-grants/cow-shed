// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.25;

import {Script} from "forge-std/Script.sol";

import {COWShed, COWShedFactory} from "src/COWShedFactory.sol";

bytes32 constant SALT = bytes32(0);

contract DeployScript is Script {
    struct Deployment {
        COWShed cowShed;
        COWShedFactory factory;
    }

    function run() external virtual {
        deploy();
    }

    function deploy() public returns (Deployment memory) {
        vm.broadcast();
        COWShed cowShed = new COWShed{salt: SALT}();
        vm.broadcast();
        COWShedFactory factory = new COWShedFactory{salt: SALT}(address(cowShed));
        return Deployment({cowShed: cowShed, factory: factory});
    }
}
