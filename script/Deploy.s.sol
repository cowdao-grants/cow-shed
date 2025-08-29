// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.25;

import {Script} from "forge-std/Script.sol";

import {COWShed, COWShedFactory} from "src/COWShedFactory.sol";

import {COWShedForComposableCoW} from "src/COWShedForComposableCoW.sol";
import {IComposableCow} from "src/IComposableCow.sol";

bytes32 constant SALT = bytes32(0);

// See https://github.com/cowprotocol/composable-cow
address constant DEFAULT_COMPOSABLE_COW = 0xfdaFc9d1902f4e0b84f65F49f244b32b31013b74;

contract DeployScript is Script {
    struct Deployment {
        COWShed cowShed;
        COWShed cowShedForComposableCoW;
        COWShedFactory factory;
        COWShedFactory factoryForComposableCoW;
    }

    function run() external virtual {
        deploy();
    }

    function deploy() public returns (Deployment memory) {
        // Deploy COWShed
        vm.broadcast();
        COWShed cowShed = new COWShed{salt: SALT}();

        // Deploy COWShed with support for Composable CoW
        IComposableCow composableCoW =
            IComposableCow(address(vm.envOr("COMPOSABLE_COW", address(DEFAULT_COMPOSABLE_COW))));

        vm.broadcast();
        COWShed cowShedForComposableCoW = new COWShedForComposableCoW{salt: SALT}(composableCoW);

        // Deploy factory
        vm.broadcast();
        COWShedFactory factory = new COWShedFactory{salt: SALT}(address(cowShed));

        // Deploy factory
        vm.broadcast();
        COWShedFactory factoryForComposableCoW = new COWShedFactory{salt: SALT}(address(cowShedForComposableCoW));

        return Deployment({
            cowShed: cowShed,
            cowShedForComposableCoW: cowShedForComposableCoW,
            factory: factory,
            factoryForComposableCoW: factoryForComposableCoW
        });
    }
}
