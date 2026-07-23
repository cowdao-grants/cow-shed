// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.25;

import {Script} from "forge-std/Script.sol";

import {COWShed, COWShedFactory} from "src/COWShedFactory.sol";

import {COWShedExecutorFactory} from "src/COWShedExecutorFactory.sol";
import {COWShedForComposableCoW} from "src/COWShedForComposableCoW.sol";
import {COWShedWithExecutorSigner} from "src/COWShedWithExecutorSigner.sol";
import {IComposableCow} from "src/IComposableCow.sol";

bytes32 constant SALT = bytes32(0);

// See https://github.com/cowprotocol/composable-cow
address constant DEFAULT_COMPOSABLE_COW = 0xfdaFc9d1902f4e0b84f65F49f244b32b31013b74;

// Canonical GPv2Settlement address (same on all supported networks).
address constant DEFAULT_SETTLEMENT = 0x9008D19f58AAbD9eD0D60971565AA8510560ab41;

contract DeployScript is Script {
    struct Deployment {
        COWShed cowShed;
        COWShed cowShedForComposableCoW;
        COWShed cowShedWithExecutorSigner;
        COWShedFactory factory;
        COWShedFactory factoryForComposableCoW;
        COWShedExecutorFactory factoryForExecutorSigner;
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

        // Deploy COWShed variant that delegates EIP-1271 signature validation to its trusted
        // executor, falling back to owner-signed CoW orders when no executor contract is set
        address cowSettlement = address(vm.envOr("COW_SETTLEMENT", address(DEFAULT_SETTLEMENT)));

        vm.broadcast();
        COWShed cowShedWithExecutorSigner = new COWShedWithExecutorSigner{salt: SALT}(cowSettlement);

        // Deploy factory
        vm.broadcast();
        COWShedFactory factory = new COWShedFactory{salt: SALT}(address(cowShed));

        // Deploy factory
        vm.broadcast();
        COWShedFactory factoryForComposableCoW = new COWShedFactory{salt: SALT}(address(cowShedForComposableCoW));

        // Deploy factory for the executor-signer variant. Integrations use its
        // (owner, trustedExecutor, salt) overloads to deploy preconfigured proxies.
        vm.broadcast();
        COWShedExecutorFactory factoryForExecutorSigner =
            new COWShedExecutorFactory{salt: SALT}(address(cowShedWithExecutorSigner));

        return Deployment({
            cowShed: cowShed,
            cowShedForComposableCoW: cowShedForComposableCoW,
            cowShedWithExecutorSigner: cowShedWithExecutorSigner,
            factory: factory,
            factoryForComposableCoW: factoryForComposableCoW,
            factoryForExecutorSigner: factoryForExecutorSigner
        });
    }
}
