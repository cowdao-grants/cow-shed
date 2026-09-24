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

    /// @dev Contracts are deployed with `CREATE2` and a fixed salt, so their addresses are known
    /// upfront. Deploying one the chain already has would revert with a create collision, so each
    /// is deployed only if its address is still empty and reused otherwise.
    function deploy() public returns (Deployment memory) {
        // Deploy COWShed
        COWShed cowShed = COWShed(payable(create2Address(type(COWShed).creationCode)));
        if (address(cowShed).code.length == 0) {
            vm.broadcast();
            new COWShed{salt: SALT}();
        }

        // Deploy COWShed with support for Composable CoW
        IComposableCow composableCoW =
            IComposableCow(address(vm.envOr("COMPOSABLE_COW", address(DEFAULT_COMPOSABLE_COW))));

        COWShed cowShedForComposableCoW = COWShed(
            payable(create2Address(
                    abi.encodePacked(type(COWShedForComposableCoW).creationCode, abi.encode(composableCoW))
                ))
        );
        if (address(cowShedForComposableCoW).code.length == 0) {
            vm.broadcast();
            new COWShedForComposableCoW{salt: SALT}(composableCoW);
        }

        // Deploy COWShed variant that delegates EIP-1271 signature validation to its trusted executor
        vm.broadcast();
        COWShed cowShedWithExecutorSigner = new COWShedWithExecutorSigner{salt: SALT}();

        // Deploy factory
        COWShedFactory factory = COWShedFactory(create2Address(factoryCreationCode(address(cowShed))));
        if (address(factory).code.length == 0) {
            vm.broadcast();
            new COWShedFactory{salt: SALT}(address(cowShed));
        }

        // Deploy factory
        COWShedFactory factoryForComposableCoW =
            COWShedFactory(create2Address(factoryCreationCode(address(cowShedForComposableCoW))));
        if (address(factoryForComposableCoW).code.length == 0) {
            vm.broadcast();
            new COWShedFactory{salt: SALT}(address(cowShedForComposableCoW));
        }

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

    function create2Address(bytes memory creationCode) internal pure returns (address) {
        return vm.computeCreate2Address(SALT, keccak256(creationCode));
    }

    function factoryCreationCode(address implementation) internal pure returns (bytes memory) {
        return abi.encodePacked(type(COWShedFactory).creationCode, abi.encode(implementation));
    }
}
