// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.25;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";

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

    /// @dev Deterministic create2 address for `initCode`, and whether a contract is already
    ///      deployed there. Each deployment below is guarded on this so the script can be replayed
    ///      on a chain that already holds part of the set: create2 to an occupied address reverts
    ///      with a create collision, which would otherwise abort the whole run on the first
    ///      already-deployed contract. Skipped contracts are logged rather than silently ignored.
    /// @dev The deployments themselves stay as `new X{salt: SALT}(...)` rather than a raw create2
    ///      through a helper, so forge records `contractName` in the broadcast file - which
    ///      `dev/generate-networks-file.sh` reads to build `networks.json`.
    function _at(bytes memory initCode, string memory name) internal view returns (address at, bool exists) {
        at = vm.computeCreate2Address(SALT, keccak256(initCode));
        exists = at.code.length > 0;
        if (exists) {
            console.log("already deployed, skipping:", name, at);
        }
    }

    function deploy() public returns (Deployment memory) {
        address at;
        bool exists;

        // Deploy COWShed
        (at, exists) = _at(type(COWShed).creationCode, "COWShed");
        if (!exists) vm.broadcast();
        COWShed cowShed = exists ? COWShed(payable(at)) : new COWShed{salt: SALT}();

        // Deploy COWShed with support for Composable CoW
        IComposableCow composableCoW =
            IComposableCow(address(vm.envOr("COMPOSABLE_COW", address(DEFAULT_COMPOSABLE_COW))));

        (at, exists) = _at(
            abi.encodePacked(type(COWShedForComposableCoW).creationCode, abi.encode(composableCoW)),
            "COWShedForComposableCoW"
        );
        if (!exists) vm.broadcast();
        COWShed cowShedForComposableCoW = exists
            ? COWShed(payable(at))
            : COWShed(payable(address(new COWShedForComposableCoW{salt: SALT}(composableCoW))));

        // Deploy COWShed variant that delegates EIP-1271 signature validation to its trusted executor
        (at, exists) = _at(type(COWShedWithExecutorSigner).creationCode, "COWShedWithExecutorSigner");
        if (!exists) vm.broadcast();
        COWShed cowShedWithExecutorSigner =
            exists ? COWShed(payable(at)) : COWShed(payable(address(new COWShedWithExecutorSigner{salt: SALT}())));

        // Deploy factory
        (at, exists) =
            _at(abi.encodePacked(type(COWShedFactory).creationCode, abi.encode(address(cowShed))), "COWShedFactory");
        if (!exists) vm.broadcast();
        COWShedFactory factory = exists ? COWShedFactory(at) : new COWShedFactory{salt: SALT}(address(cowShed));

        // Deploy factory
        (at, exists) = _at(
            abi.encodePacked(type(COWShedFactory).creationCode, abi.encode(address(cowShedForComposableCoW))),
            "COWShedFactory (Composable CoW)"
        );
        if (!exists) vm.broadcast();
        COWShedFactory factoryForComposableCoW =
            exists ? COWShedFactory(at) : new COWShedFactory{salt: SALT}(address(cowShedForComposableCoW));

        // Deploy factory for the executor-signer variant. Integrations use its
        // (owner, trustedExecutor, salt) overloads to deploy preconfigured proxies.
        (at, exists) = _at(
            abi.encodePacked(type(COWShedExecutorFactory).creationCode, abi.encode(address(cowShedWithExecutorSigner))),
            "COWShedExecutorFactory"
        );
        if (!exists) vm.broadcast();
        COWShedExecutorFactory factoryForExecutorSigner = exists
            ? COWShedExecutorFactory(at)
            : new COWShedExecutorFactory{salt: SALT}(address(cowShedWithExecutorSigner));

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
