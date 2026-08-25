// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.25;

import {Test, Vm} from "forge-std/Test.sol";

import {DeployScript, SALT} from "script/Deploy.s.sol";
import {COWShed, COWShedFactory} from "src/COWShedFactory.sol";

contract DeployTest is Test {
    DeployScript script;

    function setUp() external {
        script = new DeployScript();
    }

    function testUsesCreate2() external {
        address expectedCowShedAddress = vm.computeCreate2Address(SALT, keccak256(type(COWShed).creationCode));
        address expectedFactoryAddress =
            vm.computeCreate2Address(SALT, keccak256(factoryCreationCode(expectedCowShedAddress)));

        DeployScript.Deployment memory deployment = script.deploy();

        assertEq(address(deployment.cowShed), expectedCowShedAddress);
        assertEq(address(deployment.factory), expectedFactoryAddress);
    }

    function testMatchesOfficialAddresses() external {
        // These addresses are expected to change only if the contract code
        // changes.
        address officialCowShedAddress = 0xF0D586aB0017fDfE2ACf4AB008B3Ddb2CF50bB09;
        address officialFactoryAddress = 0xC94F7D71d022e773B0B516841ff867C06f39726B;
        address officialCowShedForComposableCoWAddress = 0xF0D400089d5b9fACA64E3422AD6614546587cfFB;
        address officialFactoryForComposableCoWAddress = 0x5E284e80F3bd6A7D80A8500D9c49878028110848;
        address officialCowShedWithExecutorSignerAddress = 0x1c4b988481d945c98a21446AB2960000d290aB22;
        address officialFactoryForExecutorSignerAddress = 0xD4B9497f258bf63A7f21d1DEAF26dA2F23e4DC99;

        DeployScript.Deployment memory deployment = script.deploy();

        assertEq(address(deployment.cowShed), officialCowShedAddress, "incorrect deployment address for COWShed");
        assertEq(address(deployment.factory), officialFactoryAddress, "incorrect deployment address for COWShedFactory");
        assertEq(
            address(deployment.cowShedForComposableCoW),
            officialCowShedForComposableCoWAddress,
            "incorrect deployment address for COWShedForComposableCoW"
        );
        assertEq(
            address(deployment.factoryForComposableCoW),
            officialFactoryForComposableCoWAddress,
            "incorrect deployment address for COWShedFactory for ComposableCoW"
        );
        assertEq(
            address(deployment.cowShedWithExecutorSigner),
            officialCowShedWithExecutorSignerAddress,
            "incorrect deployment address for COWShedWithExecutorSigner"
        );
        assertEq(
            address(deployment.factoryForExecutorSigner),
            officialFactoryForExecutorSignerAddress,
            "incorrect deployment address for COWShedExecutorFactory"
        );
    }

    /// @dev The script skips contracts that are already deployed at their deterministic address,
    /// so it can be replayed on a chain holding only part of the set instead of aborting with a
    /// create collision on the first one. Deploying twice must be a no-op the second time.
    function testSkipsAlreadyDeployedContracts() external {
        DeployScript.Deployment memory first = script.deploy();
        DeployScript.Deployment memory second = script.deploy();

        assertEq(address(second.cowShed), address(first.cowShed), "COWShed redeployed");
        assertEq(
            address(second.cowShedForComposableCoW),
            address(first.cowShedForComposableCoW),
            "COWShedForComposableCoW redeployed"
        );
        assertEq(
            address(second.cowShedWithExecutorSigner),
            address(first.cowShedWithExecutorSigner),
            "COWShedWithExecutorSigner redeployed"
        );
        assertEq(address(second.factory), address(first.factory), "COWShedFactory redeployed");
        assertEq(
            address(second.factoryForComposableCoW),
            address(first.factoryForComposableCoW),
            "COWShedFactory for ComposableCoW redeployed"
        );
        assertEq(
            address(second.factoryForExecutorSigner),
            address(first.factoryForExecutorSigner),
            "COWShedExecutorFactory redeployed"
        );
    }

    function factoryCreationCode(address cowShed) internal pure returns (bytes memory) {
        return abi.encodePacked(type(COWShedFactory).creationCode, abi.encode(cowShed));
    }
}
