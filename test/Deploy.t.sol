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
        //
        // NOTE: the factory addresses below changed because `COWShedFactory` gained new
        // entry points. Since `COWShedFactory.proxyOf` derives the proxy address from
        // `address(this)`, every user proxy moves to a new address on the new factory.
        // See the migration notes in the pull request that introduced this change.
        address officialCowShedAddress = 0xF0D586aB0017fDfE2ACf4AB008B3Ddb2CF50bB09;
        address officialFactoryAddress = 0x0a654985c5856Ab562237286f36d55c0FF637213;
        address officialCowShedForComposableCoWAddress = 0xF0D400089d5b9fACA64E3422AD6614546587cfFB;
        address officialFactoryForComposableCoWAddress = 0x221c28Ec177CF7da6f837DfD0052Ba8F265Fb4CA;

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
    }

    /// @dev Most releases change only part of the code, leaving a chain with contracts that
    /// must be reused rather than deployed again.
    function testReusesAlreadyDeployedContracts() external {
        DeployScript.Deployment memory first = script.deploy();
        DeployScript.Deployment memory second = script.deploy();

        assertEq(address(second.cowShed), address(first.cowShed));
        assertEq(address(second.cowShedForComposableCoW), address(first.cowShedForComposableCoW));
        assertEq(address(second.factory), address(first.factory));
        assertEq(address(second.factoryForComposableCoW), address(first.factoryForComposableCoW));
    }

    /// @dev The case that motivates the check: only the factories are new.
    function testDeploysFactoriesOntoExistingImplementations() external {
        address expectedCowShedAddress = vm.computeCreate2Address(SALT, keccak256(type(COWShed).creationCode));
        vm.etch(expectedCowShedAddress, address(new COWShed()).code);

        DeployScript.Deployment memory deployment = script.deploy();

        assertEq(address(deployment.cowShed), expectedCowShedAddress);
        assertEq(
            address(deployment.factory),
            vm.computeCreate2Address(SALT, keccak256(factoryCreationCode(expectedCowShedAddress)))
        );
        assertGt(address(deployment.factory).code.length, 0, "factory was not deployed");
        assertEq(deployment.factory.implementation(), expectedCowShedAddress);
    }

    function factoryCreationCode(address cowShed) internal pure returns (bytes memory) {
        return abi.encodePacked(type(COWShedFactory).creationCode, abi.encode(cowShed));
    }
}
