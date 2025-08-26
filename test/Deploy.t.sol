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
            vm.computeCreate2Address(SALT, keccak256(factoryCreationCode(vm, expectedCowShedAddress)));

        DeployScript.Deployment memory deployment = script.deploy();

        assertEq(address(deployment.cowShed), expectedCowShedAddress);
        assertEq(address(deployment.factory), expectedFactoryAddress);
    }

    function testMatchesOfficialAddresses() external {
        // These addresses are expected to change only if the contract code
        // changes.
        address officialCowShedAddress = 0x4965Fe1A8D16Dfcc1A6590A9bC995bC7E9E446aD;
        address officialFactoryAddress = 0x4e91019d28780B70955B0Ed9BA6Fa01C6B87d1E3;

        DeployScript.Deployment memory deployment = script.deploy();

        assertEq(address(deployment.cowShed), officialCowShedAddress);
        assertEq(address(deployment.factory), officialFactoryAddress);
    }

    function factoryCreationCode(Vm vm, address cowShed) internal pure returns (bytes memory) {
        return abi.encodePacked(type(COWShedFactory).creationCode, abi.encode(cowShed));
    }
}
