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
        address officialCowShedAddress = 0x62d3a7Ff48F9ae1c28a9552A055482f8C63787F8;
        address officialFactoryAddress = 0xcf1ADA436dEE1E5923Bd6195aFdb85A4237a6FC0;

        DeployScript.Deployment memory deployment = script.deploy();

        assertEq(address(deployment.cowShed), officialCowShedAddress);
        assertEq(address(deployment.factory), officialFactoryAddress);
    }

    function factoryCreationCode(address cowShed) internal pure returns (bytes memory) {
        return abi.encodePacked(type(COWShedFactory).creationCode, abi.encode(cowShed));
    }
}
