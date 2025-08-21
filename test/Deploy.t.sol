// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.25;

import {Test, Vm} from "forge-std/Test.sol";
import {LibString} from "solady/utils/LibString.sol";

import {DeployScript, SALT} from "script/Deploy.s.sol";
import {COWShed, COWShedFactory} from "src/COWShedFactory.sol";

function factoryCreationCode(Vm vm, address cowShed, string memory baseEns) pure returns (bytes memory) {
    bytes32 bName = LibString.toSmallString(baseEns);
    bytes32 bNode = vm.ensNamehash(baseEns);

    return abi.encodePacked(type(COWShedFactory).creationCode, abi.encode(cowShed, bName, bNode));
}

contract DeployTest is Test {
    string constant TEST_ENS = "base ENS";
    string constant DEPLOYED_ENS = "hooks.cow.eth";

    DeployScript script;

    function setUp() external {
        script = new DeployScript();
    }

    function testUsesCreate2() external {
        address expectedCowShedAddress = vm.computeCreate2Address(SALT, keccak256(type(COWShed).creationCode));
        address expectedFactoryAddress =
            vm.computeCreate2Address(SALT, keccak256(factoryCreationCode(vm, expectedCowShedAddress, TEST_ENS)));

        DeployScript.Deployment memory deployment = script.deploy(TEST_ENS);

        assertEq(address(deployment.cowShed), expectedCowShedAddress);
        assertEq(address(deployment.factory), expectedFactoryAddress);
    }

    function testMatchesOfficialAddresses() external {
        // These addresses are expected to change only if the contract code
        // changes.
        address officialCowShedAddress = 0xE0d6B0ce008F5f1224A491D286F03c3CF2bF6609;
        address officialFactoryAddress = 0xfed1b97Be5D12a52cA7Af423aC9Bb495A6F522d3;

        DeployScript.Deployment memory deployment = script.deploy(DEPLOYED_ENS);

        assertEq(address(deployment.cowShed), officialCowShedAddress);
        assertEq(address(deployment.factory), officialFactoryAddress);
    }
}
