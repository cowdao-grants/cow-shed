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
        address officialCowShedAddress = 0x8e7561ADC327a5f0F8525fA94C9515de1B32bc08;
        address officialFactoryAddress = 0xcf214Bf9011cA952D04a430903daBd47B3B80CFd;

        DeployScript.Deployment memory deployment = script.deploy(DEPLOYED_ENS);

        assertEq(address(deployment.cowShed), officialCowShedAddress);
        assertEq(address(deployment.factory), officialFactoryAddress);
    }
}
