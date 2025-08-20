// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.25;

import {Test} from "forge-std/Test.sol";
import {LibString} from "solady/utils/LibString.sol";

import {DeployScript, SALT} from "script/Deploy.s.sol";
import {COWShed, COWShedFactory} from "src/COWShedFactory.sol";

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
            vm.computeCreate2Address(SALT, keccak256(factoryCreationCode(expectedCowShedAddress, TEST_ENS)));

        DeployScript.Deployment memory deployment = script.deploy(TEST_ENS);

        assertEq(address(deployment.cowShed), expectedCowShedAddress);
        assertEq(address(deployment.factory), expectedFactoryAddress);
    }

    function testMatchesOfficialAddresses() external {
        // These addresses are expected to change only if the contract code
        // changes.
        address officialCowShedAddress = 0x2ba9503F27186aD4d8de6881AbC7467e79f94FfD;
        address officialFactoryAddress = 0xC5607F51555B150Be2A525beAD35c8Fb93CC7BD4;

        DeployScript.Deployment memory deployment = script.deploy(DEPLOYED_ENS);

        assertEq(address(deployment.cowShed), officialCowShedAddress);
        assertEq(address(deployment.factory), officialFactoryAddress);
    }

    function factoryCreationCode(address cowShed, string memory baseEns) private pure returns (bytes memory) {
        bytes32 bName = LibString.toSmallString(baseEns);
        bytes32 bNode = vm.ensNamehash(baseEns);

        return abi.encodePacked(type(COWShedFactory).creationCode, abi.encode(cowShed, bName, bNode));
    }
}
