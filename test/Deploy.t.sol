// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.25;

import {Test} from "forge-std/Test.sol";
import {LibString} from "solady/utils/LibString.sol";

import {COWShedFactory, COWShed} from "src/COWShedFactory.sol";
import {DeployScript, SALT} from "script/Deploy.s.sol";

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
        // Warning: these addresses currently don't match those in
        // `networks.json`. Since we expect other changes to the contracts,
        // we'll wait until all changes are done before redeploying.
        address officialCowShedAddress = 0xb2177531455922518C933bBb6B556Ef14980F6e8;
        address officialFactoryAddress = 0x1fe885F64e020cFa8554F4a6f263A923E34f1C33;

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
