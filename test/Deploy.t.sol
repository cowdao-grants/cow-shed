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

    function factoryCreationCode(address cowShed) internal pure returns (bytes memory) {
        return abi.encodePacked(type(COWShedFactory).creationCode, abi.encode(cowShed));
    }
}
