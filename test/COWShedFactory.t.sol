// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.25;

import {Test} from "forge-std/Test.sol";

import {DeployScript} from "script/Deploy.s.sol";
import {COWShed, COWShedFactory, COWShedProxy} from "src/COWShedFactory.sol";

contract COWShedFactoryTest is Test {
    string constant baseEns = "testcowhooks.eth";
    COWShed shed;
    COWShedFactory factory;

    function setUp() external {
        DeployScript s = new DeployScript();
        DeployScript.Deployment memory deployment = s.deploy(baseEns);
        shed = deployment.cowShed;
        factory = deployment.factory;
    }

    function testExposesExpectedCreationCode() external view {
        assertEq(factory.PROXY_CREATION_CODE(), type(COWShedProxy).creationCode);
    }

    function testDeploysExpectedProxyWithNoEns() external {
        address user = makeAddr("proxy owner");
        address expected = factory.proxyOf(user);
        assertEq(address(expected).code.length, 0);
        factory.initializeProxy(user, false);
        assertGt(address(expected).code.length, 0);
    }
}
