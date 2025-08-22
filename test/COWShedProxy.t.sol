// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.25;

import {BaseTest} from "./BaseTest.sol";
import {COWShed, Call} from "src/COWShed.sol";
import {COWShedProxy} from "src/COWShedProxy.sol";

contract COWShedProxyTest is BaseTest {
    function testAdmin() external {
        COWShed cowshed = new COWShed();

        // should not be able to use proxy before initialization
        COWShedProxy proxy = new COWShedProxy(address(cowshed), user.addr);

        // should return admin if the proxy calls itself
        vm.prank(address(proxy));
        assertEq(proxy.admin(), user.addr, "proxy admin function doesnt work");

        // for all other users, the call should be proxied
        vm.expectRevert();
        proxy.admin();
    }

    function testUpdateImplementation() external {
        COWShed cowshed = new COWShed();

        // should not be able to use proxy before initialization
        COWShedProxy proxy = new COWShedProxy(address(cowshed), user.addr);

        // should not proxy and directly set the implementation if the caller is the admin
        address newImpl = makeAddr("newImpl");
        vm.prank(user.addr);
        proxy.updateImplementation(newImpl);
        assertImpl(address(proxy), newImpl);

        // reset the implementation back
        vm.prank(user.addr);
        proxy.updateImplementation(address(cowshed));

        // for all other users, the call should be proxied
        vm.expectRevert(COWShed.OnlyAdmin.selector);
        proxy.updateImplementation(newImpl);
    }

    function testProxyInitialization() external {
        COWShed cowshed = new COWShed();

        // should not be able to use proxy before initialization
        COWShedProxy proxy = new COWShedProxy(address(cowshed), user.addr);
        assertImpl(address(proxy), address(cowshed));

        vm.expectRevert(COWShedProxy.InvalidInitialization.selector);
        COWShed(payable(address(proxy))).trustedExecuteHooks(new Call[](0));

        COWShed(payable(address(proxy))).initialize(address(factory));
        assertImpl(address(proxy), address(cowshed));

        // shouldnt initialize again
        vm.expectRevert(COWShed.AlreadyInitialized.selector);
        COWShed(payable(address(proxy))).initialize(address(factory));
    }
}
