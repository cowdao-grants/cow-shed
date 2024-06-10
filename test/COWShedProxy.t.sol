// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.25;

import { COWShed, Call } from "src/COWShed.sol";
import { BaseTest } from "./BaseTest.sol";
import { IMPLEMENTATION_STORAGE_SLOT } from "src/COWShedStorage.sol";
import { COWShedProxy } from "src/COWShedProxy.sol";
import { ENS, REVERSE_REGISTRAR } from "src/ens.sol";

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

        COWShed(payable(address(proxy))).initialize(address(factory), true);
        assertImpl(address(proxy), address(cowshed));

        // shouldnt initialize again
        vm.expectRevert(COWShed.AlreadyInitialized.selector);
        COWShed(payable(address(proxy))).initialize(address(factory), true);
    }

    function testProxyClaimWithResolver() external {
        COWShed cowshed = new COWShed();

        COWShedProxy proxy = new COWShedProxy(address(cowshed), user.addr);
        assertImpl(address(proxy), address(cowshed));

        COWShed(payable(address(proxy))).initialize(address(factory), false);
        _assertReverseResolver(address(proxy), address(0));

        // owner can claim
        vm.prank(user.addr);
        COWShed(payable(address(proxy))).claimWithResolver(address(factory));
        _assertReverseResolver(address(proxy), address(factory));

        address otherResolver = makeAddr("otherResolver");
        // factory is the trusted executor
        vm.prank(address(factory));
        COWShed(payable(address(proxy))).claimWithResolver(address(otherResolver));
        _assertReverseResolver(address(proxy), address(otherResolver));

        // cat set resolver when called by the proxy(self-call)
        vm.prank(address(proxy));
        COWShed(payable(address(proxy))).claimWithResolver(address(factory));
        _assertReverseResolver(address(proxy), address(factory));

        // anyone else trying to set it will revert
        vm.prank(makeAddr("otherUser"));
        vm.expectRevert(COWShed.OnlyAdminOrTrustedExecutorOrSelf.selector);
        COWShed(payable(address(proxy))).claimWithResolver(address(factory));
    }

    function _assertReverseResolver(address proxy, address expected) internal view {
        bytes32 node = REVERSE_REGISTRAR.node(proxy);
        assertEq(ENS.resolver(node), expected, "reverse resolver not as expected");
    }
}
