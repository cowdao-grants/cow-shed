// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.25;

import {BaseTest} from "./BaseTest.sol";
import {Vm} from "forge-std/Test.sol";
import {COWShed} from "src/COWShed.sol";
import {COWShedFactory, COWShedProxy} from "src/COWShedFactory.sol";
import {Call} from "src/LibAuthenticatedHooks.sol";
import {Stub} from "test/lib/Stub.sol";

contract COWShedFactoryTest is BaseTest {
    Stub stub;

    function setUp() public override {
        super.setUp();
        stub = new Stub();
    }

    function testExposesExpectedCreationCode() external view {
        assertEq(factory.PROXY_CREATION_CODE(), type(COWShedProxy).creationCode);
    }

    function testDeploysExpectedProxy() external {
        address user = makeAddr("proxy owner");
        address expected = factory.proxyOf(user);
        assertEq(address(expected).code.length, 0);
        factory.initializeProxy(user);
        assertGt(address(expected).code.length, 0);
    }

    function testDeploymentFailsIfImplementationHasNoCode() external {
        address emptyImplementation = makeAddr("empty COWShed");
        assertEq(emptyImplementation.code, hex"");
        vm.expectRevert(COWShedFactory.NoCodeAtImplementation.selector);
        new COWShedFactory(emptyImplementation);
    }

    function testExecuteHooks() external {
        Vm.Wallet memory wallet = vm.createWallet("testWallet");
        address addr1 = makeAddr("addr1");
        address addr2 = makeAddr("addr2");

        Call[] memory calls = new Call[](2);
        calls[0] = Call({target: addr1, value: 0, callData: hex"00112233", allowFailure: false, isDelegateCall: false});

        calls[1] = Call({target: addr2, value: 0, callData: hex"11", allowFailure: false, isDelegateCall: false});

        address expectedProxyAddress = factory.proxyOf(wallet.addr);
        assertEq(expectedProxyAddress.code.length, 0, "expectedProxyAddress code is not empty");

        bytes32 nonce = "nonce";
        bytes memory signature = _signForProxy(calls, nonce, _deadline(), wallet);
        vm.expectCall(addr1, calls[0].callData);
        vm.expectCall(addr2, calls[1].callData);
        factory.executeHooks(calls, nonce, _deadline(), wallet.addr, signature);
        assertGt(expectedProxyAddress.code.length, 0, "expectedProxyAddress code is still empty");

        vm.expectRevert(COWShedFactory.NonceAlreadyUsed.selector);
        factory.executeHooks(calls, nonce, _deadline(), wallet.addr, signature);
    }

    function testDomainSeparators() external {
        Vm.Wallet memory user1 = vm.createWallet("user1");
        Vm.Wallet memory user2 = vm.createWallet("user2");

        _initializeUserProxy(user1);
        _initializeUserProxy(user2);

        COWShed proxy1 = COWShed(payable(factory.proxyOf(user1.addr)));
        COWShed proxy2 = COWShed(payable(factory.proxyOf(user2.addr)));

        vm.label(address(proxy1), "proxy1");
        vm.label(address(proxy2), "proxy2");

        assertTrue(
            proxy1.domainSeparator() != proxy2.domainSeparator(),
            "different proxies should have different domain separators"
        );
    }

    function testInitializeProxy() external {
        address userAddr = makeAddr("user1");
        address proxyAddr = factory.proxyOf(userAddr);
        assertEq(proxyAddr.code.length, 0, "proxy is already initialized");
        factory.initializeProxy(userAddr);
        assertGt(proxyAddr.code.length, 0, "proxy is still not initialized");
    }

    function testInitializeProxyReturnsTheProxyAddress() external {
        address userAddr = makeAddr("user1");
        address proxyAddr = factory.proxyOf(userAddr);

        assertEq(factory.initializeProxy(userAddr), proxyAddr, "didnt return the proxy address on deployment");
        // initializing an existing proxy is a no-op that still returns the address
        assertEq(factory.initializeProxy(userAddr), proxyAddr, "didnt return the proxy address for existing proxy");
    }

    function testExecuteOwnHooks_deploysProxyAndExecutesHooks() external {
        address owner = makeAddr("shed owner");
        address proxyAddr = factory.proxyOf(owner);
        assertEq(proxyAddr.code.length, 0, "proxy is already initialized");

        Call[] memory calls = new Call[](2);
        calls[0] = Call({
            target: address(stub),
            value: 0,
            callData: abi.encodeCall(stub.returnUint, ()),
            allowFailure: false,
            isDelegateCall: false
        });
        calls[1] = Call({
            target: address(stub),
            value: 0,
            callData: abi.encodeCall(stub.willRevert, ()),
            allowFailure: true,
            isDelegateCall: false
        });

        vm.expectCall(address(stub), calls[0].callData);
        vm.expectCall(address(stub), calls[1].callData);
        vm.prank(owner);
        address proxy = factory.executeOwnHooks(calls);

        assertEq(proxy, proxyAddr, "didnt return the expected proxy address");
        assertGt(proxyAddr.code.length, 0, "proxy is still not initialized");
        assertEq(factory.ownerOf(proxyAddr), owner, "reverse mapping wasnt set");
        assertEq(COWShed(payable(proxyAddr)).trustedExecutor(), address(factory), "factory isnt the trusted executor");
    }

    function testExecuteOwnHooks_executesHooksOnAnExistingProxy() external {
        Call[] memory calls = new Call[](1);
        calls[0] = Call({
            target: address(stub),
            value: 0,
            callData: abi.encodeCall(stub.returnUint, ()),
            allowFailure: false,
            isDelegateCall: false
        });

        vm.expectCall(address(stub), calls[0].callData);
        vm.prank(user.addr);
        assertEq(factory.executeOwnHooks(calls), userProxyAddr, "didnt return the expected proxy address");
    }

    function testProxyOf_differsByOwner() external {
        address caller = makeAddr("caller");
        address someoneElse = makeAddr("someone else");
        assertTrue(factory.proxyOf(caller) != factory.proxyOf(someoneElse));
    }

    function testExecuteOwnHooks_forwardsValueToTheProxy() external {
        address owner = makeAddr("funded shed owner");
        vm.deal(owner, 1 ether);
        assertEq(factory.proxyOf(owner).balance, 0, "proxy already has ETH");

        vm.prank(owner);
        address proxy = factory.executeOwnHooks{value: 0.4 ether}(new Call[](0));

        assertEq(proxy.balance, 0.4 ether, "value wasnt forwarded to the proxy");
        assertEq(address(factory).balance, 0, "value was left in the factory");
    }

    function testExecuteOwnHooks_hooksCanSpendTheForwardedValue() external {
        address owner = makeAddr("funded shed owner");
        vm.deal(owner, 1 ether);

        Call[] memory calls = new Call[](1);
        calls[0] = Call({
            target: address(stub),
            value: 0.25 ether,
            callData: abi.encodeCall(stub.callWithValue, ()),
            allowFailure: false,
            isDelegateCall: false
        });

        vm.prank(owner);
        address proxy = factory.executeOwnHooks{value: 0.25 ether}(calls);

        assertEq(address(stub).balance, 0.25 ether, "hook couldnt spend the forwarded value");
        assertEq(proxy.balance, 0, "value was left in the proxy");
    }

    function testExecuteOwnHooks_bubblesUpFailedHooks() external {
        address owner = makeAddr("shed owner");

        Call[] memory calls = new Call[](1);
        calls[0] = Call({
            target: address(stub),
            value: 0,
            callData: abi.encodeCall(stub.willRevert, ()),
            allowFailure: false,
            isDelegateCall: false
        });

        vm.expectRevert(Stub.Revert.selector);
        vm.prank(owner);
        factory.executeOwnHooks(calls);
    }

    function testExecuteOwnHooks_revertsIfTheFactoryIsNoLongerTheTrustedExecutor() external {
        // GIVEN: the user moved the trusted executor of their existing proxy away from the factory
        Call[] memory calls = new Call[](1);
        calls[0] = Call({
            target: userProxyAddr,
            value: 0,
            callData: abi.encodeCall(COWShed.updateTrustedExecutor, (makeAddr("new trusted executor"))),
            allowFailure: false,
            isDelegateCall: false
        });
        bytes32 nonce = "update trusted executor";
        bytes memory signature = _signForProxy(calls, nonce, _deadline(), user);
        factory.executeHooks(calls, nonce, _deadline(), user.addr, signature);

        // WHEN: the user executes hooks through the factory
        // THEN: the call reverts and the user is expected to call the proxy directly
        vm.expectRevert(COWShed.OnlyTrustedRole.selector);
        vm.prank(user.addr);
        factory.executeOwnHooks(new Call[](0));
    }
}
