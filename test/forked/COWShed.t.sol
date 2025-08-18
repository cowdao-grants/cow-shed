// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.25;

import {BaseForkedTest} from "./BaseForkedTest.sol";
import {COWShed, COWShedStorage, Call} from "src/COWShed.sol";
import {COWShedFactory} from "src/COWShedFactory.sol";

import {COWShedProxy} from "src/COWShedProxy.sol";
import {LibAuthenticatedHooks} from "src/LibAuthenticatedHooks.sol";

/// @dev dummy contract
contract Stub {
    error Revert();

    function willRevert() external pure {
        revert Revert();
    }

    function callWithValue() external payable {}

    function returnUint() external pure returns (uint256) {
        return 420;
    }

    function storeAt(bytes32 slot, bytes32 value) external {
        assembly {
            sstore(slot, value)
        }
    }
}

contract ForkedCOWShedTest is BaseForkedTest {
    Stub stub;
    Call callWithValue;
    Call callWillRevert;

    function setUp() public override {
        super.setUp();
        stub = new Stub();

        callWithValue = Call({
            target: address(stub),
            value: 0.05 ether,
            allowFailure: false,
            callData: abi.encodeCall(stub.callWithValue, ()),
            isDelegateCall: false
        });

        callWillRevert = Call({
            target: address(stub),
            value: 0,
            allowFailure: true,
            callData: abi.encodeCall(stub.willRevert, ()),
            isDelegateCall: false
        });
    }

    function testExecuteHooks() external {
        // fund the proxy
        vm.deal(userProxyAddr, 1 ether);

        Call[] memory calls = new Call[](2);
        calls[0] = Call({
            target: address(stub),
            value: 0.05 ether,
            allowFailure: false,
            callData: abi.encodeCall(stub.callWithValue, ()),
            isDelegateCall: false
        });
        calls[1] = Call({
            target: address(stub),
            value: 0,
            allowFailure: true,
            callData: abi.encodeCall(stub.willRevert, ()),
            isDelegateCall: false
        });
        bytes32 nonce = "1";

        bytes memory signature = _signForProxy(calls, nonce, _deadline(), user);
        vm.expectCall(address(stub), abi.encodeCall(stub.callWithValue, ()));
        vm.expectCall(address(stub), abi.encodeCall(stub.willRevert, ()));
        factory.executeHooks(calls, nonce, _deadline(), user.addr, signature);

        // same sig shouldnt work more than once
        vm.expectRevert(COWShedFactory.NonceAlreadyUsed.selector);
        factory.executeHooks(calls, nonce, _deadline(), user.addr, signature);

        assertEq(address(stub).balance, 0.05 ether, "didnt send value as expected");

        // test that allowFailure works as expected
        calls[1].allowFailure = false;
        nonce = "2";
        signature = _signForProxy(calls, nonce, _deadline(), user);
        vm.expectCall(address(stub), abi.encodeCall(stub.callWithValue, ()));
        vm.expectCall(address(stub), abi.encodeCall(stub.willRevert, ()));
        vm.expectRevert(Stub.Revert.selector);
        userProxy.executeHooks(calls, nonce, _deadline(), signature);
    }

    function testExecuteHooksDeadline() external {
        Call[] memory calls = new Call[](1);
        calls[0] = Call({target: address(0), value: 0, allowFailure: false, callData: hex"0011", isDelegateCall: false});
        bytes32 nonce = "deadline-nonce";
        uint256 deadline = block.timestamp - 1;
        bytes memory signature = _signForProxy(calls, nonce, deadline, user);
        vm.expectRevert(LibAuthenticatedHooks.DeadlineElapsed.selector);
        userProxy.executeHooks(calls, nonce, deadline, signature);
    }

    function testExecuteHooksDelegateCall() external {
        bytes32 randomSlot = keccak256("randomSlot");
        bytes32 randomValue = keccak256("randomValue");

        Call[] memory calls = new Call[](1);
        calls[0] = Call({
            target: address(stub),
            callData: abi.encodeCall(Stub.storeAt, (randomSlot, randomValue)),
            value: 0,
            allowFailure: false,
            isDelegateCall: true
        });
        bytes32 nonce = "delegatecall-nonce";
        uint256 deadline = _deadline();

        bytes32 prev = vm.load(userProxyAddr, randomSlot);
        assertEq(prev, bytes32(0), "randomSlot is already set");

        bytes memory signature = _signForProxy(calls, nonce, deadline, user);
        userProxy.executeHooks(calls, nonce, deadline, signature);

        bytes32 aftr = vm.load(userProxyAddr, randomSlot);
        assertEq(aftr, randomValue, "randomSlot not set as expected from the delegatecall");
    }

    function testRevokeNonce() external {
        Call[] memory calls = new Call[](1);
        calls[0] = Call({target: address(0), callData: hex"0011", value: 0, allowFailure: false, isDelegateCall: false});
        bytes32 nonce = "nonce-to-revoke";
        bytes memory signature = _signForProxy(calls, nonce, _deadline(), user);
        assertFalse(userProxy.nonces(nonce), "nonce is already used");

        vm.prank(user.addr);
        userProxy.revokeNonce(nonce);
        assertTrue(userProxy.nonces(nonce), "nonce is not used yet");

        vm.expectRevert(COWShedStorage.NonceAlreadyUsed.selector);
        userProxy.executeHooks(calls, nonce, _deadline(), signature);
    }

    function testUpdateTrustedHook() external {
        address addr = makeAddr("addr");
        assertFalse(COWShed(payable(userProxy)).trustedExecutor() == addr, "should not be a trusted executor");

        Call[] memory calls = new Call[](1);
        calls[0] = Call({
            target: address(userProxy),
            callData: abi.encodeCall(COWShed.updateTrustedExecutor, (addr)),
            allowFailure: false,
            value: 0,
            isDelegateCall: false
        });
        bytes32 nonce = "1";
        bytes memory signature = _signForProxy(calls, nonce, _deadline(), user);
        userProxy.executeHooks(calls, nonce, _deadline(), signature);

        assertTrue(COWShed(payable(userProxy)).trustedExecutor() == addr, "should be a trusted executor");
    }

    function testTrustedExecuteHooks_executeCallsFromNewTrustedExecutor() external {
        // GIVEN: an address that is not the trusted executor
        address addr = makeAddr("addr");
        COWShed cowShed = COWShed(payable(userProxy));
        address trustedExecutor = cowShed.trustedExecutor();
        assertNotEq(trustedExecutor, addr, "should not be a trusted executor");

        // GIVEN: the address is not the admin neither
        vm.prank(address(userProxy));
        address admin = COWShedProxy(payable(userProxy)).admin();
        assertFalse(admin == addr, "should not be the admin");

        // GIVEN: the admin is not the trusted executor
        assertNotEq(admin, trustedExecutor, "trustedExecutor should not be the admin");

        // GIVEN: the address becomes the trusted executor
        Call[] memory calls = new Call[](1);
        calls[0] = Call({
            target: address(userProxy),
            callData: abi.encodeCall(COWShed.updateTrustedExecutor, (addr)),
            allowFailure: false,
            value: 0,
            isDelegateCall: false
        });
        bytes32 nonce = "1";
        bytes memory signature = _signForProxy(calls, nonce, _deadline(), user);
        userProxy.executeHooks(calls, nonce, _deadline(), signature);

        // WHEN: this new trusted executor executes a call
        // THEN: the call is executed
        vm.prank(addr);
        vm.expectCall(address(0), hex"1234");
        calls[0].target = address(0);
        calls[0].callData = hex"1234";
        userProxy.trustedExecuteHooks(calls);
    }

    function testTrustedExecuteHooks_trustedExecutorSuccess() external {
        // GIVEN: shed has 1 ether
        vm.deal(userProxyAddr, 1 ether);

        Call[] memory calls = new Call[](1);
        calls[0] = callWithValue;

        // WHEN: the trusted executor executes a call
        // THEN: the call is executed
        vm.expectCall(callWithValue.target, callWithValue.callData);
        vm.prank(COWShed(payable(userProxy)).trustedExecutor());
        userProxy.trustedExecuteHooks(calls);

        // THEN: the proxy sent 0.05 ether to the stub
        assertEq(callWithValue.target.balance, 0.05 ether, "didnt send value as expected");
        assertEq(address(userProxy).balance, 0.95 ether, "didnt send value as expected");
    }

    function testTrustedExecuteHooks_adminSuccess() external {
        // GIVEN: shed has 1 ether
        vm.deal(userProxyAddr, 1 ether);

        Call[] memory calls = new Call[](1);
        calls[0] = callWithValue;

        // WHEN: the admin executes a call
        // THEN: the call is executed
        vm.expectCall(callWithValue.target, callWithValue.callData);
        vm.prank(user.addr);
        userProxy.trustedExecuteHooks(calls);

        // THEN: the proxy sent 0.05 ether to the stub
        assertEq(callWithValue.target.balance, 0.05 ether, "didnt send value as expected");
        assertEq(address(userProxy).balance, 0.95 ether, "didnt send value as expected");
    }

    function testTrustedExecuteHooks_neitherAdminNorTrustedExecutorError() external {
        // GIVEN: shed has 1 ether
        vm.deal(userProxyAddr, 1 ether);

        Call[] memory calls = new Call[](1);
        calls[0] = callWithValue;

        // WHEN: someone other than the trusted executor or the admin executes a call
        // THEN: the call should revert
        vm.expectRevert(COWShed.OnlyTrustedRole.selector);
        address neitherAdminNorTrustedExecutor = makeAddr("neitherAdminNorTrustedExecutor");
        vm.prank(neitherAdminNorTrustedExecutor);
        userProxy.trustedExecuteHooks(calls);
    }

    function testUpdateImplementation() external {
        vm.prank(user.addr);
        userProxy.updateImplementation(address(stub));
        assertImpl(userProxyAddr, address(stub));
        assertEq(Stub(userProxyAddr).returnUint(), 420, "didnt update as expected");
    }

    function testExecuteHooksForSmartAccount() external {
        // fund the proxy
        vm.deal(smartWalletProxyAddr, 1 ether);

        Call[] memory calls = new Call[](2);
        calls[0] = Call({
            target: address(stub),
            value: 0.05 ether,
            allowFailure: false,
            callData: abi.encodeCall(stub.callWithValue, ()),
            isDelegateCall: false
        });
        calls[1] = Call({
            target: address(stub),
            value: 0,
            allowFailure: true,
            callData: abi.encodeCall(stub.willRevert, ()),
            isDelegateCall: false
        });
        bytes32 nonce = "1";
        bytes memory sig =
            _signWithSmartWalletForProxy(calls, nonce, _deadline(), smartWalletAddr, smartWalletProxyAddr);
        vm.expectCall(address(stub), abi.encodeCall(stub.callWithValue, ()));
        vm.expectCall(address(stub), abi.encodeCall(stub.willRevert, ()));
        smartWalletProxy.executeHooks(calls, nonce, _deadline(), sig);

        // same sig shouldnt work more than once
        vm.expectRevert(COWShedFactory.NonceAlreadyUsed.selector);
        smartWalletProxy.executeHooks(calls, nonce, _deadline(), sig);

        assertEq(address(stub).balance, 0.05 ether, "didnt send value as expected");
    }
}
