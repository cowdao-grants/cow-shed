// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.25;

import {Stub} from "../lib/Stub.sol";
import {BaseForkedTest} from "./BaseForkedTest.sol";
import {COWShed, COWShedStorage, Call} from "src/COWShed.sol";
import {COWShedFactory} from "src/COWShedFactory.sol";
import {LibAuthenticatedHooks} from "src/LibAuthenticatedHooks.sol";

contract ForkedCOWShedPreSignTest is BaseForkedTest {
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

    function preSignStorage_uninitializeReturnZero() external view {
        // GIVEN: user never set the pre-sign storage

        // WHEN: checking the pre-sign storage
        // THEN: returns the zero-address
        assertEq(userProxy.preSignStorage(), address(0));
    }

    function testPreSignStorageNotSet_isPreSignedHooksReturnsFalse() external view {
        Call[] memory calls = new Call[](1);
        calls[0] = callWithValue;
        uint256 deadline = _deadline();
        bytes32 nonce = "1";

        // GIVEN: user never set the pre-sign storage

        // WHEN: check if the hook is pre-signed
        // THEN: returns false
        assertFalse(userProxy.isPreSignedHooks(calls, nonce, deadline), "hook is not pre-signed");
    }

    function testPreSignStorageNotSet_preSignReverts() external {
        Call[] memory calls = new Call[](1);
        calls[0] = callWithValue;
        uint256 deadline = _deadline();
        bytes32 nonce = "1";

        // GIVEN: user never set the pre-sign storage

        // WHEN: pre-sign a hook from the admin account
        // THEN: reverts with PreSignStorageNotSet
        vm.expectRevert(COWShedStorage.PreSignStorageNotSet.selector);
        vm.prank(user.addr);
        userProxy.preSignHooks(calls, nonce, deadline, true);
    }

    function testPreSignStorageNotSet_revokePreSignReverts() external {
        Call[] memory calls = new Call[](1);
        calls[0] = callWithValue;
        uint256 deadline = _deadline();
        bytes32 nonce = "1";

        // GIVEN: user never set the pre-sign storage

        // WHEN: revoking the pre-sign of a hook from the admin account
        // THEN: reverts with PreSignStorageNotSet
        vm.expectRevert(COWShedStorage.PreSignStorageNotSet.selector);
        vm.prank(user.addr);
        userProxy.preSignHooks(calls, nonce, deadline, false);
    }

    function testIsPreSignedHook() external {
        Call[] memory calls = new Call[](1);
        calls[0] = callWithValue;
        uint256 deadline = _deadline();
        bytes32 nonce = "1";

        // GIVEN: user has pre-signed a hook
        _presignForProxy(calls, nonce, deadline, true, user);

        // WHEN: check if the hook is pre-signed
        // THEN: the hook is pre-signed
        assertTrue(userProxy.isPreSignedHooks(calls, nonce, deadline), "hook is not pre-signed");
    }

    function testIsPreSignedHookUnsigned() external view {
        Call[] memory calls = new Call[](1);
        calls[0] = callWithValue;
        uint256 deadline = _deadline();
        bytes32 nonce = "1";

        // GIVEN: user has not pre-signed a hook
        // WHEN: check if the hook is pre-signed
        // THEN: the hook is not pre-signed
        assertFalse(userProxy.isPreSignedHooks(calls, nonce, deadline), "hook is pre-signed");
    }

    function testIsPreSignedHookRevoked() external {
        Call[] memory calls = new Call[](1);
        calls[0] = callWithValue;
        uint256 deadline = _deadline();
        bytes32 nonce = "1";

        // GIVEN: user had a hook signed, and then revoked it
        _presignForProxy(calls, nonce, deadline, true, user);
        _presignForProxy(calls, nonce, deadline, false, user);

        // WHEN: check if the hook is pre-signed
        // THEN: the hook is not pre-signed
        assertFalse(userProxy.isPreSignedHooks(calls, nonce, deadline), "hook is pre-signed");
    }

    function testIsPreUnsignedForDifferentNonce() external {
        Call[] memory calls = new Call[](1);
        calls[0] = callWithValue;
        uint256 deadline = _deadline();
        bytes32 nonce1 = "1";
        bytes32 nonce2 = "2";

        // GIVEN: user has pre-signed the hook
        _presignForProxy(calls, nonce1, deadline, true, user);

        // WHEN: check if the hook is pre-signed if we change the nonce
        // THEN: the hook is not pre-signed
        assertFalse(userProxy.isPreSignedHooks(calls, nonce2, deadline), "hook is pre-signed");
    }

    function testIsPreSignedRevokeUnsigned() external {
        Call[] memory calls = new Call[](1);
        calls[0] = callWithValue;
        uint256 deadline = _deadline();
        bytes32 nonce = "1";

        // GIVEN: user has not pre-signed the hook
        // GIVEN: the user revokes the pre-signed hook
        _presignForProxy(calls, nonce, deadline, false, user);

        // WHEN: check if the hook is pre-signed
        // THEN: the hook is not pre-signed
        assertFalse(userProxy.isPreSignedHooks(calls, nonce, deadline), "hook is pre-signed");
    }

    function testIsPreUnsignedForDifferentDeadline() external {
        Call[] memory calls = new Call[](1);
        calls[0] = callWithValue;
        uint256 deadline = _deadline();
        bytes32 nonce = "1";

        // GIVEN: user has pre-signed the hook
        _presignForProxy(calls, nonce, deadline, true, user);

        // WHEN: check if the hook is pre-signed if we change the deadline
        // THEN: the hook is not pre-signed
        assertFalse(userProxy.isPreSignedHooks(calls, nonce, deadline + 1), "hook is pre-signed");
    }

    function testIsPreUnsignedForDifferentCalls() external {
        Call[] memory calls1 = new Call[](1);
        calls1[0] = callWithValue;

        Call[] memory calls2 = new Call[](1);
        calls2[0] = callWillRevert;
        uint256 deadline = _deadline();
        bytes32 nonce = "1";

        // GIVEN: user has pre-signed the hook
        _presignForProxy(calls1, nonce, deadline, true, user);

        // WHEN: check if the hook is pre-signed if we change the calls
        // THEN: the hook is not pre-signed
        assertFalse(userProxy.isPreSignedHooks(calls2, nonce, deadline), "hook is pre-signed");
    }

    function testPreSignFlowSuccess() external {
        // GIVEN: shed has 1 ether
        vm.deal(userProxyAddr, 1 ether);

        Call[] memory calls = new Call[](1);
        calls[0] = callWithValue;
        uint256 deadline = _deadline();
        bytes32 nonce = "1";

        // GIVEN: user has pre-signed hook to send ether to the stub
        _presignForProxy(calls, nonce, deadline, true, user);

        // WHEN: execute the pre-signed hook
        // THEN: the hook is executed
        vm.expectCall(callWithValue.target, callWithValue.callData);
        userProxy.executePreSignedHooks(calls, nonce, deadline);

        // THEN: the proxy sent ether to the stub
        assertEq(callWithValue.target.balance, callWithValue.value, "didn't send value as expected");
        assertEq(address(userProxy).balance, 1 ether - callWithValue.value, "didn't send value as expected");
    }

    function testPreSignFlowUnsigned() external {
        // GIVEN: user has 1 ether
        vm.deal(userProxyAddr, 1 ether);

        Call[] memory calls = new Call[](1);
        calls[0] = callWithValue;
        uint256 deadline = _deadline();
        bytes32 nonce = "1";

        // GIVEN: user has not pre-signed the hook

        // WHEN: pre-sign the hook
        // THEN: the call should revert
        vm.expectRevert(COWShed.NotPreSigned.selector);
        userProxy.executePreSignedHooks(calls, nonce, deadline);
    }

    function testPreSignFlowRevoke() external {
        // GIVEN: user has 1 ether
        vm.deal(userProxyAddr, 1 ether);

        Call[] memory calls = new Call[](1);
        calls[0] = callWithValue;
        uint256 deadline = _deadline();
        bytes32 nonce = "1";

        // GIVEN: user has pre-signed the hook
        _presignForProxy(calls, nonce, deadline, true, user);

        // GIVEN: the user revokes the pre-signed hook
        _presignForProxy(calls, nonce, deadline, false, user);

        // WHEN: execute the pre-signed hook
        // THEN: the call should revert
        vm.expectRevert(COWShed.NotPreSigned.selector);
        userProxy.executePreSignedHooks(calls, nonce, deadline);
    }

    function testPreSignFlowRevokeUnsigned() external {
        // GIVEN: user has 1 ether
        vm.deal(userProxyAddr, 1 ether);

        Call[] memory calls = new Call[](1);
        calls[0] = callWithValue;
        uint256 deadline = _deadline();
        bytes32 nonce = "1";

        // GIVEN: user has not pre-signed hook

        // GIVEN: the user revokes the pre-signed hook
        _presignForProxy(calls, nonce, deadline, false, user);

        // WHEN: execute the pre-signed hook
        // THEN: the call should revert
        vm.expectRevert(COWShed.NotPreSigned.selector);
        userProxy.executePreSignedHooks(calls, nonce, deadline);
    }

    function testPreSignFlowRevertsOnSecondExecution() external {
        // GIVEN: shed has 1 ether
        vm.deal(userProxyAddr, 1 ether);

        Call[] memory calls = new Call[](1);
        calls[0] = callWithValue;
        uint256 deadline = _deadline();
        bytes32 nonce = "1";

        // GIVEN: A user executes has already executed a pre-signed hook
        _presignForProxy(calls, nonce, deadline, true, user);
        userProxy.executePreSignedHooks(calls, nonce, deadline);

        // WHEN: execute the pre-signed hook
        // THEN: reverts with NonceAlreadyUsed
        vm.expectRevert(COWShedFactory.NonceAlreadyUsed.selector);
        userProxy.executePreSignedHooks(calls, nonce, deadline);
    }
}
