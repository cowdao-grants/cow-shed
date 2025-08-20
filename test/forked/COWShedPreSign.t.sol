// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.25;

import {Stub} from "../lib/Stub.sol";
import {BaseForkedTest} from "./BaseForkedTest.sol";
import {COWShed, COWShedStorage, Call} from "src/COWShed.sol";
import {COWShedFactory} from "src/COWShedFactory.sol";

import {IPreSignStorage} from "src/IPreSignStorage.sol";
import {LibAuthenticatedHooks} from "src/LibAuthenticatedHooks.sol";

event PreSignStorageChanged(address indexed newStorage);

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

    function testPreSignStorage_uninitializeReturnZero() external view {
        // GIVEN: user never set the pre-sign storage

        // WHEN: checking the pre-sign storage
        // THEN: returns the zero-address
        assertPreSignStorageEq(userProxy.preSignStorage(), ZERO_ADDRESS_PRESIGN_STORAGE);
    }

    function testPreSignStorage_initializedReturnValue() external {
        // GIVEN: user initialized the storage
        IPreSignStorage presignStorage = IPreSignStorage(makeAddr("mockStorage"));
        _setPreSignStorage(presignStorage, user);

        // WHEN: checking the pre-sign storage
        // THEN: returns the address we set
        assertPreSignStorageEq(userProxy.preSignStorage(), presignStorage);
    }

    function testPreSignStorage_replacedAddressReturnsValue() external {
        // GIVEN: user initialized the storage
        _setPreSignStorage(IPreSignStorage(makeAddr("storage1")), user);

        // GIVEN: user replaces it to a new storage
        IPreSignStorage newStorage = IPreSignStorage(makeAddr("storage2"));
        _setPreSignStorage(newStorage, user);

        // WHEN: checking the pre-sign storage
        // THEN: returns the latest storage the user set
        assertPreSignStorageEq(userProxy.preSignStorage(), newStorage);
    }

    function testResetPreSignStorage_uninitialized() external {
        // GIVEN: user never initialized the pre-sign storage

        // WHEN: initializing the pre-sign storage
        vm.prank(user.addr);
        IPreSignStorage storageReturned = userProxy.resetPreSignStorage();

        // THEN: the pre-sign storage has been initialized to a new contract
        assertNotEq(address(storageReturned), address(0));
        assertTrue(address(storageReturned).code.length > 0);

        // THEN: the contract matches the one returned in the reset function
        IPreSignStorage storageGetter = userProxy.preSignStorage();
        assertPreSignStorageEq(storageGetter, storageReturned);
    }

    function testResetPreSignStorage_alreadyInitialized() external {
        // GIVEN: user never initialized the pre-sign storage
        IPreSignStorage storageOld = _resetPreSignStorage(user);

        // WHEN: initializing the pre-sign storage again
        vm.prank(user.addr);
        IPreSignStorage storageReturned = userProxy.resetPreSignStorage();

        // THEN: the storage changed
        assertNotEq(address(storageOld), address(storageReturned));

        // THEN: The storage is not the zero-address
        assertNotEq(address(storageReturned), address(0));

        // THEN: the pre-sign storage matches the one returned in the reset function
        IPreSignStorage storageAddressNew = userProxy.preSignStorage();
        assertPreSignStorageEq(storageAddressNew, storageReturned);
    }

    function testSetPreSignStorage_setZeroAddress() external {
        // GIVEN: user never set the pre-sign storage

        // WHEN: setting the pre-sign storage to zero
        // THEN: An event with the zero-address is emitted
        vm.prank(user.addr);
        vm.expectEmit(true, true, false, false);
        emit PreSignStorageChanged(address(0));
        IPreSignStorage storageReturned = userProxy.setPreSignStorage(ZERO_ADDRESS_PRESIGN_STORAGE);

        // THEN: the returned storage is the zero-address
        assertPreSignStorageEq(storageReturned, ZERO_ADDRESS_PRESIGN_STORAGE);

        // THEN: the current storage is also the zero-address
        assertPreSignStorageEq(userProxy.preSignStorage(), ZERO_ADDRESS_PRESIGN_STORAGE);
    }

    function testSetPreSignStorage_setNonZeroAddress() external {
        // GIVEN: user never set the pre-sign storage

        // WHEN: setting the pre-sign storage to some address
        // THEN: An event with the pre-sign storage address is emitted
        IPreSignStorage presignStorage = IPreSignStorage(makeAddr("presignStorage"));
        vm.prank(user.addr);
        vm.expectEmit(true, true, false, false);
        emit PreSignStorageChanged(address(presignStorage));
        IPreSignStorage storageReturned = userProxy.setPreSignStorage(presignStorage);

        // THEN: returns the presignStorage
        assertPreSignStorageEq(storageReturned, presignStorage);
        assertPreSignStorageEq(userProxy.preSignStorage(), presignStorage);
    }

    function testSetPreSignStorage_setZeroAddressToInitializedStorage() external {
        // GIVEN: user had set the pre-sign storage
        _setPreSignStorage(IPreSignStorage(makeAddr("storageAddress")), user);

        // WHEN: setting the pre-sign storage to zero
        // THEN: An event with the zero-address is emitted
        vm.prank(user.addr);
        vm.expectEmit(true, true, false, false);
        emit PreSignStorageChanged(address(0));
        IPreSignStorage storageReturned = userProxy.setPreSignStorage(ZERO_ADDRESS_PRESIGN_STORAGE);

        // THEN: returns the zero-address
        assertPreSignStorageEq(storageReturned, ZERO_ADDRESS_PRESIGN_STORAGE);
        assertPreSignStorageEq(userProxy.preSignStorage(), ZERO_ADDRESS_PRESIGN_STORAGE);
    }

    function testPreSignHooks_initializedStorage() external {
        Call[] memory calls = new Call[](1);
        calls[0] = callWithValue;
        uint256 deadline = _deadline();
        bytes32 nonce = "1";

        // GIVEN: user initialized the pre-sign storage
        _resetPreSignStorage(user);

        // WHEN: execute pre-signed the hook
        vm.prank(user.addr);
        userProxy.preSignHooks(calls, nonce, deadline, true);

        // THEN: the hook is pre-signed
        assertTrue(userProxy.isPreSignedHooks(calls, nonce, deadline), "hook is not pre-signed");
    }

    function testPreSignHooks_storageNotSet_presign() external {
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

    function testPreSignHooks_storageNotSet_revoke() external {
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

    function testSetPreSignStorage_replaceAddress() external {
        // GIVEN: user had set the pre-sign storage
        IPreSignStorage storageAddressOld = IPreSignStorage(makeAddr("storageAddressOld"));
        _setPreSignStorage(storageAddressOld, user);

        // WHEN: setting the pre-sign storage to a new address
        // THEN: An event with the new storage address is emitted
        IPreSignStorage storageAddressNew = IPreSignStorage(makeAddr("storageAddressNew"));
        vm.prank(user.addr);
        vm.expectEmit(true, true, false, false);
        emit PreSignStorageChanged(address(storageAddressNew));
        userProxy.setPreSignStorage(storageAddressNew);

        // THEN: returns the new address
        assertPreSignStorageEq(userProxy.preSignStorage(), storageAddressNew);
    }

    function testIsPreSignedHooks_storageNotSetReturnsFalse() external view {
        Call[] memory calls = new Call[](1);
        calls[0] = callWithValue;
        uint256 deadline = _deadline();
        bytes32 nonce = "1";

        // GIVEN: user never set the pre-sign storage

        // WHEN: check if the hook is pre-signed
        // THEN: returns false
        assertFalse(userProxy.isPreSignedHooks(calls, nonce, deadline), "hook is not pre-signed");
    }

    function testIsPreSignedHooks_signed() external {
        Call[] memory calls = new Call[](1);
        calls[0] = callWithValue;
        uint256 deadline = _deadline();
        bytes32 nonce = "1";

        // GIVEN: user has pre-signed a hook
        _resetPreSignStorage(user);
        _presignForProxy(calls, nonce, deadline, true, user);

        // WHEN: check if the hook is pre-signed
        // THEN: the hook is pre-signed
        assertTrue(userProxy.isPreSignedHooks(calls, nonce, deadline), "hook is not pre-signed");
    }

    function testIsPreSignedHooks_unsigned() external view {
        Call[] memory calls = new Call[](1);
        calls[0] = callWithValue;
        uint256 deadline = _deadline();
        bytes32 nonce = "1";

        // GIVEN: user has not pre-signed a hook
        // WHEN: check if the hook is pre-signed
        // THEN: the hook is not pre-signed
        assertFalse(userProxy.isPreSignedHooks(calls, nonce, deadline), "hook is pre-signed");
    }

    function testIsPreSignedHooks_revoked() external {
        Call[] memory calls = new Call[](1);
        calls[0] = callWithValue;
        uint256 deadline = _deadline();
        bytes32 nonce = "1";

        // GIVEN: user had a hook signed, and then revoked it
        _resetPreSignStorage(user);
        _presignForProxy(calls, nonce, deadline, true, user);
        _presignForProxy(calls, nonce, deadline, false, user);

        // WHEN: check if the hook is pre-signed
        // THEN: the hook is not pre-signed
        assertFalse(userProxy.isPreSignedHooks(calls, nonce, deadline), "hook is pre-signed");
    }

    function testIsPreSignedHooks_signedForDifferentNonce() external {
        Call[] memory calls = new Call[](1);
        calls[0] = callWithValue;
        uint256 deadline = _deadline();
        bytes32 nonce1 = "1";
        bytes32 nonce2 = "2";

        // GIVEN: user has pre-signed the hook
        _resetPreSignStorage(user);
        _presignForProxy(calls, nonce1, deadline, true, user);

        // WHEN: check if the hook is pre-signed if we change the nonce
        // THEN: the hook is not pre-signed
        assertFalse(userProxy.isPreSignedHooks(calls, nonce2, deadline), "hook is pre-signed");
    }

    function testIsPreSignedHooks_revokeUnsigned() external {
        Call[] memory calls = new Call[](1);
        calls[0] = callWithValue;
        uint256 deadline = _deadline();
        bytes32 nonce = "1";

        // GIVEN: user has not pre-signed the hook
        _resetPreSignStorage(user);

        // GIVEN: the user revokes the pre-signed hook
        _presignForProxy(calls, nonce, deadline, false, user);

        // WHEN: check if the hook is pre-signed
        // THEN: the hook is not pre-signed
        assertFalse(userProxy.isPreSignedHooks(calls, nonce, deadline), "hook is pre-signed");
    }

    function testIsPreSignedHooks_signedForDifferentDeadline() external {
        Call[] memory calls = new Call[](1);
        calls[0] = callWithValue;
        uint256 deadline = _deadline();
        bytes32 nonce = "1";

        // GIVEN: user has pre-signed the hook
        _resetPreSignStorage(user);
        _presignForProxy(calls, nonce, deadline, true, user);

        // WHEN: check if the hook is pre-signed if we change the deadline
        // THEN: the hook is not pre-signed
        assertFalse(userProxy.isPreSignedHooks(calls, nonce, deadline + 1), "hook is pre-signed");
    }

    function testIsPreSignedHooks_signedForDifferentCalls() external {
        Call[] memory calls1 = new Call[](1);
        calls1[0] = callWithValue;

        Call[] memory calls2 = new Call[](1);
        calls2[0] = callWillRevert;
        uint256 deadline = _deadline();
        bytes32 nonce = "1";

        // GIVEN: user has pre-signed the hook
        _resetPreSignStorage(user);
        _presignForProxy(calls1, nonce, deadline, true, user);

        // WHEN: check if the hook is pre-signed if we change the calls
        // THEN: the hook is not pre-signed
        assertFalse(userProxy.isPreSignedHooks(calls2, nonce, deadline), "hook is pre-signed");
    }

    function testExecutePreSignedHooks_success() external {
        // GIVEN: shed has 1 ether
        vm.deal(userProxyAddr, 1 ether);

        Call[] memory calls = new Call[](1);
        calls[0] = callWithValue;
        uint256 deadline = _deadline();
        bytes32 nonce = "1";

        // GIVEN: user has pre-signed hook to send ether to the stub
        _resetPreSignStorage(user);
        _presignForProxy(calls, nonce, deadline, true, user);

        // WHEN: execute the pre-signed hook
        // THEN: the hook is executed
        vm.expectCall(callWithValue.target, callWithValue.callData);
        userProxy.executePreSignedHooks(calls, nonce, deadline);

        // THEN: the proxy sent ether to the stub
        assertEq(callWithValue.target.balance, callWithValue.value, "didn't send value as expected");
        assertEq(address(userProxy).balance, 1 ether - callWithValue.value, "didn't send value as expected");
    }

    function testExecutePreSignedHooks_unsignedReverts() external {
        // GIVEN: user has 1 ether
        vm.deal(userProxyAddr, 1 ether);

        Call[] memory calls = new Call[](1);
        calls[0] = callWithValue;
        uint256 deadline = _deadline();
        bytes32 nonce = "1";

        // GIVEN: user has not pre-signed the hook
        _resetPreSignStorage(user);

        // WHEN: pre-sign the hook
        // THEN: the call should revert
        vm.expectRevert(COWShed.NotPreSigned.selector);
        userProxy.executePreSignedHooks(calls, nonce, deadline);
    }

    function testExecutePreSignedHooks_revokedPreSignReverts() external {
        // GIVEN: user has 1 ether
        vm.deal(userProxyAddr, 1 ether);

        Call[] memory calls = new Call[](1);
        calls[0] = callWithValue;
        uint256 deadline = _deadline();
        bytes32 nonce = "1";

        // GIVEN: user has pre-signed the hook
        _resetPreSignStorage(user);
        _presignForProxy(calls, nonce, deadline, true, user);

        // GIVEN: the user revokes the pre-signed hook
        _presignForProxy(calls, nonce, deadline, false, user);

        // WHEN: execute the pre-signed hook
        // THEN: the call should revert
        vm.expectRevert(COWShed.NotPreSigned.selector);
        userProxy.executePreSignedHooks(calls, nonce, deadline);
    }

    function testExecutePreSignedHooks_revokedUnsignedReverts() external {
        // GIVEN: user has 1 ether
        vm.deal(userProxyAddr, 1 ether);

        Call[] memory calls = new Call[](1);
        calls[0] = callWithValue;
        uint256 deadline = _deadline();
        bytes32 nonce = "1";

        // GIVEN: user has not pre-signed hook
        _resetPreSignStorage(user);

        // GIVEN: the user revokes the pre-signed hook
        _presignForProxy(calls, nonce, deadline, false, user);

        // WHEN: execute the pre-signed hook
        // THEN: the call should revert
        vm.expectRevert(COWShed.NotPreSigned.selector);
        userProxy.executePreSignedHooks(calls, nonce, deadline);
    }

    function testExecutePreSignedHooks_revertsOnSecondExecution() external {
        // GIVEN: shed has 1 ether
        vm.deal(userProxyAddr, 1 ether);

        Call[] memory calls = new Call[](1);
        calls[0] = callWithValue;
        uint256 deadline = _deadline();
        bytes32 nonce = "1";

        // GIVEN: A user executes has already executed a pre-signed hook
        _resetPreSignStorage(user);
        _presignForProxy(calls, nonce, deadline, true, user);
        userProxy.executePreSignedHooks(calls, nonce, deadline);

        // WHEN: execute the pre-signed hook
        // THEN: reverts with NonceAlreadyUsed
        vm.expectRevert(COWShedFactory.NonceAlreadyUsed.selector);
        userProxy.executePreSignedHooks(calls, nonce, deadline);
    }

    function testExecutePreSignedHooks_revertsAfterSetPreSignStorageToZero() external {
        // GIVEN: shed has 1 ether
        vm.deal(userProxyAddr, 1 ether);

        Call[] memory calls = new Call[](1);
        calls[0] = callWithValue;
        uint256 deadline = _deadline();
        bytes32 nonce = "1";

        // GIVEN: user has pre-signed hook
        _resetPreSignStorage(user);
        _presignForProxy(calls, nonce, deadline, true, user);

        // GIVEN: they set the pre-sign storage to zero
        _setPreSignStorage(ZERO_ADDRESS_PRESIGN_STORAGE, user);

        // WHEN: execute the pre-signed hook
        // THEN: the hook is not pre-signed anymore
        vm.expectRevert(COWShed.NotPreSigned.selector);
        userProxy.executePreSignedHooks(calls, nonce, deadline);
    }

    function testExecutePreSignedHooks_revertsAfterReresetPreSignStorage() external {
        // GIVEN: shed has 1 ether
        vm.deal(userProxyAddr, 1 ether);

        Call[] memory calls = new Call[](1);
        calls[0] = callWithValue;
        uint256 deadline = _deadline();
        bytes32 nonce = "1";

        // GIVEN: user has pre-signed hook to send ether to the stub
        _resetPreSignStorage(user);
        _presignForProxy(calls, nonce, deadline, true, user);

        // GIVEN: they re-initialized the pre-sign storage
        _resetPreSignStorage(user);

        // WHEN: execute the pre-signed hook
        // THEN: the hook is executed
        vm.expectRevert(COWShed.NotPreSigned.selector);
        userProxy.executePreSignedHooks(calls, nonce, deadline);
    }
}
