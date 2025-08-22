// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.25;

import {Test} from "forge-std/Test.sol";

import {IPreSignStorage} from "src/IPreSignStorage.sol";
import {PreSignStateStorage} from "src/PreSignStateStorage.sol";

contract PreSignStateStorageTest is Test {
    PreSignStateStorage storageContract;
    address cowShed;
    address unauthorizedUser;

    bytes32 hash1 = keccak256("hash1");
    bytes32 hash2 = keccak256("hash2");
    bytes32 hash3 = keccak256("hash3");

    event PreSigned(bytes32 indexed hash, bool signed);

    function setUp() public {
        cowShed = makeAddr("cowShed");
        unauthorizedUser = makeAddr("unauthorizedUser");
        storageContract = new PreSignStateStorage(cowShed);
    }

    function testConstructor() public view {
        // GIVEN: a new storage contract initialized with a specific cowShed address

        // WHEN: checking the cowShed address
        // THEN: the cowShed address is set expected
        assertEq(storageContract.cowShed(), cowShed);
    }

    function testSetPreSigned_OnlyCowShed() public {
        // WHEN: calling setPreSigned from unauthorized address
        // THEN: reverts with OnlyCowShed error
        vm.prank(unauthorizedUser);
        vm.expectRevert(PreSignStateStorage.OnlyCowShed.selector);
        storageContract.setPreSigned(hash1, true);
    }

    function testSetPreSigned_Success() public {
        // GIVEN: the storage didn't have a hash pre-signed
        assertFalse(storageContract.isPreSigned(hash1));

        // WHEN: calling setPreSigned from cowShed address
        vm.prank(cowShed);
        vm.expectEmit(true, false, false, false);
        emit PreSigned(hash1, true);
        storageContract.setPreSigned(hash1, true);

        // THEN: the hash is marked as pre-signed
        assertTrue(storageContract.isPreSigned(hash1));
    }

    function testSetPreSigned_Revoke() public {
        // GIVEN: a hash is already pre-signed
        vm.prank(cowShed);
        storageContract.setPreSigned(hash1, true);

        // WHEN: cowShed revokes the pre-signature
        vm.prank(cowShed);
        vm.expectEmit(true, false, false, false);
        emit PreSigned(hash1, false);
        storageContract.setPreSigned(hash1, false);

        // THEN: the hash is no longer pre-signed
        assertFalse(storageContract.isPreSigned(hash1));
    }

    function testSetPreSigned_UpdateExisting() public {
        // GIVEN: a hash is already pre-signed
        vm.prank(cowShed);
        storageContract.setPreSigned(hash1, true);
        assertTrue(storageContract.isPreSigned(hash1));

        // WHEN: updating the same hash to false
        vm.prank(cowShed);
        vm.expectEmit(true, false, false, false);
        emit PreSigned(hash1, false);
        storageContract.setPreSigned(hash1, false);

        // THEN: the hash state is updated
        assertFalse(storageContract.isPreSigned(hash1));
    }

    function testSetPreSigned_ZeroHash() public {
        // GIVEN: setting zero hash
        bytes32 zeroHash = bytes32(0);

        // WHEN: setting zero hash as pre-signed
        vm.prank(cowShed);
        vm.expectEmit(true, false, false, false);
        emit PreSigned(zeroHash, true);
        storageContract.setPreSigned(zeroHash, true);

        // THEN: zero hash is marked as pre-signed
        assertTrue(storageContract.isPreSigned(zeroHash));
    }

    function testSetPreSigned_MaxHash() public {
        bytes32 maxHash = bytes32(type(uint256).max);

        // WHEN: setting max hash as pre-signed
        vm.prank(cowShed);
        vm.expectEmit(true, false, false, false);
        emit PreSigned(maxHash, true);
        storageContract.setPreSigned(maxHash, true);

        // THEN: max hash is marked as pre-signed
        assertTrue(storageContract.isPreSigned(maxHash));
    }

    function testIsPreSigned_DefaultState() public view {
        // GIVEN: no hashes have been set
        // WHEN: checking if a hash is pre-signed
        // THEN: returns false (default mapping value)
        assertFalse(storageContract.isPreSigned(hash1));
    }

    function testIsPreSigned_AfterSet() public {
        // GIVEN: a hash is set as pre-signed
        vm.prank(cowShed);
        storageContract.setPreSigned(hash1, true);

        // WHEN: checking if the hash is pre-signed
        // THEN: returns true
        assertTrue(storageContract.isPreSigned(hash1));
    }

    function testIsPreSigned_AfterRevoke() public {
        // GIVEN: a hash is set as pre-signed then revoked
        vm.prank(cowShed);
        storageContract.setPreSigned(hash1, true);
        vm.prank(cowShed);
        storageContract.setPreSigned(hash1, false);

        // WHEN: checking if the hash is pre-signed
        // THEN: returns false
        assertFalse(storageContract.isPreSigned(hash1));
    }

    function testIsPreSigned_UnrelatedHashes() public {
        // GIVEN: one hash is set as pre-signed
        vm.prank(cowShed);
        storageContract.setPreSigned(hash1, true);

        // WHEN: checking unrelated hashes
        // THEN: they return false (default mapping value)
        assertFalse(storageContract.isPreSigned(hash2));
        assertFalse(storageContract.isPreSigned(hash3));
    }
}
