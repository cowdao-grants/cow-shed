// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.25;

import {BaseTest} from "./BaseTest.sol";
import {Vm} from "forge-std/Test.sol";
import {COWShed, Call} from "src/COWShed.sol";
import {COWShedExecutorFactory} from "src/COWShedExecutorFactory.sol";
import {COWShedProxy} from "src/COWShedProxy.sol";
import {COWShedWithExecutorSigner} from "src/COWShedWithExecutorSigner.sol";
import {IERC1271} from "src/IERC1271.sol";
import {LibAuthenticatedHooks} from "src/LibAuthenticatedHooks.sol";

/// @dev Minimal trusted-executor stand-in: acts as an EIP-1271 authority (blesses digests)
///      and can be pranked as the caller of `trustedExecuteHooks`.
contract MockExecutor is IERC1271 {
    mapping(bytes32 => bool) public blessed;

    function bless(bytes32 hash, bool ok) external {
        blessed[hash] = ok;
    }

    function isValidSignature(bytes32 hash, bytes calldata) external view override returns (bytes4) {
        return blessed[hash] ? LibAuthenticatedHooks.MAGIC_VALUE_1271 : bytes4(0);
    }
}

contract COWShedWithExecutorSignerTest is BaseTest {
    COWShed executorSignerImpl;
    COWShedExecutorFactory executorFactory;
    MockExecutor executor;

    bytes32 constant SALT_A = bytes32(uint256(1));
    bytes32 constant SALT_B = bytes32(uint256(2));

    function setUp() public override {
        super.setUp();

        executorSignerImpl = new COWShedWithExecutorSigner();
        executorFactory = new COWShedExecutorFactory(address(executorSignerImpl));
        executor = new MockExecutor();
    }

    // --- address binding ---------------------------------------------------

    function testDeploysAtPredictedAddressWithExecutor() external {
        address predicted = executorFactory.proxyOf(user.addr, address(executor), SALT_A);
        assertEq(predicted.code.length, 0, "already deployed");

        address deployed = executorFactory.initializeProxy(user.addr, address(executor), SALT_A);
        assertEq(deployed, predicted, "deployed at unexpected address");
        assertGt(deployed.code.length, 0, "not deployed");

        // preconfigured executor is set, owner (admin) is preserved
        assertEq(COWShed(payable(deployed)).trustedExecutor(), address(executor), "executor not preconfigured");
        assertEq(executorFactory.ownerOf(deployed), user.addr, "ownerOf not recorded");
        vm.prank(deployed);
        assertEq(COWShedProxy(payable(deployed)).admin(), user.addr, "admin should be the owner");
    }

    function testAddressCommitsToExecutorAndSalt() external {
        address a = executorFactory.proxyOf(user.addr, address(executor), SALT_A);
        // different salt -> different shed for the same (owner, executor)
        address b = executorFactory.proxyOf(user.addr, address(executor), SALT_B);
        // different executor -> different address (grief-free)
        address c = executorFactory.proxyOf(user.addr, makeAddr("otherExecutor"), SALT_A);
        // legacy per-owner path is distinct from any preconfigured address
        address legacy = executorFactory.proxyOf(user.addr);

        assertTrue(a != b, "salt should change address");
        assertTrue(a != c, "executor should change address");
        assertTrue(a != legacy && b != legacy && c != legacy, "should differ from legacy path");
    }

    function testInitializeProxyIsIdempotent() external {
        address first = executorFactory.initializeProxy(user.addr, address(executor), SALT_A);
        address second = executorFactory.initializeProxy(user.addr, address(executor), SALT_A);
        assertEq(first, second, "should return the same proxy");
    }

    // --- executor powers ---------------------------------------------------

    function testPreconfiguredExecutorCanTrustedExecute() external {
        address proxy = executorFactory.initializeProxy(user.addr, address(executor), SALT_A);
        vm.deal(proxy, 1 ether);

        Call[] memory calls = new Call[](1);
        calls[0] = Call({
            target: makeAddr("sink"),
            value: 0.1 ether,
            callData: hex"",
            allowFailure: false,
            isDelegateCall: false
        });

        vm.prank(address(executor));
        COWShed(payable(proxy)).trustedExecuteHooks(calls);
        assertEq(makeAddr("sink").balance, 0.1 ether, "executor call did not run");
    }

    function testRandomCallerCannotTrustedExecute() external {
        address proxy = executorFactory.initializeProxy(user.addr, address(executor), SALT_A);
        Call[] memory calls = new Call[](0);

        vm.expectRevert(COWShed.OnlyTrustedRole.selector);
        vm.prank(makeAddr("randomCaller"));
        COWShed(payable(proxy)).trustedExecuteHooks(calls);
    }

    function testOwnerCanExecuteHooksWithSignature() external {
        address proxy = executorFactory.initializeProxy(user.addr, address(executor), SALT_A);
        vm.deal(proxy, 1 ether);

        address sink = makeAddr("sink");
        Call[] memory calls = new Call[](1);
        calls[0] =
            Call({target: sink, value: 0.2 ether, callData: hex"", allowFailure: false, isDelegateCall: false});

        bytes32 nonce = "1";
        bytes memory sig = _signForShed(proxy, calls, nonce, _deadline());
        COWShed(payable(proxy)).executeHooks(calls, nonce, _deadline(), sig);
        assertEq(sink.balance, 0.2 ether, "owner-signed hook did not run");
    }

    function testOwnerCanSwapExecutor() external {
        address proxy = executorFactory.initializeProxy(user.addr, address(executor), SALT_A);
        address newExecutor = makeAddr("newExecutor");

        Call[] memory calls = new Call[](1);
        calls[0] = Call({
            target: proxy,
            value: 0,
            callData: abi.encodeCall(COWShed.updateTrustedExecutor, (newExecutor)),
            allowFailure: false,
            isDelegateCall: false
        });
        bytes32 nonce = "swap";
        bytes memory sig = _signForShed(proxy, calls, nonce, _deadline());
        COWShed(payable(proxy)).executeHooks(calls, nonce, _deadline(), sig);

        assertEq(COWShed(payable(proxy)).trustedExecutor(), newExecutor, "executor not swapped");
    }

    // --- EIP-1271 delegation ----------------------------------------------

    function testIsValidSignatureDelegatesToExecutor() external {
        address proxy = executorFactory.initializeProxy(user.addr, address(executor), SALT_A);
        bytes32 orderDigest = keccak256("some order digest");

        // not blessed yet
        assertEq(IERC1271(proxy).isValidSignature(orderDigest, hex""), bytes4(0), "should not be valid");

        // executor blesses the digest -> shed reports it valid
        executor.bless(orderDigest, true);
        assertEq(
            IERC1271(proxy).isValidSignature(orderDigest, hex""),
            LibAuthenticatedHooks.MAGIC_VALUE_1271,
            "should be valid once blessed"
        );

        // revoked -> invalid again
        executor.bless(orderDigest, false);
        assertEq(IERC1271(proxy).isValidSignature(orderDigest, hex""), bytes4(0), "should be invalid after revoke");
    }

    function testIsValidSignatureFailsClosedForEoaExecutor() external {
        address eoaExecutor = makeAddr("eoaExecutor");
        address proxy = executorFactory.initializeProxy(user.addr, eoaExecutor, SALT_A);
        assertEq(
            IERC1271(proxy).isValidSignature(keccak256("x"), hex""),
            bytes4(0),
            "EOA executor should fail closed"
        );
    }

    // --- helpers -----------------------------------------------------------

    function _signForShed(address proxy, Call[] memory calls, bytes32 nonce, uint256 deadline)
        internal
        view
        returns (bytes memory)
    {
        bytes32 domainSeparator = COWShed(payable(proxy)).domainSeparator();
        bytes32 digest = cproxy.hashToSign(calls, nonce, deadline, domainSeparator);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(user.privateKey, digest);
        return abi.encodePacked(r, s, v);
    }
}
