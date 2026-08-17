// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.25;

import {BaseTest} from "./BaseTest.sol";
import {COWShed, Call} from "src/COWShed.sol";
import {COWShedExecutorFactory} from "src/COWShedExecutorFactory.sol";
import {ICOWShedSetup} from "src/ICOWShedSetup.sol";

/// @dev Records its caller and any value received.
contract Recorder {
    address public lastCaller;
    uint256 public pings;
    uint256 public lastValue;

    function ping() external payable {
        lastCaller = msg.sender;
        pings++;
        lastValue = msg.value;
    }
}

/// @dev A setup target that is also the shed's trusted executor. On setup it routes a call
///      through the shed via `trustedExecuteHooks`, so the final call runs as the shed.
contract RoutingSetupExecutor is ICOWShedSetup {
    uint256 public setupCount;
    address public lastShed;
    address public lastOwner;

    function setup(address shed, address owner, bytes calldata setupData) external override {
        setupCount++;
        lastShed = shed;
        lastOwner = owner;
        (address target, uint256 value, bytes memory cd) = abi.decode(setupData, (address, uint256, bytes));
        Call[] memory calls = new Call[](1);
        calls[0] = Call({target: target, value: value, callData: cd, allowFailure: false, isDelegateCall: false});
        COWShed(payable(shed)).trustedExecuteHooks(calls);
    }
}

/// @dev A setup target that always reverts.
contract RevertingSetup is ICOWShedSetup {
    error SetupBoom();

    function setup(address, address, bytes calldata) external pure override {
        revert SetupBoom();
    }
}

contract COWShedExecutorFactorySetupTest is BaseTest {
    COWShedExecutorFactory executorFactory;
    RoutingSetupExecutor routingExecutor;
    Recorder recorder;

    bytes32 constant SALT = bytes32(uint256(1));

    function setUp() public override {
        super.setUp();
        // base COWShed implementation (deployed by BaseTest) behind the executor factory
        executorFactory = new COWShedExecutorFactory(address(cowshedImpl));
        routingExecutor = new RoutingSetupExecutor();
        recorder = new Recorder();
    }

    function _pingData(uint256 value) internal view returns (bytes memory) {
        return abi.encode(address(recorder), value, abi.encodeCall(Recorder.ping, ()));
    }

    function testDeploysAtPredictedAddressAndRunsSetup() external {
        bytes memory data = _pingData(0);
        address predicted =
            executorFactory.proxyOf(user.addr, address(routingExecutor), SALT, address(routingExecutor), data);
        assertEq(predicted.code.length, 0, "already deployed");

        address deployed = executorFactory.initializeProxyWithSetup(
            user.addr, address(routingExecutor), SALT, address(routingExecutor), data
        );
        assertEq(deployed, predicted, "deployed at unexpected address");
        assertGt(deployed.code.length, 0, "not deployed");

        // shed is configured with the executor and owner
        assertEq(COWShed(payable(deployed)).trustedExecutor(), address(routingExecutor), "executor not set");
        assertEq(executorFactory.ownerOf(deployed), user.addr, "ownerOf not recorded");

        // setup ran once and received the freshly deployed shed address + owner
        assertEq(routingExecutor.setupCount(), 1, "setup not run once");
        assertEq(routingExecutor.lastShed(), deployed, "setup got wrong shed");
        assertEq(routingExecutor.lastOwner(), user.addr, "setup got wrong owner");

        // the routed call executed AS THE SHED (msg.sender == shed at the final target)
        assertEq(recorder.lastCaller(), deployed, "call did not run as the shed");
        assertEq(recorder.pings(), 1, "recorder not pinged");
    }

    function testSetupCallCommitsToAddress() external {
        bytes memory dataA = _pingData(0);
        bytes memory dataB = abi.encode(makeAddr("other"), uint256(0), bytes(""));

        address a = executorFactory.proxyOf(user.addr, address(routingExecutor), SALT, address(routingExecutor), dataA);
        // different setup data -> different address
        address diffData =
            executorFactory.proxyOf(user.addr, address(routingExecutor), SALT, address(routingExecutor), dataB);
        // different setup target -> different address
        address diffTarget =
            executorFactory.proxyOf(user.addr, address(routingExecutor), SALT, makeAddr("otherTarget"), dataA);
        // plain (no-setup) path from #61 is distinct
        address plain = executorFactory.proxyOf(user.addr, address(routingExecutor), SALT);

        assertTrue(a != diffData, "setup data should change address");
        assertTrue(a != diffTarget, "setup target should change address");
        assertTrue(a != plain, "setup path should differ from plain path");
    }

    function testSetupRunsOnlyOnFirstDeploy() external {
        bytes memory data = _pingData(0);
        address first = executorFactory.initializeProxyWithSetup(
            user.addr, address(routingExecutor), SALT, address(routingExecutor), data
        );
        address second = executorFactory.initializeProxyWithSetup(
            user.addr, address(routingExecutor), SALT, address(routingExecutor), data
        );
        assertEq(first, second, "should return the same proxy");
        assertEq(routingExecutor.setupCount(), 1, "setup should run only once");
        assertEq(recorder.pings(), 1, "recorder should be pinged only once");
    }

    function testSetupRevertRevertsDeployment() external {
        RevertingSetup bad = new RevertingSetup();
        bytes memory data = hex"";
        address predicted = executorFactory.proxyOf(user.addr, address(bad), SALT, address(bad), data);

        vm.expectRevert(RevertingSetup.SetupBoom.selector);
        executorFactory.initializeProxyWithSetup(user.addr, address(bad), SALT, address(bad), data);

        // nothing was deployed, so the deployment can be retried
        assertEq(predicted.code.length, 0, "should not have deployed when setup reverts");
    }

    function testOwnerCanRecoverFundsWhenSetupAlwaysReverts() external {
        RevertingSetup bad = new RevertingSetup();
        bytes memory data = hex"";
        address predicted = executorFactory.proxyOf(user.addr, address(routingExecutor), SALT, address(bad), data);

        // funds land at the counterfactual address, but the setup call can never succeed
        vm.deal(predicted, 1 ether);
        vm.expectRevert(RevertingSetup.SetupBoom.selector);
        executorFactory.initializeProxyWithSetup(user.addr, address(routingExecutor), SALT, address(bad), data);

        // the owner deploys the shed anyway, skipping the setup call, and sweeps the stranded
        // funds out in the same transaction
        address recipient = makeAddr("recipient");
        Call[] memory calls = new Call[](1);
        calls[0] =
            Call({target: recipient, value: 1 ether, callData: hex"", allowFailure: false, isDelegateCall: false});

        vm.expectEmit(true, true, true, true);
        emit COWShedExecutorFactory.SetupSkipped(user.addr, predicted, address(bad));
        vm.prank(user.addr);
        address deployed = executorFactory.initializeProxyWithoutSetup(
            user.addr, address(routingExecutor), SALT, address(bad), data, calls
        );

        assertEq(deployed, predicted, "deployed at unexpected address");
        assertEq(executorFactory.ownerOf(deployed), user.addr, "ownerOf not recorded");
        assertEq(recipient.balance, 1 ether, "funds not recovered");
        assertEq(deployed.balance, 0, "shed should be drained");

        // the factory only held the trusted role for the duration of the call: the shed ends up
        // configured with the executor its address commits to
        assertEq(COWShed(payable(deployed)).trustedExecutor(), address(routingExecutor), "executor not handed over");
    }

    function testRescueCallsRunAsTheShed() external {
        bytes memory data = hex"";
        Call[] memory calls = new Call[](1);
        calls[0] = Call({
            target: address(recorder),
            value: 0,
            callData: abi.encodeCall(Recorder.ping, ()),
            allowFailure: false,
            isDelegateCall: false
        });

        vm.prank(user.addr);
        address deployed = executorFactory.initializeProxyWithoutSetup(
            user.addr, address(routingExecutor), SALT, makeAddr("brokenSetup"), data, calls
        );

        assertEq(recorder.lastCaller(), deployed, "call did not run as the shed");
        assertEq(recorder.pings(), 1, "recorder not pinged");
        assertEq(COWShed(payable(deployed)).trustedExecutor(), address(routingExecutor), "executor not handed over");
    }

    function testRescueHandsOverExecutorEvenIfCallsChangeIt() external {
        bytes memory data = hex"";
        // a rescue call that points the shed at the caller's own executor. the appended handover
        // runs last, so the shed still ends up with the committed executor.
        Call[] memory calls = new Call[](1);
        calls[0] = Call({
            target: address(0), // patched below, needs the shed address
            value: 0,
            callData: abi.encodeCall(COWShed.updateTrustedExecutor, (makeAddr("hijacked"))),
            allowFailure: false,
            isDelegateCall: false
        });
        address predicted =
            executorFactory.proxyOf(user.addr, address(routingExecutor), SALT, makeAddr("brokenSetup"), data);
        calls[0].target = predicted;

        vm.prank(user.addr);
        address deployed = executorFactory.initializeProxyWithoutSetup(
            user.addr, address(routingExecutor), SALT, makeAddr("brokenSetup"), data, calls
        );

        assertEq(deployed, predicted, "deployed at unexpected address");
        assertEq(
            COWShed(payable(deployed)).trustedExecutor(),
            address(routingExecutor),
            "committed executor must win over the rescue calls"
        );
    }

    function testRescueRevertsIfACallReverts() external {
        RevertingSetup bad = new RevertingSetup();
        bytes memory data = hex"";
        address predicted = executorFactory.proxyOf(user.addr, address(routingExecutor), SALT, address(bad), data);

        Call[] memory calls = new Call[](1);
        calls[0] = Call({
            target: address(bad),
            value: 0,
            callData: abi.encodeCall(ICOWShedSetup.setup, (predicted, user.addr, hex"")),
            allowFailure: false,
            isDelegateCall: false
        });

        vm.prank(user.addr);
        vm.expectRevert(RevertingSetup.SetupBoom.selector);
        executorFactory.initializeProxyWithoutSetup(
            user.addr, address(routingExecutor), SALT, address(bad), data, calls
        );

        assertEq(predicted.code.length, 0, "should not have deployed when a rescue call reverts");
    }

    function testInitializeProxyWithoutSetupOnlyOwner() external {
        bytes memory data = _pingData(0);
        address predicted =
            executorFactory.proxyOf(user.addr, address(routingExecutor), SALT, address(routingExecutor), data);

        vm.prank(makeAddr("notTheOwner"));
        vm.expectRevert(COWShedExecutorFactory.OnlyOwner.selector);
        executorFactory.initializeProxyWithoutSetup(
            user.addr, address(routingExecutor), SALT, address(routingExecutor), data, new Call[](0)
        );

        assertEq(predicted.code.length, 0, "should not have deployed");
    }

    function testInitializeProxyWithoutSetupDoesNotRunSetup() external {
        bytes memory data = _pingData(0);

        vm.prank(user.addr);
        address deployed = executorFactory.initializeProxyWithoutSetup(
            user.addr, address(routingExecutor), SALT, address(routingExecutor), data, new Call[](0)
        );

        // with no rescue calls the shed is initialized with the committed executor directly
        assertEq(COWShed(payable(deployed)).trustedExecutor(), address(routingExecutor), "executor not set");

        // same address as the with-setup path, but the setup call never ran
        assertEq(
            deployed,
            executorFactory.proxyOf(user.addr, address(routingExecutor), SALT, address(routingExecutor), data),
            "deployed at unexpected address"
        );
        assertEq(routingExecutor.setupCount(), 0, "setup should not have run");
        assertEq(recorder.pings(), 0, "recorder should not have been pinged");

        // the with-setup path is now a no-op on the same address, it does not re-run the setup
        address again = executorFactory.initializeProxyWithSetup(
            user.addr, address(routingExecutor), SALT, address(routingExecutor), data
        );
        assertEq(again, deployed, "should return the same proxy");
        assertEq(routingExecutor.setupCount(), 0, "setup should still not have run");
    }

    function testSetupCanSpendPreFundedEth() external {
        bytes memory data = _pingData(0.3 ether);
        address predicted =
            executorFactory.proxyOf(user.addr, address(routingExecutor), SALT, address(routingExecutor), data);

        // pre-fund the counterfactual address before it is deployed
        vm.deal(predicted, 1 ether);

        address deployed = executorFactory.initializeProxyWithSetup(
            user.addr, address(routingExecutor), SALT, address(routingExecutor), data
        );

        assertEq(deployed, predicted, "deployed at unexpected address");
        assertEq(recorder.lastValue(), 0.3 ether, "value not forwarded by the shed");
        assertEq(address(recorder).balance, 0.3 ether, "recorder did not receive value");
        assertEq(deployed.balance, 0.7 ether, "shed should retain the remainder");
    }
}
