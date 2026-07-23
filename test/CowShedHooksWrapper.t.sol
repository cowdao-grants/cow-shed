// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.25;

import {Test, Vm} from "forge-std/Test.sol";
import {COWShed, Call} from "src/COWShed.sol";
import {COWShedExecutorFactory} from "src/COWShedExecutorFactory.sol";
import {COWShedWithExecutorSigner} from "src/COWShedWithExecutorSigner.sol";
import {CowShedHooksWrapper} from "src/CowShedHooksWrapper.sol";
import {CowWrapper, ICowAuthentication, ICowSettlement} from "src/vendor/CowWrapper.sol";
import {IERC1271} from "src/IERC1271.sol";
import {LibCowOrder} from "src/LibCowOrder.sol";
import {IERC20} from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";

contract MockAuthenticator is ICowAuthentication {
    mapping(address => bool) public solver;

    function setSolver(address who, bool ok) external {
        solver[who] = ok;
    }

    function isSolver(address who) external view override returns (bool) {
        return solver[who];
    }
}

/// @dev Any call with the GPv2 `settle` selector lands in the fallback: it validates each primed
///      order via the shed's EIP-1271 and records its fill.
contract MockSettlement {
    ICowAuthentication public immutable authenticator;
    bytes32 public constant domainSeparator = keccak256("MockSettlement.domain");

    struct Primed {
        address shed;
        bytes32 digest;
        bytes uid;
        uint256 fill;
    }

    Primed[] internal primed;
    mapping(bytes32 => uint256) internal filled;

    constructor(ICowAuthentication auth) {
        authenticator = auth;
    }

    function prime(address shed, bytes32 digest, bytes calldata uid, uint256 fill) external {
        primed.push(Primed(shed, digest, uid, fill));
    }

    function filledAmount(bytes calldata uid) external view returns (uint256) {
        return filled[keccak256(uid)];
    }

    fallback() external {
        require(msg.sig == 0x13d79a0b, "unexpected selector");
        for (uint256 i; i < primed.length; ++i) {
            Primed memory p = primed[i];
            require(IERC1271(p.shed).isValidSignature(p.digest, "") == 0x1626ba7e, "order sig invalid");
            filled[keccak256(p.uid)] = p.fill;
        }
    }
}

contract Recorder {
    address public preCaller;
    address public postCaller;
    uint256 public prePings;
    uint256 public postPings;
    bool public failPre;
    bool public failPost;

    function setFail(bool failPre_, bool failPost_) external {
        failPre = failPre_;
        failPost = failPost_;
    }

    function pre() external {
        require(!failPre, "pre fail");
        preCaller = msg.sender;
        prePings++;
    }

    function post() external {
        require(!failPost, "post fail");
        postCaller = msg.sender;
        postPings++;
    }
}

contract CowShedHooksWrapperTest is Test {
    Vm.Wallet user;
    address solver = makeAddr("solver");

    MockAuthenticator auth;
    MockSettlement settlement;
    COWShedWithExecutorSigner impl;
    COWShedExecutorFactory factory;
    CowShedHooksWrapper wrapper;
    Recorder recorder;

    address shed;
    bytes32 constant SALT = bytes32(uint256(1));

    function setUp() public {
        user = vm.createWallet("owner");

        auth = new MockAuthenticator();
        settlement = new MockSettlement(auth);
        impl = new COWShedWithExecutorSigner();
        factory = new COWShedExecutorFactory(address(impl));
        wrapper = new CowShedHooksWrapper(ICowSettlement(address(settlement)), factory);

        auth.setSolver(solver, true);

        shed = factory.initializeProxy(user.addr, address(wrapper), SALT);
        recorder = new Recorder();
    }

    // --- helpers -----------------------------------------------------------

    function _order() internal returns (LibCowOrder.Data memory o) {
        o = LibCowOrder.Data({
            sellToken: IERC20(makeAddr("sell")),
            buyToken: IERC20(makeAddr("buy")),
            receiver: address(0), // pay the owner (the shed)
            sellAmount: 1 ether,
            buyAmount: 2 ether,
            validTo: uint32(block.timestamp + 1 hours),
            appData: keccak256("app"),
            feeAmount: 0,
            kind: keccak256("sell"),
            partiallyFillable: false,
            sellTokenBalance: keccak256("erc20"),
            buyTokenBalance: keccak256("erc20")
        });
    }

    function _digest(LibCowOrder.Data memory o) internal view returns (bytes32) {
        return LibCowOrder.hash(o, settlement.domainSeparator());
    }

    function _uid(LibCowOrder.Data memory o) internal view returns (bytes memory) {
        return abi.encodePacked(_digest(o), shed, o.validTo);
    }

    function _hooks(address target, bytes memory cd) internal pure returns (Call[] memory calls) {
        calls = new Call[](1);
        calls[0] = Call({target: target, value: 0, callData: cd, allowFailure: false, isDelegateCall: false});
    }

    function _exec(uint256 nonce, uint256 expectedFill)
        internal
        returns (CowShedHooksWrapper.HooksOrderExec memory e)
    {
        e.owner = user.addr;
        e.salt = SALT;
        e.preHooks = _hooks(address(recorder), abi.encodeCall(Recorder.pre, ()));
        e.postHooks = _hooks(address(recorder), abi.encodeCall(Recorder.post, ()));
        e.order = _order();
        e.expectedFill = expectedFill;
        e.nonce = nonce;
        e.signature = _sign(e);
    }

    function _sign(CowShedHooksWrapper.HooksOrderExec memory e) internal returns (bytes memory) {
        return _signWith(e, user.privateKey);
    }

    function _signWith(CowShedHooksWrapper.HooksOrderExec memory e, uint256 pk)
        internal
        returns (bytes memory)
    {
        bytes32 structHash = keccak256(
            abi.encode(
                wrapper.HOOKS_ORDER_TYPE_HASH(),
                e.owner,
                e.salt,
                keccak256(abi.encode(e.preHooks)),
                keccak256(abi.encode(e.postHooks)),
                _digest(e.order),
                e.expectedFill,
                e.nonce
            )
        );
        bytes32 signHash = keccak256(abi.encodePacked(hex"1901", wrapper.domainSeparator(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, signHash);
        return abi.encodePacked(r, s, v);
    }

    function _settle(CowShedHooksWrapper.HooksOrderExec memory e) internal {
        CowShedHooksWrapper.HooksOrderExec[] memory exs = new CowShedHooksWrapper.HooksOrderExec[](1);
        exs[0] = e;
        bytes memory wrapperData = abi.encode(exs);
        bytes memory chained = abi.encodePacked(uint16(wrapperData.length), wrapperData);
        bytes memory settleData = abi.encodePacked(bytes4(0x13d79a0b));
        vm.prank(solver);
        wrapper.wrappedSettle(settleData, chained);
    }

    // --- tests -------------------------------------------------------------

    function testHappyPathRunsHooksAsShedAroundFill() external {
        LibCowOrder.Data memory o = _order();
        settlement.prime(shed, _digest(o), _uid(o), 1 ether);

        CowShedHooksWrapper.HooksOrderExec memory e = _exec(1, 1 ether);
        _settle(e);

        assertEq(recorder.preCaller(), shed, "pre-hook did not run as the shed");
        assertEq(recorder.postCaller(), shed, "post-hook did not run as the shed");
        assertEq(recorder.prePings(), 1, "pre not run once");
        assertEq(recorder.postPings(), 1, "post not run once");
        assertEq(settlement.filledAmount(_uid(o)), 1 ether, "order not filled");
        assertTrue(wrapper.isNonceUsed(shed, 1), "nonce not consumed");
    }

    function testRevertingPreHookBlocksOrder() external {
        LibCowOrder.Data memory o = _order();
        settlement.prime(shed, _digest(o), _uid(o), 1 ether);
        recorder.setFail(true, false);

        CowShedHooksWrapper.HooksOrderExec memory e = _exec(1, 1 ether);
        vm.expectRevert(); // pre-hook reverts before settle
        _settle(e);

        assertEq(settlement.filledAmount(_uid(o)), 0, "order must not fill when pre-hook fails");
    }

    function testRevertingPostHookRevertsWholeSettlement() external {
        LibCowOrder.Data memory o = _order();
        settlement.prime(shed, _digest(o), _uid(o), 1 ether);
        recorder.setFail(false, true);

        CowShedHooksWrapper.HooksOrderExec memory e = _exec(1, 1 ether);
        vm.expectRevert(); // post-hook reverts -> whole tx reverts, fill rolled back
        _settle(e);
        assertFalse(wrapper.isNonceUsed(shed, 1), "nonce must not be consumed on revert");
    }

    function testUnfilledOrderReverts() external {
        LibCowOrder.Data memory o = _order();
        settlement.prime(shed, _digest(o), _uid(o), 0); // settles 0 < expectedFill

        CowShedHooksWrapper.HooksOrderExec memory e = _exec(1, 1 ether);
        vm.expectRevert(CowShedHooksWrapper.OrderNotSettled.selector);
        _settle(e);
    }

    function testBlessOnlyDuringSettlement() external {
        // outside a settlement, the shed's 1271 (delegating to the wrapper) is not valid
        LibCowOrder.Data memory o = _order();
        assertEq(IERC1271(shed).isValidSignature(_digest(o), ""), bytes4(0), "should not be blessed at rest");
    }

    function testNonSolverCannotSettle() external {
        LibCowOrder.Data memory o = _order();
        settlement.prime(shed, _digest(o), _uid(o), 1 ether);
        CowShedHooksWrapper.HooksOrderExec memory e = _exec(1, 1 ether);

        CowShedHooksWrapper.HooksOrderExec[] memory exs = new CowShedHooksWrapper.HooksOrderExec[](1);
        exs[0] = e;
        bytes memory wrapperData = abi.encode(exs);
        bytes memory chained = abi.encodePacked(uint16(wrapperData.length), wrapperData);

        vm.expectRevert(abi.encodeWithSelector(CowWrapper.NotASolver.selector, address(this)));
        wrapper.wrappedSettle(abi.encodePacked(bytes4(0x13d79a0b)), chained);
    }

    function testWrongSignerRejected() external {
        LibCowOrder.Data memory o = _order();
        settlement.prime(shed, _digest(o), _uid(o), 1 ether);

        CowShedHooksWrapper.HooksOrderExec memory e = _exec(1, 1 ether);
        (, uint256 strangerPk) = makeAddrAndKey("stranger");
        e.signature = _signWith(e, strangerPk);

        vm.expectRevert(CowShedHooksWrapper.BadSignature.selector);
        _settle(e);
    }

    function testNonceReplayRejected() external {
        LibCowOrder.Data memory o = _order();
        settlement.prime(shed, _digest(o), _uid(o), 1 ether);

        CowShedHooksWrapper.HooksOrderExec memory e = _exec(1, 1 ether);
        _settle(e);

        // reusing the same nonce is rejected (nonce is checked before the fill check)
        vm.expectRevert(CowShedHooksWrapper.NonceAlreadyUsed.selector);
        _settle(e);
    }

    function testNonZeroReceiverRejected() external {
        CowShedHooksWrapper.HooksOrderExec memory e = _exec(1, 1 ether);
        e.order.receiver = makeAddr("elsewhere");
        e.signature = _sign(e); // re-sign so the signature is valid for this (bad) order

        vm.expectRevert(CowShedHooksWrapper.NonZeroReceiver.selector);
        _settle(e);
    }

    function testCancelledNonceCannotBeUsed() external {
        LibCowOrder.Data memory o = _order();
        settlement.prime(shed, _digest(o), _uid(o), 1 ether);

        vm.prank(user.addr);
        wrapper.cancelNonce(SALT, 1);

        CowShedHooksWrapper.HooksOrderExec memory e = _exec(1, 1 ether);
        vm.expectRevert(CowShedHooksWrapper.NonceAlreadyUsed.selector);
        _settle(e);
    }
}
