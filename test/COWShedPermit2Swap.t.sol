// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.25;

import {Test, Vm} from "forge-std/Test.sol";
import {COWShed, Call} from "src/COWShed.sol";
import {COWShedFactory} from "src/COWShedFactory.sol";
import {COWShedWithOwnerSigner} from "src/COWShedWithOwnerSigner.sol";
import {IERC20} from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {LibCowOrder} from "src/LibCowOrder.sol";
import {LibAuthenticatedHooksCalldataProxy} from "test/lib/LibAuthenticatedHooksCalldataProxy.sol";
import {MockERC20} from "test/lib/MockERC20.sol";
import {MockPermit2} from "test/lib/MockPermit2.sol";
import {MockSettlement, MockVaultRelayer} from "test/lib/MockGPv2.sol";

/// @notice Prototype: an EOA holds the funds and uses its cow-shed as the CoW
///         Protocol order trader. A pre-hook pulls the funds EOA -> shed via
///         Permit2 and approves the vault relayer; the order itself is
///         authorized by the EOA signing the order digest, which the shed
///         validates via EIP-1271.
///
/// Signatures produced by the EOA:
///   1. Permit2 SignatureTransfer permit (spender = shed) -> lets the shed pull funds.
///   2. cow-shed executeHooks batch          -> authorizes the pre-hook calls.
///   3. CoW order digest                     -> authorizes the order (EIP-1271 via shed).
contract COWShedPermit2SwapTest is Test {
    using LibCowOrder for LibCowOrder.Data;

    Vm.Wallet user;
    address shed;
    address solver = makeAddr("solver");

    COWShedWithOwnerSigner impl;
    COWShedFactory factory;
    LibAuthenticatedHooksCalldataProxy cproxy;

    MockPermit2 permit2;
    MockSettlement settlement;
    MockVaultRelayer relayer;

    MockERC20 sellToken; // e.g. WETH
    MockERC20 buyToken; // e.g. USDC

    bytes32 constant KIND_SELL = keccak256("sell");
    bytes32 constant BALANCE_ERC20 = keccak256("erc20");

    uint256 constant SELL_AMOUNT = 1 ether;
    uint256 constant BUY_AMOUNT = 2000 ether; // pretend price
    uint256 constant EOA_START = 10 ether;
    uint256 constant SETTLEMENT_BUFFER = 1_000_000 ether;

    function setUp() public {
        user = vm.createWallet("user");

        impl = new COWShedWithOwnerSigner();
        factory = new COWShedFactory(address(impl));
        cproxy = new LibAuthenticatedHooksCalldataProxy();

        permit2 = new MockPermit2();
        settlement = new MockSettlement();
        relayer = settlement.vaultRelayer();
        settlement.setSolver(solver, true);

        sellToken = new MockERC20("Wrapped Ether", "WETH");
        buyToken = new MockERC20("USD Coin", "USDC");

        shed = factory.proxyOf(user.addr);

        // EOA is funded and grants the one-time Permit2 allowance.
        sellToken.mint(user.addr, EOA_START);
        vm.prank(user.addr);
        sellToken.approve(address(permit2), type(uint256).max);

        // Settlement holds a buffer of the buy token to deliver.
        buyToken.mint(address(settlement), SETTLEMENT_BUFFER);
    }

    function testSwapWithShedAsTrader() public {
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 hookNonce = "swap-1";
        uint256 permitNonce = 0;

        // --- 1. Permit2 permit signed by the EOA, spender = shed ---
        MockPermit2.PermitTransferFrom memory permit = MockPermit2.PermitTransferFrom({
            permitted: MockPermit2.TokenPermissions({token: address(sellToken), amount: SELL_AMOUNT}),
            nonce: permitNonce,
            deadline: deadline
        });
        bytes memory permitSig = _signPermit2(permit, shed);

        // --- 2. cow-shed hook batch: pull funds via Permit2 + approve relayer ---
        Call[] memory calls = new Call[](2);
        calls[0] = Call({
            target: address(permit2),
            value: 0,
            callData: abi.encodeCall(
                MockPermit2.permitTransferFrom,
                (
                    permit,
                    MockPermit2.SignatureTransferDetails({to: shed, requestedAmount: SELL_AMOUNT}),
                    user.addr,
                    permitSig
                )
            ),
            allowFailure: false,
            isDelegateCall: false
        });
        calls[1] = Call({
            target: address(sellToken),
            value: 0,
            callData: abi.encodeCall(IERC20.approve, (address(relayer), SELL_AMOUNT)),
            allowFailure: false,
            isDelegateCall: false
        });
        bytes memory hookSig = _signHookBatch(calls, hookNonce, deadline);

        // --- 3. the CoW order, trader = shed, receiver = EOA ---
        LibCowOrder.Data memory order = LibCowOrder.Data({
            sellToken: IERC20(address(sellToken)),
            buyToken: IERC20(address(buyToken)),
            receiver: user.addr,
            sellAmount: SELL_AMOUNT,
            buyAmount: BUY_AMOUNT,
            validTo: uint32(deadline),
            appData: bytes32(0),
            feeAmount: 0,
            kind: KIND_SELL,
            partiallyFillable: false,
            sellTokenBalance: BALANCE_ERC20,
            buyTokenBalance: BALANCE_ERC20
        });
        bytes memory orderSig = _signOrder(order);

        // --- 4. solver settles: pre-interaction runs the hook, then the swap ---
        MockSettlement.Interaction[] memory preInteractions = new MockSettlement.Interaction[](1);
        preInteractions[0] = MockSettlement.Interaction({
            target: address(factory),
            value: 0,
            callData: abi.encodeCall(
                COWShedFactory.executeHooks, (calls, hookNonce, deadline, user.addr, hookSig)
            )
        });

        vm.prank(solver);
        settlement.settle(preInteractions, order, orderSig, MockSettlement.SigningScheme.Eip1271, BUY_AMOUNT);

        // --- assertions ---
        assertGt(shed.code.length, 0, "shed should be deployed by the hook");
        assertEq(sellToken.balanceOf(user.addr), EOA_START - SELL_AMOUNT, "EOA sell balance");
        assertEq(sellToken.balanceOf(shed), 0, "shed should hold no leftover sell token");
        assertEq(sellToken.balanceOf(address(settlement)), SELL_AMOUNT, "settlement received sell token");
        assertEq(buyToken.balanceOf(user.addr), BUY_AMOUNT, "EOA received buy token");
        assertEq(buyToken.balanceOf(address(settlement)), SETTLEMENT_BUFFER - BUY_AMOUNT, "settlement buffer spent");
    }

    function testSettleRevertsWithForgedOrderSignature() public {
        uint256 deadline = block.timestamp + 1 hours;

        // deploy + fund the shed so the sell-side transfer isn't what fails
        _deployShedWithFunds(deadline);

        LibCowOrder.Data memory order = _baseOrder(deadline);

        // sign the order with a stranger, not the shed owner
        Vm.Wallet memory stranger = vm.createWallet("stranger");
        bytes32 digest = order.hash(settlement.domainSeparator());
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(stranger.privateKey, digest);
        bytes memory orderSig = abi.encodePacked(shed, abi.encodePacked(r, s, v));

        MockSettlement.Interaction[] memory none = new MockSettlement.Interaction[](0);
        vm.prank(solver);
        vm.expectRevert(MockSettlement.InvalidOrderSignature.selector);
        settlement.settle(none, order, orderSig, MockSettlement.SigningScheme.Eip1271, BUY_AMOUNT);
    }

    function testSettleRevertsForNonSolver() public {
        uint256 deadline = block.timestamp + 1 hours;
        LibCowOrder.Data memory order = _baseOrder(deadline);
        bytes memory orderSig = _signOrder(order);
        MockSettlement.Interaction[] memory none = new MockSettlement.Interaction[](0);

        vm.prank(makeAddr("notASolver"));
        vm.expectRevert(MockSettlement.NotASolver.selector);
        settlement.settle(none, order, orderSig, MockSettlement.SigningScheme.Eip1271, BUY_AMOUNT);
    }

    // --- helpers -----------------------------------------------------------

    function _baseOrder(uint256 deadline) internal view returns (LibCowOrder.Data memory) {
        return LibCowOrder.Data({
            sellToken: IERC20(address(sellToken)),
            buyToken: IERC20(address(buyToken)),
            receiver: user.addr,
            sellAmount: SELL_AMOUNT,
            buyAmount: BUY_AMOUNT,
            validTo: uint32(deadline),
            appData: bytes32(0),
            feeAmount: 0,
            kind: KIND_SELL,
            partiallyFillable: false,
            sellTokenBalance: BALANCE_ERC20,
            buyTokenBalance: BALANCE_ERC20
        });
    }

    /// @dev Deploy the shed and give it the sell token + relayer approval, so a
    ///      settlement can proceed past the funding stage without the hook.
    function _deployShedWithFunds(uint256 deadline) internal {
        Call[] memory empty = new Call[](0);
        bytes32 nonce = "init";
        bytes memory sig = _signHookBatch(empty, nonce, deadline);
        factory.executeHooks(empty, nonce, deadline, user.addr, sig);
        sellToken.mint(shed, SELL_AMOUNT);
        vm.prank(shed);
        sellToken.approve(address(relayer), SELL_AMOUNT);
    }

    function _signPermit2(MockPermit2.PermitTransferFrom memory permit, address spender)
        internal
        view
        returns (bytes memory)
    {
        bytes32 tokenPermissionsHash = keccak256(
            abi.encode(permit2.TOKEN_PERMISSIONS_TYPEHASH(), permit.permitted.token, permit.permitted.amount)
        );
        bytes32 structHash = keccak256(
            abi.encode(
                permit2.PERMIT_TRANSFER_FROM_TYPEHASH(),
                tokenPermissionsHash,
                spender,
                permit.nonce,
                permit.deadline
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", permit2.DOMAIN_SEPARATOR(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(user.privateKey, digest);
        return abi.encodePacked(r, s, v);
    }

    function _signHookBatch(Call[] memory calls, bytes32 nonce, uint256 deadline)
        internal
        view
        returns (bytes memory)
    {
        bytes32 digest = cproxy.hashToSign(calls, nonce, deadline, _shedDomainSeparator());
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(user.privateKey, digest);
        return abi.encodePacked(r, s, v);
    }

    function _signOrder(LibCowOrder.Data memory order) internal view returns (bytes memory) {
        bytes32 digest = order.hash(settlement.domainSeparator());
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(user.privateKey, digest);
        // GPv2 EIP-1271 encoding: verifier/owner address ++ 1271 signature payload.
        return abi.encodePacked(shed, abi.encodePacked(r, s, v));
    }

    /// @dev The shed's COWShed domain separator, computable before deployment.
    function _shedDomainSeparator() internal view returns (bytes32) {
        bytes32 domainTypeHash =
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
        return keccak256(
            abi.encode(
                domainTypeHash, keccak256("COWShed"), keccak256(bytes(impl.VERSION())), block.chainid, shed
            )
        );
    }
}
