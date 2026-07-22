// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.25;

import {IERC20} from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {IERC1271} from "src/IERC1271.sol";
import {LibCowOrder} from "src/LibCowOrder.sol";
import {ECDSA} from "solady/utils/ECDSA.sol";

/// @dev Pulls tokens on behalf of the settlement contract, mirroring the real
///      GPv2VaultRelayer split (traders approve the relayer, not settlement).
contract MockVaultRelayer {
    address public immutable settlement;

    constructor() {
        settlement = msg.sender;
    }

    function transferFromTrader(IERC20 token, address from, address to, uint256 amount) external {
        require(msg.sender == settlement, "only settlement");
        require(token.transferFrom(from, to, amount), "transferFrom failed");
    }
}

/// @dev Minimal single-order stand-in for GPv2Settlement. Reproduces the real
///      order EIP-712 digest (via LibCowOrder + "Gnosis Protocol"/"v2" domain)
///      and the EIP-1271 signature encoding (owner ++ signature), but settles
///      exactly one order against the settlement's own buffer instead of a full
///      batch with clearing prices.
contract MockSettlement {
    using LibCowOrder for LibCowOrder.Data;

    error NotASolver();
    error OrderExpired();
    error LimitPriceNotRespected();
    error InvalidOrderSignature();
    error PreInteractionFailed(bytes reason);
    error UnsupportedScheme();

    enum SigningScheme {
        Eip712,
        EthSign,
        Eip1271,
        PreSign
    }

    struct Interaction {
        address target;
        uint256 value;
        bytes callData;
    }

    bytes32 internal constant DOMAIN_TYPE_HASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    MockVaultRelayer public immutable vaultRelayer;
    bytes32 public immutable domainSeparator;

    mapping(address => bool) public solvers;

    constructor() {
        vaultRelayer = new MockVaultRelayer();
        solvers[msg.sender] = true;
        domainSeparator = keccak256(
            abi.encode(
                DOMAIN_TYPE_HASH, keccak256("Gnosis Protocol"), keccak256("v2"), block.chainid, address(this)
            )
        );
    }

    function setSolver(address solver, bool allowed) external {
        solvers[solver] = allowed;
    }

    /// @notice Settle a single order: run pre-interactions, validate the order
    ///         signature, pull the sell token from the trader and deliver the
    ///         buy token from the settlement buffer.
    /// @param executedBuyAmount buy tokens the solver delivers to the receiver.
    function settle(
        Interaction[] calldata preInteractions,
        LibCowOrder.Data calldata order,
        bytes calldata signature,
        SigningScheme scheme,
        uint256 executedBuyAmount
    ) external {
        if (!solvers[msg.sender]) revert NotASolver();

        for (uint256 i = 0; i < preInteractions.length; i++) {
            (bool ok, bytes memory ret) =
                preInteractions[i].target.call{value: preInteractions[i].value}(preInteractions[i].callData);
            if (!ok) revert PreInteractionFailed(ret);
        }

        LibCowOrder.Data memory ord = order;
        bytes32 orderDigest = ord.hash(domainSeparator);
        address owner = _recoverOwner(orderDigest, signature, scheme);

        if (block.timestamp > order.validTo) revert OrderExpired();
        if (executedBuyAmount < order.buyAmount) revert LimitPriceNotRespected();

        address receiver = order.receiver == address(0) ? owner : order.receiver;

        // Pull the sell token from the trader (the shed) via the relayer.
        vaultRelayer.transferFromTrader(order.sellToken, owner, address(this), order.sellAmount);
        // Deliver the buy token from the settlement's buffer.
        require(order.buyToken.transfer(receiver, executedBuyAmount), "buy transfer failed");
    }

    function _recoverOwner(bytes32 orderDigest, bytes calldata signature, SigningScheme scheme)
        internal
        view
        returns (address owner)
    {
        if (scheme == SigningScheme.Eip1271) {
            // GPv2 encoding: first 20 bytes = verifier/owner, remainder = 1271 signature.
            owner = address(bytes20(signature[0:20]));
            if (IERC1271(owner).isValidSignature(orderDigest, signature[20:]) != 0x1626ba7e) {
                revert InvalidOrderSignature();
            }
        } else if (scheme == SigningScheme.Eip712) {
            owner = ECDSA.recoverCalldata(orderDigest, signature);
        } else {
            revert UnsupportedScheme();
        }
    }
}
