// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.25;

import {IERC20} from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {ECDSA} from "solady/utils/ECDSA.sol";

/// @dev Minimal stand-in for Uniswap's Permit2 `SignatureTransfer`. Reproduces
///      the real EIP-712 typehashes and digest layout so signing logic matches
///      production, but simplifies nonce accounting to a plain used-flag mapping.
///      Only `permitTransferFrom` is implemented.
contract MockPermit2 {
    error InvalidSigner();
    error SignatureExpired();
    error InvalidAmount();
    error InvalidNonce();

    struct TokenPermissions {
        address token;
        uint256 amount;
    }

    struct PermitTransferFrom {
        TokenPermissions permitted;
        uint256 nonce;
        uint256 deadline;
    }

    struct SignatureTransferDetails {
        address to;
        uint256 requestedAmount;
    }

    bytes32 internal constant DOMAIN_TYPE_HASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    bytes32 public constant TOKEN_PERMISSIONS_TYPEHASH = keccak256("TokenPermissions(address token,uint256 amount)");

    bytes32 public constant PERMIT_TRANSFER_FROM_TYPEHASH = keccak256(
        "PermitTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline)TokenPermissions(address token,uint256 amount)"
    );

    /// @dev owner => nonce => used
    mapping(address => mapping(uint256 => bool)) public nonceUsed;

    function DOMAIN_SEPARATOR() public view returns (bytes32) {
        return keccak256(
            abi.encode(DOMAIN_TYPE_HASH, keccak256("Permit2"), keccak256("1"), block.chainid, address(this))
        );
    }

    /// @notice Transfer tokens from `owner` using their signed permit. The
    ///         caller (`msg.sender`) is the spender bound into the signature.
    function permitTransferFrom(
        PermitTransferFrom calldata permit,
        SignatureTransferDetails calldata transferDetails,
        address owner,
        bytes calldata signature
    ) external {
        if (block.timestamp > permit.deadline) revert SignatureExpired();
        if (transferDetails.requestedAmount > permit.permitted.amount) revert InvalidAmount();
        if (nonceUsed[owner][permit.nonce]) revert InvalidNonce();

        bytes32 tokenPermissionsHash =
            keccak256(abi.encode(TOKEN_PERMISSIONS_TYPEHASH, permit.permitted.token, permit.permitted.amount));
        bytes32 structHash = keccak256(
            abi.encode(
                PERMIT_TRANSFER_FROM_TYPEHASH, tokenPermissionsHash, msg.sender, permit.nonce, permit.deadline
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR(), structHash));

        if (ECDSA.recoverCalldata(digest, signature) != owner) revert InvalidSigner();

        nonceUsed[owner][permit.nonce] = true;
        IERC20(permit.permitted.token).transferFrom(owner, transferDetails.to, transferDetails.requestedAmount);
    }
}
