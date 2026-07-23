// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.25;

/// @title ICOWShedSetup
/// @notice Callback invoked by `COWShedExecutorFactory` immediately after a shed is deployed and
///         initialized, to perform one-time setup (register the shed with a manager, deploy/kick
///         the trusted executor, ...) in the same transaction as the deployment.
/// @dev The factory commits `(setupTarget, setupData)` into the shed's CREATE2 address and then
///      calls `setup(shed, owner, setupData)` on the target. The `shed` address is supplied at
///      call time on purpose: it cannot be embedded in `setupData`, since `setupData` is committed
///      into that very address (a circular dependency). The target is typically the shed's trusted
///      executor, which - being trusted - can act as the shed via `trustedExecuteHooks`.
interface ICOWShedSetup {
    /// @param shed      The freshly deployed shed proxy.
    /// @param owner     The shed owner/admin.
    /// @param setupData Arbitrary data committed into the shed address (e.g. a leverage intent).
    function setup(address shed, address owner, bytes calldata setupData) external;
}
