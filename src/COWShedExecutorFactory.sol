// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.25;

import {COWShed} from "./COWShed.sol";
import {COWShedFactory} from "./COWShedFactory.sol";
import {COWShedProxy} from "./COWShedProxy.sol";
import {Call} from "./ICOWAuthHook.sol";
import {ICOWShedSetup} from "./ICOWShedSetup.sol";

/// @title COWShedExecutorFactory
/// @notice A COWShedFactory that can deploy proxies preconfigured with a specific trusted
///         executor, at an address that also commits to that executor and a caller-supplied
///         salt.
/// @dev Kept as a subclass so the canonical `COWShedFactory` bytecode (and hence its
///      deterministic deployment address) is untouched. The base per-owner path
///      (`proxyOf(address)` / `initializeProxy(address)` / `executeHooks(...)`) is inherited
///      unchanged; this contract only adds the preconfigured-executor overloads.
contract COWShedExecutorFactory is COWShedFactory {
    error OnlyOwner();

    /// @notice emitted when the owner deploys a shed at its setup-committed address without
    ///         running the committed setup call.
    event SetupSkipped(address indexed owner, address indexed shed, address setupTarget);

    constructor(address impl) COWShedFactory(impl) {}

    /// @notice deterministic address for a proxy preconfigured with a specific trusted executor
    ///         and salt.
    /// @dev The trusted executor and salt are committed into the create2 salt (alongside the
    ///      owner, which is also part of the proxy init code). A different trusted executor or
    ///      salt therefore yields a different address, so nobody can front-run initialization to
    ///      preconfigure the proxy at this address with a different executor. The same owner can
    ///      also have multiple independent proxies by varying `salt`.
    /// @param owner           - The owner/admin of the proxy.
    /// @param trustedExecutor - The trusted executor the proxy is initialized with.
    /// @param salt            - Arbitrary salt to allow multiple proxies per (owner, executor).
    function proxyOf(address owner, address trustedExecutor, bytes32 salt) public view returns (address) {
        bytes32 initCodeHash = keccak256(abi.encodePacked(PROXY_CREATION_CODE, abi.encode(implementation, owner)));
        return address(
            uint160(
                uint256(
                    keccak256(
                        abi.encodePacked(
                            hex"ff", address(this), _create2Salt(owner, trustedExecutor, salt), initCodeHash
                        )
                    )
                )
            )
        );
    }

    /// @notice deploy a proxy preconfigured with a specific trusted executor if not already
    ///         deployed.
    /// @param owner           - The owner/admin of the proxy.
    /// @param trustedExecutor - The trusted executor to initialize the proxy with.
    /// @param salt            - Arbitrary salt to allow multiple proxies per (owner, executor).
    /// @return proxy          - The address of the (possibly newly) deployed proxy.
    function initializeProxy(address owner, address trustedExecutor, bytes32 salt) public returns (address proxy) {
        proxy = proxyOf(owner, trustedExecutor, salt);
        if (proxy.code.length == 0) {
            _deployPreconfiguredProxy(owner, trustedExecutor, _create2Salt(owner, trustedExecutor, salt), proxy);
        }
    }

    /// @notice execute hooks on a proxy preconfigured with a specific trusted executor.
    /// @dev Will deploy and initialize the proxy at a deterministic address if one doesn't
    ///      already exist. The authorization checks are implemented in COWShed.executeHooks.
    function executeHooks(
        Call[] calldata calls,
        bytes32 nonce,
        uint256 deadline,
        address owner,
        address trustedExecutor,
        bytes32 salt,
        bytes calldata signature
    ) external {
        address proxy = initializeProxy(owner, trustedExecutor, salt);
        COWShed(payable(proxy)).executeHooks(calls, nonce, deadline, signature);
    }

    /// @dev create2 salt committing to the owner, the preconfigured trusted executor and a
    ///      user-supplied salt. The keccak output is effectively always >= 2**160, so it can
    ///      never collide with the base per-owner salt `bytes32(uint256(uint160(owner)))`.
    function _create2Salt(address owner, address trustedExecutor, bytes32 salt) internal pure returns (bytes32) {
        return keccak256(abi.encode(owner, trustedExecutor, salt));
    }

    /// @dev deploy and initialize a preconfigured proxy at `proxy`, which the caller must have
    ///      derived from `create2Salt`. Callers are responsible for the "not already deployed"
    ///      check.
    function _deployPreconfiguredProxy(address owner, address trustedExecutor, bytes32 create2Salt, address proxy)
        internal
    {
        new COWShedProxy{salt: create2Salt}(implementation, owner);
        COWShed(payable(proxy)).initialize(trustedExecutor);
        emit COWShedBuilt(owner, proxy);

        // set reverse mapping of proxy to owner
        ownerOf[proxy] = owner;
    }

    // --- deploy-time setup call --------------------------------------------------------------

    /// @notice deterministic address for a shed preconfigured with a trusted executor and salt,
    ///         that also runs a one-time setup call on `setupTarget` at deployment.
    /// @dev The setup target and data are committed into the create2 salt, so a different setup
    ///      call yields a different address (grief-free): nobody can deploy the shed at this
    ///      address with a different setup call. A shed created with a setup call therefore has a
    ///      different address than the plain `proxyOf(owner, trustedExecutor, salt)`.
    /// @param owner           - The owner/admin of the proxy.
    /// @param trustedExecutor - The trusted executor the proxy is initialized with.
    /// @param salt            - Arbitrary salt to allow multiple proxies per (owner, executor).
    /// @param setupTarget     - Contract called back via `ICOWShedSetup.setup` right after deploy.
    /// @param setupData       - Data passed to the setup callback (committed into the address).
    function proxyOf(
        address owner,
        address trustedExecutor,
        bytes32 salt,
        address setupTarget,
        bytes calldata setupData
    ) public view returns (address) {
        bytes32 initCodeHash = keccak256(abi.encodePacked(PROXY_CREATION_CODE, abi.encode(implementation, owner)));
        return address(
            uint160(
                uint256(
                    keccak256(
                        abi.encodePacked(
                            hex"ff",
                            address(this),
                            _setupSalt(owner, trustedExecutor, salt, setupTarget, setupData),
                            initCodeHash
                        )
                    )
                )
            )
        );
    }

    /// @notice deploy a preconfigured proxy (if not already deployed) and run a one-time setup
    ///         call on `setupTarget` in the same transaction.
    /// @dev The setup call is only executed on first deployment (idempotent), so this can be run
    ///      as a discardable solver pre-interaction. The callback receives the freshly deployed
    ///      `proxy` address, which it cannot know from `setupData` alone (that data is committed
    ///      into the proxy address). If the setup call reverts, the whole deployment reverts.
    /// @return proxy - The address of the (possibly newly) deployed proxy.
    function initializeProxyWithSetup(
        address owner,
        address trustedExecutor,
        bytes32 salt,
        address setupTarget,
        bytes calldata setupData
    ) public returns (address proxy) {
        proxy = proxyOf(owner, trustedExecutor, salt, setupTarget, setupData);
        if (proxy.code.length == 0) {
            _deployPreconfiguredProxy(
                owner, trustedExecutor, _setupSalt(owner, trustedExecutor, salt, setupTarget, setupData), proxy
            );

            // run the one-time setup call, passing the deployed proxy address to the target
            ICOWShedSetup(setupTarget).setup(proxy, owner, setupData);
        }
    }

    /// @notice deploy a preconfigured proxy at its setup-committed address *without* running the
    ///         committed setup call. Only callable by the shed owner.
    /// @dev Last-resort recovery hatch. The address returned by `proxyOf(owner, trustedExecutor,
    ///      salt, setupTarget, setupData)` can only ever be deployed by `initializeProxyWithSetup`,
    ///      which reverts as a whole if the setup call reverts. If the setup call can never
    ///      succeed (buggy or permanently reverting target, data that can never validate), any
    ///      funds already sent to that counterfactual address would be stuck forever. This lets
    ///      the owner deploy the shed anyway and recover them.
    ///
    ///      Restricting this to `msg.sender == owner` preserves the grief-free property of the
    ///      setup path: a third party still cannot deploy a shed at an address that commits to a
    ///      setup call without running it. It also grants the owner nothing they don't already
    ///      have, since the owner is the proxy admin and can `updateImplementation` on any shed
    ///      they own.
    ///
    ///      Callers relying on the setup having run must therefore not infer it from the shed's
    ///      address alone; watch for `SetupSkipped` (or check the setup target's own state).
    ///
    ///      `calls` runs as the shed in the same transaction, so the owner can deploy and empty a
    ///      stranded shed atomically. That matters beyond convenience: the committed
    ///      `trustedExecutor` cannot be swapped out (it is part of the address), so it gains its
    ///      trusted role the moment the shed exists. Sweeping in a separate transaction would
    ///      leave a window for it to drain the shed first.
    /// @param owner           - The owner/admin of the proxy. Must be the caller.
    /// @param trustedExecutor - The trusted executor the proxy ends up configured with.
    /// @param salt            - Arbitrary salt to allow multiple proxies per (owner, executor).
    /// @param setupTarget     - The setup target committed into the address, *not* called.
    /// @param setupData       - The setup data committed into the address, *not* used.
    /// @param calls           - Calls to execute as the shed right after deploying it, e.g. to
    ///                          withdraw stranded funds. May be empty.
    /// @return proxy          - The address of the (possibly newly) deployed proxy.
    function initializeProxyWithoutSetup(
        address owner,
        address trustedExecutor,
        bytes32 salt,
        address setupTarget,
        bytes calldata setupData,
        Call[] calldata calls
    ) external returns (address proxy) {
        if (msg.sender != owner) {
            revert OnlyOwner();
        }
        proxy = proxyOf(owner, trustedExecutor, salt, setupTarget, setupData);
        if (proxy.code.length == 0) {
            // to run `calls` as the shed, the factory has to hold a trusted role on it. It takes
            // that role for the duration of this call only, and hands it over to the committed
            // executor as the last thing it does.
            bool takeTrustedRole = calls.length > 0;
            _deployPreconfiguredProxy(
                owner,
                takeTrustedRole ? address(this) : trustedExecutor,
                _setupSalt(owner, trustedExecutor, salt, setupTarget, setupData),
                proxy
            );
            emit SetupSkipped(owner, proxy, setupTarget);

            if (takeTrustedRole) {
                COWShed(payable(proxy)).trustedExecuteHooks(_withHandover(calls, proxy, trustedExecutor));
            }
        }
    }

    /// @dev `calls` followed by a call handing the trusted role over to `trustedExecutor`, so the
    ///      shed ends up in exactly the configuration its address commits to. Appended last and
    ///      not allowed to fail, so no owner-supplied call can leave the factory trusted:
    ///      `updateTrustedExecutor` is `onlySelf`, hence routed as a call from the shed itself.
    function _withHandover(Call[] calldata calls, address proxy, address trustedExecutor)
        internal
        pure
        returns (Call[] memory withHandover)
    {
        withHandover = new Call[](calls.length + 1);
        for (uint256 i = 0; i < calls.length; i++) {
            withHandover[i] = calls[i];
        }
        withHandover[calls.length] = Call({
            target: proxy,
            value: 0,
            callData: abi.encodeCall(COWShed.updateTrustedExecutor, (trustedExecutor)),
            allowFailure: false,
            isDelegateCall: false
        });
    }

    /// @dev create2 salt committing to the owner, trusted executor, user salt, and the setup call
    ///      (target + data). Binding the setup call makes the deployment grief-free.
    function _setupSalt(
        address owner,
        address trustedExecutor,
        bytes32 salt,
        address setupTarget,
        bytes calldata setupData
    ) internal pure returns (bytes32) {
        return keccak256(abi.encode(owner, trustedExecutor, salt, setupTarget, keccak256(setupData)));
    }
}
