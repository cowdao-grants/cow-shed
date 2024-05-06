struct Call {
    address target;
    uint256 value;
    bytes callData;
    bool allowFailure;
}

interface ICOWAuthHook {
    function executeHooks(Call[] calldata calls, bytes32 nonce, uint256 deadline, bytes calldata signature) external;
    function trustedExecuteHooks(Call[] calldata calls) external;
    function updateTrustedExecutor(address who) external;
}
