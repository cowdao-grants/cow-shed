struct Call {
    address target;
    uint256 value;
    bytes callData;
    bool allowFailure;
}

interface ICOWAuthHook {
    function executeHooks(Call[] calldata calls, bytes32 nonce, bytes calldata signature) external;
    function trustedExecuteHooks(Call[] calldata calls) external;
    function updateTrustedExecutor(address who, bool authorized) external;
}
