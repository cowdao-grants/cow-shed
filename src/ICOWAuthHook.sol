struct Call {
    address target;
    uint256 value;
    bytes callData;
    bool allowFailure;
}

interface ICOWAuthHook {
    function executeHooks(Call[] calldata calls, bytes32 nonce, bytes32 r, bytes32 s, uint8 v) external;
    function trustedExecuteHooks(Call[] calldata calls) external;
    function updateTrustedExecutor(address who, bool authorized) external;
}
