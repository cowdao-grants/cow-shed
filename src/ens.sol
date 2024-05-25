/// @dev IReverseRegistrar interface as defined in ENSIP-3.
///      See: https://github.com/ensdomains/ens-contracts/blob/8e8cf71bc50fb1a5055dcf3d523d2ed54e725d28/contracts/reverseRegistrar/IReverseRegistrar.sol
interface IReverseRegistrar {
    function claim(address owner) external returns (bytes32 node);
    function claimWithResolver(address owner, address resolver) external returns (bytes32 node);
    function setName(string calldata name) external returns (bytes32 node);
    function node(address) external view returns (bytes32 node);
}

/// @dev INameResolver interface as defined in ENSIP-3
///      See: https://github.com/ensdomains/ens-contracts/blob/8e8cf71bc50fb1a5055dcf3d523d2ed54e725d28/contracts/resolvers/profiles/INameResolver.sol
interface INameResolver {
    function name(bytes32 node) external view returns (string memory);
}

/// @dev ENS registry interface as defined in ENSIP-1
///      See: https://github.com/ensdomains/ens-contracts/blob/8e8cf71bc50fb1a5055dcf3d523d2ed54e725d28/contracts/registry/ENS.sol
interface IENS {
    function setSubnodeRecord(bytes32 node, bytes32 label, address owner, address resolver, uint64 ttl) external;
    function resolver(bytes32 node) external view returns (address);
    function owner(bytes32 node) external view returns (address);
    function setResolver(bytes32 node, address resolver) external;
}

/// @dev ENS address resolution interface as defined in ENSIP-1
///      See: https://github.com/ensdomains/ens-contracts/blob/8e8cf71bc50fb1a5055dcf3d523d2ed54e725d28/contracts/resolvers/profiles/IAddrResolver.sol
interface IAddrResolver {
    function addr(bytes32 node) external view returns (address);
}

IReverseRegistrar constant REVERSE_REGISTRAR = IReverseRegistrar(0xa58E81fe9b61B5c3fE2AFD33CF304c454AbFc7Cb);
IENS constant ENS = IENS(0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e);
/// @dev namehash of `addr.reverse`
bytes32 constant ADDR_REVERSE_NODE = 0x91d1777781884d03a6757a803996e38de2a42967fb37eeaca72729271025a9e2;

/// @dev constant used in the sha3HexAddress, also copied over.
bytes32 constant sha3HexLookup = "0123456789abcdef";

/**
 * @dev An optimised function to compute the sha3 of the lower-case
 *      hexadecimal representation of an Ethereum address.
 *      Copied over from [ReverseRegistrar.sol](https://github.com/ensdomains/ens-contracts/blob/8e8cf71bc50fb1a5055dcf3d523d2ed54e725d28/contracts/reverseRegistrar/ReverseRegistrar.sol#L157-L181)
 * @param who The address to hash
 * @return ret The SHA3 hash of the lower-case hexadecimal encoding of the
 *         input address.
 */
function sha3HexAddress(address who) pure returns (bytes32 ret) {
    assembly {
        for { let i := 40 } gt(i, 0) { } {
            i := sub(i, 1)
            mstore8(i, byte(and(who, 0xf), sha3HexLookup))
            who := div(who, 0x10)
            i := sub(i, 1)
            mstore8(i, byte(and(who, 0xf), sha3HexLookup))
            who := div(who, 0x10)
        }

        ret := keccak256(0, 40)
    }
}
