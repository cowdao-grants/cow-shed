// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.25;

import {PreSignStateStorage} from "./PreSignStateStorage.sol";

/// @notice Factory contract for deploying PreSignStateStorage contracts
/// This makes it easy for users to deploy storage contracts for their COWShed
contract PreSignStateStorageFactory {
    event PreSignStateStorageDeployed(address indexed storageContract, address indexed cowShed);

    /// @notice Deploy a new PreSignStateStorage contract for a specific COWShed
    /// @param cowShed The address of the COWShed contract that will control this storage
    /// @return The address of the deployed storage contract
    function deployPreSignStateStorage(address cowShed) external returns (address) {
        require(cowShed != address(0), "COWShed address cannot be zero");

        PreSignStateStorage storageContract = new PreSignStateStorage(cowShed);

        emit PreSignStateStorageDeployed(address(storageContract), cowShed);

        return address(storageContract);
    }

    /// @notice Deploy a new PreSignStateStorage contract for the caller's COWShed
    /// @return The address of the deployed storage contract
    function deployPreSignStateStorageForSelf() external returns (address) {
        return _deployPreSignStateStorage(msg.sender);
    }

    /// @notice Internal function to deploy PreSignStateStorage contracts
    function _deployPreSignStateStorage(address cowShed) internal returns (address) {
        require(cowShed != address(0), "COWShed address cannot be zero");

        PreSignStateStorage storageContract = new PreSignStateStorage(cowShed);

        emit PreSignStateStorageDeployed(address(storageContract), cowShed);

        return address(storageContract);
    }
}
