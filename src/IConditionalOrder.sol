// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.25;

interface IConditionalOrder {
    /**
     * @dev This struct is used to uniquely identify a conditional order for an owner.
     *      H(handler || salt || staticInput) **MUST** be unique for an owner.
     */
    struct ConditionalOrderParams {
        IConditionalOrder handler;
        bytes32 salt;
        bytes staticInput;
    }
}
