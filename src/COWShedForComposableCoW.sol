// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.25;

import {COWShed} from "./COWShed.sol";
import {ERC1271Forwarder} from "./ERC1271Forwarder.sol";
import {IComposableCow} from "./IComposableCow.sol";

import {IComposableCow} from "./IComposableCow.sol";

contract COWShedForComposableCoW is COWShed, ERC1271Forwarder {
    constructor(IComposableCow _composableCoW) ERC1271Forwarder(_composableCoW) {}
}
