export const FACTORY_ABI = [
  {
    "type": "function",
    "name": "executeHooks",
    "inputs": [
      {
        "name": "calls",
        "type": "tuple[]",
        "internalType": "struct Call[]",
        "components": [
          {
            "name": "target",
            "type": "address",
            "internalType": "address"
          },
          {
            "name": "value",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "callData",
            "type": "bytes",
            "internalType": "bytes"
          },
          {
            "name": "allowFailure",
            "type": "bool",
            "internalType": "bool"
          },
          {
            "name": "isDelegateCall",
            "type": "bool",
            "internalType": "bool"
          }
        ]
      },
      {
        "name": "nonce",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "deadline",
        "type": "uint256",
        "internalType": "uint256"
      },
      {
        "name": "user",
        "type": "address",
        "internalType": "address"
      },
      {
        "name": "signature",
        "type": "bytes",
        "internalType": "bytes"
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
] as const;

export const SHED_ABI = [
  {
    "type": "function",
    "name": "executeHooks",
    "inputs": [
      {
        "name": "calls",
        "type": "tuple[]",
        "internalType": "struct Call[]",
        "components": [
          {
            "name": "target",
            "type": "address",
            "internalType": "address"
          },
          {
            "name": "value",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "callData",
            "type": "bytes",
            "internalType": "bytes"
          },
          {
            "name": "allowFailure",
            "type": "bool",
            "internalType": "bool"
          },
          {
            "name": "isDelegateCall",
            "type": "bool",
            "internalType": "bool"
          }
        ]
      },
      {
        "name": "nonce",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "deadline",
        "type": "uint256",
        "internalType": "uint256"
      },
      {
        "name": "signature",
        "type": "bytes",
        "internalType": "bytes"
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
] as const;

export const PROXY_CREATION_CODE = "0x"
