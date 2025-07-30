import { TypedDataEncoder, ZeroAddress } from 'ethers_v6';

interface ICall {
  target: string;
  value: bigint;
  callData: string;
  allowFailure: boolean;
  isDelegateCall: boolean;
}

interface IExecuteHooks {
  calls: ICall[];
  nonce: string;
  deadline: bigint;
}

const cowShedTypes = {
  ExecuteHooks: [
    {
      name: 'calls',
      type: 'Call[]',
    },
    {
      name: 'nonce',
      type: 'bytes32',
    },
    {
      type: 'uint256',
      name: 'deadline',
    },
  ],
  Call: [
    { type: 'address', name: 'target' },
    { type: 'uint256', name: 'value' },
    { type: 'bytes', name: 'callData' },
    { type: 'bool', name: 'allowFailure' },
    { type: 'bool', name: 'isDelegateCall' },
  ],
};

const typedDomain = {
  chainId: 1,
  name: 'COWShed',
  version: '1.0.1',
  verifyingContract: '0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC',
};

const TYPE_ENCODER = new TypedDataEncoder(cowShedTypes);

const getCallHash = (call: ICall): string => {
  return TYPE_ENCODER.hashStruct('Call', call);
};

const getCallsHash = (calls: ICall[]): string => {
  return TYPE_ENCODER.encodeData('Call[]', calls);
};

const getExecuteHooksMessageHash = (message: IExecuteHooks): string => {
  return TYPE_ENCODER.hashStruct('ExecuteHooks', message);
};

const testCallsHash = () => {
  const calls = [
    {
      target: ZeroAddress,
      callData: '0x1223',
      value: 20n,
      allowFailure: false,
      isDelegateCall: false,
    },
    {
      target: ZeroAddress,
      callData: '0x00112233',
      value: 200000000n,
      allowFailure: false,
      isDelegateCall: false,
    },
  ];
  return getCallsHash(calls);
};

const testCallHash = () => {
  const call1 = {
    target: ZeroAddress,
    callData: '0x1223',
    value: 20n,
    allowFailure: false,
    isDelegateCall: false,
  };
  const call2 = {
    target: ZeroAddress,
    callData: '0x00112233',
    value: 200000000n,
    allowFailure: false,
    isDelegateCall: false,
  };
  return { call1: getCallHash(call1), call2: getCallHash(call2) };
};

const testExecuteHooksCallHash = () => {
  const message = {
    calls: [
      {
        target: ZeroAddress,
        callData: '0x1223',
        value: 20n,
        allowFailure: false,
        isDelegateCall: false,
      },
      {
        target: ZeroAddress,
        callData: '0x00112233',
        value: 200000000n,
        allowFailure: false,
        isDelegateCall: false,
      },
    ],
    nonce: '0x0000000000000000000000000000000000000000000000000000000000000001',
    deadline: 1714971380n,
  };
  return {
    messageHash: getExecuteHooksMessageHash(message),
    hashToSign: TypedDataEncoder.hash(typedDomain, cowShedTypes, message),
  };
};

const main = async () => {
  console.log({
    testCallHash: testCallHash(),
    testCallsHash: testCallsHash(),
    testExecuteHooksCallHash: testExecuteHooksCallHash(),
  });
};
main();
