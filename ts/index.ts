import {
  ethers,
  getCreate2Address,
  solidityPacked,
  solidityPackedKeccak256,
  TypedDataDomain,
  TypedDataEncoder,
} from 'ethers';
import { FACTORY_ABI, PROXY_CREATION_CODE, SHED_ABI } from './constants';

export const computeProxyAddress = (user: string) => {
  getCreate2Address;
};

interface ISdkOptions {
  factoryAddress: string;
  proxyCreationCode?: string;
  implementationAddress: string;
  chainId: number;
}

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

const ABI_CODER = new ethers.AbiCoder();

const COW_SHED_712_TYPES = {
  EIP712Domain: [
    { type: 'string', name: 'name' },
    { type: 'string', name: 'version' },
    { type: 'uint256', name: 'chainId' },
    { type: 'address', name: 'verifyingContract' },
  ],
  ExecuteHooks: [
    { type: 'Call[]', name: 'calls' },
    { type: 'bytes32', name: 'nonce' },
    { type: 'uint256', name: 'deadline' },
  ],
  Call: [
    { type: 'address', name: 'target' },
    { type: 'uint256', name: 'value' },
    { type: 'bytes', name: 'callData' },
    { type: 'bool', name: 'allowFailure' },
    { type: 'bool', name: 'isDelegateCall' },
  ],
};
const TYPED_DATA_ENCODER = new TypedDataEncoder(COW_SHED_712_TYPES);

const FACTORY_INTERFACE: ethers.Interface = new ethers.Interface(FACTORY_ABI);
const SHED_INTERFACE: ethers.Interface = new ethers.Interface(SHED_ABI);

export class CowShedSdk {
  constructor(private options: ISdkOptions) {}

  computeProxyAddress(user: string) {
    const salt = ABI_CODER.encode(['address'], [user]);
    const initCodeHash = solidityPackedKeccak256(
      ['bytes', 'bytes'],
      [
        this._proxyCreationCode(),
        ABI_CODER.encode(
          ['address', 'address'],
          [this.options.implementationAddress, user]
        ),
      ]
    );
    return getCreate2Address(this.options.factoryAddress, salt, initCodeHash);
  }

  computeDomainSeparator(proxy: string) {
    return TYPED_DATA_ENCODER.hashStruct(
      'EIP712Domain',
      this._getDomain(proxy)
    );
  }

  hashToSignWithProxy(
    calls: ICall[],
    nonce: string,
    deadline: bigint,
    proxy: string
  ) {
    return this._hashToSign(calls, nonce, deadline, proxy);
  }

  hashToSignWithUser(
    calls: ICall[],
    nonce: string,
    deadline: bigint,
    user: string
  ) {
    return this._hashToSign(
      calls,
      nonce,
      deadline,
      this.computeProxyAddress(user)
    );
  }

  static encodeExecuteHooksForFactory(
    calls: ICall[],
    nonce: string,
    deadline: bigint,
    user: string,
    signature: string
  ) {
    return FACTORY_INTERFACE.encodeFunctionData('executeHooks', [
      calls,
      nonce,
      deadline,
      user,
      signature,
    ]);
  }

  static encodeExecuteHooksForProxy(
    calls: ICall[],
    nonce: string,
    deadline: bigint,
    signature: string
  ) {
    return SHED_INTERFACE.encodeFunctionData('executeHooks', [
      calls,
      nonce,
      deadline,
      signature,
    ]);
  }

  static encodeEOASignature(r: bigint, s: bigint, v: number) {
    return solidityPacked(['bytes32', 'bytes32', 'uint8'], [r, s, v]);
  }

  private _hashToSign(
    calls: ICall[],
    nonce: string,
    deadline: bigint,
    proxy: string
  ) {
    const message: IExecuteHooks = {
      calls,
      nonce,
      deadline,
    };
    return TypedDataEncoder.hash(
      this._getDomain(proxy),
      COW_SHED_712_TYPES,
      message
    );
  }

  private _getDomain(proxy: string): TypedDataDomain {
    const domain: TypedDataDomain = {
      name: 'COWShed',
      version: '1.0.0',
      chainId: this.options.chainId,
      verifyingContract: proxy,
    };
    return domain;
  }

  private _proxyCreationCode() {
    return this.options.proxyCreationCode ?? PROXY_CREATION_CODE;
  }
}
