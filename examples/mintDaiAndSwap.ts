import { Order, OrderBalance, OrderKind } from '@cowprotocol/contracts';
import { CowShedSdk, ICall } from '../ts';
import {
  ABI_CODER,
  COW,
  DAI,
  DAI_JOIN,
  ETH_A_JOIN,
  VAT,
  VAULT_RELAYER,
  WETH,
  approveToken,
  createOrder,
  fnCalldata,
  frobFnSignature,
  getIlk,
  joinEth,
  resolveName,
  settleOrder,
  vatHope,
  withAnvilProvider,
  wrapEther,
} from './common';
import { ethers } from 'ethers_v6';

const mintDaiAndSwap: Parameters<typeof withAnvilProvider>[0] = async (
  provider: ethers.JsonRpcProvider,
  signers: ethers.Wallet[],
  { factory, implementation, proxyInitCode }
) => {
  // initialize the sdk
  const shedSdk = new CowShedSdk({
    factoryAddress: factory,
    implementationAddress: implementation,
    proxyCreationCode: proxyInitCode,
    chainId: 1,
  });

  const user = signers[1];
  // collateral to deposit
  const collateral = ethers.parseEther('10');
  // debt to take out
  const daiDebt = ethers.parseEther('8000');

  const proxyAddress = shedSdk.computeProxyAddress(user.address);
  console.log(
    'Computed proxy address for user',
    user.address,
    'is',
    proxyAddress
  );
  await wrapEther(provider, user.address, collateral);
  // allow proxy to take actions on behalf of the user
  await vatHope(provider, user.address, proxyAddress);
  // approve and deposit WETH into WETH Join
  await approveToken(provider, WETH, user.address, ETH_A_JOIN, collateral);
  await joinEth(provider, user.address, collateral);

  const validTo = Math.floor(new Date().getTime() / 1000) + 7200;
  const buyAmount = ethers.parseEther('100');

  // create a sell order for DAI to COW
  const order: Order = {
    sellToken: DAI,
    buyToken: COW,
    receiver: proxyAddress,
    sellAmount: daiDebt,
    buyAmount,
    validTo,
    appData: '',
    feeAmount: 0n,
    kind: OrderKind.SELL,
    partiallyFillable: true,
    sellTokenBalance: OrderBalance.ERC20,
    buyTokenBalance: OrderBalance.ERC20,
  };

  const ilk = await getIlk(provider, ETH_A_JOIN);

  // pre hooks, need to borrow the DAI right before the swap, in the pre hook
  const calls: ICall[] = [
    // create cdp on behalf of the user
    {
      target: VAT,
      isDelegateCall: false,
      value: 0n,
      allowFailure: false,
      callData: fnCalldata(
        frobFnSignature,
        ABI_CODER.encode(
          ['bytes32', 'address', 'address', 'address', 'int256', 'int256'],
          [ilk, user.address, user.address, proxyAddress, collateral, daiDebt]
        )
      ),
    },
    // approve dai join to mint the dai
    {
      allowFailure: false,
      target: VAT,
      value: 0n,
      isDelegateCall: false,
      callData: fnCalldata(
        'hope(address)',
        ABI_CODER.encode(['address'], [DAI_JOIN])
      ),
    },
    // withdraw the debt dai to the user address
    {
      allowFailure: false,
      target: DAI_JOIN,
      value: 0n,
      isDelegateCall: false,
      callData: fnCalldata(
        'exit(address,uint256)',
        ABI_CODER.encode(['address', 'uint256'], [user.address, daiDebt])
      ),
    },
  ];
  const nonce = ethers.encodeBytes32String('first');

  // signing the hooks intent
  const hashToSign = shedSdk.hashToSignWithUser(
    calls,
    nonce,
    BigInt(validTo),
    user.address
  );
  console.log('hash to sign', hashToSign);
  const signature = user.signingKey.sign(hashToSign);
  console.log('actual signature', signature.r, signature.s, signature.v);
  const encodedSignature = CowShedSdk.encodeEOASignature(
    BigInt(signature.r),
    BigInt(signature.s),
    signature.v
  );

  const hooksCalldata = CowShedSdk.encodeExecuteHooksForFactory(
    calls,
    nonce,
    BigInt(validTo),
    user.address,
    encodedSignature
  );
  const hooks = {
    pre: [{ target: factory, callData: hooksCalldata, gasLimit: '1000000000' }],
  };

  // approve dai to the vault relayer
  await approveToken(provider, DAI, user.address, VAULT_RELAYER, daiDebt);
  // create order
  const orderTx = await createOrder(provider, order, hooks, user.address);
  console.log('Create order tx', orderTx?.hash);

  // settle order
  const settleTx = await settleOrder(provider, order, hooks, user.address);
  console.log('Settle tx', settleTx?.hash);

  const resolvedAddressLowerCase = await resolveName(
    provider,
    `${user.address.toLowerCase()}.cowhooks.eth`
  );
  const resolvedAddressChecksummed = await resolveName(
    provider,
    `${ethers.getAddress(user.address)}.cowhooks.eth`
  );
  const proxyName = await provider.lookupAddress(proxyAddress);
  console.log({
    resolvedAddressLowerCase,
    resolvedAddressChecksummed,
    proxyName,
    proxyAddress,
    userAddress: user.address,
  });
};

const main = async () => {
  await withAnvilProvider(mintDaiAndSwap, 6000_0000);
};

main();
