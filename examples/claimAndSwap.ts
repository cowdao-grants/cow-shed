import { Order, OrderBalance, OrderKind } from '@cowprotocol/contracts';
import {
  ABI_CODER,
  WETH,
  createOrder,
  fnCalldata,
  getTokenBalance,
  resolveName,
  settleOrder,
  withAnvilProvider,
} from './common';
import { ethers } from 'ethers_v6';
import { CowShedSdk, ICall } from '../ts';

const VESTING_ESCROW = '0xB802E2A5B79301d69BbCb4C43cA68fA54b22392B';

const WXDAI = '0xe91d153e0b41518a2ce8dd3d7944fa863463a97d';
const USDC = '0xDDAfbb505ad214D7b80b1f830fcCc89B60fb7A83';

const claimAndSwap: Parameters<typeof withAnvilProvider>[0] = async (
  provider: ethers.JsonRpcProvider,
  signers: ethers.Wallet[],
  { factory, implementation, proxyInitCode }
) => {
  const user = signers[1];
  const userAddr = await user.getAddress();

  // wrap the ether and approve to cowswap
  const amount = 1n;

  // compute the proxy address with CowShedSdk
  const shedSdk = new CowShedSdk({
    factoryAddress: factory,
    implementationAddress: implementation,
    chainId: 100,
    proxyCreationCode: proxyInitCode,
  });
  const proxyAddress = shedSdk.computeProxyAddress(userAddr);
  console.log('Computed proxy address for user', userAddr, 'is', proxyAddress);

  const validTo = Math.floor(new Date().getTime() / 1000) + 7200;

  const order: Order = {
    sellToken: WXDAI,
    buyToken: USDC,
    receiver: proxyAddress,
    sellAmount: amount,
    buyAmount: 0,
    validTo,
    appData: '',
    feeAmount: 0n,
    kind: OrderKind.SELL,
    partiallyFillable: true,
    sellTokenBalance: OrderBalance.ERC20,
    buyTokenBalance: OrderBalance.ERC20,
  };

  // pre-hooks
  const calls: ICall[] = [
    // approve the bridge to spend the swapped usdc
    {
      target: VESTING_ESCROW,
      callData: fnCalldata(
        'claim()',
        '0x'
      ),
      value: 0n,
      isDelegateCall: false,
      allowFailure: false,
    },
  ];
  const nonce = ethers.encodeBytes32String('first');

  // signing the hooks intent
  const hashToSign = shedSdk.hashToSignWithUser(
    calls,
    nonce,
    BigInt(validTo),
    userAddr
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
    userAddr,
    encodedSignature
  );


  const hooks = {
    post: [{ target: factory, callData: hooksCalldata, gasLimit: '9999999999999999999999' }],
  };

  // create order
  const orderTx = await createOrder(provider, order, hooks, userAddr);
  console.log('Create order tx', orderTx?.hash);

  // settle order
  const settleTx = await settleOrder(provider, order, hooks, userAddr);
  console.log('Settle tx', settleTx?.hash);

  // check if the tokens got claimed
  const claimedLog = settleTx!.logs.find(
    (log) =>
      // Claim(address,uint256)
      log.topics[0] ===
      '0x47cee97cb7acd717b3c0aa1435d004cd5b3c8c57d70dbceb4e4458bbd60e39d4' &&
      log.address.toLowerCase() === VESTING_ESCROW.toLowerCase()
  );
  if (claimedLog === undefined) {
    console.log('Bridge didnt happen!!!');
    return;
  }

  const amountClaimed = ABI_CODER.decode(['uint256'], claimedLog.data)[0];
  const sender = ABI_CODER.decode(['address'], claimedLog.topics[2])[0];
  console.log({ amountClaimed, sender, proxyAddress });

  const resolvedAddressLowerCase = await resolveName(
    provider,
    `${userAddr.toLowerCase()}.cowhooks.eth`
  );
  const resolvedAddressChecksummed = await resolveName(
    provider,
    `${ethers.getAddress(userAddr)}.cowhooks.eth`
  );
  const proxyName = await provider.lookupAddress(proxyAddress);
  const proxyUsdcBalanceAfterBridge = await getTokenBalance(
    provider,
    USDC,
    proxyAddress
  );
  console.log({
    resolvedAddressLowerCase,
    resolvedAddressChecksummed,
    proxyName,
    proxyAddress,
    userAddr,
    proxyUsdcBalanceAfterBridge,
  });
};

const main = async () => {
  await withAnvilProvider(claimAndSwap, 6_000_000);
};

main();
