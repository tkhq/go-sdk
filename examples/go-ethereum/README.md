# Turnkey + go-ethereum examples

This directory shows how to integrate Turnkey as the signer for Ethereum transactions using [`go-ethereum`](https://github.com/ethereum/go-ethereum), across three common integration levels:

- **Manual EIP-1559 transaction construction**
- **Drop-in signing for [bind.SignerFn](https://pkg.go.dev/github.com/ethereum/go-ethereum/accounts/abi/bind) flows**
- **Typed smart-contract calls generated with [`abigen`](https://geth.ethereum.org/docs/tools/abigen)**

---

These examples mirror real-world integration paths people take when adopting Turnkey:

1. **eip1559-unsigned — “I just want to sign a raw tx”**  

You already know how to build a transaction (or you have one coming from elsewhere) and just need to:
- format it the way Turnkey expects,  
- sign it with Turnkey
- and broadcast the signed bytes.

2. **bindsigner-basic — “I want a drop-in signer for go-ethereum”**  

Instead of manually building RLP payloads all over the place, you want a **single reusable `bind.SignerFn`** that:
- takes any EIP-1559 `*types.Transaction`,  
- normalizes it (e.g. ensures the chain ID is present),  
- signs it with Turnkey,
- and returns a fully signed transaction.  

3. **bindsigner-abigen — “I’m using abigen-generated contract bindings”**  

Use abigen-generated bindings and call functions like `token.Transfer(opts, to, amount)` without caring about tx construction.

This example shows how to:
- use the same Turnkey-backed `SignerFn`,
- plug it into `bind.TransactOpts`,
- let `abigen` build the tx,
- let Turnkey sign it,
- then broadcast it.

---

## `eip1559-unsigned`

**Goal:**  
Manually build an unsigned EIP-1559 transaction, RLP-encode it in the exact format Turnkey expects, sign it with Turnkey, and broadcast it.

**How it works:**

- Constructs a `types.DynamicFeeTx` manually.
- Builds the unsigned payload:
  ```text
  [chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gas, to, value, data, accessList]
  ```
- RLP-encodes that array and prepends the EIP-1559 type byte `0x02`.
- Signs the resulting hex string with Turnkey.
- Decodes the signed RLP back into *types.Transaction.
- Broadcasts via `ethclient.Client.SendTransaction`.

## `bindsigner-basic`

**Goal:**  
Provide a reusable Turnkey-backed `bind.SignerFn` that can sign any EIP-1559 transaction created by `go-ethereum`.

**How it works:**

- Creates a `MakeTurnkeySignerFn(client, signWith, chainID)` helper that returns a `bind.SignerFn`.
- Inside the signer:
  - checks the from address matches the Turnkey address,
	- ensures the tx is `DynamicFeeTxType`,
	- injects the chain ID if missing,
	- builds the minimal unsigned payload,
	- RLP-encodes and prepends `0x02`,
	- calls Turnkey `SignTransaction`,
	- rebuilds and returns a signed `*types.Transaction`.
  - broadcasts via `ethclient.Client.SendTransaction`.

## `bindsigner-abigen`

**Goal:**  
Demonstrate Turnkey signing in a full ERC-20 workflow using abigen-generated Go types.

**How it works:**

- Uses `abigen` to generate a typed ERC-20 binding from `ERC20.abi`.
- Imports the generated erc20 package and binds to a deployed ERC-20:
```go
token, err := erc20.NewErc20(tokenAddr, rpc)
```
- Constructs `bind.TransactOpts` using the same `MakeTurnkeySignerFn`.

```go
opts := &bind.TransactOpts{
    From:   turnkeyAddress,
    Signer: signerFn,
}
```
- Calls the typed contract method:
```go
tx, err := token.Transfer(opts, to, amount)
```

Under the hood:
- abigen builds the unsigned tx,
- calls your SignerFn,
- Turnkey signs it,
- you broadcast it normally.

**About the ERC-20 binding:**

The erc20.go file included in this directory was generated with:
```bash
abigen --abi ERC20.abi --pkg erc20 --out erc20.go
```
You **do not** need to regenerate it to run this example.


## Prerequisites

Before running any of the examples, you’ll need:

- A Turnkey [organization](https://docs.turnkey.com/getting-started/quickstart) with:
  - an API key (P-256),
  - and an Ethereum wallet account (the address you’ll sign with).
- A working Ethereum JSON-RPC endpoint (e.g. Sepolia from Alchemy, Infura, etc.).

Once you've gathered these values, add them to a new .env.local file. Notice that your private key should be securely managed and never be committed to git.

```bash
cd go-sdk/examples/go-ethereum
cp .env.example .env
```

Now open `.env` and add the missing environment variables:

```bash
TURNKEY_ORGANIZATION_ID="<Turnkey organization ID>"
TURNKEY_API_PUBLIC_KEY="<Turnkey API public key (starts with 02 or 03)>"
TURNKEY_API_PRIVATE_KEY="<Turnkey API private key>"

RPC_URL="<Ethereum RPC provider URL>"
SIGN_WITH="<Turnkey-managed Ethereum address>"

# Only needed for the abigen ERC20 example:
CONTRACT_ADDRESS="<ERC20 contract address>"
```

## Running the examples

Each example is fully independent and can be executed directly:

```bash
go run eip1559-unsigned/main.go
```

```bash
go run bindsigner-basic/main.go
```

```bash
go run bindsigner-abigen/main.go
```