# navcoin-js

Navcoin Javascript wallet library. Tested with Node v15.14.0 and NPM v7.7.6.

Minimal working examples in `example.js` and `web/`

## Specification

```angular2html
const njs = require('navcoin-js');
```

## Static methods.

### wallet.bitcore

Exposes low level methods from `@aguycalled/bitcore-lib`.

### wallet.Init()

Required before making any operation with the wallet. Initialises the cryptographic modules.

Parameters: `none`

Returns: `Promise`

Example:

````javascript
njs.wallet.Init().then(async () => {
    console.log(`library initialised`);
})
````

### wallet.WalletFile(parameters)

Creates a new Wallet object. Loads a wallet from storage or creates a new one if the name of the database does not exist.

Parameters: `parameters` object:

| Key        | Description                                                                                                                              | Default value |
|------------------|------------------------------------------------------------------------------------------------------------------------------------------|---------------|
| file             | Name of the wallet database. Will store in memory if `undefined`                                                                         |  undefined    |
| mnemonic         | When creating a new wallet, it will try to import the specified mnemonic.                                                                | undefined     |
| type             | Mnemonic type. Options: `navcoin-js-v1` (this library), `navcash`, `next`, `navcoin-core` or `navpay`                                    | navcoin-js-v1 |
| password         | Password used to encrypt the wallet data base. User will need to specify it every time the wallet is loaded.                             | undefined     |
| spendingPassword | When a new wallet is created, sets the password used to encrypt the wallet private keys. User will need to specify it every time it spends coins or wants to see a private key. | undefined     |
| zapwallettxes    | Wipe all wallet entries and resync if set to `true`                                                                                   | false         |
| network          | Which network should it connect to. Options: `mainnet` or `testnet` | `mainnet` |
| log              | Prints log to the console.                                                                                                         | false         |

Returns: `Wallet object`

Example:

````javascript
const wallet = new njs.wallet.WalletFile({file: 'wallet.db', password: 'myw4ll3tp455w0rd'})
````

### wallet.WalletFile.ListWallets()

Lists the names of the already created wallets.

Parameters: `none`

Returns: `Promise<Array>`

Example:

````javascript
const listWallets = await njs.wallet.WalletFile.ListWallets();

console.log("List of wallets:\n");
for (var wallet in listWallets) {
    console.log(listWallets[wallet]);
}
````

### wallet.WalletFile.RemoveWallet(name)

Remove the wallet with the specified name.

Parameters: `wallet database file name`

Returns: `Promise`

Example:

```javascript
await njs.wallet.WalletFile.RemoveWallet("wallet.db");
````

## Wallet methods

### Load(parameters)

Loads the wallet.

Parameters: `parameters` object:

| Key        | Description                                                                                                                              | Default value |
|------------------|------------------------------------------------------------------------------------------------------------------------------------------|---------------|
| bootstrap       | Object with a cached history of xNAV transaction keys, meant to speed sync speed.                                                                         |  undefined    |

Returns: `Promise`

Example:

```javascript
await wallet.Load({
  bootstrap: njs.wallet.xNavBootstrap
});
````

### AddNode(host, port, proto)

Adds an Electrum server to the nodes list. This is currently not persisted.

Parameters:

| Parameter        | Description                                                       |
|------------------|-------------------------------------------------------------------|
| host             | Electrum server host.                                             |
| port             | Electrum server port.                                             |
| proto            | Electrum server protocol.                                         |

Returns: `void`

Example:
````javascript
wallet.AddNode('electrum8.nav.community', 40004, 'wss')
````

### ClearNodeList()

Clears the Electrum server list. Not persisted.

Parameters: `none`

Returns: `void`

Example:
````javascript
wallet.ClearNodeList()
````

### Connect()

Connects to the Navcoin network.

Parameters: `none`

Returns: `promise`

Example:
````javascript
await wallet.Connect()
````

### Disconnect()

Disconnects from the electrum server.

Parameters: `none`

Returns: `void`

Example:

```javascript
wallet.Disconnect()
```

### NavReceivingAddresses()

Returns the list of addresses to receive NAV.

Returns: `Promise<Array>`

Example:

````javascript
console.log('NAV receiving address: '+ (await wallet.NavReceivingAddresses(false))[0].address);
````

### xNavReceivingAddresses()

Returns the list of addresses to receive xNAV.

Returns: `Promise<Array>`

Example:

````javascript
console.log('xNAV receiving address: '+ (await wallet.xNavReceivingAddresses(false))[0].address);
````


### NavGetPrivateKeys(spendingPassword, address)

Returns the list of private keys for the NAV addresses

Parameters:

`spendingPassword` The spending password of the wallet.

`address` Return the private key only for one specific address.


Returns: `Promise<Array>`

Example:

````javascript
console.log('NAV private keys: '+ (await wallet.NavGetPrivateKeys()));
````

### GetHistory()

Returns an ordered list of wallet balance changes and transactions.

Returns: `Promise<Array>`

Example:

````javascript
console.log('Wallet history: '+ (await wallet.GetHistory()));
````

### GetBalance()

Returns the current balances. Only needed to update when events `new_tx`, `remove_tx` or `sync_finished`.

Returns: `Promise<Object>`

Example:

````javascript
console.log('Wallet balance: '+ (await wallet.GetBalance()));
````

### NavCreateTransaction(destination, amount, memo, spendingPassword, subtractFee, fee, from)

Creates a transaction which sends NAV.

Parameters:

- `destination` The address destination. Can be NAV or xNAV.
- `amount` The amount to send.
- `memo` Only applies when destination is an xNAV address.
- `spendingPassword` The wallet spending password.
- `subtractFee` Should the fee be subtracted from the specified amount. Default: `true`.
- `fee` Use a custom fee
- `type` Select which coin types are selected, use `0x1` for non staking funds, `0x2` for staked funds, `0x3` for both. Default: `0x1`
- `address' Spend coins only from this address.

Returns: `Promise<Object>` with the transaction encoded in hex and the fee. Use `try` to catch error.


Example, normal NAV to NAV transaction:

````javascript
try {
    let tx = await wallet.NavCreateTransaction("NhSoiAPHvjiTLePzW1qKy9RZr2Bkny2ZF3", 10 * 1e8, undefined, "myw4ll3tp455w0rd")
    console.log(`transaction created with fee ${tx.fee}`)
    
} catch(e)
{
    console.log(`error creating transaction: ${e}`);
}
````

Example 2, moving coins out of staking:

````javascript
try {
    let tx = await wallet.NavCreateTransaction(
      (await wallet.NavReceivingAddresses(true))[0].address,
      (await wallet.GetBalance()).staked.confirmed,
      undefined,
      "myw4ll3tp455w0rd",
      true,
      100000,
      0x2
    )
    console.log(`transaction created with fee ${tx.fee}`)
    
} catch(e)
{
    console.log(`error creating transaction: ${e}`);
}
````

### xNavCreateTransaction(destination, amount, memo, spendingPassword, subtractFee)

Creates a transaction which sends xNAV.

Parameters:

- `destination` The address destination. Can be NAV or xNAV.
- `amount` The amount to send.
- `memo` Only applies when destination is xNAV.
- `spendingPassword` The wallet spending password.
- `subtractFee` Should the fee be subtracted from the specified amount. Default: `true`.

Returns: `Promise<Object>` with the transaction encoded in hex and the fee. Use `try` to catch error.

Example:

````javascript
try {
    let hash = await wallet.xNavCreateTransaction("NhSoiAPHvjiTLePzW1qKy9RZr2Bkny2ZF3", 10 * 1e8, undefined, "myw4ll3tp455w0rd")
    console.log(`transaction with fee ${tx.fee}`)
    
} catch(e)
{
    console.log(`error creating transaction: ${e}`);
}
````

### xNavCreateTransactionMultiple(destination, spendingPassword, subtractFee)

Creates a transaction which sends xNAV to mulple destinations.

Parameters:

- `destinations` An array of objects with the destinations.
- `spendingPassword` The wallet spending password.
- `subtractFee` Should the fee be subtracted from the specified amount. Default: `true`.

Returns: `Promise<Object>` with the transaction encoded in hex and the fee. Use `try` to catch error.

Example:

````javascript
try {
    let hash = await wallet.xNavCreateTransactionMultiple([{dest:"NhSoiAPHvjiTLePzW1qKy9RZr2Bkny2ZF3", amount: 10 * 1e8, memo: undefined}], "myw4ll3tp455w0rd")
    console.log(`transaction with fee ${tx.fee}`)
}
catch(e)
{
    console.log(`error creating transaction: ${e}`);
}
````

### tokenCreateTransaction(destination, amount, memo, spendingPassword, tokenId, nftId)

Creates a transaction which sends a private token or nft..

Parameters:

- `destination` The address destination. Must be xNAV.
- `amount` The amount to send. Should be 1 if `tokenId` is a NFT.
- `memo` Only applies when destination is xNAV.
- `spendingPassword` The wallet spending password.
- `tokenId` The token id.
- `tokenNftId` The NFT id, if `tokenId` is a NFT.

Returns: `Promise<Object>` with the transaction encoded in hex and the fee. Use `try` to catch error.

Example:

````javascript
try {
    let hash = await wallet.tokenCreateTransaction("NhSoiAPHvjiTLePzW1qKy9RZr2Bkny2ZF3", 10 * 1e8, undefined, "myw4ll3tp455w0rd", "8b130a7e21b7da3a8897205d7735dc5434c0019a35f3a5dec475fbc2cbd4f56a")
    console.log(`transaction with fee ${tx.fee}`)
    
} catch(e)
{
    console.log(`error creating transaction: ${e}`);
}
````

### SendTransaction(tx)

Broadcasts a transaction.

Parameters:

- `tx` The hex encoded transaction(s).

Returns: `Promise<Object>` 


Example:

````javascript
try {
    let tx = await wallet.SendTransaction(tx)
    console.log(`transaction sent with hashes ${tx.hashes} and error ${tx.error}`)
}
catch(e)
{
    console.log(`error sending: ${e}`)
}
````

### ImportPrivateKey(key, spendingKey)

Imports the specified private key `key` to the wallet.

Returns: `Promise`

Example:

````javascript
await wallet.ImportPrivateKey('P123123123123123123121', 'myw4ll3tp4ssw0rd')
````

### Sign(privateKey, message)

Signs a message with the specified private key.

### VerifySignature(address, message, signature)

Verifies a signed message.

### ResolveName(name)

Resolves a dotNav name.

Returns: `Promise<Object>` with the associated data to the name. Use `try` to catch error.

Example:

````javascript
try {
    let data = await wallet.ResolveName("myname.nav")
    console.log(`myname.nav is: ${JSON.stringify(data, undefined, 4)}`)
}
catch(e)
{
    console.log(`error resolving name: ${e}`);
}
````

### RegisterName(name, spendingPassword)

Registers a dotNav name.

Returns: `Promise<Object>` with the transaction encoded in hex and the fee. Use `try` to catch error.

Example:

````javascript
try {
    let hash = await wallet.RegisterName("myname.nav", "myw4ll3tp455w0rd")
    console.log(`transaction with fee ${tx.fee}`)
}
catch(e)
{
    console.log(`error creating transaction: ${e}`);
}
````

### UpdateName(name, subdomain, key, value, spendingPassword)

Updates a dotNav name.

Returns: `Promise<Object>` with the transaction encoded in hex and the fee. Use `try` to catch error.

Example:

````javascript
try {
    let hash = await wallet.UpdateName("myname.nav", "www", "ip", "127.0.0.1", "myw4ll3tp455w0rd")
    console.log(`transaction with fee ${tx.fee}`)
}
catch(e)
{
    console.log(`error creating transaction: ${e}`);
}
````

### GetMyNames()

Returns the list of dotNav names owned by the wallet.

Example:

````javascript
try {
    let names = await wallet.GetMyNames()
    console.log(`my names are: ${JSON.stringify(names, undefined, 4)}`)
}
catch(e)
{
    console.log(`error getting my names: ${e}`);
}
````

### IsValidDotNavName(name)

Returns whether a string is a valid dotNav name.

### IsValidDotNavKey(name)

Returns whether a string is a valid dotNav key.

### CreateToken(name, code, max_sypplu, spending_password)

Creates a private token with name `name`, currency code `code` and max supply `max_supply`.

Returns: `Promise<Object>` with the transaction encoded in hex and the fee. Use `try` to catch error.

Example:

````javascript
try {
    let hash = await wallet.CreateToken("Baby NAV", "BNAV", 1000*1e8, "myw4ll3tp455w0rd")
    console.log(`cost is fee ${tx.fee}`)
}
catch(e)
{
    console.log(`error creating transaction: ${e}`);
}
````

### CreateNft(name, scheme, max_sypplu, spending_password)

Creates a NFT with name `name`, scheme `scheme` and max supply `max_supply`.

Returns: `Promise<Object>` with the transaction encoded in hex and the fee. Use `try` to catch error.

Example:

````javascript
try {
    let hash = await wallet.CreateNft("Art Collection", "{'url':'resource'}", 1000, "myw4ll3tp455w0rd")
    console.log(`cost is fee ${tx.fee}`)
}
catch(e)
{
    console.log(`error creating transaction: ${e}`);
}
````

### MintToken(id, dest, amount, spending_password)

Mints `amount` tokens of token `id` to address `dest`.

Returns: `Promise<Object>` with the transaction encoded in hex and the fee. Use `try` to catch error.

Example:

````javascript
try {
    let hash = await wallet.MintToken("50c89fd9661dfeca262dbc9d796e8b4c74987b9c5a37a87254ba1a940fbfb382", "xNTvzWPMSAJYUMRTaqGEepADBPRs3CQ3JJVUWJU8JEUm5xBCdhrBGiYbozkDNbWuzHpCuSFT8fHv9NLthb7ga3vxMfCrSjH7HTQRnbtPmaGHJ9uekiiir1foLfMNQ9CAXJ9CRTgedbE", 1*1e8, "myw4ll3tp455w0rd")
    console.log(`cost is fee ${tx.fee}`)
}
catch(e)
{
    console.log(`error creating transaction: ${e}`);
}
````

### MintNft(id, nftId, dest, scheme, spending_password)

Mints 1 NFT of `id` with index `nftId` and scheme `scheme` to address `dest`.

Returns: `Promise<Object>` with the transaction encoded in hex and the fee. Use `try` to catch error.

Example:

````javascript
try {
    let hash = await wallet.MintNft("50c89fd9661dfeca262dbc9d796e8b4c74987b9c5a37a87254ba1a940fbfb382", 0, "xNTvzWPMSAJYUMRTaqGEepADBPRs3CQ3JJVUWJU8JEUm5xBCdhrBGiYbozkDNbWuzHpCuSFT8fHv9NLthb7ga3vxMfCrSjH7HTQRnbtPmaGHJ9uekiiir1foLfMNQ9CAXJ9CRTgedbE", "{'resource':'https://art.net/image.jpeg'}", "myw4ll3tp455w0rd")
    console.log(`cost is fee ${tx.fee}`)
}
catch(e)
{
    console.log(`error creating transaction: ${e}`);
}
````

### GetMyTokens(spendingPassword)

Returns the list of tokens owned by the wallet.

Example:

````javascript
try {
    let tokens = await wallet.GetMyTokens("my password")
    console.log(`my tokens are: ${JSON.stringify(tokens, undefined, 4)}`)
}
catch(e)
{
    console.log(`error getting my tokens: ${e}`);
}
````

## Events

### new_mnemonic

Emitted when a new wallet is created.

Example:

````javascript
wallet.on('new_mnemonic', (mnemonic) => console.log(`wallet created with mnemonic ${mnemonic} - please back it up!`));
````

### loaded

Emitted when the wallet has been loaded.

Example:

````javascript
wallet.on('loaded', async () => {     
    console.log('wallet loaded')
    
    console.log('NAV receiving address: '+ (await wallet.NavReceivingAddresses(false))[0].address);
        
    await wallet.Connect();
});
````


### connected

Emitted when a connection has been established to an electrum server.

Example:

````javascript
wallet.on('connected', (server) => console.log(`connected to ${server}. waiting for sync`));
````

### no_servers_available

Emitted when none of the servers is available

Example:

````javascript
wallet.on('no_servers_available', () => console.log(`none of the servers is available`));
````

### sync_finished

Emitted when the wallet finished synchronizing the transaction history.

````javascript
wallet.on('sync_finished', (scripthash) => console.log('sync complete'));
````

### sync_status

Emitted to update the sync progress.

````javascript
wallet.on('sync_status', (progress, pending, total) => console.log(`sync status: ${progress}%`));
````

### new_tx

Emitted when a new transaction affecting the wallet has been received.

````javascript
wallet.on('new_tx', async (list) => {
    console.log(`Received transaction ${JSON.stringify(list)}`)
    console.log(`Balance ${JSON.stringify(await wallet.GetBalance())}`)
});
````

### new_name

Emitted when a new dotNav name owned by the wallet has been seen.

````javascript
wallet.on('new_name', async (name) => {
    console.log(`Seen dotNav name ${name}`)
});
````

### db_load_error

Emitted when the wallet database could not be loaded.

````javascript
wallet.on('db_load_error', (error) => console.log(`error loading database: ${progress}%`));
````

### db_open

Emitted when the wallet database has been opened.

````javascript
wallet.on('db_open', () => console.log(`database is now open`));
````

### db_closed

Emitted when the wallet database has been closed.

````javascript
wallet.on('db_closed', () => console.log(`database is now closed`));
````
