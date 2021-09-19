const Db = require('nedb-async').AsyncNedb;
const crypto = require('crypto');
const Mnemonic = require('bitcore-mnemonic');
const electrumMnemonic = require('electrum-mnemonic');
const bitcore = require('bitcore-lib');
const blsct = bitcore.Transaction.Blsct;
const algorithm = 'aes-256-cbc';
const EventEmitter = require('events');
const ripemd160 = bitcore.crypto.Hash.ripemd160;
const sha256 = bitcore.crypto.Hash.sha256;
const electrum = require('electrum-client-js')
const assert = require('assert');
const _ = require("lodash");
const Message = require("bitcore-message")
const nodes = require('./nodes')
const queue = require('./utils/queue')

function msleep(n) {
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, n);
}
function sleep(n) {
    msleep(n*1000);
}

class WalletFile extends EventEmitter {
    constructor(options)
    {
        super();

        options = options || {};

        this.storage = options.file || '';
        this.type = options.type || 'navcoin-js-v1';
        this.mnemonic = options.mnemonic;
        this.spendingPassword = options.spendingPassword;
        this.zapwallettxes = options.zapwallettxes || false;
        this.log = options.log || false;
        this.queue = new queue();

        let self = this;

        this.queue.on('progress', (progress, pending, total) => {
            self.emit('sync_status', progress, pending, total);
        })

        this.queue.on('end', () => {
            self.emit('sync_finished')
        })

        this.network = options.network || 'mainnet';

        this.electrumNodes = nodes[this.network];

        if (!this.electrumNodes.length) {
            throw new Error('Wrong network')
        }

        this.electrumNodeIndex = 0;

        let secret = options.password || 'secret navcoinjs';
        let key = crypto.createHash('sha256').update(String(secret)).digest('base64').substr(0, 32)

        let dbOptions = {
            afterSerialization(plaintext) {
                const iv = crypto.randomBytes(16)
                const aes = crypto.createCipheriv(algorithm, key, iv)
                let ciphertext = aes.update(plaintext)
                ciphertext = Buffer.concat([iv, ciphertext, aes.final()])
                return ciphertext.toString('base64')
            },
            beforeDeserialization(ciphertext) {
                const ciphertextBytes = Buffer.from(ciphertext, 'base64')
                const iv = ciphertextBytes.slice(0, 16)
                const data = ciphertextBytes.slice(16)
                const aes = crypto.createDecipheriv(algorithm, key, iv)
                let plaintextBytes = Buffer.from(aes.update(data))
                plaintextBytes = Buffer.concat([plaintextBytes, aes.final()])
                return plaintextBytes.toString()
            }
        }

        dbOptions.filename = this.storage;

        this.db = new Db(dbOptions);

        this.db.asyncEnsureIndex({ fieldName: 'outPoint', unique: true, sparse: true })
        this.db.asyncEnsureIndex({ fieldName: 'creationTip', unique: true, sparse: true })
        this.db.asyncEnsureIndex({ fieldName: 'network', unique: true, sparse: true })
        this.db.asyncEnsureIndex({ fieldName: 'walletType', unique: true, sparse: true })

        this.db.loadDatabase(e => {
            if (e)
                this.emit('db_load_error', e);
            else
                this.emit('db_open')
        })

        this.db.on('compaction.done', () => {
            this.emit('db_closed')
        })
    }

    static CloseDb() {
        this.db.persistence.compactDataFile();
    }

    static async ListWallets() {
        var localforage = require('localforage')

        localforage.config({
            name: 'NeDB'
            , storeName: 'nedbdata'
        });

        return await localforage.keys();
    }

    static async RemoveWallet(filename) {
        var localforage = require('localforage')

        await localforage.removeItem(filename);
    }

    async xNavGetPoolSize() {
        return await this.db.asyncCount({xnavAddress: true, used: false})
    }

    async NavGetPoolSize() {
        return await this.db.asyncCount({navAddress: true, used: false})
    }

    async Log(str) {
        if (!this.log) return
        console.log(` [navcoin-js] ${str}`)
    }

    async Load(options) {
        options = options || {};

        if (!((await this.db.asyncFind({key: 'masterPubKey'})).length))
        {
            await this.db.asyncUpdate({walletType: {$exists: true}}, {walletType: this.type}, {upsert: true})
            let mnemonic = this.mnemonic;

            if (!this.mnemonic)
            {
                this.newWallet = true;
                mnemonic = new Mnemonic().toString();
                this.emit('new_mnemonic', mnemonic);
            }

            if (this.type == 'next')
            {
                var value=Buffer.from(new Mnemonic(mnemonic).toString());
                var hash=bitcore.crypto.Hash.sha256(value);
                var bn=bitcore.crypto.BN.fromBuffer(hash);
                let pk=new bitcore.PrivateKey(bn);

                await this.ImportPrivateKey(pk, this.spendingPassword)

                let masterKey = new Mnemonic(mnemonic).toHDPrivateKey();

                await this.SetMasterKey(masterKey, this.spendingPassword)
            }
            else if (this.type == 'navcoin-core')
            {
                let keyMaterial = Mnemonic.mnemonicToData(mnemonic)

                await this.SetMasterKey(keyMaterial, this.spendingPassword)
            }
            else if (this.type == 'navcash')
            {
                this.AddStakingAddress("NfLgDYL4C3KKXDS8tLRAFM7spvLykV8v9A", false)

                let masterKey = bitcore.HDPrivateKey.fromSeed(await electrumMnemonic.mnemonicToSeed(mnemonic, {prefix: electrumMnemonic.PREFIXES.standard}))

                await this.SetMasterKey(masterKey, this.spendingPassword)
            }
            else
            {
                let masterKey = new Mnemonic(mnemonic).toHDPrivateKey();

                await this.SetMasterKey(masterKey, this.spendingPassword)
            }

            if (options.bootstrap)
            {
                await this.db.asyncInsert(options.bootstrap[this.network] ? options.bootstrap[this.network] : options.bootstrap)
            }
        }

        let wallet_type = (await this.db.asyncFind({walletType: {$exists: true}}))
        this.type = wallet_type.length ? wallet_type[0].walletType : 'navcoin-js-v1'

        let network = (await this.db.asyncFind({network: {$exists: true}}))

        if (!network.length)
        {
            await this.db.asyncInsert({network: this.network})
        }
        else
        {
            this.network = network[0].network;
        }


        this.mvk = await this.GetMasterViewKey();

        this.synced = {};
        this.firstSync = false;
        this.creationTip = undefined;

        let creationTipDb = (await this.db.asyncFind({creationTip: {$exists: true}}))

        if (creationTipDb.length) {
            this.creationTip = creationTipDb[0].creationTip;
        }

        if (this.GetMasterKey(this.spendingPassword))
        {
            await this.xNavFillKeyPool(this.spendingPassword);
            await this.NavFillKeyPool(this.spendingPassword);
        }

        this.poolFilled = true;

        this.mnemonic = '';
        this.spendingPassword = '';

        if (this.zapwallettxes)
        {
            await this.db.asyncRemove({ scriptHashHistory: {$exists: true} }, { multi: true });
            await this.db.asyncRemove({ outPoint: {$exists: true} }, { multi: true });
            await this.db.asyncRemove({ txid: {$exists: true} }, { multi: true });
            await this.db.asyncRemove({ wallettxid: {$exists: true} }, { multi: true });
        }

        this.emit('loaded')
    }

    async xNavFillKeyPool (spendingPassword) {
        let mk = await this.GetMasterKey(spendingPassword);

        if (!mk)
            return;

        while (await this.xNavGetPoolSize() < 10)
        {
            await this.xNavCreateSubaddress(spendingPassword);
        }
    }

    async NavFillKeyPool (spendingPassword) {
        if (this.type == 'next')
            return;

        let mk = await this.GetMasterKey(spendingPassword);

        if (!mk)
            return;

        while (await this.NavGetPoolSize() < 10)
        {
            await this.NavCreateAddress(spendingPassword);
        }
    }

    async xNavReceivingAddresses (all=true) {
        let list = all ? await this.db.asyncFind({xnavAddress: true}, [['sort', { index: 1 }]]) : await this.db.asyncFind({xnavAddress: true, used: false}, [['sort', { index: 1 }]]);

        return list;
    }

    async NavReceivingAddresses (all=true) {
        let list = all ? await this.db.asyncFind({navAddress: true}, [['sort', { index: 1 }]]) : await this.db.asyncFind({navAddress: true, used: false}, [['sort', { index: 1 }]]);

        return list;
    }

    async NavGetPrivateKeys (spendingPassword, address) {
        let list = address ? await this.db.asyncFind({navAddress: true, address: address}) : await this.db.asyncFind({navAddress: true});

        for (var i in list) {
            list[i].privateKey = (await this.GetPrivateKey(list[i].key, spendingPassword)).toWIF()
            delete list[i].value
        }

        return list;
    }

    async GetMasterKey(key) {
        if (!this.db)
            return undefined;

        key = key || 'masterkey navcoinjs';
        key = crypto.createHash('sha256').update(String(key)).digest('base64').substr(0, 32)

        let masterKey = await this.db.asyncFind({key: 'masterKey'})
        let masterPubKey = await this.db.asyncFind({key: 'masterPubKey'})

        if (masterKey.length == 0)
            return undefined;

        let ret = masterKey[0].value;

        if (key)
        {
            const ciphertextBytes = Buffer.from(ret, 'base64')
            const iv = ciphertextBytes.slice(0, 16)
            const data = ciphertextBytes.slice(16)
            const aes = crypto.createDecipheriv(algorithm, key, iv)
            let plaintextBytes = Buffer.from(aes.update(data))
            plaintextBytes = Buffer.concat([plaintextBytes, aes.final()])
            ret = plaintextBytes.toString()
        }

        if (bitcore.HDPrivateKey(ret).hdPublicKey.toString() != bitcore.HDPublicKey(masterPubKey[0].value).toString())
            return undefined;

        return ret;
    }

    async GetMasterSpendKey(key) {
        if (!this.db)
            return undefined;

        key = key || 'masterkey navcoinjs';
        key = crypto.createHash('sha256').update(String(key)).digest('base64').substr(0, 32)

        let masterSpendKey = await this.db.asyncFind({key: 'masterSpendKey'})
        let masterSpendPubKey = await this.db.asyncFind({key: 'masterSpendPubKey'})

        if (masterSpendKey.length == 0 || masterSpendPubKey.length == 0)
            return undefined;

        masterSpendPubKey = masterSpendPubKey[0].value;
        masterSpendKey = masterSpendKey[0].value;

        if (key)
        {
            const ciphertextBytes = Buffer.from(masterSpendKey, 'base64')
            const iv = ciphertextBytes.slice(0, 16)
            const data = ciphertextBytes.slice(16)
            const aes = crypto.createDecipheriv(algorithm, key, iv)
            let plaintextBytes = Buffer.from(aes.update(data))
            plaintextBytes = Buffer.concat([plaintextBytes, aes.final()])
            masterSpendKey = plaintextBytes.toString()
        }

        if (!blsct.mcl.deserializeHexStrToG1(masterSpendPubKey).isEqual(blsct.mcl.mul(blsct.G(), blsct.mcl.deserializeHexStrToFr(masterSpendKey))))
            return undefined;

        return blsct.mcl.deserializeHexStrToFr(masterSpendKey);
    }

    async GetMasterViewKey() {
        if (!this.db)
            return undefined;

        let masterViewKey = await this.db.asyncFind({key: 'masterViewKey'})

        if (masterViewKey.length == 0)
            return undefined;

        masterViewKey = masterViewKey[0].value;

        return blsct.mcl.deserializeHexStrToFr(masterViewKey);
    }

    Encrypt(plain, key) {
        const iv = crypto.randomBytes(16)
        const aes = crypto.createCipheriv(algorithm, key, iv)
        let ciphertext = aes.update(plain)
        ciphertext = Buffer.concat([iv, ciphertext, aes.final()])
        return ciphertext.toString('base64')
    }

    async xNavCreateSubaddress(sk, acct=0) {
        let masterViewKey = this.mvk;

        let masterSpendKey = await this.GetMasterSpendKey(sk);

        if (!masterSpendKey)
            return;

        let index = 0;

        let dbLastIndex = await this.db.asyncFind({key: 'xNavLastIndex'});

        index = dbLastIndex.length ? dbLastIndex[0].value : index;

        let {viewKey, spendKey} = blsct.DerivePublicKeys(masterViewKey, masterSpendKey, acct, index);

        let hashId = new Buffer(ripemd160(sha256(spendKey.serialize()))).toString('hex')

        await this.db.asyncUpdate({key: 'xNavLastIndex'}, {key: 'xNavLastIndex', value: index+1}, {upsert: true});
        await this.db.asyncUpdate({key: hashId}, {key: hashId, value: [acct, index], xnavAddress: true, address: blsct.KeysToAddress(viewKey, spendKey).toString(), used: false, index: index}, {upsert: true});
    }

    async NavCreateAddress(sk, change=false) {
        if (this.type == 'next')
            return;

        let mk = await this.GetMasterKey(sk);

        if (!mk)
            return;

        let key = sk || 'masterkey navcoinjs';
        key = crypto.createHash('sha256').update(String(key)).digest('base64').substr(0, 32)

        let index = 0;

        let dbLastIndex = await this.db.asyncFind({key: (change?'NavChangeLastIndex':'NavLastIndex')});

        index = dbLastIndex.length ? dbLastIndex[0].value : index;

        let path = 'm/44\'/130\'/0\'/'+(change?'1':'0')+'/'+index;
        let privK;

        if (this.type == 'next')
        {
            if (index == 0 && !change)
            {
                index++;
            }

            path = 'm/'+(change?1:0)+'/'+index;
            privK = bitcore.HDPrivateKey(mk).deriveChild(path)
        }
        else if (this.type == 'navcash')
        {
            path = 'm/'+(change?1:0)+'/'+index;
            privK = bitcore.HDPrivateKey(mk).deriveChild(path)
        }
        else if (this.type == 'navcoin-js-v1')
        {
            privK = bitcore.HDPrivateKey(mk).deriveChild(path)
        }
        else if (this.type == 'navpay')
        {
            path = 'm/44\'/0\'/0\'/'+(change?'1':'0')+'/'+index;
            privK = bitcore.HDPrivateKey(mk).deriveChild(path)
        }
        else if (this.type == 'navcoin-core')
        {
            path = 'm/0\'/'+(change?1:0)+'\'/'+index+'\'';
            privK = bitcore.HDPrivateKey(mk).deriveChild(path)
        }

        let pk = privK.publicKey;
        let hashId = new Buffer(ripemd160(sha256(pk.toBuffer()))).toString('hex')
        let pkStr = this.Encrypt(privK.toString(), key);
        let addrStr = bitcore.Address(pk, this.network).toString()

        await this.db.asyncUpdate({key: (change?'NavChangeLastIndex':'NavLastIndex')}, {key: (change?'NavChangeLastIndex':'NavLastIndex'), value: index+1}, {upsert: true});
        await this.db.asyncUpdate({key: hashId}, {key: hashId, value: pkStr, navAddress: true, path: path, address: addrStr, used: false, change: change, index: index}, {upsert: true});

        if (this.poolFilled)
        {
            await this.SyncScriptHash(this.AddressToScriptHash(addrStr))
        }
    }

    async ImportPrivateKey(privK, key)
    {
        if (_.isString(privK))
        {
            return this.ImportPrivateKey(bitcore.PrivateKey.fromWIF(privK), key);
        }

        key = key || 'masterkey navcoinjs';
        key = crypto.createHash('sha256').update(String(key)).digest('base64').substr(0, 32)

        let path = 'imported'
        let pk = privK.publicKey;
        let hashId = new Buffer(ripemd160(sha256(pk.toBuffer()))).toString('hex')
        let pkStr = this.Encrypt(privK.toString(), key);

        await this.db.asyncUpdate({key: hashId}, {key: hashId, value: pkStr, navAddress: true, path: path, address: bitcore.Address(pk, this.network).toString(), used: false, change: false}, {upsert: true});

        if (this.connected)
        {
            await this.Sync()
        }
    }

    async SetTip(height) {
        this.lastBlock = height;
        await this.db.asyncUpdate({key: 'ChainTip'}, {key: 'ChainTip', value: height}, {upsert: true});
    }

    async GetTip() {
        let ret = -1

        let dbFind = await this.db.asyncFind({key: 'ChainTip'});

        if (dbFind.length) ret = dbFind[0].value;

        return ret;
    }

    AddressToScriptHash(address) {
        return this.ScriptToScriptHash(bitcore.Script.fromAddress(address))
    }

    ScriptToScriptHash(script) {
        return Buffer.from(bitcore.crypto.Hash.sha256(script.toBuffer()).reverse()).toString("hex")
    }

    async GetScriptHashes(stakingAddress = undefined) {
        let ret = [];

        let addresses = await this.db.asyncFind({navAddress: true});

        for (var i in addresses)
        {
            if (!stakingAddress)
            {
                ret.push(this.AddressToScriptHash(addresses[i].address))
            }
            else
            {
                ret.push(this.ScriptToScriptHash(new bitcore.Script.fromAddresses(stakingAddress, bitcore.Address(addresses[i].address))))
            }
        }

        if (!stakingAddress)
            ret.push(Buffer.from(bitcore.crypto.Hash.sha256(bitcore.Script.fromHex("51").toBuffer()).reverse()).toString("hex"))

        return ret;
    }

    async GetStakingAddresses() {
        let ret = [];

        let addresses = await this.db.asyncFind({stakingAddress: {$exists: true}});

        for (var i in addresses)
        {
            ret.push(addresses[i].stakingAddress)
        }

        return ret;
    }

    async GetStatusHashForScriptHash(s) {
        let status = await this.db.asyncFind({scripthash: s})

        if (!status.length)
            return undefined;

        return status[0].statushash;
    }

    async SetMasterKey(masterkey, key) {
        if (!this.db)
            return false;

        key = key || 'masterkey navcoinjs';
        key = crypto.createHash('sha256').update(String(key)).digest('base64').substr(0, 32)

        if (await this.GetMasterKey(key))
            return false;

        let masterKey = ((this.type == 'navcoin-core') ? bitcore.HDPrivateKey.fromSeed(masterkey) : masterkey).toString();
        let masterPubKey = bitcore.HDPrivateKey(masterKey).hdPublicKey.toString();

        let {masterViewKey, masterSpendKey} = blsct.DeriveMasterKeys(this.type == 'navcoin-core' ? bitcore.PrivateKey(masterkey) : bitcore.HDPrivateKey(masterKey));
        let masterSpendPubKey = blsct.mcl.mul(blsct.G(), masterSpendKey);
        let masterViewPubKey = blsct.mcl.mul(blsct.G(), masterViewKey);

        if (key)
        {
            masterKey = this.Encrypt(masterKey, key);
            masterSpendKey = this.Encrypt(masterSpendKey.serializeToHexStr(), key);
        }
        else
        {
            masterSpendKey = masterSpendKey.serializeToHexStr();
        }

        await this.db.asyncUpdate({key: 'masterKey'}, {key: 'masterKey', value: masterKey}, {upsert: true});
        await this.db.asyncUpdate({key: 'masterSpendKey'}, {key: 'masterSpendKey', value: masterSpendKey}, {upsert: true});
        await this.db.asyncUpdate({key: 'masterViewKey'}, {key: 'masterViewKey', value: masterViewKey.serializeToHexStr()}, {upsert: true});
        await this.db.asyncUpdate({key: 'masterSpendPubKey'}, {key: 'masterSpendPubKey', value: masterSpendPubKey.serializeToHexStr()}, {upsert: true});
        await this.db.asyncUpdate({key: 'masterViewPubKey'}, {key: 'masterViewPubKey', value: masterViewPubKey.serializeToHexStr()}, {upsert: true});
        await this.db.asyncUpdate({key: 'masterPubKey'}, {key: 'masterPubKey', value: masterPubKey}, {upsert: true});

        this.Log('master keys written')

        return true;
    }

    async Connect(options)
    {
        options = options || {};


        this.client = new electrum(this.electrumNodes[this.electrumNodeIndex].host,
            this.electrumNodes[this.electrumNodeIndex].port,
            this.electrumNodes[this.electrumNodeIndex].proto)

        this.Log(`Trying to connect to ${this.electrumNodes[this.electrumNodeIndex].host}:${this.electrumNodes[this.electrumNodeIndex].port}`)

        try {
            await this.client.connect('navcoin-js', '1.5');
            this.connected = true;

            let tip = (await this.client.blockchain_headers_subscribe()).height
            await this.SetTip(tip);

            if (this.newWallet && !this.creationTip) {
                this.creationTip = tip;
                try {
                    await this.db.asyncInsert({creationTip: tip})
                } catch (e) {}
            }

            this.client.subscribe.on('blockchain.headers.subscribe', async (event) => {
                await self.SetTip(event[0].height)
            });
        }
        catch(e)
        {
            this.connected = false;
            this.emit('connection_failed')
            console.error(`error connecting to electrum ${this.electrumNodes[this.electrumNodeIndex].host}:${this.electrumNodes[this.electrumNodeIndex].port}: ${e}`)
            return await this.ManageElectrumError(e)
        }

        this.emit('connected', this.electrumNodes[this.electrumNodeIndex].host+':'+this.electrumNodes[this.electrumNodeIndex].port)

        let self = this

        await this.Sync();

        try {
            this.client.subscribe.on('blockchain.scripthash.subscribe', async (event) => {
                await self.ReceivedScriptHashStatus(event[0], event[1])
            });
        }
        catch(e)
        {
            console.error(`error electrum: ${e}`)
            await this.ManageElectrumError(e)
            return false
        }
    }

    async QueueTx(hash, inMine, height, requestInputs, priority) {
        this.queue.add(this, this.GetTx, [hash, inMine, height, requestInputs], priority)
    }

    async QueueTxKeys(hash, height, useCache, priority) {
        this.queue.add(this, this.GetTxKeys, [hash, height, useCache], priority)
    }

    async Sync(staking = undefined)
    {
        let scriptHashes = await this.GetScriptHashes(staking)

        if (!staking) {
            let pending = await this.db.asyncFind({fetched: false})

            for (var i in pending) {
                await this.QueueTxKeys(pending[i].tx_hash, pending[i].height, true)
            }
        }

        for (var i in scriptHashes) {
            let s = scriptHashes[i];

            try
            {
                this.synced[s] = false;
                let currentStatus = await this.client.blockchain_scripthash_subscribe(s)
                await this.ReceivedScriptHashStatus(s, currentStatus)
            }
            catch(e) {
                console.log(e)
                await this.ManageElectrumError(e)
                return await this.Sync(staking)
            }
        }

        if (!staking)
        {
            let stakingAddresses = await this.GetStakingAddresses();

            for (var i in stakingAddresses)
            {
                let address = stakingAddresses[i]
                await this.Sync(address)
            }
        }
    }

    async ManageElectrumError(e)
    {
        if (e == 'Error: close connect' || e == 'Error: connection not established' ||
            e == 'Error: failed to connect to electrum server: [Error: websocket connection closed: code: [1006], reason: [connection failed]]')
        {
            this.connected = false;
            this.electrumNodeIndex = (this.electrumNodeIndex+1) % (this.electrumNodes.length)
            this.emit('connection_failed')
            this.client.close()
            sleep(1)
            this.Log(`Reconnecting to electrum node ${this.electrumNodeIndex}`)
            await this.Connect()
        }

        if (e == 'server busy - request timed out') {
            sleep(5)
        }
    }

    Disconnect()
    {
        this.client.close()
        this.connected = false;

        delete this.client;
    }

    async ReceivedScriptHashStatus(s, status)
    {
        let prevStatus = this.GetStatusHashForScriptHash(s);

        if (status && status != prevStatus)
        {
            await this.db.asyncUpdate({scripthash: s}, {scripthash: s, statushash: status}, {upsert: true})

            this.queue.add(this, this.SyncScriptHash, [s], true, !this.firstSync)
        }
    }

    async SyncScriptHash(scripthash)
    {
        var currentHistory = [];
        let prevMaxHeight = [];
        let lb = this.lastBlock + 0;

        let historyRange = {}
        let xnav = scripthash == "6032c38c0bc0e91e726f1e55e1832e434509001a7aed5cfd881b6ef07215e84a"

        while (true) {
            try {
                currentHistory = await this.db.asyncFind({scriptHashHistory: scripthash});
            } catch(e) {
                this.Log(`error getting history from db: ${e}`)
            }

            var currentLastHeight = this.creationTip ? this.creationTip : 0;

            for (var i in currentHistory)
            {
                if (currentHistory[i].height > currentLastHeight) currentLastHeight = currentHistory[i].height;
            }

            let filteredHistory = currentHistory.filter((e) => e.height >= 0 && e.height < Math.max(1, currentLastHeight-10));
            historyRange = currentHistory.filter(x => !filteredHistory.includes(x)).reduce(function(map, obj) {
                map[obj.tx_hash] = obj;
                return map;
            }, {});
            currentHistory = filteredHistory;

            try {
                await this.db.asyncRemove({ height: { $lte: 0 }, scriptHashHistory: scripthash }, { multi: true });
                await this.db.asyncRemove({ height: { $gte: Math.max(1, currentLastHeight-10) }, scriptHashHistory: scripthash }, { multi: true });
            } catch(e) {
                this.Log(`error removing from db: ${e}`)
            }

            var newHistory = [];

            try
            {
                this.Log(`requesting tx history for ${scripthash} from ${currentLastHeight-10}`)
                newHistory = await this.client.blockchain_scripthash_getHistory(scripthash, Math.max(0, currentLastHeight-10));
                this.Log(`${scripthash}: received ${newHistory.history.length} transactions`)
            }
            catch(e)
            {
                this.Log(`error getting history: ${e}`)
                await this.ManageElectrumError(e)
                return false
            }

            if (!newHistory.history.length || newHistory.history.length == 0) break;

            let maxHeight;

            for (var i in newHistory.history) {
                if (newHistory.history[i].height > maxHeight)
                    maxHeight = newHistory.history[i].height;
            }

            if (maxHeight == prevMaxHeight)
                break;

            prevMaxHeight = maxHeight;

            currentLastHeight = 0;
            let reachedMempool = false;

            for (var j in newHistory.history) {
                if (newHistory.history[j].height > currentLastHeight) currentLastHeight = newHistory.history[j].height;

                if (newHistory.history[j].height <= 0) reachedMempool = true;

                currentHistory.push(newHistory.history[j]);

                try {
                    await this.db.asyncUpdate({scriptHashHistory: scripthash, tx_hash: newHistory.history[j].tx_hash}, {scriptHashHistory: scripthash, tx_hash: newHistory.history[j].tx_hash, height: newHistory.history[j].height, fetched: false}, {upsert: true});
                } catch(e) { }

                let hash = newHistory.history[j].tx_hash;
                let height = newHistory.history[j].height;

                await this.QueueTxKeys(hash, height, true)

                if (j % 100 == 0)
                    this.queue.emitProgress();
            }

            this.queue.emitProgress();

            if (reachedMempool || (currentLastHeight >= lb && lb > 0)) break;
        }

        /*for (var e in historyRange)
        {
            await this.db.asyncRemove({wallettxid: historyRange[e].tx_hash}, { multi: true })
            await this.db.asyncRemove({outPoint: {$regex: new RegExp(`^${historyRange[e].tx_hash}:`)}}, { multi: true })

            let tx = await this.GetTx(historyRange[e].tx_hash)

            for (var i in tx.tx.inputs)
            {
                let input = tx.tx.inputs[i].toObject();

                await this.Spend(`${input.prevTxId}:${input.outputIndex}`, '')

                await this.db.asyncRemove({outPoint: `${input.prevTxId}:${input.outputIndex}`}, { multi: true })
            }

            this.emit('remove_tx', historyRange[e].tx_hash);
        }*/

        this.synced[scripthash] = true;

        for (var i in this.synced)
        {
            this.firstSync &= this.synced[i]
        }
    }

    Sign(key, msg) {
        if (_.isString(key))
        {
            return this.Sign(bitcore.PrivateKey.fromWIF(key), msg);
        }
        return Message(msg).sign(key);
    }

    VerifySignature(address, msg, sig) {
        return Message(msg).verify(address, sig);
    }

    async GetHistory()
    {
        let list_unconfirmed = (await this.db.asyncFind({wallettxid: {$exists: true}, height: {$lte: 0}}, [['sort', { height: 1, pos: 1 }]]))
        let list_confirmed = (await this.db.asyncFind({wallettxid: {$exists: true}, height: {$gt: 0}}, [['sort', { height: -1, pos: -1 }]]))

        return list_unconfirmed.concat(list_confirmed);
    }

    async GetUtxos(xnav = false, onlyCold = false)
    {
        let utxos = (await this.db.asyncFind({outPoint: {$exists: true}, spentIn: ''}))

        let tip = await this.GetTip()
        let ret = []

        for (var u in utxos) {
            let utxo = utxos[u];

            if (utxo.xnav && !xnav)
                continue;

            if (!utxo.xnav && xnav)
                continue;

            if (!utxo.cold && onlyCold)
                continue;

            let outpoint = utxo.outPoint.split(':')

            let tx = await this.db.asyncFind({txid: outpoint[0]})

            if (!tx.length)
                continue;

            tx = tx[0]

            let pending = false;

            if ((tx.pos < 2 && (tip - tx.height) < 120) || tx.height <= 0)
                pending = true;

            if (!pending)
            {
                let out = bitcore.Transaction.Output.fromBufferReader(new bitcore.encoding.BufferReader(new Buffer(utxo.out, 'hex')))
                let item = {txid: outpoint[0], vout: outpoint[1], output: out}

                if (xnav)
                {
                    let hashid = new Buffer(blsct.GetHashId(out, this.mvk)).toString('hex')
                    let value = (await this.db.asyncFind({key: hashid}))[0]

                    if (value)
                    {
                        item.accIndex = value.value;
                    }
                }

                ret.push(item)
            }
        }

        return ret;
    }

    async GetBalance()
    {
        let utxos = (await this.db.asyncFind({outPoint: {$exists: true}, spentIn: ''}))

        let navConfirmed = bitcore.crypto.BN.Zero;
        let xNavConfirmed = bitcore.crypto.BN.Zero;
        let coldConfirmed = bitcore.crypto.BN.Zero;
        let navPending = bitcore.crypto.BN.Zero;
        let xNavPending = bitcore.crypto.BN.Zero;
        let coldPending = bitcore.crypto.BN.Zero;

        let tip = await this.GetTip()

        for (var u in utxos)
        {
            let utxo = utxos[u];

            let tx = await this.db.asyncFind({txid: utxo.outPoint.split(':')[0]})

            if (!tx.length)
                continue;

            tx = tx[0]

            let pending = false;

            if ((tx.pos < 2 && (tip-tx.height) < 120) || tx.height <= 0)
                pending = true;

            if (utxo.xnav)
            {
                if (pending)
                    xNavPending = xNavPending.add(new bitcore.crypto.BN(utxo.amount));
                else
                    xNavConfirmed = xNavConfirmed.add(new bitcore.crypto.BN(utxo.amount));
            }
            else
            {
                if (utxo.cold)
                {
                    if (pending)
                        coldPending = coldPending.add(new bitcore.crypto.BN(utxo.amount));
                    else
                        coldConfirmed = coldConfirmed.add(new bitcore.crypto.BN(utxo.amount));
                }
                else
                {
                    if (pending)
                        navPending = navPending.add(new bitcore.crypto.BN(utxo.amount));
                    else
                        navConfirmed = navConfirmed.add(new bitcore.crypto.BN(utxo.amount));
                }
            }
        }

        return {nav: {confirmed: navConfirmed.toNumber(), pending: navPending.toNumber()}, xnav: {confirmed: xNavConfirmed.toNumber(), pending: xNavPending.toNumber()}, staked: {confirmed: coldConfirmed.toNumber(), pending: coldPending.toNumber()}}
    }

    async AddOutput(outpoint, out)
    {
        let amount = out.isCt() ? out.amount : out.satoshis;
        let label = out.isCt() ? out.memo : out.script.toAddress(this.network);
        let isCold = out.script.isColdStakingOutP2PKH() || out.script.isColdStakingV2Out()

        try {
            await this.db.asyncInsert({outPoint: outpoint, out: out.toBufferWriter().toBuffer().toString('hex'), spentIn: '', amount: amount, label: label, xnav: out.isCt(), cold: isCold})

            if (!out.isCt()) {
                await this.db.asyncUpdate({navAddress: true, address: out.script.toAddress(this.network)}, {$set: {used: true}})
            } else {
                let hashid = new Buffer(blsct.GetHashId(out, this.mvk)).toString('hex')
                await this.db.asyncUpdate({xnavAddress: true, key: hashid}, {$set: {used: true}})
            }

            return true;
        } catch(e) {
            return false;
        }
    }

    async Spend(outpoint, spentin)
    {
        let prev = await this.db.asyncFind({outPoint: outpoint})
        if (prev.length && prev.spentIn && spentin) {
            return false;
        }
        await this.db.asyncUpdate({outPoint: outpoint}, {$set: {spentIn: spentin}})
        return true;
    }

    async GetTx (hash, inMine, height, requestInputs = true)
    {
        let tx;
        let prevHeight;

        var cacheTx = (await this.db.asyncFind({txid: hash}))[0]

        if (cacheTx) {
            cacheTx.tx = bitcore.Transaction(cacheTx.hex)
            tx = cacheTx;
            prevHeight = tx.height;
        }

        if (!tx) {
            var tx_
            try {
                tx_ = await this.client.blockchain_transaction_get(hash, false);
            } catch (e) {
                this.Log(`error getting tx ${hash}: ${e}`)
                await this.ManageElectrumError(e)
                sleep(1)
                return await this.GetTx(hash, inMine)
            }

            tx = {txid: hash, hex: tx_}

            try {
                await this.db.asyncUpdate({txid: hash}, tx, {upsert: true});
            } catch (e) {
            }

            tx.tx = bitcore.Transaction(tx.hex)
        }

        if (!tx.height || tx.height <= 0 || (height && height != tx.height)) {
            let height = await this.client.blockchain_transaction_getMerkle(hash);
            tx.height = height.block_height;
            tx.pos = height.pos;
        }

        let mustNotify = false;

        if (tx.height != prevHeight) {
            try {
                await this.db.asyncUpdate({txid: hash}, tx, {upsert: true});
            } catch (e) {
            }

            mustNotify = true;
        }

        let mine = false;
        let memos = {in: [], out: []}

        let historyEntry = await this.db.asyncFindOne({scriptHashHistory: {$exists: true}, tx_hash: hash})

        let deltaNav = 0;
        let deltaXNav = 0;
        let deltaCold = 0;

        if (requestInputs) {
            for (var i in tx.tx.inputs) {
                if (typeof inMine !== 'undefined' && !inMine[i]) continue;

                let input = tx.tx.inputs[i].toObject();

                if (input.prevTxId == "0000000000000000000000000000000000000000000000000000000000000000")
                    continue;

                let prevTx = (await this.GetTx(input.prevTxId, undefined, undefined, false)).tx
                let prevOut = prevTx.outputs[input.outputIndex];

                if (prevOut.isCt()) {
                    let hid = blsct.GetHashId(prevOut, this.mvk);
                    if (hid) {
                        let hashId = new Buffer(hid).toString('hex')
                        if ((await this.db.asyncFind({key: hashId})).length) {
                            if (blsct.RecoverBLSCTOutput(prevOut, this.mvk)) {

                                mine = true;
                                let newOutput = await this.AddOutput(`${input.prevTxId}:${input.outputIndex}`, prevOut, prevTx.height)
                                let newSpend = await this.Spend(`${input.prevTxId}:${input.outputIndex}`, `${tx.txid}:${i}`)
                                if (newSpend || newOutput) mustNotify = true;
                                deltaXNav -= prevOut.amount;
                                memos.in.push(prevOut.memo);
                            }
                        }
                    }
                } else if (prevOut.script.isPublicKeyHashOut() || prevOut.script.isPublicKeyOut()) {
                    let hashId = new Buffer(prevOut.script.isPublicKeyOut() ?
                        ripemd160(sha256(prevOut.script.getPublicKey())) :
                        prevOut.script.getPublicKeyHash()).toString('hex')

                    if ((await this.db.asyncFind({key: hashId})).length) {
                        mine = true;
                        let newOutput = await this.AddOutput(`${input.prevTxId}:${input.outputIndex}`, prevOut, prevTx.height)
                        let newSpend = await this.Spend(`${input.prevTxId}:${input.outputIndex}`, `${tx.txid}:${i}`)
                        if (newSpend || newOutput) mustNotify = true;
                        deltaNav -= prevOut.satoshis;
                    }
                }
                else if (prevOut.script.isColdStakingOutP2PKH() || prevOut.script.isColdStakingV2Out())
                {
                    let hashId = new Buffer(prevOut.script.getPublicKeyHash()).toString('hex')

                    if ((await this.db.asyncFind({key: hashId})).length)
                    {
                        mine = true;
                        let newOutput = await this.AddOutput(`${input.prevTxId}:${input.outputIndex}`, prevOut, prevTx.height)
                        let newSpend = await this.Spend(`${input.prevTxId}:${input.outputIndex}`, `${tx.txid}:${i}`)
                        if (newSpend || newOutput) mustNotify = true;
                        deltaCold -= prevOut.satoshis;
                    }
                }
            }

            for (var i in tx.tx.outputs)
            {
                let out = tx.tx.outputs[i];

                if (out.isCt())
                {
                    let hid = blsct.GetHashId(out, this.mvk);
                    if (hid) {
                        let hashId = new Buffer(hid).toString('hex')
                        if ((await this.db.asyncFind({key: hashId})).length) {
                            if (blsct.RecoverBLSCTOutput(out, this.mvk)) {
                                mine = true;
                                let newOutput = await this.AddOutput(`${tx.txid}:${i}`, out, tx.height)
                                if (newOutput) mustNotify = true;
                                deltaXNav += out.amount;
                                memos.out.push(out.memo);
                            }
                        }
                    }
                }
                else if (out.script.isPublicKeyHashOut() || out.script.isPublicKeyOut())
                {
                    let hashId = new Buffer(out.script.isPublicKeyOut() ?
                        ripemd160(sha256(out.script.getPublicKey())) :
                        out.script.getPublicKeyHash()).toString('hex')
                    if ((await this.db.asyncFind({key: hashId})).length)
                    {
                        mine = true;
                        let newOutput = await this.AddOutput(`${tx.txid}:${i}`, out, tx.height)
                        if (newOutput) mustNotify = true;
                        deltaNav += out.satoshis;
                    }
                } else if (out.script.isColdStakingOutP2PKH() || out.script.isColdStakingV2Out())
                {
                    let hashId = new Buffer(out.script.getPublicKeyHash()).toString('hex')

                    if ((await this.db.asyncFind({key: hashId})).length)
                    {
                        mine = true;
                        let newOutput = await this.AddOutput(`${tx.txid}:${i}`, out, tx.height)
                        if (newOutput) mustNotify = true;
                        deltaCold += out.satoshis;
                    }
                }
            }

            if (mustNotify && mine)
            {
                if (deltaXNav != 0) {
                    this.emit('new_tx', {
                        txid: tx.txid,
                        amount: deltaXNav,
                        type: 'xnav',
                        confirmed: tx.height > -0,
                        height: tx.height,
                        pos: tx.pos,
                        timestamp: tx.tx.time,
                        memos: memos
                    })
                    await this.db.asyncUpdate({wallettxid: tx.txid, type: 'xnav'},
                        {
                            wallettxid: tx.txid,
                            amount: deltaXNav,
                            type: 'xnav',
                            confirmed: tx.height > 0,
                            height: tx.height,
                            pos: tx.pos,
                            timestamp: tx.tx.time,
                            memos: memos
                        },
                        {upsert: true})
                }
                if (deltaNav != 0) {
                    this.emit('new_tx', {
                        txid: tx.txid,
                        amount: deltaNav,
                        type: 'nav',
                        confirmed: tx.height > 0,
                        height: tx.height,
                        pos: tx.pos,
                        timestamp: tx.tx.time
                    })
                    await this.db.asyncUpdate({wallettxid: tx.txid, type: 'nav'},
                        {
                            wallettxid: tx.txid,
                            amount: deltaNav,
                            type: 'nav',
                            confirmed: tx.height > 0,
                            height: tx.height,
                            pos: tx.pos,
                            timestamp: tx.tx.time
                        },
                        {upsert: true})
                }
                if (deltaCold != 0) {
                    this.emit('new_tx', {
                        txid: tx.txid,
                        amount: deltaCold,
                        type: 'cold_staking',
                        confirmed: tx.height > 0,
                        height: tx.height,
                        pos: tx.pos,
                        timestamp: tx.tx.time
                    })
                    await this.db.asyncUpdate({wallettxid: tx.txid, type: 'cold_staking'},
                        {
                            wallettxid: tx.txid,
                            amount: deltaCold,
                            type: 'cold_staking',
                            confirmed: tx.height > 0,
                            height: tx.height,
                            pos: tx.pos,
                            timestamp: tx.tx.time
                        },
                        {upsert: true})
                }
            }
        }

        await this.db.asyncUpdate({tx_hash: hash}, {$set: {fetched: true}})

        return tx;
    }

    async AddStakingAddress(pk, sync=false) {
        if (pk instanceof bitcore.Address || (typeof pk === 'string' && !bitcore.util.js.isHexa(pk)))
            return await this.AddStakingAddress(bitcore.Address(pk).toObject().hash, sync)

        if (pk instanceof Buffer)
            return await this.AddStakingAddress(pk.toString('hex'), sync)

        let strAddress = bitcore.Address(new Buffer(pk, 'hex')).toString(this.network)

        let isInDb = await this.db.asyncFind({stakingAddress: strAddress})

        if (!isInDb.length)
        {
            let obj = {
                stakingAddress: strAddress,
                hash: pk
            }

            this.Log(`New staking address: ${strAddress}`)
            await this.db.asyncInsert(obj)

            if (sync)
                await this.Sync(strAddress)
        }
    }

    async IsMine (input) {
        if (input.script)
        {
            let script = bitcore.Script(input.script)

            if (script.isPublicKeyHashOut() || script.isPublicKeyOut())
            {
                let hashId = new Buffer(script.isPublicKeyOut() ?
                    ripemd160(sha256(script.getPublicKey())) :
                    script.getPublicKeyHash()).toString('hex')

                if ((await this.db.asyncFind({key: hashId})).length)
                {
                    return true;
                }
            }
            else if (script.isColdStakingOutP2PKH() || script.isColdStakingV2Out())
            {
                let hashId = new Buffer(script.getPublicKeyHash()).toString('hex')

                if ((await this.db.asyncFind({key: hashId})).length)
                {
                    if (script.isColdStakingOutP2PKH()) {
                        let stakingPk = script.getStakingPublicKeyHash()
                        await this.AddStakingAddress(stakingPk, true)
                    } else if (script.isColdStakingV2Out()) {
                        let stakingPk = script.getStakingPublicKeyHash()
                        let votingPk = script.getVotingPublicKeyHash()
                        await this.AddStakingAddress(stakingPk, true)
                    }

                    return true;
                }
            }
        }
        else if (input.spendingKey && input.outputKey)
        {
            let hid = blsct.GetHashId({ok: input.outputKey, sk: input.spendingKey}, this.mvk);
            if (hid) {
                let hashId = new Buffer(hid).toString('hex')
                if (hashId && (await this.db.asyncFind({key: hashId})).length) {
                    return true;
                }
            }
        }

        return false;
    }

    async GetTxKeys (hash, height, useCache = true) {
        let txKeys;

        if (useCache) {
            var cacheTx = (await this.db.asyncFind({txidkeys: hash}))[0]
            if (cacheTx) {
                txKeys = cacheTx;
            }
        }

        if (!txKeys) {
            try {
                txKeys = await this.client.blockchain_transaction_getKeys(hash);
            } catch (e) {
                this.Log(`error getting tx keys ${hash}: ${e}`)
                await this.ManageElectrumError(e)
                sleep(3)
                return await this.GetTxKeys(hash, height, useCache)
            }
            txKeys.txidkeys = hash

            try {
                await this.db.asyncUpdate({txidkeys: hash}, txKeys, {upsert: true});
            } catch (e) {
            }
        }

        let inMine = [];
        let isMine = false;

        for (var i in txKeys.vin)
        {
            let input = txKeys.vin[i]

            let thisMine = await this.IsMine(input)

            if (thisMine)
            {
                //await this.GetTx(input.txid, undefined, undefined, false)
                isMine = true;
            }

            inMine.push(thisMine)
        }

        for (var i in txKeys.vout)
        {
            let output = txKeys.vout[i]

            isMine |= await this.IsMine(output);
        }

        if (isMine)
        {
            await this.QueueTx(hash, inMine, height, true)
        }
        else
        {
            await this.db.asyncUpdate({tx_hash: hash}, {$set: {fetched: true}})
        }

        txKeys.txid = hash;

        return txKeys;
    }

    async xNavCreateTransaction(dest, amount, memo, spendingPassword, subtractFee=true)
    {
        if (amount <= 0)
            throw new TypeError("Amount must be greater than 0")

        let mvk = this.mvk;
        let msk = await this.GetMasterSpendKey(spendingPassword);

        if (!(msk && mvk))
            return;

        let utx = await this.GetUtxos(true)
        let utxos = [];

        for (const out_i in utx) {
            let out = utx[out_i];

            if (!out.output.isCt())
                continue;

            utxos.push(out)
        }

        if (!utxos.length)
            throw new Error("No available xNAV outputs")

        let tx = blsct.CreateTransaction(utxos, dest, amount, memo, mvk, msk, subtractFee);

        return {tx: [tx.toString()], fee: tx.feeAmount}
    }

    async SendTransaction(txs) {
        if (_.isArray(txs)) {
            let ret = [];

            for (const i in txs) {
                var tx = txs[i];
                try
                {
                    let hash = await this.client.blockchain_transaction_broadcast(tx)
                    ret.push(hash);
                }
                catch(e)
                {
                    console.error(`error sending tx: ${e}`)
                    await this.ManageElectrumError(e)
                    return {hashes: ret, error: e};
                }
            }

            return {hashes: ret, error: undefined};
        }
        else
        {
            try
            {
                return {hashes: [await this.client.blockchain_transaction_broadcast(txs)], error: undefined};
            }
            catch(e)
            {
                console.error(`error sending tx: ${e}`)
                await this.ManageElectrumError(e)
                return {hashes: [], error: e};
            }
        }
    }

    async NavCreateTransaction(dest, amount, memo, spendingPassword, subtractFee=true, fee=100000, ret = {fee:0,tx:[]}, selectxnav = false)
    {
        if (amount <= 0)
            throw new TypeError("Amount must be greater than 0")

        if (!(dest instanceof bitcore.Address))
            return await this.NavCreateTransaction(new bitcore.Address(dest), amount, memo, spendingPassword, subtractFee, fee, ret, selectxnav);

        let msk = await this.GetMasterKey(spendingPassword);

        if (!msk)
            return;

        let utxos = await this.GetUtxos();

        let tx = bitcore.Transaction()
        let addedInputs = 0
        let privateKeys = [];
        let gammaIns = new blsct.mcl.Fr();

        for (var u in utxos)
        {
            let out = utxos[u];

            if (out.output.isCt())
                throw new TypeError("NavSend can only spend nav outputs")

            let prevtx = await this.GetTx(out.txid)

            if (prevtx.tx.version & 0x20 && !selectxnav)
                continue;

            if (!(prevtx.tx.version & 0x20) && selectxnav)
                continue;

            let utxo = bitcore.Transaction.UnspentOutput({
                "txid" : out.txid,
                "vout" : parseInt(out.vout),
                "scriptPubKey" : out.output.script,
                "satoshis" : out.output.satoshis
            })

            let hashId = new Buffer(out.output.script.isPublicKeyOut() ?
                ripemd160(sha256(out.output.script.getPublicKey())) :
                out.output.script.getPublicKeyHash()).toString('hex')

            let privK = await this.GetPrivateKey(hashId, spendingPassword)

            if (privK)
            {
                addedInputs += out.output.satoshis;

                tx.from(utxo);
                privateKeys.push(privK)
            }

            if (privK && addedInputs >= amount+(subtractFee?0:fee))
                break;
        }

        if (addedInputs < amount+(subtractFee?0:fee))
        {
            if (selectxnav)
            {
                throw new Error(`Not enough balance (required ${amount+(subtractFee?0:fee)}, selected ${addedInputs})`)
            }
            else
            {
                await this.NavCreateTransaction(dest, amount+(subtractFee?0:fee)-addedInputs, memo, spendingPassword, subtractFee, fee, ret, true)
                amount = addedInputs;
            }
        }


        if (dest.isXnav()) {
            if (amount >= (subtractFee?fee:0)) {
                let out = blsct.CreateBLSCTOutput(dest, amount - (subtractFee ? fee : 0), memo)
                tx.addOutput(out)
                blsct.SigBalance(tx, blsct.mcl.sub(gammaIns, out.gamma));
                tx.addOutput(new bitcore.Transaction.Output({satoshis: fee, script: bitcore.Script.fromHex("6a")}))
            }
        }
        else {
            if (amount >= (subtractFee?fee:0)) {
                tx.to(dest, amount - (subtractFee ? fee : 0))
            }
        }

        if (addedInputs-(amount+(subtractFee?0:fee)) > 0) {
            tx.to((await this.NavReceivingAddresses())[0].address, addedInputs - (amount + (subtractFee ? 0 : fee)))
        }

        tx.settime(Math.floor(Date.now() / 1000))
            .sign(privateKeys);

        if (tx.inputs.length > 0)
        {
            ret.fee += fee;
            ret.tx.push(tx.toString())
        }

        return ret;
    }

    async GetPrivateKey(hashId, key)
    {
        let pk = await this.db.asyncFind({key: hashId})

        if (!pk.length)
            return;

        key = key || 'masterkey navcoinjs';
        key = crypto.createHash('sha256').update(String(key)).digest('base64').substr(0, 32)

        let ret = pk[0].value;

        if (key)
        {
            const ciphertextBytes = Buffer.from(ret, 'base64')
            const iv = ciphertextBytes.slice(0, 16)
            const data = ciphertextBytes.slice(16)
            const aes = crypto.createDecipheriv(algorithm, key, iv)
            let plaintextBytes = Buffer.from(aes.update(data))
            plaintextBytes = Buffer.concat([plaintextBytes, aes.final()])
            ret = plaintextBytes.toString()
        }

        return ret.substr(0,4) == "xprv" ? bitcore.HDPrivateKey(ret).privateKey : bitcore.PrivateKey(ret);
    }
};

module.exports.WalletFile = WalletFile

module.exports.Init = async () => {
    await blsct.Init()
}

module.exports.xNavBootstrap = {
    mainnet: require('./xnav_bootstrap'),
    testnet: require('./xnav_bootstrap_testnet')
}