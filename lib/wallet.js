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
        this.network = options.network || 'mainnet';
        this.mnemonic = options.mnemonic;
        this.spendingPassword = options.spendingPassword;
        this.zapwallettxes = options.zapwallettxes || false;
        this.log = options.log || false;

        this.host = 'electrum4.nav.community'
        this.port = 40004
        this.proto = 'wss'

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
                await this.db.asyncInsert(options.bootstrap)
            }
        }

        let wallet_type = (await this.db.asyncFind({walletType: {$exists: true}}))
        this.type = wallet_type.length ? wallet_type[0].walletType : 'navcoin-js-v1'

        this.mvk = await this.GetMasterViewKey();

        if (this.GetMasterKey(this.spendingPassword))
        {
            await this.xNavFillKeyPool(this.spendingPassword);
            await this.NavFillKeyPool(this.spendingPassword);
        }

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

        while (await this.xNavGetPoolSize() < 100)
            await this.xNavCreateSubaddress(spendingPassword);
    }

    async NavFillKeyPool (spendingPassword) {
        if (this.type == 'next')
            return;

        let mk = await this.GetMasterKey(spendingPassword);

        if (!mk)
            return;

        while (await this.NavGetPoolSize() < 100)
            await this.NavCreateAddress(spendingPassword);
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

        await this.db.asyncUpdate({key: (change?'NavChangeLastIndex':'NavLastIndex')}, {key: (change?'NavChangeLastIndex':'NavLastIndex'), value: index+1}, {upsert: true});
        await this.db.asyncUpdate({key: hashId}, {key: hashId, value: pkStr, navAddress: true, path: path, address: bitcore.Address(pk).toString(), used: false, change: change, index: index}, {upsert: true});
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

        await this.db.asyncUpdate({key: hashId}, {key: hashId, value: pkStr, navAddress: true, path: path, address: bitcore.Address(pk).toString(), used: false, change: false}, {upsert: true});

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

    async GetScriptHashes() {
        let ret = [];

        ret.push(Buffer.from(bitcore.crypto.Hash.sha256(bitcore.Script.fromHex("51").toBuffer()).reverse()).toString("hex"))

        let addresses = await this.db.asyncFind({navAddress: true});

        for (var i in addresses)
        {
            ret.push(Buffer.from(bitcore.crypto.Hash.sha256(bitcore.Script.fromAddress(addresses[i].address).toBuffer()).reverse()).toString("hex"))
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
        options = options || {host: this.host, port: this.port, proto: this.proto};

        this.host = options.host
        this.port = options.port
        this.proto = options.proto
        this.connected = true;

        this.client = new electrum(this.host, this.port, this.proto)

        try {
            await this.client.connect('navcoin-js', '1.5');
            await this.SetTip(await this.client.blockchain_headers_subscribe().height);

            this.client.subscribe.on('blockchain.headers.subscribe', async (event) => {
                await self.SetTip(event[0].height)
            });
        }
        catch(e)
        {
            this.emit('connection_failed')
            console.error(`error connecting to electrum: ${e}`)
            await this.ManageElectrumError(e)
            return false
        }

        this.emit('connected')

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

    async Sync()
    {
        let scriptHashes = await this.GetScriptHashes()

        for (var i in scriptHashes) {
            let s = scriptHashes[i];

            try
            {
                let currentStatus = await this.client.blockchain_scripthash_subscribe(s)
                await this.ReceivedScriptHashStatus(s, currentStatus)
            }
            catch(e) {
                await this.ManageElectrumError(e)
                return await this.Sync()
            }
        }
    }

    async ManageElectrumError(e)
    {
        if (e == 'close connect' || e == 'connection not established')
        {
            this.emit('connection_failed')
            this.client.close()
            this.Log(`Reconnecting to electrum`)
            await this.Connect()
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
            await this.SyncScriptHash(s)
        }
    }

    async SyncScriptHash(scripthash)
    {
        var currentHistory = [];
        let lb = this.lastBlock + 0;

        let historyRange = {}
        let xnav = scripthash == "6032c38c0bc0e91e726f1e55e1832e434509001a7aed5cfd881b6ef07215e84a"

        this.emit('sync_started', scripthash)

        while (true) {
            try {
                currentHistory = await this.db.asyncFind({scriptHashHistory: scripthash});
            } catch(e) {
                this.Log(`error getting history from db: ${e}`)
            }

            var currentLastHeight = 0;

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
                this.Log(`requesting tx history for ${scripthash}`)
                newHistory = await this.client.blockchain_scripthash_getHistory(scripthash, Math.max(0, currentLastHeight-10));
                this.Log(`received ${newHistory.history.length} transactions`)
            }
            catch(e)
            {
                this.Log(`error getting history: ${e}`)
                await this.ManageElectrumError(e)
                return false
            }

            if (!newHistory.history.length) break;

            currentLastHeight = 0;
            let reachedMempool = false;
            let foundTx = false;

            for (var j in newHistory.history) {
                if (newHistory.history[j].height > currentLastHeight) currentLastHeight = newHistory.history[j].height;

                if (newHistory.history[j].height <= 0) reachedMempool = true;

                let progress = Math.floor(j*100/newHistory.history.length)

                if (progress > 0)
                    this.emit('sync_status', progress, scripthash)

                currentHistory.push(newHistory.history[j]);

                let tx;
                let mine = false;
                let inputsMine = false;
                let outputsMine = false;
                let mustNotify = false;
                let txKeys

                try
                {
                    txKeys = await this.GetTxKeys(newHistory.history[j].tx_hash)
                }
                catch(e)
                {
                    this.Log(`error getting txkeys: ${e}`)
                }


                let inMine = [];

                for (var i in txKeys.vin)
                {
                    let input = txKeys.vin[i]
                    let ismine = false;

                    if (input.script)
                    {
                        let script = bitcore.Script(input.script)

                        if (script.isPublicKeyHashOut() || script.isPublicKeyOut() || script.isColdStakingOutP2PKH() || script.isColdStakingV2Out())
                        {
                            let hashId = new Buffer(script.isPublicKeyOut() ?
                                ripemd160(sha256(script.getPublicKey())) :
                                script.getPublicKeyHash()).toString('hex')
                            if ((await this.db.asyncFind({key: hashId})).length)
                            {
                                this.GetTx(input.txid)
                                inputsMine = true;
                                ismine = true;
                            }
                        }
                    }
                    else if (input.spendingKey && input.outputKey)
                    {
                        let hid = blsct.GetHashId({ok: input.outputKey, sk: input.spendingKey}, this.mvk);
                        if (hid) {
                            let hashId = new Buffer(hid).toString('hex')
                            if (hashId && (await this.db.asyncFind({key: hashId})).length) {
                                this.GetTx(input.txid)
                                inputsMine = true;
                                ismine = true;
                            }
                        }
                    }

                    inMine.push(ismine)
                }

                for (var i in txKeys.vout)
                {
                    let output = txKeys.vout[i]

                    if (output.script)
                    {
                        let script = bitcore.Script(output.script)

                        if (script.isPublicKeyHashOut() || script.isPublicKeyOut() || script.isColdStakingOutP2PKH() || script.isColdStakingV2Out())
                        {
                            let hashId = new Buffer(script.isPublicKeyOut() ?
                                ripemd160(sha256(script.getPublicKey())) :
                                script.getPublicKeyHash()).toString('hex')
                            if ((await this.db.asyncFind({key: hashId})).length)
                            {
                                outputsMine = true;
                            }
                        }
                    }
                    else if (output.spendingKey && output.outputKey)
                    {
                        let hid = blsct.GetHashId({ok: output.outputKey, sk: output.spendingKey}, this.mvk);
                        if (hid)
                        {
                            let hashId = new Buffer(hid).toString('hex')
                            if (hashId && (await this.db.asyncFind({key: hashId})).length) {
                                outputsMine = true;
                            }
                        }
                    }
                }

                try {
                    this.db.asyncUpdate({scriptHashHistory: scripthash, tx_hash: newHistory.history[j].tx_hash}, {scriptHashHistory: scripthash, tx_hash: newHistory.history[j].tx_hash, height: newHistory.history[j].height}, {upsert: true});
                } catch(e) { }

                if (inputsMine || outputsMine)
                {
                    if (historyRange[newHistory.history[j].tx_hash]) {
                        if (historyRange[newHistory.history[j].tx_hash].height != newHistory.history[j].height) {
                            mustNotify = true;
                        }
                        tx = await this.GetTx(newHistory.history[j].tx_hash, false)
                        delete historyRange[newHistory.history[j].tx_hash];
                    } else {
                        mustNotify = true;
                        tx = await this.GetTx(newHistory.history[j].tx_hash, false)
                        delete historyRange[newHistory.history[j].tx_hash];
                    }
                }
                else
                {
                    continue;
                }

                let deltaNav = 0;
                let deltaXNav = 0;

                if (inputsMine)
                {
                    for (var i in tx.tx.inputs)
                    {
                        if (!inMine[i]) continue;

                        let input = tx.tx.inputs[i].toObject();
                        let prevTx = (await this.GetTx(input.prevTxId)).tx
                        let prevOut = prevTx.outputs[input.outputIndex];

                        if (prevOut.isCt())
                        {
                            let hid = blsct.GetHashId(prevOut, this.mvk);
                            if (hid) {
                                let hashId = new Buffer(hid).toString('hex')
                                if ((await this.db.asyncFind({key: hashId})).length) {
                                    if (blsct.RecoverBLSCTOutput(prevOut, this.mvk)) {
                                        mine = true;
                                        await this.AddOutput(`${input.prevTxId}:${input.outputIndex}`, prevOut)
                                        await this.Spend(`${input.prevTxId}:${input.outputIndex}`, `${tx.txid}:${i}`)
                                        deltaXNav -= prevOut.amount;
                                    }
                                }
                            }
                        }
                        else if (prevOut.script.isPublicKeyHashOut() || prevOut.script.isPublicKeyOut() || prevOut.script.isColdStakingOutP2PKH() || prevOut.script.isColdStakingV2Out())
                        {
                            let hashId = new Buffer(prevOut.script.isPublicKeyOut() ?
                                ripemd160(sha256(prevOut.script.getPublicKey())) :
                                prevOut.script.getPublicKeyHash()).toString('hex')
                            if ((await this.db.asyncFind({key: hashId})).length)
                            {
                                mine = true;
                                await this.AddOutput(`${input.prevTxId}:${input.outputIndex}`, prevOut)
                                await this.Spend(`${input.prevTxId}:${input.outputIndex}`, `${tx.txid}:${i}`)
                                deltaNav -= prevOut.satoshis;
                            }
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
                                    await this.AddOutput(`${tx.txid}:${i}`, out)
                                    deltaXNav += out.amount;
                                }
                            }
                        }
                    }
                    else if (out.script.isPublicKeyHashOut() || out.script.isPublicKeyOut()) // || out.script.isColdStakingOutP2PKH() || out.script.isColdStakingV2Out())
                    {
                        let hashId = new Buffer(out.script.isPublicKeyOut() ?
                            ripemd160(sha256(out.script.getPublicKey())) :
                            out.script.getPublicKeyHash()).toString('hex')
                        if ((await this.db.asyncFind({key: hashId})).length)
                        {
                            mine = true;
                            await this.AddOutput(`${tx.txid}:${i}`, out)
                            deltaNav += out.satoshis;
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
                            timestamp: tx.tx.time
                        })
                        await this.db.asyncUpdate({wallettxid: tx.txid, type: 'xnav'},
                            {
                                wallettxid: tx.txid,
                                amount: deltaXNav,
                                type: 'xnav',
                                confirmed: tx.height > 0,
                                height: tx.height,
                                pos: tx.pos,
                                timestamp: tx.tx.time
                            },
                            {upsert: true})
                        foundTx = true;
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
                        foundTx = true;
                    }
                }
            }

            if (reachedMempool || !foundTx || (currentLastHeight >= lb && lb > 0)) break;
        }

        for (var e in historyRange)
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
        }

        this.emit('sync_status', 100, scripthash)
        this.emit('sync_finished', scripthash)
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

    async GetUtxos(xnav = false)
    {
        let utxos = (await this.db.asyncFind({outPoint: {$exists: true}, spentIn: '', xnav: xnav?1:0}))

        let tip = await this.GetTip()
        let ret = []

        for (var u in utxos) {
            let utxo = utxos[u];
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
        let navPending = bitcore.crypto.BN.Zero;
        let xNavPending = bitcore.crypto.BN.Zero;

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
                if (pending)
                    navPending = navPending.add(new bitcore.crypto.BN(utxo.amount));
                else
                    navConfirmed = navConfirmed.add(new bitcore.crypto.BN(utxo.amount));
            }
        }

        return {nav: {confirmed: navConfirmed.toNumber(), pending: navPending.toNumber()}, xnav: {confirmed: xNavConfirmed.toNumber(), pending: xNavPending.toNumber()}}
    }

    async AddOutput(outpoint, out)
    {
        let exists = (await this.db.asyncFind({outPoint: outpoint})).length

        if (exists)
            return;

        let amount = out.isCt() ? out.amount : out.satoshis;
        let label = out.isCt() ? out.memo : out.script.toAddress(this.network);

        await this.db.asyncUpdate({outPoint: outpoint}, {outPoint: outpoint, out: out.toBufferWriter().toBuffer().toString('hex'), spentIn: '', amount: amount, label: label, xnav: out.isCt()}, {upsert: true})
    }

    async Spend(outpoint, spentin)
    {
        await this.db.asyncUpdate({outPoint: outpoint}, {$set: {spentIn: spentin}})
    }

    async GetTx (hash, useCache = true) {
        if (useCache)
        {
            var cacheTx = (await this.db.asyncFind({txid: hash}))[0]
            if (cacheTx) {
                cacheTx.tx = bitcore.Transaction(cacheTx.hex)
                return cacheTx;
            }
        }
        let height = {block_height: 0, pos: 0};
        try
        {
            var tx = await this.client.blockchain_transaction_get(hash, false);
            try
            {
                height = await this.client.blockchain_transaction_getMerkle(hash);
            }
            catch(e)
            {

            }
        }
        catch(e)
        {
            this.Log(`error getting tx ${hash}: ${e}`)
            await this.ManageElectrumError(e)
            sleep(1)
            return await this.GetTx(hash, useCache)
        }
        tx = {txid: hash, hex: tx}
        tx.height = height.block_height;
        tx.pos = height.pos;

        try {
            await this.db.asyncUpdate({txid: hash}, tx, {upsert: true});
        } catch(e) {
        }

        tx.tx = bitcore.Transaction(tx.hex)
        return tx;
    }

    async GetTxKeys (hash, useCache = true) {
        if (useCache)
        {
            var cacheTx = (await this.db.asyncFind({txidkeys: hash}))[0]
            if (cacheTx) {
                return cacheTx;
            }
        }
        try
        {
            var tx = await this.client.blockchain_transaction_getKeys(hash);
        }
        catch(e)
        {
            this.Log(`error getting tx keys ${hash}: ${e}`)
            await this.ManageElectrumError(e)
            sleep(1)
            return await this.GetTxKeys(hash, useCache)
        }
        tx.txidkeys = hash

        try {
            await this.db.asyncUpdate({txidkeys: hash}, tx, {upsert: true});
        } catch(e) {
        }

        return tx;
    }

    async xNavCreateTransaction(dest, amount, memo, spendingPassword, subtractFee=true)
    {
        let mvk = this.mvk;
        let msk = await this.GetMasterSpendKey(spendingPassword);

        if (!(msk && mvk))
            return;

        let utxos = await this.GetUtxos(true)

        for (var out_i in utxos) {
            let out = utxos[out_i];

            if (!out.output.isCt())
                continue;
        }

        let tx = blsct.CreateTransaction(utxos, dest, amount, memo, mvk, msk, subtractFee);

        return {tx: tx.toString(), fee: tx.feeAmount}
    }

    async SendTransaction(tx) {
        try
        {
            return await this.client.blockchain_transaction_broadcast(tx)
        }
        catch(e)
        {
            console.error(`error sending tx: ${e}`)
            await this.ManageElectrumError(e)
            return false
        }
    }

    async NavCreateTransaction(dest, amount, memo, spendingPassword, subtractFee=true, fee=100000)
    {
        if (!(dest instanceof bitcore.Address))
            return await this.NavCreateTransaction(new bitcore.Address(dest), amount, memo, spendingPassword, subtractFee);
        
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

            console.log(privK)

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
            throw new Error(`Not enough balance (required ${amount+(subtractFee?0:fee)}, selected ${addedInputs})`)

        if (dest.isXnav()) {
            let out = blsct.CreateBLSCTOutput(dest, amount-(subtractFee?fee:0), memo)
            tx.addOutput(out)
            blsct.SigBalance(tx, blsct.mcl.sub(gammaIns, out.gamma));
        }
        else
            tx.to(dest, amount-(subtractFee?fee:0))

        tx.addOutput(new bitcore.Transaction.Output({satoshis: fee, script: bitcore.Script.fromHex("6a")}))
        tx.to((await this.NavReceivingAddresses())[0].address, addedInputs-(amount+(subtractFee?0:fee)))
        tx.settime(Math.floor(Date.now() / 1000))
        .sign(privateKeys);

        return {fee: fee, tx: tx.toString()};
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
        
        return bitcore.PrivateKey(ret);
    }
};

module.exports.WalletFile = WalletFile

module.exports.Init = async () => {
    await blsct.Init()
}

module.exports.xNavBootstrap = require('./xnav_bootstrap')