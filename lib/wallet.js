const Db = require('nedb-async').AsyncNedb;
const crypto = require('crypto');
const Mnemonic = require('bitcore-mnemonic');
const bitcore = require('bitcore-lib');
const blsct = bitcore.Transaction.Blsct;
const algorithm = 'aes-256-cbc';
const EventEmitter = require('events');
const ripemd160 = bitcore.crypto.Hash.ripemd160;
const sha256 = bitcore.crypto.Hash.sha256;
const electrum = require('electrum-client-js')

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

        this.host = 'electrum.nav.community'
        this.port = 40004
        this.proto = 'wss'

        let secret = options.password || 'secret navcoinjs';
        let key = crypto.createHash('sha256').update(String(secret)).digest('base64').substr(0, 32)

        let dbOptions = {
            autoload: true,
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
    }

    async xNavGetPoolSize() {
        return await this.db.asyncCount({xnavAddress: true, used: false})
    }

    async NavGetPoolSize() {
        return await this.db.asyncCount({navAddress: true, used: false})
    }

    async Load() {
        if (!((await this.db.asyncFind({key: 'masterPubKey'})).length))
        {
            let mnemonic = this.mnemonic;

            if (!this.mnemonic)
            {
                mnemonic = new Mnemonic().toString();
                this.emit('new_mnemonic', mnemonic);
            }

            let masterKey = new Mnemonic(mnemonic).toHDPrivateKey();

            await this.SetMasterKey(masterKey, this.spendingPassword)
        }

        if (this.GetMasterKey(this.spendingPassword))
        {
            await this.xNavFillKeyPool(this.spendingPassword);
            await this.NavFillKeyPool(this.spendingPassword);
        }

        this.mvk = await this.GetMasterViewKey();
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
        while (await this.xNavGetPoolSize() < 100)
            await this.xNavCreateSubaddress(this.spendingPassword);
    }

    async NavFillKeyPool (spendingPassword) {
        while (await this.NavGetPoolSize() < 100)
            await this.NavCreateAddress(this.spendingPassword);
    }

    async xNavReceivingAddresses (all=true) {
        let list = all ? await this.db.asyncFind({xnavAddress: true}) : await this.db.asyncFind({xnavAddress: true, used: false});

        return list;
    }

    async NavReceivingAddresses (all=true) {
        let list = all ? await this.db.asyncFind({navAddress: true}) : await this.db.asyncFind({navAddress: true, used: false});

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

        return masterSpendKey;
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
        let mvk = await this.db.asyncFind({key: 'masterViewKey'});

        if (!mvk.length)
            return;

        let masterViewKey = blsct.mcl.deserializeHexStrToFr(mvk[0].value);

        let msk = await this.GetMasterSpendKey(sk);

        if (!msk)
            return;

        let masterSpendKey = blsct.mcl.deserializeHexStrToFr(msk);

        let index = 0;

        let dbLastIndex = await this.db.asyncFind({key: 'xNavLastIndex'});

        index = dbLastIndex.length ? dbLastIndex[0].value : index;

        let {viewKey, spendKey} = blsct.DerivePublicKeys(masterViewKey, masterSpendKey, acct, index);

        let hashId = new Buffer(ripemd160(sha256(spendKey.serialize()))).toString('hex')

        await this.db.asyncUpdate({key: 'xNavLastIndex'}, {key: 'xNavLastIndex', value: index+1}, {upsert: true});
        await this.db.asyncUpdate({key: hashId}, {key: hashId, value: [acct, index], xnavAddress: true, address: blsct.KeysToAddress(viewKey, spendKey).toString(), used: false}, {upsert: true});
    }

    async NavCreateAddress(sk, change=false) {
        let mk = await this.GetMasterKey(sk);

        if (!mk)
            return;

        let key = sk || 'masterkey navcoinjs';
        key = crypto.createHash('sha256').update(String(key)).digest('base64').substr(0, 32)

        let index = 0;

        let dbLastIndex = await this.db.asyncFind({key: (change?'NavChangeLastIndex':'NavLastIndex')});

        index = dbLastIndex.length ? dbLastIndex[0].value : index;

        let path = 'm/44\'/130\'/0\'/'+(change?'1':'0')+'/'+index;
        let privK = bitcore.HDPrivateKey(mk).deriveChild(path)
        let pk = privK.publicKey;
        let hashId = new Buffer(ripemd160(sha256(pk.toBuffer()))).toString('hex')
        let pkStr = this.Encrypt(privK.toString(), key);

        await this.db.asyncUpdate({key: (change?'NavChangeLastIndex':'NavLastIndex')}, {key: (change?'NavChangeLastIndex':'NavLastIndex'), value: index+1}, {upsert: true});
        await this.db.asyncUpdate({key: hashId}, {key: hashId, value: pkStr, navAddress: true, path: path, address: bitcore.Address(pk).toString(), used: false, change: change}, {upsert: true});
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

        let masterKey = masterkey.toString();
        let masterPubKey = bitcore.HDPrivateKey(masterKey).hdPublicKey.toString();

        let {masterViewKey, masterSpendKey} = blsct.DeriveMasterKeys(bitcore.HDPrivateKey(masterKey).privateKey);
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

        return true;
    }

    async Connect(options)
    {
        options = options || {host: this.host, port: this.port, proto: this.proto};

        this.host = options.host
        this.port = options.port
        this.proto = options.proto

        this.client = new electrum(this.host, this.port, this.proto)

        await this.client.connect('navcoin-js', '1.5');

        this.emit('connected')

        let self = this

        this.client.subscribe.on('blockchain.scripthash.subscribe', async (event) =>
        {
            await self.ReceivedScriptHashStatus(event[0], event[1])
        });

        this.client.subscribe.on('blockchain.headers.subscribe', async (event) =>
        {
            await self.SetTip(event[0].height)
        });
        
        await this.SetTip(await this.client.blockchain_headers_subscribe().height);

        let scriptHashes = await this.GetScriptHashes()

        for (var i in scriptHashes) {
            let s = scriptHashes[i];

            let currentStatus = await this.client.blockchain_scripthash_subscribe(s)

            await this.ReceivedScriptHashStatus(s, currentStatus)
        }
    }

    async ReceivedScriptHashStatus(s, status)
    {
        let prevStatus = this.GetStatusHashForScriptHash(s);

        if (status && status != prevStatus)
        {
            await this.SyncScriptHash(s)
        }
    }

    async SyncScriptHash(scripthash)
    {
        var currentHistory = [];
        let lb = this.lastBlock + 0;

        let uniqueTxs = (array) => {
            return array.reduce(function(acc, curr) {
                var count = 0;
                let isElemExist = acc.findIndex(function(item) {
                    return item.tx_hash === curr.tx_hash;
                })
                if (isElemExist === -1) acc.push({tx_hash: curr.tx_hash});
                return acc;
            }, []).length;
        }

        let historyRange = {}

        while (true) {
            try {
                currentHistory = await this.db.asyncFind({scriptHashHistory: scripthash});
            } catch(e) {
                console.log(e)
            }

            var currentLastHeight = 0;
            var prevHistoryLength = uniqueTxs(currentHistory);

            for (var i in currentHistory)
            {
                if (currentHistory[i].height > currentLastHeight) currentLastHeight = currentHistory[i].height;
            }

            let filteredHistory = currentHistory.filter((e) => e.height > 0 && e.height < Math.max(0, currentLastHeight-10));
            historyRange = currentHistory.filter(x => !filteredHistory.includes(x)).reduce(function(map, obj) {
                map[obj.tx_hash] = obj;
                return map;
            }, {});
            currentHistory = filteredHistory;

            try {
                await this.db.asyncRemove({ height: { $lt: 0 }, scriptHashHistory: scripthash }, { multi: true });
                await this.db.asyncRemove({ height: { $gte: Math.max(0, currentLastHeight-10) }, scriptHashHistory: scripthash }, { multi: true });
            } catch(e) {
                console.log(e)
            }

            var newHistory = [];

            try
            {
                newHistory = await this.client.blockchain_scripthash_getHistory(scripthash, Math.max(0, currentLastHeight-10));
            }
            catch(e) {
                console.log('historyerror: '+e)
                break;
            }

            if (!newHistory.history.length) break;

            currentLastHeight = 0;
            let reachedMempool = false;

            for (var j in newHistory.history) {
                if (newHistory.history[j].height > currentLastHeight) currentLastHeight = newHistory.history[j].height;

                if (newHistory.history[j].height == -1) reachedMempool = true;

                currentHistory.push(newHistory.history[j]);

                let tx;
                let mine = false;
                let mustNotify = false;

                if (historyRange[newHistory.history[j].tx_hash])
                {
                    if (historyRange[newHistory.history[j].tx_hash].height != newHistory.history[j].height)
                    {
                        mustNotify = true;
                    }
                    tx = await this.GetTx(newHistory.history[j].tx_hash, false)
                    delete historyRange[newHistory.history[j].tx_hash];
                }
                else
                {
                    mustNotify = true;
                    tx = await this.GetTx(newHistory.history[j].tx_hash)
                    delete historyRange[newHistory.history[j].tx_hash];
                }

                let deltaNav = 0;
                let deltaXNav = 0;

                for (var i in tx.tx.inputs)
                {
                    let input = tx.tx.inputs[i].toObject();
                    let prevTx = (await this.GetTx(input.prevTxId)).tx
                    let prevOut = prevTx.outputs[input.outputIndex];

                    if (prevOut.isCt())
                    {
                        let hashId = new Buffer(blsct.GetHashId(prevOut, this.mvk)).toString('hex')
                        if ((await this.db.asyncFind({key: hashId})).length) {
                            if (blsct.RecoverBLSCTOutput(prevOut, this.mvk)) {
                                mine = true;
                                await this.AddOutput(`${input.prevTxId}:${input.outputIndex}`, prevOut)
                                await this.Spend(`${input.prevTxId}:${input.outputIndex}`, `${tx.txid}:${i}`)
                                deltaXNav -= prevOut.amount;
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

                for (var i in tx.tx.outputs)
                {
                    let out = tx.tx.outputs[i];

                    if (out.isCt())
                    {
                        let hashId = new Buffer(blsct.GetHashId(out, this.mvk)).toString('hex')
                        if ((await this.db.asyncFind({key: hashId})).length) {
                            if (blsct.RecoverBLSCTOutput(out, this.mvk)) {
                                mine = true;
                                await this.AddOutput(`${tx.txid}:${i}`, out)
                                deltaXNav += out.amount;
                            }
                        }
                    }
                    else if (out.script.isPublicKeyHashOut() || out.script.isPublicKeyOut() || out.script.isColdStakingOutP2PKH() || out.script.isColdStakingV2Out())
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

                try {
                    this.db.asyncInsert({scriptHashHistory: scripthash, tx_hash: newHistory.history[j].tx_hash, height: newHistory.history[j].height});
                } catch(e) { }

                if (mustNotify && mine)
                {
                    if (deltaXNav != 0) {
                        this.emit('new_tx', {
                            txid: tx.txid,
                            amount: deltaXNav,
                            type: 'xnav',
                            confirmed: tx.height != -1,
                            height: tx.height,
                            pos: tx.pos,
                            timestamp: tx.tx.time
                        })
                        await this.db.asyncUpdate({wallettxid: tx.txid, type: 'xnav'},
                            {
                                wallettxid: tx.txid,
                                amount: deltaXNav,
                                type: 'xnav',
                                confirmed: tx.height != -1,
                                height: tx.height,
                                pos: tx.pos,
                                timestamp: tx.tx.time
                            },
                            {upsert: true})
                    }
                    if (deltaNav != 0) {
                        this.emit('new_tx', {
                            txid: tx.txid,
                            amount: deltaNav,
                            type: 'nav',
                            confirmed: tx.height != -1,
                            height: tx.height,
                            pos: tx.pos,
                            timestamp: tx.tx.time
                        })
                        await this.db.asyncUpdate({wallettxid: tx.txid, type: 'nav'},
                            {
                                wallettxid: tx.txid,
                                amount: deltaNav,
                                type: 'nav',
                                confirmed: tx.height != -1,
                                height: tx.height,
                                pos: tx.pos,
                                timestamp: tx.tx.time
                            },
                            {upsert: true})
                    }
                }

                let progress = Math.ceil(j*100/newHistory.history.length)

                if (progress > 0)
                    this.emit('sync_status', progress)
            }

            if (reachedMempool || uniqueTxs(currentHistory) == prevHistoryLength || (currentLastHeight >= lb && lb != -1)) break;
        }

        for (var e in historyRange)
        {
            await this.db.asyncRemove({wallettxid: historyRange[e].tx_hash}, { multi: true })
            await this.db.asyncRemove({outPoint: {$regex: new RegExp(`^${historyRange[e].tx_hash}:`)}}, { multi: true })
            this.emit('remove_tx', historyRange[e].tx_hash);
        }
    }

    async GetHistory()
    {
        let list = await this.db.asyncFind({wallettxid: {$exists: true}})

        return list;
    }

    async GetUtxos(xnav = false)
    {
        let utxos = (await this.db.asyncFind({outPoint: {$exists: true}, spentIn: '', xnav: xnav}))

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

            if ((tx.pos < 2 && (tip - tx.height) < 120) || tx.height == -1)
                pending = true;

            if (!pending)
                ret.push({txid: outpoint[0], vout: outpoint[1], out: utxo.out})
        }

        return ret;
    }

    async GetBalance()
    {
        let utxos = (await this.db.asyncFind({outPoint: {$exists: true}, spentIn: ''}))

        let navConfirmed = 0;
        let xNavConfirmed = 0;
        let navPending = 0;
        let xNavPending = 0;

        let tip = await this.GetTip()

        for (var u in utxos)
        {
            let utxo = utxos[u];

            let tx = await this.db.asyncFind({txid: utxo.outPoint.split(':')[0]})

            if (!tx.length)
                continue;

            tx = tx[0]

            let pending = false;

            if ((tx.pos < 2 && (tip-tx.height) < 120) || tx.height == -1)
                pending = true;

            if (utxo.xnav)
            {
                if (pending)
                    xNavPending += utxo.amount;
                else
                    xNavConfirmed += utxo.amount;
            }
            else
            {
                if (pending)
                    navPending += utxo.amount;
                else
                    navConfirmed += utxo.amount;
            }
        }

        return {nav: {confirmed: navConfirmed, pending: navPending}, xnav: {confirmed: xNavConfirmed, pending: xNavPending}}
    }

    async AddOutput(outpoint, out)
    {
        let exists = (await this.db.asyncFind({outPoint: outpoint})).length

        if (exists)
            return;

        let amount = out.isCt() ? out.amount : out.satoshis;
        let label = out.isCt() ? out.memo : out.script.toAddress(this.network);

        await this.db.asyncInsert({outPoint: outpoint, out: out, spentIn: '', amount: amount, label: label, xnav: out.isCt()})
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
        try
        {
            var tx = await this.client.blockchain_transaction_get(hash, false);
            var height = await this.client.blockchain_transaction_getMerkle(hash);
        }
        catch(e)
        {
            console.error(`error getting tx ${hash}: ${e}`)
            sleep.sleep(1)
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

    async xNavSend(dest, amount, memo, spendingPassword)
    {
        let mvk = this.mvk;
        let msk = await this.GetMasterSpendKey(spendingPassword);

        if (!(msk && mvk))
            return;

        let tx = blsct.CreateTransaction(await this.GetUtxos(true), dest, amount, memo, mvk, msk);

        return await this.client.blockchain_transaction_broadcast(tx.toString())
    }
};

module.exports.WalletFile = WalletFile

module.exports.Init = async () => {
    await blsct.Init()
}