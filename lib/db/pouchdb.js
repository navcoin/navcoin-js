const EventEmitter = require('events');
const AddressTypes = require("../utils/address_types");
const crypto = require('crypto');
const algorithm = 'aes-256-cbc';
var PouchDB = require('pouchdb')

if (!PouchDB.on) {
    PouchDB = require('pouchdb').default;

    require('pouchdb-all-dbs')(PouchDB);
    //PouchDB.plugin(require('crypto-pouch'))
    //PouchDB.plugin(require('pouchdb-find').default);
    PouchDB.plugin(require('pouchdb-adapter-memory').default);
    PouchDB.plugin(require('pouchdb-adapter-websql').default);
}
else
{
    PouchDB = require('pouchdb');

    //require('pouchdb-all-dbs')(PouchDB);
    //PouchDB.plugin(require('crypto-pouch'))
    //PouchDB.plugin(require('pouchdb-find'));
    PouchDB.plugin(require('pouchdb-adapter-memory'));
}



module.exports = class extends EventEmitter  {
    constructor(filename, secret, adapter) {
        super();

        let key = crypto.createHash('sha256').update(String(secret)).digest('base64').substr(0, 32)

        let opts = {auto_compaction: true}

        if (!filename)
            opts.adapter = 'memory'

        try {
            this.db = new PouchDB(filename, opts);
            //this.db.crypto({password: key, ignore: ['vin', 'vout']}).then(() => {
            /*this.db.createIndex({
                index: {
                    fields: ['doc_type', 'type', 'used', '_id'],
                    ddoc: "key-type-used"
                }
            })
            this.db.createIndex({
                index: {
                    fields: ['doc_type', '_id'],
                    ddoc: "type-id"
                }
            })
            this.db.createIndex({
                index: {
                    fields: ['tx_hash', 'doc_type'],
                    ddoc: "hash-type"
                }
            })*/
            this.emit('db_open')
            //})
        } catch (e) {
            console.log(e)
            this.emit('db_load_error', e)
        }
    }

    Close() {
        this.db.close();
        this.emit('db_closed')
    }

    async FindId(id) {
        let ret = await this.db.allDocs({
            startkey: id,
            endkey: id + '\uffff',
            include_docs: true
        })

        if (ret.rows.length)
            return ret.rows[0].doc;

        return undefined;
    }

    async Upsert(obj) {
        let self = this;

        await new Promise((res, rej) => {
            self.db.get(obj._id).then((doc) => {
                obj._rev = doc._rev
                self.db.put(obj).then((response) => {
                    res()
                }).catch(async (e) => {
                    if (e.status == 409) {
                        await self.Upsert(obj);
                        res();
                    }
                })

            }).catch((e) => {
                if (e.status == 404) {
                    delete obj._rev
                    self.db.put(obj).then((response) => {
                        res()
                    }).catch(async (e) => {
                        if (e.status == 409) {
                            await self.Upsert(obj);
                            res()
                        }
                    })
                }
            })
        });
    }

    Encrypt(plain, key) {
        const iv = crypto.randomBytes(16)
        const aes = crypto.createCipheriv(algorithm, key, iv)
        let ciphertext = aes.update(plain)
        ciphertext = Buffer.concat([iv, ciphertext, aes.final()])
        return ciphertext.toString('base64')
    }

    static async ListWallets() {
        return await PouchDB.allDbs();
    }

    static async RemoveWallet(filename) {
        try {
            await new PouchDB('wallet_'+filename).destroy()
            return true;
        } catch (e) {
            return false
        }
    }

    async GetPoolSize(type) {
        let obj = await this.db.allDocs({
            startkey: 'key',
            endkey: 'key\uffff',
            include_docs: true
        })

        let ret = []

        if (obj.rows.length)
            ret = obj.rows.filter((e) => e.doc.type == type && e.doc.used == false).map((e) => e.doc);

        return ret.length;
    }

    async GetMasterKey(key, password) {
        let dbFind = await this.FindId('masterKey_'+key)

        if (!dbFind)
            return undefined;

        password = this.HashPassword(password)

        let ret = dbFind.value;

        try
        {
            const ciphertextBytes = Buffer.from(ret, 'base64')
            const iv = ciphertextBytes.slice(0, 16)
            const data = ciphertextBytes.slice(16)
            const aes = crypto.createDecipheriv(algorithm, password, iv)
            let plaintextBytes = Buffer.from(aes.update(data))
            plaintextBytes = Buffer.concat([plaintextBytes, aes.final()])
            ret = plaintextBytes.toString()
        } catch(e) {
            return undefined;
        }

        return ret;
    }

    async AddMasterKey(type, value, password) {
        password = this.HashPassword(password)
        value = this.Encrypt(value, password);

        try {
            await this.db.put({doc_type: 'masterKey', _id: 'masterKey_' + type, value: value});
            return true;
        } catch (e) {
            return false;
        }
    }

    async UpdateCounter(index, value) {
        await this.Upsert({_id: 'counter_'+index,
            doc_type: 'counter',
            value: value
        });
    }

    async GetCounter(index) {
        let ret = await this.FindId('counter_'+index)

        if (ret)
            return ret.value;

        return undefined;
    }

    HashPassword(password) {
        password = password || 'masterkey navcoinjs';
        password = crypto.createHash('sha256').update(String(password)).digest('base64').substr(0, 32)
        return password;
    }

    async AddKey(hashId, value, type, address, used, change, path, password) {
        if (type != AddressTypes.XNAV) {
            password = this.HashPassword(password);
            value = this.Encrypt(value, password);
        }

        try {
            await this.db.put({
                doc_type: 'key',
                _id: 'key_'+hashId,
                value: value,
                type: type,
                address: address,
                used: false,
                change: change,
                path: path
            });
        } catch (e) {
            return false;
        }
    }

    async GetKey(key, password) {
        let dbFind = await this.FindId('key_'+key)

        if (!dbFind)
            return undefined;

        password = this.HashPassword(password)

        let ret = dbFind.value;

        if (dbFind.type != AddressTypes.XNAV)
        {
            try {
                const ciphertextBytes = Buffer.from(ret, 'base64')
                const iv = ciphertextBytes.slice(0, 16)
                const data = ciphertextBytes.slice(16)
                const aes = crypto.createDecipheriv(algorithm, password, iv)
                let plaintextBytes = Buffer.from(aes.update(data))
                plaintextBytes = Buffer.concat([plaintextBytes, aes.final()])
                ret = plaintextBytes.toString()
            } catch(e) {
                return ret;
            }
        }

        return ret;
    }

    async SetValue(key, value) {
        await this.Upsert({_id :'setting_'+key,
            doc_type: 'setting',
            value: value
        });
    }

    async GetValue(key) {
        let ret = await this.FindId('setting_'+key)

        if (ret)
            return ret.value;

        return undefined;
    }

    async GetNavAddresses() {
        let obj = await this.db.allDocs({
            startkey: 'key',
            endkey: 'key\uffff',
            include_docs: true
        })

        let ret = []

        if (obj.rows.length)
            ret = obj.rows.filter((e) => e.doc.type == AddressTypes.NAV).map((e) => e.doc);

        return ret;
    }

    async GetStakingAddresses() {
        let obj = await this.db.allDocs({
            startkey: 'stakingAddress',
            endkey: 'stakingAddress\uffff',
            include_docs: true
        })

        let ret = []

        if (obj.rows.length)
            ret = obj.rows.map((e) => e.doc);

        return ret;
    }

    async AddStakingAddress(address, hash) {
        await this.db.put({_id: 'staking'+address, doc_type: 'stakingAddress', hash: hash});
    }

    async GetStakingAddress(address) {
        let ret = await this.FindId('staking_'+address)

        return ret;
    }

    async GetStatusForScriptHash(s) {
        let ret = await this.FindId('status_'+s)

        return ret ? ret.status : undefined;
    }

    async SetStatusForScriptHash(s, st) {
        await this.Upsert({_id: 'status_'+s,
            doc_type: 'status',
            status: s
        });
    }

    async BulkRawInsert(documents) {
        await this.db.bulkDocs(documents).catch(console.log)

        return;
        for (var i in documents) {
            try {
                await this.db.put(documents[i])
            } catch (e) {
                console.log(e)
            }
        }
    }

    async ZapWalletTxes() {
        let types = ['status', 'scriptHistory', 'outPoint', 'walletTx', 'stakingAddress'];

        for (var i in types) {
            let type = types[i]
            let entries = await this.db.allDocs({
                startkey: type+'_',
                endkey: type+'_\uffff',
                include_docs: true
            })

            if (entries.rows.length)
            {
                for (var j in entries.rows) {
                    let row = entries.rows[j];
                    await this.db.remove(row.id, row.value.rev);
                }
            }
        }
    }

    async GetXNavReceivingAddresses(all) {
        let obj = await this.db.allDocs({
            startkey: 'key',
            endkey: 'key\uffff',
            include_docs: true
        })

        let ret = []

        if (obj.rows.length)
            ret = obj.rows.filter((e) => e.doc.type == AddressTypes.XNAV && (all || e.doc.used == all)).map((e) => e.doc)

        return ret;
    }

    async GetNavReceivingAddresses(all) {
        let obj = await this.db.allDocs({
            startkey: 'key',
            endkey: 'key\uffff',
            include_docs: true
        })

        let ret = []


        if (obj.rows.length)
            ret = obj.rows.filter((e) => e.doc.type == AddressTypes.NAV && (all || e.doc.used == all)).map((e) => {
                return e.doc
            })

        return ret;
    }

    async GetNavAddress(address) {
        let obj = await this.db.allDocs({
            startkey: 'key',
            endkey: 'key\uffff',
            include_docs: true
        })

        let ret = []

        if (obj.rows.length)
            ret = obj.rows.filter((e) => e.doc.address == address).map((e) => e.doc)

        return ret[0];
    }

    async GetPendingTxs(downloaded = false) {
        let obj = await this.db.allDocs({
            startkey: 'scriptHistory',
            endkey: 'scriptHistory\uffff',
            include_docs: true
        })

        let ret = []
        if (obj.rows.length) {
            ret = obj.rows.filter((e) => {
                return !e.doc.fetched
            }).map((e) => e.doc)
        }
        
        return ret;
    }

    async RemoveTx(hash) {
        let tx = await this.FindId('tx_'+hash);
        if (tx)
            await this.db.remove(tx._id, tx._rev);

        let walletTx = await this.FindId('walletTx_'+hash);
        if (walletTx)
            await this.db.remove(walletTx._id, walletTx._rev);

        let txKeys = await this.FindId('txKeys_'+hash);
        if (txKeys)
            await this.db.remove(txKeys._id, txKeys._rev);

        let objOuts = await this.db.allDocs({
            startkey: 'outPoint_'+hash,
            endkey: 'outPoint_'+hash+'\uffff',
            include_docs: true
        })

        for (var i in objOuts.rows) {
            let out = objOuts.rows[i]
            await this.db.remove(out.doc._id, out.doc._rev);
        }
    }

    async CleanScriptHashHistory(scriptHash, lowerLimit, upperLimit) {
        let ret = await this.db.allDocs({
            startkey: 'scriptHistory_'+scriptHash,
            endkey: 'scriptHistory_'+scriptHash+'\uffff',
            include_docs: true
        })

        let self = this;
        for (var i in ret.rows) {
            if (ret.rows[0].doc.height >= upperLimit || ret.rows[0].doc.height <= lowerLimit)
                await self.db.remove(ret.rows[0].doc)
        }
    }

    async AddScriptHashHistory(scriptHash, hash, height, fetched) {
        await this.Upsert({_id: 'scriptHistory_' + scriptHash+'_'+hash,
            doc_type: 'scriptHistory',
            tx_hash: hash,
            height: height,
            fetched: fetched
        });
    }

    async GetScriptHashHistory(scriptHash) {
        let obj = await this.db.allDocs({
            startkey: 'scriptHistory_'+scriptHash,
            endkey: 'scriptHistory_'+scriptHash+'\uffff',
            include_docs: true
        })

        let ret = []

        if (obj.rows.length)
            ret = obj.rows.map((e) => { return e.doc});

        return ret;
    }

    async MarkAsFetched(hash) {
        let obj = await this.db.allDocs({
            startkey: 'scriptHistory',
            endkey: 'scriptHistory\uffff',
            include_docs: true
        })

        let ret = []

        if (obj.rows.length)
            ret = obj.rows.filter((e) => e.doc.tx_hash == hash).map((e) => e.doc)

        for (var i in ret.rows)
        {
            ret.rows[i].fetched = true
            await this.Upsert(ret.rows[i])
        }
    }

    async GetWalletHistory() {
        /*let list_unconfirmed = (await this.db.asyncFind({doc_type: 'walletTx', height: {$lte: 0}}, [['sort', { height: 1, pos: 1 }]]))
        let list_confirmed = (await this.db.asyncFind({doc_type: 'walletTx', height: {$gt: 0}}, [['sort', { height: -1, pos: -1 }]]))

        return list_unconfirmed.concat(list_confirmed);*/
    }

    async AddWalletTx(hash, type, amount, confirmed, height, pos, timestamp, memos) {
        await this.Upsert({_id: 'walletTx_'+hash,
            doc_type: 'walletTx',
            amount: amount,
            type: type,
            confirmed: confirmed,
            height: height,
            pos: pos,
            timestamp: timestamp,
            memos: memos
        })
    }

    async GetUtxos() {
        let find = await this.db.allDocs({
            startkey: 'outPoint',
            endkey: 'outPoint\uffff',
            include_docs: true
        })

        let ret = []

        if (find.rows.length) {
            ret = find.rows.filter((e) => {
                return e.doc.spentIn == ''
            }).map((e) => e.doc);
        }

        return ret;
    }

    async GetTx(hash) {
        return await this.FindId('tx_'+hash)
    }

    async AddUtxo(outPoint, out, spentIn, amount, label, type) {
        await this.db.put({_id: 'outPoint_' + outPoint,
            doc_type: 'outPoint',
            out: out,
            spentIn: spentIn,
            amount: amount,
            label: label,
            type: type
        })
    }

    async GetUtxo(outPoint) {
        return await this.FindId('outPoint_'+outPoint)
    }

    async SpendUtxo(outPoint, spentIn) {
        let ret = await this.FindId('outPoint_'+outPoint)
        ret.spentIn = spentIn;
        await this.Upsert(ret)
    }

    async SetTxHeight(hash, height, pos) {
        let ret = await this.FindId('tx_'+hash)
        ret.height = height;
        ret.pos = pos;
        await this.Upsert(ret)
    }

    async UseNavAddress(address) {
        let ret = await this.GetNavAddress(address)
        ret.used = true;
        await this.Upsert(ret)
    }

    async UseXNavAddress(hashId) {
        let ret = await this.FindId('key_'+hashId)
        ret.used = true;
        await this.Upsert(ret)
    }

    async AddTx(tx) {
        tx._id = 'tx_'+tx.txid;
        tx.doc_type = 'tx';
        await this.Upsert(tx)
    }

    async AddTxKeys(tx) {
        tx._id = 'txKeys_'+tx.txidkeys;
        tx.doc_type = 'txKeys'
        await this.Upsert(tx)
    }

    async GetTxKeys(hash) {
        return await this.FindId('txKeys_'+hash)
    }
}
