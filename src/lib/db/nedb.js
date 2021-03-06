const { AsyncNedb } = require('nedb-async')
const EventEmitter = require('events');
const AddressTypes = require("../utils/address_types");
const crypto = require('crypto');
const algorithm = 'aes-256-cbc';

module.exports = class extends EventEmitter  {
    constructor(filename, secret) {
        super();

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

        this.storage = filename;
        dbOptions.filename = this.storage;

        console.log(`Using database "${filename}"`)

        this.db = new AsyncNedb(dbOptions);

        this.db.loadDatabase(async (e) => {
            if (e)
                this.emit('db_load_error', e);
            else {
                this.emit('db_open')
                console.log(` - Script Hash History (${(await this.db.asyncFind({doc_type: 'scriptHistory'})).length} entries)`)
                console.log(` - Statuses (${(await this.db.asyncFind({doc_type: 'status'})).length} entries)`)
                console.log(` - Outpoints (${(await this.db.asyncFind({doc_type: 'outPoint'})).length} entries)`)
            }
        })

        this.db.on('compaction.done', () => {
            this.emit('db_closed')
        })
    }

    Close() {
        this.db.persistence.compactDataFile();
    }

    Encrypt(plain, key) {
        const iv = crypto.randomBytes(16)
        const aes = crypto.createCipheriv(algorithm, key, iv)
        let ciphertext = aes.update(plain)
        ciphertext = Buffer.concat([iv, ciphertext, aes.final()])
        return ciphertext.toString('base64')
    }

    static async ListWallets() {
        var localforage = require('localforage')

        localforage.config({
            name: 'NeDB', storeName: 'nedbdata'
        });

        let ret = await localforage.keys();

        return ret ? ret : [];
    }

    static async RemoveWallet(filename) {
        var localforage = require('localforage')

        await localforage.removeItem(filename);
    }

    async GetPoolSize(type) {
        return await this.db.asyncCount({type: type, doc_type: 'key', used: false})
    }

    async GetMasterKey(key, password) {
        let dbFind = await this.db.asyncFindOne({_id: 'masterKey_'+key})

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
            await this.db.asyncInsert({_id: 'masterKey_'+type, value: value});
        } catch (e) {
            console.log(e)
        }
    }

    async UpdateCounter(index, value) {
        try {
            await this.db.asyncInsert({
                _id: 'counter_' + index,
                value: value
            });
        }
        catch(e) {
            await this.db.asyncUpdate({_id: 'counter_' + index}, {
                _id: 'counter_' + index,
                value: value
            });
        }
    }

    async GetCounter(index) {
        let ret = await this.db.asyncFindOne({_id: 'counter_'+index})

        return ret ? ret.value : undefined;
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
            await this.db.asyncInsert({
                _id: 'key_' + hashId,
                doc_type: 'key',
                value: value,
                type: type,
                address: address,
                used: false,
                change: change,
                path: path
            });
        }
        catch(e)
        {
            await this.db.asyncUpdate({_id: 'key_' + hashId}, {
                _id: 'key_' + hashId,
                doc_type: 'key',
                value: value,
                type: type,
                address: address,
                used: false,
                change: change,
                path: path
            });
        }
    }

    async GetKey(key, password) {
        let dbFind = await this.db.asyncFindOne({_id: 'key_'+key})

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
        try {
            await this.db.asyncInsert({_id: 'setting_' + key, value: value});
        } catch(e) {
            await this.db.asyncUpdate({_id: 'setting_' + key}, {_id: 'setting_' + key, value: value});
        }
    }

    async GetValue(key) {
        let ret = await this.db.asyncFindOne({_id: 'setting_' + key})
        return  ret ? ret.value : undefined;
    }

    async GetNavAddresses() {
        return await this.db.asyncFind({type: AddressTypes.NAV, doc_type: 'key'});
    }

    async GetStakingAddresses() {
        return await this.db.asyncFind({labelStaking: {$exists: true}, doc_type: 'stakingAddress'});
    }

    async AddStakingAddress(address, hash) {
        try {
            await this.db.asyncInsert({_id: 'staking_'+address, hash: hash, doc_type: 'stakingAddress'})
        } catch(e) {

        }
    }

    async GetStakingAddress(address) {
        return await this.db.asyncFindOne({_id: 'staking_'+address})
    }

    async GetStatusForScriptHash(s) {
        let ret = await this.db.asyncFindOne({_id: 'status_'+s})

        return ret ? ret.status : undefined;
    }

    async SetStatusForScriptHash(s, st) {
        try {
            return await this.db.asyncInsert({
                _id: 'status_' + s,
                status: st,
                doc_type: 'status'
            })
        } catch(e) {
            return await this.db.asyncUpdate({_id: 'status_' + s}, {
                _id: 'status_' + s,
                status: st,
                doc_type: 'status'
            })
        }
    }

    async BulkRawInsert(documents) {
        return await this.db.asyncInsert(documents)
    }

    async ZapWalletTxes() {
        await this.db.asyncRemove({ doc_type: 'status' }, { multi: true });
        await this.db.asyncRemove({ doc_type: 'scriptHistory' }, { multi: true });
        await this.db.asyncRemove({ doc_type: 'outPoint' }, { multi: true });
        await this.db.asyncRemove({ doc_type: 'walletTx'}, { multi: true });
        await this.db.asyncRemove({ doc_type: 'stakingAddress'}, { multi: true });
    }

    async GetXNavReceivingAddresses(all) {
        let ret = all ?
            await this.db.asyncFind({type: AddressTypes.XNAV, doc_type: 'key'}, [['sort', { path: 1 }]]) :
            await this.db.asyncFind({type: AddressTypes.XNAV, used: false, doc_type: 'key'}, [['sort', { path: 1 }]]);

        return ret ? ret : [];
    }

    async GetNavReceivingAddresses(all) {
        let ret = all ?
            await this.db.asyncFind({type: AddressTypes.NAV, doc_type: 'key'}, [['sort', { path: 1 }]]) :
            await this.db.asyncFind({type: AddressTypes.NAV, used: false, doc_type: 'key'}, [['sort', { path: 1 }]]);

        return ret ? ret : [];
    }

    async GetNavAddress(address) {
        return await this.db.asyncFind({type: AddressTypes.NAV, address: address, doc_type: 'key'})
    }

    async GetPendingTxs(downloaded = false) {
        return await this.db.asyncFind({doc_type: 'scriptHistory', fetched: downloaded})
    }

    async CleanScriptHashHistory(scriptHash, lowerLimit, upperLimit) {
        await this.db.asyncRemove({ height: { $lte: lowerLimit }, script_hash: scriptHash, doc_type: 'scriptHistory' }, { multi: true });
        await this.db.asyncRemove({ height: { $gte: upperLimit }, script_hash: scriptHash, doc_type: 'scriptHistory' }, { multi: true });
    }

    async AddScriptHashHistory(scriptHash, hash, height, fetched) {
        try {
            await this.db.asyncInsert({
                _id: 'scriptHistory_' + scriptHash + '_' + hash,
                script_hash: scriptHash,
                doc_type: 'scriptHistory',
                tx_hash: hash,
                height: height,
                fetched: fetched,
            });
        } catch (e) {
            await this.db.asyncUpdate({
                _id: 'scriptHistory_' + scriptHash + '_' + hash,
                script_hash: scriptHash,
                tx_hash: hash
            }, {
                _id: 'scriptHistory_' + scriptHash + '_' + hash,
                script_hash: scriptHash,
                doc_type: 'scriptHistory',
                tx_hash: hash,
                height: height,
                fetched: fetched,
            });
        }
    }

    async GetScriptHashHistory(scriptHash, hash, height, fetched) {
        return await this.db.asyncFind({script_hash: scriptHash, doc_type: 'scriptHistory'});
    }

    async MarkAsFetched(hash) {
        await this.db.asyncUpdate({tx_hash: hash, doc_type: 'scriptHistory'}, {$set: {fetched: true}})
    }

    async SetTxHeight(hash, height, pos) {
        await this.db.asyncUpdate({_id: 'tx_'+hash}, {$set: {height: height, pos: pos}})
    }

    async GetWalletHistory() {
        let list_unconfirmed = (await this.db.asyncFind({doc_type: 'walletTx', height: {$lte: 0}}, [['sort', { height: 1, pos: 1 }]]))
        let list_confirmed = (await this.db.asyncFind({doc_type: 'walletTx', height: {$gt: 0}}, [['sort', { height: -1, pos: -1 }]]))

        return list_unconfirmed.concat(list_confirmed);
    }

    async AddWalletTx(hash, type, amount, confirmed, height, pos, timestamp, memos) {
        try {
            await this.db.asyncInsert({
                _id: 'walletTx_'+hash,
                doc_type: 'walletTx',
                amount: amount,
                type: type,
                confirmed: confirmed,
                height: height,
                pos: pos,
                timestamp: timestamp,
                memos: memos
            })
        } catch(e) {
            await this.db.asyncUpdate({_id: 'walletTx_'+hash, type: type},
                {
                    _id: 'walletTx_'+hash,
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
    }

    async GetUtxos() {
        return await this.db.asyncFind({doc_type: 'outPoint', spentIn: ''})
    }

    async GetTx(hash) {
        return await this.db.asyncFindOne({_id: 'tx_'+hash})
    }

    async AddUtxo(outPoint, out, spentIn, amount, label, type) {
        return await this.db.asyncInsert({
            _id: 'outPoint_' + outPoint,
            doc_type: 'outPoint',
            out: out,
            spentIn: spentIn,
            amount: amount,
            label: label,
            type: type
        })
    }

    async GetUtxo(outPoint) {
        return await this.db.asyncFindOne({_id: 'outPoint_'+outPoint})
    }

    async SpendUtxo(outPoint, spentIn) {
        return await this.db.asyncUpdate({_id: 'outPoint_'+outPoint}, {$set: {spentIn: spentIn}})
    }

    async UseNavAddress(address) {
        return await this.db.asyncUpdate({address: address}, {$set: {used: true}})
    }

    async UseXNavAddress(hashId) {
        await this.db.asyncUpdate({_id: 'key_'+hashId}, {$set: {used: true}})
    }

    async AddTx(tx) {
        tx._id = 'tx_'+tx.txid;
        tx.doc_type = 'tx';
        try {
            await this.db.asyncInsert(tx)
        }
        catch (e) {
            await this.db.asyncUpdate({_id: tx._id}, tx)
        }
    }

    async AddTxKeys(tx) {
        tx._id = 'txKeys_'+tx.txidkeys;
        tx.doc_type = 'txKeys'
        try {
            await this.db.asyncInsert(tx)
        }
        catch (e) {
            await this.db.asyncUpdate({_id: tx._id}, tx)
        }
    }

    async GetTxKeys(hash) {
        return await this.db.asyncFindOne({_id: 'txKeys_'+hash})
    }
}
