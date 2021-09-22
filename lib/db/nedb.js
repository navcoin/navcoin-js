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

        this.db = new AsyncNedb(dbOptions);

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
        return await this.db.asyncCount({type: type, _type: 'key', used: false})
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
                _type: 'key',
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
                _type: 'key',
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
        return await this.db.asyncFind({type: AddressTypes.NAV, _type: 'key'});
    }

    async GetStakingAddresses() {
        return await this.db.asyncFind({labelStaking: {$exists: true}, _type: 'stakingAddress'});
    }

    async AddStakingAddress(address, hash) {
        try {
            await this.db.asyncInsert({_id: 'staking_'+address, hash: hash, _type: 'stakingAddress'})
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
                _type: 'status'
            })
        } catch(e) {
            return await this.db.asyncUpdate({_id: 'status_' + s}, {
                _id: 'status_' + s,
                status: st,
                _type: 'status'
            })
        }
    }

    async BulkRawInsert(documents) {
        return await this.db.asyncInsert(documents)
    }

    async ZapWalletTxes() {
        await this.db.asyncRemove({ _type: 'status' }, { multi: true });
        await this.db.asyncRemove({ _type: 'scriptHistory' }, { multi: true });
        await this.db.asyncRemove({ _type: 'outPoint' }, { multi: true });
        await this.db.asyncRemove({ _type: 'walletTx'}, { multi: true });
        await this.db.asyncRemove({ _type: 'stakingAddress'}, { multi: true });
    }

    async GetXNavReceivingAddresses(all) {
        let ret = all ?
            await this.db.asyncFind({type: AddressTypes.XNAV, _type: 'key'}, [['sort', { path: 1 }]]) :
            await this.db.asyncFind({type: AddressTypes.XNAV, used: false, _type: 'key'}, [['sort', { path: 1 }]]);

        return ret ? ret : [];
    }

    async GetNavReceivingAddresses(all) {
        let ret = all ?
            await this.db.asyncFind({type: AddressTypes.NAV, _type: 'key'}, [['sort', { path: 1 }]]) :
            await this.db.asyncFind({type: AddressTypes.NAV, used: false, _type: 'key'}, [['sort', { path: 1 }]]);

        return ret ? ret : [];
    }

    async GetNavAddress(address) {
        return await this.db.asyncFind({type: AddressTypes.NAV, address: address, _type: 'key'})
    }

    async GetTxs(downloaded = false) {
        return await this.db.asyncFind({_type: 'scriptHistory', fetched: downloaded})
    }

    async CleanScriptHashHistory(scriptHash, lowerLimit, upperLimit) {
        await this.db.asyncRemove({ height: { $lte: lowerLimit }, _id: 'scriptHistory_'+scriptHash }, { multi: true });
        await this.db.asyncRemove({ height: { $gte: upperLimit }, _id: 'scriptHistory_'+scriptHash }, { multi: true });
    }

    async AddScriptHashHistory(scriptHash, hash, height, fetched) {
        try {
            await this.db.asyncInsert({
                _id: 'scriptHistory_' + scriptHash,
                _type: 'scriptHistory',
                tx_hash: hash,
                height: height,
                fetched: fetched,
            });
        } catch (e) {
            await this.db.asyncUpdate({
                _id: 'scriptHistory_' + scriptHash,
                tx_hash: hash
            }, {
                _id: 'scriptHistory_' + scriptHash,
                _type: 'scriptHistory',
                tx_hash: hash,
                height: height,
                fetched: fetched,
            });
        }
    }

    async GetScriptHashHistory(scriptHash, hash, height, fetched) {
        return await this.db.asyncFind({_id: 'scriptHistory_'+scriptHash});
    }

    async MarkAsFetched(hash) {
        await this.db.asyncUpdate({tx_hash: hash, type: 'scriptHistory'}, {$set: {fetched: true}})
    }

    async GetWalletHistory() {
        let list_unconfirmed = (await this.db.asyncFind({_type: 'walletTx', height: {$lte: 0}}, [['sort', { height: 1, pos: 1 }]]))
        let list_confirmed = (await this.db.asyncFind({_type: 'walletTx', height: {$gt: 0}}, [['sort', { height: -1, pos: -1 }]]))

        return list_unconfirmed.concat(list_confirmed);
    }

    async AddWalletTx(hash, type, amount, confirmed, height, pos, timestamp, memos) {
        try {
            await this.db.asyncInsert({
                _id: 'walletTx_'+hash,
                _type: 'walletTx',
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
                    _type: 'walletTx',
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
        return await this.db.asyncFind({_type: 'outPoint', spentIn: ''})
    }

    async GetTx(hash) {
        return await this.db.asyncFindOne({_id: 'tx_'+hash})
    }

    async AddUtxo(outPoint, out, spentIn, amount, label, type) {
        return await this.db.asyncInsert({
            _id: 'outPoint_' + outPoint,
            _type: 'outPoint',
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
        tx._type = 'tx';
        try {
            await this.db.asyncInsert(tx)
        }
        catch (e) {
            await this.db.asyncUpdate({_id: tx._id}, tx)
        }
    }

    async AddTxKeys(tx) {
        tx._id = 'txKeys_'+tx.txidkeys;
        tx._type = 'txKeys'
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
