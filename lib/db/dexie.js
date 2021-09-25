const EventEmitter = require('events');
const AddressTypes = require("../utils/address_types");
const crypto = require('crypto');
const algorithm = 'aes-256-cbc';
const Dexie = require('dexie');
const {applyEncryptionMiddleware} = require('dexie-encrypted');

module.exports = class extends EventEmitter  {
    constructor(filename, secret) {
        super();

        let key = new Buffer(crypto.createHash('sha256').update(String(secret)).digest('hex').substr(0, 64), 'hex')

        try {
            this.db = new Dexie(filename);

            applyEncryptionMiddleware(this.db, key, {
            });

            this.db.version(1).stores({
                keys: "&hash, type, address, used, change",
                txs: "&hash",
                txKeys: "&hash",
                walletTxs: "&hash, amount, type, confirmed, height, pos, timestamp",
                outPoints: "&id, spentIn, amount, label, type",
                scriptHistories: "&id, [scriptHash+tx_hash], height, fetched",
                settings: "&key",
                encryptedSettings: "&key",
                statuses: "&scriptHash",
                stakingAddresses: "&address",
            });

            this.emit('db_open')
        } catch (e) {
            this.emit('db_load_error', e)
        }
    }

    Close() {
        this.db.close();
        this.emit('db_closed')
    }

    async Find(table, fields) {
        if (!this.db[table])
            return undefined;

        try {
            return await this.db[table].get(fields);
        }
        catch(e) {
            return undefined;
        }
    }

    Encrypt(plain, key) {
        const iv = crypto.randomBytes(16)
        const aes = crypto.createCipheriv(algorithm, key, iv)
        let ciphertext = aes.update(plain)
        ciphertext = Buffer.concat([iv, ciphertext, aes.final()])
        return ciphertext.toString('base64')
    }

    static async ListWallets() {
        return await Dexie.getDatabaseNames();
    }

    static async RemoveWallet(filename) {
        try {
            await new Dexie.delete(filename)
            return true;
        } catch (e) {
            return false
        }
    }

    async GetPoolSize(type) {
        return await this.db.keys.where({type: type}).count();
    }

    async GetMasterKey(key, password) {
        let dbFind = await this.Find('encryptedSettings', {key: 'masterKey_'+key})

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
            await this.db.encryptedSettings.put({key: 'masterKey_' + type, value: value});
            return true;
        } catch (e) {
            return false;
        }
    }

    async UpdateCounter(index, value) {
        await this.db.settings.put({key: 'counter_'+index,
            value: value
        });
    }

    async GetCounter(index) {
        let ret = await this.db.settings.get('counter_'+index)

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
            await this.db.keys.add({
                hash: hashId,
                value: value,
                type: type,
                address: address,
                used: 0,
                change: change,
                path: path
            });
        } catch (e) {
            return false;
        }
    }

    async GetKey(key, password) {
        let dbFind = await this.db.keys.get(key)

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
        await this.db.settings.put({
            key: key,
            value: value
        });
    }

    async GetValue(key) {
        let ret = await this.db.settings.get(key)

        if (ret)
            return ret.value;

        return undefined;
    }

    async GetNavAddresses() {
        return await this.db.keys.where({type: AddressTypes.NAV}).toArray();
    }

    async GetStakingAddresses() {
        return await this.db.stakingAddresses.toArray();
    }

    async AddStakingAddress(address, hash) {
        await this.db.stakingAddresses.add({address: hash});
    }

    async GetStakingAddress(address) {
        return await this.db.stakingAddresses.get(address)
    }

    async GetStatusForScriptHash(s) {
        let ret = await this.db.statuses.get(s)

        return ret ? ret.status : undefined;
    }

    async SetStatusForScriptHash(s, st) {
        await this.db.statuses.put({scriptHash: s,
            status: st
        });
    }

    async BulkRawInsert(documents) {
        await this.db.txKeys.bulkPut(documents).catch(console.log)
    }

    async ZapWalletTxes() {
        let types = ['statuses', 'scriptHistories', 'outPoints', 'walletTxs', 'stakingAddresses'];

        for (var i in types) {
            let type = types[i]
            await this.db[type].delete()
        }
    }

    async GetXNavReceivingAddresses(all) {
        return await this.db.keys.where({type: AddressTypes.XNAV}).toArray();
    }

    async GetNavReceivingAddresses(all) {
        return await this.db.keys.where({type: AddressTypes.NAV}).toArray();
    }

    async GetNavAddress(address) {
        return await this.db.keys.where({address: address}).toArray()[0];
    }

    async GetPendingTxs(downloaded = 0) {
        return await this.db.scriptHistories.where({fetched: downloaded}).toArray();
    }

    async CleanScriptHashHistory(scriptHash, lowerLimit, upperLimit) {
        await this.db.scriptHistories.where("height").aboveOrEqual(upperLimit).or("height").belowOrEqual(lowerLimit).delete()
    }

    async AddScriptHashHistory(scriptHash, hash, height, fetched) {
        await this.db.scriptHistories.put({id: scriptHash+'_'+hash,
            scriptHash: scriptHash,
            tx_hash: hash,
            height: height,
            fetched: fetched?1:0
        });
    }

    async GetScriptHashHistory(scriptHash) {
        try {
            return await this.db.scriptHistories.where({scriptHash: scriptHash}).toArray();
        }
        catch (e) {
            return []
        }
    }

    async MarkAsFetched(hash) {
        try {
            await this.db.scriptHistories.where({tx_hash: hash}).modify({fetched: 1});
        }
        catch (e) {
            return []
        }
    }

    async GetWalletHistory() {
        let unconfirmed = await this.db.walletTxs.where("height").belowOrEqual(0).toArray();
        let confirmed = await this.db.walletTxs.where("height").above(0).toArray();

        return unconfirmed.concat(confirmed);
    }

    async AddWalletTx(hash, type, amount, confirmed, height, pos, timestamp, memos) {
        await this.db.walletTxs.put({hash: hash,
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
        return await this.db.outPoints.where({spentIn: ''}).toArray()
    }

    async GetTx(hash) {
        return await this.db.txs.get(hash)
    }

    async AddUtxo(outPoint, out, spentIn, amount, label, type) {
        await this.db.outPoints.add({id: outPoint,
            out: out,
            spentIn: spentIn,
            amount: amount,
            label: label,
            type: type
        })
    }

    async GetUtxo(outPoint) {
        return await this.db.outPoints.get(outPoint)
    }

    async SpendUtxo(outPoint, spentIn) {
        try {
            await this.db.outPoints.where({id: outPoint}).modify({spentIn: spentIn})
        } catch(e) {
            console.log('SpendUtxo', e)
        }
    }

    async SetTxHeight(hash, height, pos) {
        try {
            await this.db.txs.where({hash:hash}).modify({height: height, pos: pos})
        } catch(e) {
            console.log('SetTxHeight', e)
        }
    }

    async UseNavAddress(address) {
        try{
            await this.db.keys.where({address: address}).modify({used: 1})
        } catch(e) {
            console.log('usenav', e)
        }
    }

    async UseXNavAddress(hashId) {
        try {
            await this.db.keys.get(hashId).modify({used: 1})
        } catch(e) {
            console.log('usexnav', e)
        }
    }

    async AddTx(tx) {
        tx.hash = tx.txid;
        delete tx.tx;
        try {
            await this.db.txs.add(tx)
            return true;
        } catch(e) {
            return false;
        }
    }

    async AddTxKeys(tx) {
        tx.hash = tx.txidkeys;
        try {
            await this.db.txKeys.add(tx)
            return true;
        } catch(e) {
            return false;
        }
    }

    async GetTxKeys(hash) {
        return await this.db.txKeys.get(hash)
    }
}
