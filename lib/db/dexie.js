const EventEmitter = require('events');
const AddressTypes = require("../utils/address_types");
const crypto = require('crypto');
const algorithm = 'aes-256-cbc';
let Dexie = require('dexie');
const {applyEncryptionMiddleware} = require('dexie-encrypted');

if (!Dexie.getDatabaseNames) {
    Dexie = require('dexie').default;
}

module.exports = class extends EventEmitter  {
    constructor(filename, secret) {
        super();

        let key = new Buffer(crypto.createHash('sha256').update(String(secret)).digest('hex').substr(0, 64), 'hex')

        try {
            this.db = new Dexie(filename);

            applyEncryptionMiddleware(this.db, key, {
            }, async (db) => {
                this.emit('db_load_error', 'Wrong key')
                this.db.close()
                delete this.db
            });

            this.db.version(1).stores({
                keys: "&hash, type, address, used, change",
                txs: "&hash",
                txKeys: "&hash",
                walletTxs: "&hash, amount, type, confirmed, height, pos, timestamp",
                outPoints: "&id, spentIn, amount, label, type",
                scriptHistories: "&id, scriptHash, tx_hash, height, fetched",
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
        if (!this.db) return

        this.db.close();
        this.emit('db_closed')
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
        if (!this.db) return

        return await this.db.keys.where({type: type}).count();
    }

    async GetMasterKey(key, password) {
        if (!this.db) return

        let dbFind = await this.db.encryptedSettings.get({key: 'masterKey_'+key})

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
        if (!this.db) return

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
        if (!this.db) return

        await this.db.settings.put({key: 'counter_'+index,
            value: value
        });
    }

    async GetCounter(index) {
        if (!this.db) return

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
        if (!this.db) return

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
        if (!this.db) return

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
        if (!this.db) return

        await this.db.settings.put({
            key: key,
            value: value
        });
    }

    async GetValue(key) {
        if (!this.db) return

        let ret = await this.db.settings.get(key)

        if (ret)
            return ret.value;

        return undefined;
    }

    async GetNavAddresses() {
        if (!this.db) return

        return await this.db.keys.where({type: AddressTypes.NAV}).toArray();
    }

    async GetStakingAddresses() {
        if (!this.db) return

        return await this.db.stakingAddresses.toArray();
    }

    async AddStakingAddress(address, hash) {
        if (!this.db) return

        await this.db.stakingAddresses.add({address: address, hash: hash});
    }

    async GetStakingAddress(address) {
        if (!this.db) return

        return await this.db.stakingAddresses.get(address)
    }

    async GetStatusForScriptHash(s) {
        if (!this.db) return

        let ret = await this.db.statuses.get(s)

        return ret ? ret.status : undefined;
    }

    async SetStatusForScriptHash(s, st) {
        if (!this.db) return

        await this.db.statuses.put({scriptHash: s,
            status: st
        });
    }

    async BulkRawInsert(documents) {
        if (!this.db) return

        await this.db.txKeys.bulkPut(documents).catch(console.log)
    }

    async ZapWalletTxes() {
        if (!this.db) return

        let types = ['statuses', 'scriptHistories', 'outPoints', 'walletTxs', 'stakingAddresses'];

        for (var i in types) {
            let type = types[i]
            await this.db[type].clear()
        }
    }

    async GetXNavReceivingAddresses(all) {
        if (!this.db) return

        return await this.db.keys.where({type: AddressTypes.XNAV}).toArray();
    }

    async GetNavReceivingAddresses(all) {
        if (!this.db) return

        return await this.db.keys.where({type: AddressTypes.NAV}).toArray();
    }

    async GetNavAddress(address) {
        if (!this.db) return

        return await this.db.keys.where({address: address}).toArray()[0];
    }

    async GetPendingTxs(downloaded = 0) {
        if (!this.db) return

        return await this.db.scriptHistories.where({fetched: downloaded}).toArray();
    }

    async CleanScriptHashHistory(scriptHash, lowerLimit, upperLimit) {
        if (!this.db) return

        await this.db.scriptHistories.where("height").aboveOrEqual(upperLimit).or("height").belowOrEqual(lowerLimit).delete()
    }

    async AddScriptHashHistory(scriptHash, hash, height, fetched) {
        if (!this.db) return

        await this.db.scriptHistories.put({id: scriptHash+'_'+hash,
            scriptHash: scriptHash,
            tx_hash: hash,
            height: height,
            fetched: fetched?1:0
        });
    }

    async GetScriptHashHistory(scriptHash) {
        if (!this.db) return

        try {
            return await this.db.scriptHistories.where({scriptHash: scriptHash}).toArray();
        }
        catch (e) {
            return []
        }
    }

    async MarkAsFetched(hash) {
        if (!this.db) return

        try {
            await this.db.scriptHistories.where({tx_hash: hash}).modify({fetched: 1});
        }
        catch (e) {
            return []
        }
    }

    async GetWalletHistory() {
        if (!this.db) return

        let unconfirmed = await this.db.walletTxs.where("height").belowOrEqual(0).toArray();
        let confirmed = await this.db.walletTxs.where("height").above(0).toArray();

        return unconfirmed.concat(confirmed);
    }

    async AddWalletTx(hash, type, amount, confirmed, height, pos, timestamp, memos) {
        if (!this.db) return

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
        if (!this.db) return

        return await this.db.outPoints.where({spentIn: ''}).toArray()
    }

    async GetTx(hash) {
        if (!this.db) return

        return await this.db.txs.get(hash)
    }

    async AddUtxo(outPoint, out, spentIn, amount, label, type, spendingPk= '', stakingPk = '', votingPk = '') {
        if (!this.db) return

        await this.db.outPoints.add({
            id: outPoint,
            out: out,
            spentIn: spentIn,
            amount: amount,
            label: label,
            type: type,
            spendingPk: spendingPk,
            stakingPk: stakingPk,
            votingPk: votingPk
        })
    }

    async GetUtxo(outPoint) {
        if (!this.db) return

        return await this.db.outPoints.get(outPoint)
    }

    async SpendUtxo(outPoint, spentIn) {
        if (!this.db) return

        try {
            await this.db.outPoints.where({id: outPoint}).modify({spentIn: spentIn})
        } catch(e) {
            console.log('SpendUtxo', e)
        }
    }

    async SetTxHeight(hash, height, pos) {
        if (!this.db) return

        try {
            await this.db.txs.where({hash:hash}).modify({height: height, pos: pos})
        } catch(e) {
            console.log('SetTxHeight', e)
        }
    }

    async UseNavAddress(address) {
        if (!this.db) return

        try{
            await this.db.keys.where({address: address}).modify({used: 1})
        } catch(e) {
            console.log('usenav', e)
        }
    }

    async UseXNavAddress(hashId) {
        if (!this.db) return

        try {
            await this.db.keys.get(hashId).modify({used: 1})
        } catch(e) {
            console.log('usexnav', e)
        }
    }

    async AddTx(tx) {
        if (!this.db) return

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
        if (!this.db) return

        tx.hash = tx.txidkeys;
        try {
            await this.db.txKeys.add(tx)
            return true;
        } catch(e) {
            return false;
        }
    }

    async GetTxKeys(hash) {
        if (!this.db) return

        return await this.db.txKeys.get(hash)
    }
}