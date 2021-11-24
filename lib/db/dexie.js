const EventEmitter = require("events");
const AddressTypes = require("../utils/address_types");
const crypto = require("crypto");
const algorithm = "aes-256-cbc";
let Dexie = require("dexie");
const { applyEncryptionMiddleware } = require("dexie-encrypted");

if (!Dexie.getDatabaseNames) {
  Dexie = require("dexie").default;
}

module.exports = class extends EventEmitter {
  constructor(filename, secret) {
    super();

    let key = new Buffer(
      crypto
        .createHash("sha256")
        .update(String(secret))
        .digest("hex")
        .substr(0, 64),
      "hex"
    );

    try {
      this.db = new Dexie(filename);

      applyEncryptionMiddleware(this.db, key, {}, async (db) => {
        this.emit("db_load_error", "Wrong key");
      });

      this.db.version(1).stores({
        keys: "&hash, type, address, used, change",
        txs: "&hash",
        txKeys: "&hash",
        walletTxs: "&id, hash, amount, type, confirmed, height, pos, timestamp",
        outPoints: "&id, spentIn, amount, label, type",
        scriptHistories: "&id, scriptHash, tx_hash, height, fetched",
        settings: "&key",
        encryptedSettings: "&key",
        statuses: "&scriptHash",
        stakingAddresses: "&id, [address+addressVoting]",
        labels: "&address, name",
      });

      this.emit("db_open");
    } catch (e) {
      this.emit("db_load_error", e);
    }
  }

  Close() {
    if (!this.db) return;

    this.db.close();
    this.emit("db_closed");
  }

  Encrypt(plain, key) {
    const iv = crypto.randomBytes(16);
    const aes = crypto.createCipheriv(algorithm, key, iv);
    let ciphertext = aes.update(plain);
    ciphertext = Buffer.concat([iv, ciphertext, aes.final()]);
    return ciphertext.toString("base64");
  }

  static async ListWallets() {
    return (await Dexie.getDatabaseNames()).filter((e) => e != "localforage");
  }

  static async RemoveWallet(filename) {
    try {
      await new Dexie.delete(filename);
      return true;
    } catch (e) {
      return false;
    }
  }

  async GetPoolSize(type) {
    if (!this.db) return;

    return await this.db.keys
      .where({ type: type, used: 0 })
      .count()
      .catch("DatabaseClosedError", (e) => {
        console.error("DatabaseClosed error: " + e.message);
      });
  }

  async GetMasterKey(key, password) {
    if (!this.db) return;

    let dbFind = await this.db.encryptedSettings
      .get({
        key: "masterKey_" + key,
      })
      .catch("DatabaseClosedError", (e) => {
        console.error("DatabaseClosed error: " + e.message);
      });

    if (!dbFind) return undefined;

    password = this.HashPassword(password);

    let ret = dbFind.value;

    try {
      const ciphertextBytes = Buffer.from(ret, "base64");
      const iv = ciphertextBytes.slice(0, 16);
      const data = ciphertextBytes.slice(16);
      const aes = crypto.createDecipheriv(algorithm, password, iv);
      let plaintextBytes = Buffer.from(aes.update(data));
      plaintextBytes = Buffer.concat([plaintextBytes, aes.final()]);
      ret = plaintextBytes.toString();
    } catch (e) {
      return undefined;
    }

    return ret;
  }

  async AddMasterKey(type, value, password) {
    if (!this.db) return;

    password = this.HashPassword(password);
    value = this.Encrypt(value, password);

    try {
      await this.db.encryptedSettings
        .put({
          key: "masterKey_" + type,
          value: value,
        })
        .catch("DatabaseClosedError", (e) => {
          console.error("DatabaseClosed error: " + e.message);
        });
      return true;
    } catch (e) {
      return false;
    }
  }

  async UpdateCounter(index, value) {
    if (!this.db) return;

    await this.db.settings
      .put({ key: "counter_" + index, value: value })
      .catch("DatabaseClosedError", (e) => {
        console.error("DatabaseClosed error: " + e.message);
      });
  }

  async GetCounter(index) {
    if (!this.db) return;

    let ret = await this.db.settings
      .get("counter_" + index)
      .catch("DatabaseClosedError", (e) => {
        console.error("DatabaseClosed error: " + e.message);
      });

    if (ret) return ret.value;

    return undefined;
  }

  HashPassword(password) {
    password = password || "masterkey navcoinjs";
    password = crypto
      .createHash("sha256")
      .update(String(password))
      .digest("base64")
      .substr(0, 32);
    return password;
  }

  async AddKey(hashId, value, type, address, used, change, path, password) {
    if (!this.db) return;

    if (type != AddressTypes.XNAV) {
      password = this.HashPassword(password);
      value = this.Encrypt(value, password);
    }

    try {
      await this.db.keys
        .add({
          hash: hashId,
          value: value,
          type: type,
          address: address,
          used: 0,
          change: change,
          path: path,
        })
        .catch("DatabaseClosedError", (e) => {
          console.error("DatabaseClosed error: " + e.message);
        });
    } catch (e) {
      return false;
    }
  }

  async GetKey(key, password) {
    if (!this.db) return;

    let dbFind = await this.db.keys
      .get(key)
      .catch("DatabaseClosedError", (e) => {
        console.error("DatabaseClosed error: " + e.message);
      });

    if (!dbFind) return undefined;

    password = this.HashPassword(password);

    let ret = dbFind.value;

    if (dbFind.type != AddressTypes.XNAV) {
      try {
        const ciphertextBytes = Buffer.from(ret, "base64");
        const iv = ciphertextBytes.slice(0, 16);
        const data = ciphertextBytes.slice(16);
        const aes = crypto.createDecipheriv(algorithm, password, iv);
        let plaintextBytes = Buffer.from(aes.update(data));
        plaintextBytes = Buffer.concat([plaintextBytes, aes.final()]);
        ret = plaintextBytes.toString();
      } catch (e) {
        return ret;
      }
    }

    return ret;
  }

  async SetValue(key, value) {
    if (!this.db) return;

    await this.db.settings
      .put({
        key: key,
        value: value,
      })
      .catch("DatabaseClosedError", (e) => {
        console.error("DatabaseClosed error: " + e.message);
      });
  }

  async GetValue(key) {
    if (!this.db) return;

    let ret = await this.db.settings
      .get(key)
      .catch("DatabaseClosedError", (e) => {
        console.error("DatabaseClosed error: " + e.message);
      });

    if (ret) return ret.value;

    return undefined;
  }

  async GetNavAddresses() {
    if (!this.db) return;

    return await this.db.keys
      .where({ type: AddressTypes.NAV })
      .toArray()
      .catch("DatabaseClosedError", (e) => {
        console.error("DatabaseClosed error: " + e.message);
      });
  }

  async GetStakingAddresses() {
    if (!this.db) return;

    return await this.db.stakingAddresses
      .toArray()
      .catch("DatabaseClosedError", (e) => {
        console.error("DatabaseClosed error: " + e.message);
      });
  }

  async AddStakingAddress(address, address2, hash, pk2) {
    if (!this.db) return;

    await this.db.stakingAddresses
      .add({
        id: address + "_" + address2,
        address: address,
        addressVoting: address2,
        hash: hash,
        hashVoting: pk2,
      })
      .catch("DatabaseClosedError", (e) => {
        console.error("DatabaseClosed error: " + e.message);
      });
  }

  async GetStakingAddress(address, address2) {
    if (!this.db) return;

    return await this.db.stakingAddresses
      .get({ address: address, addressVoting: address2 })
      .catch("DatabaseClosedError", (e) => {
        console.error("DatabaseClosed error: " + e.message);
      });
  }

  async GetStatusForScriptHash(s) {
    if (!this.db) return;

    let ret = await this.db.statuses
      .get(s)
      .catch("DatabaseClosedError", (e) => {
        console.error("DatabaseClosed error: " + e.message);
      });

    return ret ? ret.status : undefined;
  }

  async SetStatusForScriptHash(s, st) {
    if (!this.db) return;

    await this.db.statuses
      .put({ scriptHash: s, status: st })
      .catch("DatabaseClosedError", (e) => {
        console.error("DatabaseClosed error: " + e.message);
      });
  }

  async BulkRawInsert(documents) {
    if (!this.db) return;

    await this.db.txKeys.bulkPut(documents).catch(console.log);
  }

  async BulkRawInsertHistory(documents) {
    if (!this.db) return;

    await this.db.scriptHistories.bulkPut(documents).catch(console.log);
  }

  async ZapWalletTxes() {
    if (!this.db) return;

    let types = [
      "statuses",
      "scriptHistories",
      "outPoints",
      "walletTxs",
      "stakingAddresses",
    ];

    for (var i in types) {
      let type = types[i];
      await this.db[type].clear().catch("DatabaseClosedError", (e) => {
        console.error("DatabaseClosed error: " + e.message);
      });
    }
  }

  async GetXNavReceivingAddresses(all) {
    if (!this.db) return;

    return await this.db.keys
      .where({ type: AddressTypes.XNAV })
      .toArray()
      .catch("DatabaseClosedError", (e) => {
        console.error("DatabaseClosed error: " + e.message);
      });
  }

  async GetNavReceivingAddresses(all) {
    if (!this.db) return;

    return await this.db.keys
      .where({ type: AddressTypes.NAV })
      .toArray()
      .catch("DatabaseClosedError", (e) => {
        console.error("DatabaseClosed error: " + e.message);
      });
  }

  async GetNavAddress(address) {
    if (!this.db) return;

    let ret = await this.db.keys
      .where({ address: address })
      .toArray()
      .catch("DatabaseClosedError", (e) => {
        console.error("DatabaseClosed error: " + e.message);
      });

    return ret[0];
  }

  async GetPendingTxs(downloaded = 0) {
    if (!this.db) return;

    return await this.db.scriptHistories
      .where({ fetched: downloaded })
      .toArray()
      .catch("DatabaseClosedError", (e) => {
        console.error("DatabaseClosed error: " + e.message);
      });
  }

  async CleanScriptHashHistory(scriptHash, lowerLimit, upperLimit) {
    if (!this.db) return;

    await this.db.scriptHistories
      .where("height")
      .aboveOrEqual(upperLimit)
      .or("height")
      .belowOrEqual(lowerLimit)
      .filter((e) => e.scriptHash == scriptHash)
      .delete()
      .catch("DatabaseClosedError", (e) => {
        console.error("DatabaseClosed error: " + e.message);
      });
  }

  async AddScriptHashHistory(scriptHash, hash, height, fetched) {
    if (!this.db) return;

    await this.db.scriptHistories
      .put({
        id: scriptHash + "_" + hash,
        scriptHash: scriptHash,
        tx_hash: hash,
        height: height,
        fetched: fetched ? 1 : 0,
      })
      .catch("DatabaseClosedError", (e) => {
        console.error("DatabaseClosed error: " + e.message);
      });
  }

  async AddLabel(address, name) {
    if (!this.db) return;

    await this.db.labels
      .put({ address: address, name: name })
      .catch("DatabaseClosedError", (e) => {
        console.error("DatabaseClosed error: " + e.message);
      });
  }

  async GetLabel(address) {
    let label = await this.db.labels
      .get(address)
      .catch("DatabaseClosedError", (e) => {
        console.error("DatabaseClosed error: " + e.message);
      });

    return label ? label : address;
  }

  async GetScriptHashHistory(scriptHash) {
    if (!this.db) return;

    try {
      return await this.db.scriptHistories
        .where({ scriptHash: scriptHash })
        .toArray()
        .catch("DatabaseClosedError", (e) => {
          console.error("DatabaseClosed error: " + e.message);
        });
    } catch (e) {
      return [];
    }
  }

  async MarkAsFetched(hash) {
    if (!this.db) return;

    try {
      await this.db.scriptHistories
        .where({ tx_hash: hash })
        .modify({ fetched: 1 })
        .catch("DatabaseClosedError", (e) => {
          console.error("DatabaseClosed error: " + e.message);
        });
    } catch (e) {
      return [];
    }
  }

  async GetWalletHistory() {
    if (!this.db) return;

    let unconfirmed = await this.db.walletTxs
      .where("confirmed")
      .equals(0)
      .toArray()
      .catch("DatabaseClosedError", (e) => {
        console.error("DatabaseClosed error: " + e.message);
      });
    let confirmed = await this.db.walletTxs
      .where("confirmed")
      .equals(1)
      .toArray()
      .catch("DatabaseClosedError", (e) => {
        console.error("DatabaseClosed error: " + e.message);
      });

    let ret = unconfirmed.concat(confirmed.reverse());

    ret.sort((a, b) => {
      if (a.height == b.height) {
        if (a.pos == b.pos) return a.amount > 0 && b.amount < 0 ? -1 : 1;
        else return a.pos - b.pos;
      }
      return b.height - a.height;
    });

    return ret;
  }

  async AddWalletTx(
    hash,
    type,
    amount,
    confirmed,
    height,
    pos,
    timestamp,
    memos,
    strdzeel
  ) {
    if (!this.db) return;

    await this.db.walletTxs
      .put({
        id: hash + "_" + type,
        hash: hash,
        amount: amount,
        type: type,
        confirmed: confirmed ? 1 : 0,
        height: height,
        pos: pos,
        timestamp: timestamp,
        memos: memos,
        strdzeel: strdzeel,
      })
      .catch("DatabaseClosedError", (e) => {
        console.error("DatabaseClosed error: " + e.message);
      });
  }

  async GetUtxos() {
    if (!this.db) return;

    return await this.db.outPoints
      .where({ spentIn: "" })
      .toArray()
      .catch("DatabaseClosedError", (e) => {
        console.error("DatabaseClosed error: " + e.message);
      });
  }

  async GetTx(hash) {
    if (!this.db) return;

    return await this.db.txs.get(hash).catch("DatabaseClosedError", (e) => {
      console.error("DatabaseClosed error: " + e.message);
    });
  }

  async AddUtxo(
    outPoint,
    out,
    spentIn,
    amount,
    label,
    type,
    spendingPk = "",
    stakingPk = "",
    votingPk = "",
    hashId = ""
  ) {
    if (!this.db) return;

    await this.db.outPoints
      .add({
        id: outPoint,
        out: out,
        spentIn: spentIn,
        amount: amount,
        label: label,
        type: type,
        spendingPk: spendingPk,
        stakingPk: stakingPk,
        votingPk: votingPk,
        hashId: hashId,
      })
      .catch("DatabaseClosedError", (e) => {
        console.error("DatabaseClosed error: " + e.message);
      });
  }

  async GetUtxo(outPoint) {
    if (!this.db) return;

    return await this.db.outPoints
      .get(outPoint)
      .catch("DatabaseClosedError", (e) => {
        console.error("DatabaseClosed error: " + e.message);
      });
  }

  async SpendUtxo(outPoint, spentIn) {
    if (!this.db) return;

    try {
      await this.db.outPoints
        .where({ id: outPoint })
        .modify({ spentIn: spentIn })
        .catch("DatabaseClosedError", (e) => {
          console.error("DatabaseClosed error: " + e.message);
        });
    } catch (e) {
      console.log("SpendUtxo", e);
    }
  }

  async SetTxHeight(hash, height, pos) {
    if (!this.db) return;

    try {
      await this.db.txs
        .where({ hash: hash })
        .modify({ height: height, pos: pos })
        .catch("DatabaseClosedError", (e) => {
          console.error("DatabaseClosed error: " + e.message);
        });
    } catch (e) {
      console.log("SetTxHeight", e);
    }
  }

  async UseNavAddress(address) {
    if (!this.db) return;

    try {
      await this.db.keys
        .where({ address: address })
        .modify({ used: 1 })
        .catch("DatabaseClosedError", (e) => {
          console.error("DatabaseClosed error: " + e.message);
        });
    } catch (e) {
      console.log("usenav", e);
    }
  }

  async UseXNavAddress(hashId) {
    if (!this.db) return;

    try {
      await this.db.keys
        .where({ hash: hashId })
        .modify({ used: 1 })
        .catch("DatabaseClosedError", (e) => {
          console.error("DatabaseClosed error: " + e.message);
        });
    } catch (e) {
      console.log("usexnav", e);
    }
  }

  async AddTx(tx) {
    if (!this.db) return;

    tx.hash = tx.txid;
    delete tx.tx;
    try {
      await this.db.txs.add(tx).catch("DatabaseClosedError", (e) => {
        console.error("DatabaseClosed error: " + e.message);
      });
      return true;
    } catch (e) {
      return false;
    }
  }

  async AddTxKeys(tx) {
    if (!this.db) return;

    tx.hash = tx.txidkeys;
    try {
      await this.db.txKeys.add(tx).catch("DatabaseClosedError", (e) => {
        console.error("DatabaseClosed error: " + e.message);
      });
      return true;
    } catch (e) {
      return false;
    }
  }

  async GetTxKeys(hash) {
    if (!this.db) return;

    return await this.db.txKeys.get(hash).catch("DatabaseClosedError", (e) => {
      console.error("DatabaseClosed error: " + e.message);
    });
  }
};
