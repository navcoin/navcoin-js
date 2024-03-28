import { default as bitcore } from "@aguycalled/bitcore-lib";


const blsct = bitcore.Transaction.Blsct;

export async function getMasterKey(key, password, db) {
    if (!db) return undefined;

    let privK = await db.GetMasterKey("nav", password);

    if (!privK) return undefined;

    return privK;
}

export async function getMasterSpendKey(db, key) {
    if (!db) return undefined;

    let privK = await db.GetMasterKey("xNavSpend", key);

    if (!privK) return undefined;

    return blsct.mcl.deserializeHexStrToFr(privK);
}

export async function getMasterViewKey(db) {
    if (!db) return undefined;

    let pubK = await db.GetValue("masterViewKey");

    if (!pubK) return undefined;

    return blsct.mcl.deserializeHexStrToFr(pubK);
}

export async function setMasterKey(db, masterkey, key, type) {
    if (await db.GetMasterKey(key)) return false;

    let masterKey = (
        type === "navcoin-core"
            ? bitcore.HDPrivateKey.fromSeed(masterkey)
            : masterkey
    ).toString();
    let masterPubKey = bitcore.HDPrivateKey(masterKey).hdPublicKey.toString();

    let { masterViewKey, masterSpendKey } = blsct.DeriveMasterKeys(
        type === "navcoin-core"
            ? bitcore.PrivateKey(masterkey)
            : bitcore.HDPrivateKey(masterKey)
    );
    let masterSpendPubKey = blsct.mcl.mul(blsct.G(), masterSpendKey);
    let masterViewPubKey = blsct.mcl.mul(blsct.G(), masterViewKey);

    await db.AddMasterKey("nav", masterKey, key);
    await db.AddMasterKey(
        "xNavSpend",
        masterSpendKey.serializeToHexStr(),
        key
    );
    await db.SetValue("masterViewKey", masterViewKey.serializeToHexStr());
    await db.SetValue(
        "masterSpendPubKey",
        masterSpendPubKey.serializeToHexStr()
    );
    await db.SetValue(
        "masterViewPubKey",
        masterViewPubKey.serializeToHexStr()
    );
    await db.SetValue("masterPubKey", masterPubKey);

    console.log("master keys written");

    return true;
}

export async function getPrivateKey(db, hashId, key, network) {
    let ret = await db.GetKey(hashId, key);

    if (!ret) return;

    return ret.length > 100
        ? bitcore.HDPrivateKey(ret, network).privateKey
        : bitcore.PrivateKey(ret);
}

export async function navGetPrivateKeys(db, spendingPassword, address, network) {
    let list = address
      ? [await db.GetNavAddress(address)]
      : await db.GetNavReceivingAddresses(true);

    for (let i in list) {
      list[i].privateKey = (
        await this.getPrivateKey(db, list[i].hash, spendingPassword, network)
      ).toWIF();
      delete list[i].value;
    }

    return list;
  }