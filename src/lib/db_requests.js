import { asyncFilter } from "./utils/async_filter";

export async function isMyName(db, name) {
  return await db.GetName(name);
}

export async function getMyTokens(db) {
  let allTokens = await db.GetMyTokens();

  return await asyncFilter(allTokens, async (token) => {
    return db.HaveKey(token.id);
  });
}

export async function addName(db, emit, name, height, data = {}) {
  try {
    let exists = await db.GetName(name);
    await db.AddName(name, height || exists.height, data);
    if (!exists) emit("new_name", name, height);
    else emit("update_name", name, exists.height, data);
    return true;
  } catch (e) {
    return false;
  }
}

export async function getMyNames(db) {
  return await db.GetMyNames();
}

export async function getStatusHashForScriptHash(db, s) {
  return await db.GetStatusForScriptHash(s);
}

export async function spend(db, outPoint, spentIn) {
  console.log("outPoint  ", outPoint)
  let prev = await db.GetUtxo(outPoint);
  console.log("PREVIOUS  ", prev)
  console.log("spentIn  ", spentIn)
  if (prev && prev.spentIn && spentIn && prev.spentIn == spentIn) {
    return false;
  }
  await db.SpendUtxo(outPoint, spentIn);
  return true;
}

export async function getPoolSize(db, type, change) {
  return await db.GetPoolSize(type, change);
}
