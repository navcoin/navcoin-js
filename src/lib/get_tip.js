export async function getTip(db) {
    return (await db.GetValue("ChainTip")) || -1;
}
