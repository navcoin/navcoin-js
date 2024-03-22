
export function isValidDotNavName(name) {
    if (!name || !name.length) return false;

    if (name.length >= 64 || name.length < 5) return false;

    if (
        !/^[abcdefghijklmnopqrstuvwxyz01234566789][abcdefghijklmnopqrstuvwxyz01234566789-]*\.nav$/.test(
            name
        )
    )
        return false;

    return true;
}

export function isValidDotNavKey(key) {
    if (!key || !key.length) return false;

    if (key.length >= 64 || key.length < 1) return false;

    if (
        !/^[abcdefghijklmnopqrstuvwxyz01234566789][abcdefghijklmnopqrstuvwxyz01234566789-]*$/.test(
            key
        )
    )
        return false;

    return true;
}