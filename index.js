import { readFile } from "fs/promises";
const json = JSON.parse(
  await readFile(new URL("./package.json", import.meta.url))
);
export var version = "v" + json.version;
export * as wallet from "./lib/wallet.js";
