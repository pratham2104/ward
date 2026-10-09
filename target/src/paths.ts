/**
 * Runtime data locations for the target app. Everything regenerable lives under
 * target/.data so `POST /reset` can wipe + reseed it to a clean state.
 */
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const here = dirname(fileURLToPath(import.meta.url)); // target/src
export const DATA_DIR = resolve(here, "../.data"); // target/.data
export const DOCS_DIR = resolve(DATA_DIR, "docs"); // target/.data/docs  (search_docs base dir)
export const DB_PATH = resolve(DATA_DIR, "target.db"); // seeded SQLite
export const LOG_PATH = resolve(DATA_DIR, "logstore.json"); // LogStore sink (with gaps)
export const GT_PATH = resolve(DATA_DIR, "groundtruth.json"); // ground-truth sink mirror
