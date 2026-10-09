/**
 * Case store — one CaseFile document per repo.
 * Backend: MongoDB when config.mongoUri is set, else a local JSON file.
 * Pure plumbing; no security logic.
 */
import { mkdirSync } from "node:fs";
import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { config } from "../config";
import { emptyCase, type CaseFile, type CaseStore } from "../types";

const REPORTS_DIR = resolve(process.cwd(), "reports");

/** Make a repo string safe for use in a filename / document id. */
function safeRepo(repo: string): string {
  return repo.replace(/[^a-zA-Z0-9._-]+/g, "_").replace(/^_+|_+$/g, "") || "repo";
}

/** Strip Mongo's internal _id before handing a CaseFile back to callers. */
function stripId(doc: Record<string, unknown> | null): CaseFile | null {
  if (!doc) return null;
  const { _id, ...rest } = doc;
  return rest as unknown as CaseFile;
}

async function makeMongoCaseStore(repo: string): Promise<CaseStore> {
  const { MongoClient } = await import("mongodb");
  // Fail fast instead of hanging if the cluster is unreachable/refuses (network/IP/TLS).
  const client = new MongoClient(config.mongoUri, {
    serverSelectionTimeoutMS: 8000,
    connectTimeoutMS: 8000,
  });
  await client.connect();
  const col = client.db("ward").collection("cases");
  const id = safeRepo(repo);
  console.log(`[caseStore] backend=mongodb db=ward collection=cases repo=${repo}`);

  return {
    async load(): Promise<CaseFile> {
      const doc = await col.findOne({ _id: id as unknown as import("mongodb").ObjectId });
      return stripId(doc as Record<string, unknown> | null) ?? emptyCase(repo);
    },
    async save(c: CaseFile): Promise<void> {
      await col.replaceOne(
        { _id: id as unknown as import("mongodb").ObjectId },
        { _id: id, ...c },
        { upsert: true },
      );
    },
  };
}

async function makeJsonCaseStore(repo: string): Promise<CaseStore> {
  mkdirSync(REPORTS_DIR, { recursive: true });
  const file = resolve(REPORTS_DIR, `case.${safeRepo(repo)}.json`);
  console.log(`[caseStore] backend=json file=${file} repo=${repo}`);

  return {
    async load(): Promise<CaseFile> {
      try {
        const raw = await readFile(file, "utf8");
        return JSON.parse(raw) as CaseFile;
      } catch (err: unknown) {
        if ((err as NodeJS.ErrnoException)?.code === "ENOENT") return emptyCase(repo);
        throw err;
      }
    },
    async save(c: CaseFile): Promise<void> {
      await writeFile(file, JSON.stringify(c, null, 2), "utf8");
    },
  };
}

export async function makeCaseStore(repo: string): Promise<CaseStore> {
  if (config.mongoUri) return makeMongoCaseStore(repo);
  return makeJsonCaseStore(repo);
}
