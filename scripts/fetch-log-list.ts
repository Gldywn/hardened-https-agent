import { writeFile, readFile, mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { exit } from 'node:process';
import type { UnifiedCertificateTransparencyLogList } from '../src/types/uni-ct-log-list-schema';
import { getTestDataDir, getResDir } from './utils';
import { LOG_LISTS } from './constants';
import { createHash } from 'node:crypto';

const forTest = process.argv.includes('--for-test');
const forceBump = process.argv.includes('--force-bump');
const OUTPUT_DIR = forTest ? getTestDataDir() : getResDir();

// Provider-specific top-level keys that should not affect our canonical hash
// and should not appear in unified output
const PROVIDER_TOP_LEVEL_KEYS = ['version', 'log_list_timestamp', '$schema', 'assetVersion', 'assetVersionV2'] as const;

async function fetchAndSave(name: string, url: string) {
  try {
    console.log(`[+] Fetching ${name} from ${url}...`);
    const response = await fetch(url);
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    const data = await response.json();
    const filePath = join(OUTPUT_DIR, name);
    await writeFile(filePath, JSON.stringify(data, null, 2));
    console.log(`[+] Successfully saved to ${filePath}`);
  } catch (error) {
    console.error(`[-] Error fetching or saving ${name}:`, error);
    exit(1);
  }
}

async function fetchLogLists() {
  console.log('[*] Starting download of CT log lists...');
  await mkdir(OUTPUT_DIR, { recursive: true });
  for (const logList of LOG_LISTS) {
    await fetchAndSave(logList.name, logList.sourceUrl);
  }
  console.log('[*] All CT log lists downloaded successfully.');
  await mergeLogLists();
}

function stableStringify(obj: unknown): string {
  function order(value: any): any {
    if (Array.isArray(value)) {
      return value.map(order);
    }
    if (value && typeof value === 'object') {
      const ordered: Record<string, any> = {};
      for (const key of Object.keys(value).sort()) {
        ordered[key] = order((value as Record<string, any>)[key]);
      }
      return ordered;
    }
    return value;
  }
  return JSON.stringify(order(obj));
}

function sha256Hex(input: string): string {
  return createHash('sha256').update(input).digest('hex');
}

function sortOperatorsAndLogs(list: UnifiedCertificateTransparencyLogList): UnifiedCertificateTransparencyLogList {
  const cloned: UnifiedCertificateTransparencyLogList = JSON.parse(JSON.stringify(list));
  if (cloned.operators) {
    cloned.operators = [...cloned.operators].sort((a, b) => (a.name || '').localeCompare(b.name || ''));
    for (const op of cloned.operators) {
      if (op.logs) {
        op.logs = [...op.logs].sort((a, b) => (a.log_id || '').localeCompare(b.log_id || ''));
      }
    }
  }
  return cloned;
}

function cleanForHash(list: UnifiedCertificateTransparencyLogList): Record<string, unknown> {
  const IGNORED_TOP_LEVEL = new Set([
    ...PROVIDER_TOP_LEVEL_KEYS,
    'unified_version',
    'unified_generated_at',
    'unified_sources',
  ]);

  const clone = JSON.parse(JSON.stringify(list)) as Record<string, unknown>;
  for (const key of Object.keys(clone)) {
    if (IGNORED_TOP_LEVEL.has(key)) {
      // eslint-disable-next-line @typescript-eslint/no-dynamic-delete
      delete (clone as Record<string, unknown>)[key];
    }
  }
  return clone;
}

function removeProviderTopLevelKeys(
  list: UnifiedCertificateTransparencyLogList,
): UnifiedCertificateTransparencyLogList {
  const clone: UnifiedCertificateTransparencyLogList = JSON.parse(JSON.stringify(list));
  // Remove fields that come from providers and should not appear in our unified output
  for (const key of PROVIDER_TOP_LEVEL_KEYS) {
    // eslint-disable-next-line @typescript-eslint/no-dynamic-delete
    delete (clone as unknown as Record<string, unknown>)[key as unknown as string];
  }
  return clone;
}

async function mergeLogLists() {
  console.log('[*] Merging Google and Apple log lists...');
  try {
    const googleListPath = join(OUTPUT_DIR, 'google-log-list.json');
    const appleListPath = join(OUTPUT_DIR, 'apple-log-list.json');

    const googleRaw = await readFile(googleListPath, 'utf-8');
    const appleRaw = await readFile(appleListPath, 'utf-8');
    const googleList: UnifiedCertificateTransparencyLogList = JSON.parse(googleRaw);
    const appleList: UnifiedCertificateTransparencyLogList = JSON.parse(appleRaw);

    const unifiedList: UnifiedCertificateTransparencyLogList = {
      ...googleList,
      operators: [...(googleList.operators || [])],
    };

    const operatorMap = new Map(unifiedList.operators?.map((op) => [op.name, op]));

    for (const appleOp of appleList.operators || []) {
      if (operatorMap.has(appleOp.name)) {
        const googleOp = operatorMap.get(appleOp.name);
        if (googleOp) {
          if (!googleOp.logs) {
            googleOp.logs = [];
          }
          const logMap = new Map(googleOp.logs.map((log) => [log.log_id, log]));
          for (const appleLog of appleOp.logs || []) {
            if (!logMap.has(appleLog.log_id)) {
              googleOp.logs.push(appleLog);
            }
          }
        }
      } else {
        unifiedList.operators?.push(appleOp);
      }
    }

    // Canonicalize order for stability
    const ordered = sortOperatorsAndLogs(unifiedList);
    const sanitizedForOutput = removeProviderTopLevelKeys(ordered);

    // Compute deterministic version based on canonical content
    const canonical = cleanForHash(ordered);
    const canonicalHash = sha256Hex(stableStringify(canonical));

    // Prepare output with audit fields
    const output: UnifiedCertificateTransparencyLogList & {
      unified_version: string;
      unified_generated_at: string;
      unified_sources: {
        google?: { sha256: string };
        apple?: { sha256: string };
      };
    } = {
      unified_version: canonicalHash,
      unified_generated_at: new Date().toISOString(),
      unified_sources: {
        google: { sha256: sha256Hex(googleRaw) },
        apple: { sha256: sha256Hex(appleRaw) },
      },
      ...sanitizedForOutput,
    };

    const unifiedListPath = join(OUTPUT_DIR, 'unified-log-list.json');

    // Compare with existing file to avoid empty PRs unless forced
    let previousHash: string | null = null;
    try {
      const previousRaw = await readFile(unifiedListPath, 'utf-8');
      const previous = JSON.parse(previousRaw) as UnifiedCertificateTransparencyLogList;
      previousHash = sha256Hex(stableStringify(cleanForHash(previous)));
    } catch {
      // File may not exist on first run, that's fine
    }

    if (!forceBump && previousHash === canonicalHash) {
      console.log('[*] No meaningful changes detected in unified log list. Skipping write.');
      return;
    }

    await writeFile(unifiedListPath, JSON.stringify(output, null, 2));
    console.log(`[+] Successfully merged and saved to ${unifiedListPath}`);
  } catch (error) {
    console.error('[-] Error merging log lists:', error);
    exit(1);
  }
}

async function main() {
  await fetchLogLists();
}

main();
