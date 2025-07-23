import { writeFile, readFile, mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { exit } from 'node:process';
import type { UnifiedCertificateTransparencyLogList } from '../src/types/uni-ct-log-list-schema';
import { getTestDataDir } from './utils';
import { LOG_LISTS } from './constants';

const TEST_DATA_DIR = getTestDataDir();

async function fetchAndSave(name: string, url: string) {
  try {
    console.log(`[+] Fetching ${name} from ${url}...`);
    const response = await fetch(url);
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    const data = await response.json();
    const filePath = join(TEST_DATA_DIR, name);
    await writeFile(filePath, JSON.stringify(data, null, 2));
    console.log(`[+] Successfully saved to ${filePath}`);
  } catch (error) {
    console.error(`[-] Error fetching or saving ${name}:`, error);
    exit(1);
  }
}

async function fetchLogLists() {
  console.log('[*] Starting download of CT log lists...');
  await mkdir(TEST_DATA_DIR, { recursive: true });
  for (const logList of LOG_LISTS) {
    await fetchAndSave(logList.name, logList.sourceUrl);
  }
  console.log('[*] All CT log lists downloaded successfully.');
  await mergeLogLists();
}

async function mergeLogLists() {
  console.log('[*] Merging Google and Apple log lists...');
  try {
    const googleListPath = join(TEST_DATA_DIR, 'google-log-list.json');
    const appleListPath = join(TEST_DATA_DIR, 'apple-log-list.json');

    const googleList: UnifiedCertificateTransparencyLogList = JSON.parse(await readFile(googleListPath, 'utf-8'));
    const appleList: UnifiedCertificateTransparencyLogList = JSON.parse(await readFile(appleListPath, 'utf-8'));

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

    const unifiedListPath = join(TEST_DATA_DIR, 'unified-log-list.json');
    await writeFile(unifiedListPath, JSON.stringify(unifiedList, null, 2));
    console.log(`[+] Successfully merged and saved to ${unifiedListPath}`);
  } catch (error) {
    console.error('[-] Error merging log lists:', error);
    exit(1);
  }
}

async function main() {
  await fetchLogLists();
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
