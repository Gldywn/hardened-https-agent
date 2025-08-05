import { writeFile, mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { CFSSL_CA_BUNDLE_URL } from './constants';
import { getTestDataDir, getResDir } from './utils';

const forTest = process.argv.includes('--for-test');
const OUTPUT_DIR = forTest ? getTestDataDir() : getResDir();

async function fetchCaBundle() {
  try {
    console.log(`[+] Fetching CA bundle from ${CFSSL_CA_BUNDLE_URL}...`);
    const response = await fetch(CFSSL_CA_BUNDLE_URL);
    if (!response.ok) {
      throw new Error(`Failed to fetch CA bundle: ${response.statusText}`);
    }
    const certBundle = await response.text();

    await mkdir(OUTPUT_DIR, { recursive: true });

    const outputPath = join(OUTPUT_DIR, 'cfssl-ca-bundle.crt');
    await writeFile(outputPath, certBundle);
    console.log(`[+] CA bundle successfully saved to ${outputPath}`);
  } catch (error) {
    console.error('[-] Error fetching CA bundle:', error);
    process.exit(1);
  }
}

async function main() {
  await fetchCaBundle();
}

main();
