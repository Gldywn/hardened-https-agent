import { writeFile, mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import tls from 'node:tls';
import { getTestDataDir } from './utils';
import { TEST_CERT_HOSTS } from './constants';

const TEST_DATA_DIR = getTestDataDir();
const CERT_FETCH_TIMEOUT = 5000;

async function fetchCerts() {
  console.log('[*] Starting download of certificates...');
  await mkdir(TEST_DATA_DIR, { recursive: true });

  for (const host of TEST_CERT_HOSTS) {
    try {
      console.log(`[+] Fetching certificate for ${host}...`);
      const pemCert = await getCertificateChain(host);
      const name = `${host.replace(/\./g, '-')}-certs-chain.pem`;
      const filePath = join(TEST_DATA_DIR, name);
      await writeFile(filePath, pemCert);
      console.log(`[+] Successfully saved to ${filePath}`);
    } catch (error) {
      console.error(`[-] Error fetching certificate for ${host}:`, error);
    }
  }
  console.log('[*] Certificates downloaded successfully.');
}

function getCertificateChain(host: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const options = {
      host,
      port: 443,
      rejectUnauthorized: false,
      servername: host,
    };

    const socket = tls.connect(options, () => {
      let chain = '';
      let cert: tls.DetailedPeerCertificate | undefined = socket.getPeerCertificate(true);
      const seenCerts = new Set();

      while (cert && cert.raw && !seenCerts.has(cert.fingerprint256)) {
        seenCerts.add(cert.fingerprint256);
        const pem = `-----BEGIN CERTIFICATE-----\n${cert.raw
          .toString('base64')
          .replace(/(.{64})/g, '$1\n')}\n-----END CERTIFICATE-----\n`;
        chain += pem;
        if (cert.issuerCertificate) {
          cert = cert.issuerCertificate;
        } else {
          cert = undefined;
        }
      }
      socket.end();
      resolve(chain);
    });

    socket.on('error', (err) => {
      reject(err);
    });

    socket.setTimeout(CERT_FETCH_TIMEOUT, () => {
      socket.destroy(new Error(`TLS connection to ${host} timed out.`));
    });
  });
}

async function main() {
  await fetchCerts();
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
