import * as fs from 'node:fs';
import * as path from 'node:path';
import { Certificate } from 'pkijs';
import { fromBER } from 'asn1js';
import { getTestDataDir } from '../../scripts/utils';
import { HardenedHttpsAgent, CertificateTransparencyPolicy, OCSPPolicy, CRLSetPolicy } from '../../src';

export { createMockSocket, createMockPeerCertificate } from './createMock';
export { startTlsServer, getCa } from './server';
export { spoofedAxios } from './spoofedAxios';

const TEST_DATA_DIR = getTestDataDir();

function loadTestFile(filename: string): string {
  return fs.readFileSync(path.join(TEST_DATA_DIR, filename), 'utf8');
}

export function loadTestCertsChain(hostname: string) {
  const filename = `${hostname.replace(/\./g, '-')}-certs-chain.pem`;
  const certChainPem = loadTestFile(filename);
  const certPems = certChainPem
    .split('-----END CERTIFICATE-----')
    .filter((pem) => pem.trim() !== '')
    .map((pem) => `${pem.trim()}\n-----END CERTIFICATE-----`);

  const pkiCerts = certPems.map((pem) => {
    const der = Buffer.from(
      pem.replace('-----BEGIN CERTIFICATE-----', '').replace('-----END CERTIFICATE-----', '').replace(/\r\n/g, ''),
      'base64',
    );
    const asn1 = fromBER(der);
    return new Certificate({ schema: asn1.result });
  });

  return { certPems, pkiCerts };
}

export const TEST_CFSSL_CA_BUNDLE = loadTestFile('cfssl-ca-bundle.crt');

export const TEST_UNIFIED_LOG_LIST = JSON.parse(loadTestFile('unified-log-list.json'));

export const TEST_CT_POLICY = {
  logList: TEST_UNIFIED_LOG_LIST,
  minEmbeddedScts: 2,
  minDistinctOperators: 2,
};

/**
 * Creates a pre-configured `HardenedHttpsAgent` for testing purposes.
 *
 * By default, it is pre-configured with the Cloudflare CA, which is retrieved
 * from `testdata/ca-bundle.crt` and updated via the `fetch-test-ca-bundle.ts` script.
 * The default Certificate Transparency (CT) policy is set to Chrome's requirements,
 * and logging is disabled. All properties can be overridden for specific test needs.
 *
 * @returns A pre-configured `HardenedHttpsAgent` for testing.
 */
export function getTestHardenedHttpsAgent(
  options: {
    ca?: string | Buffer | (string | Buffer)[];
    ctPolicy?: CertificateTransparencyPolicy | undefined;
    ocspPolicy?: OCSPPolicy | undefined;
    crlSetPolicy?: CRLSetPolicy | undefined;
    enableLogging?: boolean;
    rejectUnauthorized?: boolean;
  } = {},
) {
  const { ca = TEST_CFSSL_CA_BUNDLE, ctPolicy, ocspPolicy, crlSetPolicy, enableLogging = false, rejectUnauthorized = true } = options;

  return new HardenedHttpsAgent({
    ca,
    ctPolicy,
    ocspPolicy,
    crlSetPolicy,
    enableLogging,
    rejectUnauthorized,
  });
}

export const delay = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
