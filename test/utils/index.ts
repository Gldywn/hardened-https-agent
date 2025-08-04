import * as fs from 'node:fs';
import * as path from 'node:path';
import { Certificate } from 'pkijs';
import { fromBER } from 'asn1js';
import { getTestDataDir } from '../../scripts/utils';
import { TlsPolicyAgent, CertificateTransparencyPolicy, OCSPPolicy } from '../../src';
import { CRLSet } from '@gldywn/crlset.js';

export { createMockSocket, createMockPeerCertificate } from './createMock';

const testDataDir = getTestDataDir();

export function loadTestCertsChain(hostname: string) {
  const filename = `${hostname.replace(/\./g, '-')}-certs-chain.pem`;
  const certChainPem = fs.readFileSync(path.join(testDataDir, filename), 'utf8');
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

export function loadLogList(filename: string) {
  return JSON.parse(fs.readFileSync(path.join(testDataDir, filename), 'utf8'));
}

export function loadTestCaBundle(): string {
  const caBundlePath = path.join(testDataDir, 'ca-bundle.crt');
  return fs.readFileSync(caBundlePath, 'utf8');
}

export const UNIFIED_LOG_LIST = loadLogList('unified-log-list.json');

export const DEFAULT_CT_POLICY = {
  logList: UNIFIED_LOG_LIST,
  minEmbeddedScts: 2,
  minDistinctOperators: 2,
};

export const CFSSL_CA_BUNDLE = loadTestCaBundle();

/**
 * Creates a pre-configured `TlsPolicyAgent` for testing purposes.
 *
 * By default, it is pre-configured with the Cloudflare CA, which is retrieved
 * from `testdata/ca-bundle.crt` and updated via the `fetch-test-ca-bundle.ts` script.
 * The default Certificate Transparency (CT) policy is set to Chrome's requirements,
 * and logging is disabled. All properties can be overridden for specific test needs.
 *
 * @returns A pre-configured `TlsPolicyAgent` for testing.
 */
export function getTestTlsPolicyAgent(
  options: {
    ca?: string | Buffer | (string | Buffer)[];
    ctPolicy?: CertificateTransparencyPolicy | undefined;
    ocspPolicy?: OCSPPolicy | undefined;
    crlSet?: 'downloadLatest' | CRLSet | undefined;
    enableLogging?: boolean;
  } = {},
) {
  const { ca = CFSSL_CA_BUNDLE, ctPolicy, ocspPolicy, crlSet, enableLogging = false } = options;

  return new TlsPolicyAgent({
    ca,
    ctPolicy,
    ocspPolicy,
    crlSet,
    enableLogging,
  });
}

export const delay = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
