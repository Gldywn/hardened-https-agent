import axios, { type AxiosRequestConfig } from 'axios';
import { delay, getTestTlsPolicyAgent } from '../utils';

// Note: This test file is not completely stable because it relies on network.
// If the remote server (e.g. google.com) updates its certificates and our local CA bundle becomes outdated,
// these tests may fail due to certificate validation errors unrelated to our code.
// Additionally, these tests may also fail for many other network-related reasons, such as DNS resolution issues, temporary server downtime, rate limiting, etc.
// For this reason, this file is excluded from CI environments.
//
// Furthermore, some of these tests validate behavior that is natively handled by the underlying Node.js TLS stack
// (e.g., certificate expiration, hostname verification). While our agent doesn't add logic for these specific checks,
// these tests are included to ensure that our agent correctly propagates these fundamental TLS errors, providing
// transparency and confirming the behavior of the underlying stack.

const SCENARIOS = [
  {
    domain: 'https://expired.badssl.com/',
    description: 'an expired certificate',
    expectedError: 'certificate has expired',
  },
  {
    domain: 'https://wrong.host.badssl.com/',
    description: 'a certificate with a hostname mismatch',
    expectedError: "Hostname/IP does not match certificate's altnames: Host: wrong.host.badssl.com. is not in the cert's altnames: DNS:*.badssl.com, DNS:badssl.com",
  },
  {
    domain: 'https://untrusted-root.badssl.com/',
    description: 'a certificate signed by an untrusted CA',
    expectedError: 'self-signed certificate in certificate chain',
  },
  // TODO: Waiting for OCSP check implementation
  // {
  //   domain: 'https://revoked.badssl.com/',
  //   description: 'a revoked certificate',
  //   expectedError: 'CERT_REVOKED',
  // },
  {
    domain: 'https://no-sct.badssl.com/',
    description: 'a certificate missing SCTs (Certificate Transparency)',
    expectedError: 'No SCTs found in the certificate',
  },
];

describe('End-to-end TLS policy validation on known rejection scenarios', () => {
  jest.setTimeout(15000); // 15 seconds timeout for network requests

  test.each(SCENARIOS)('should reject connection to $domain due to $description', async ({ domain, description, expectedError }) => {
    console.log(`[E2E] Starting rejection test for ${domain} (${description})...`);
    await delay(500); // Avoid network congestion
    
    const agent = getTestTlsPolicyAgent({ enableLogging: false });

    const config: AxiosRequestConfig = {
      httpsAgent: agent,
    };

    await expect(axios.get(domain, config)).rejects.toThrow(expectedError);
    console.log(`[E2E] Successfully rejected connection to ${domain}.`);
  });
}); 