import { type AxiosRequestConfig } from 'axios';
import { delay } from '../utils';
import { spoofedAxios } from '../utils/spoofedAxios';
import { HardenedHttpsAgent, type HardenedHttpsAgentOptions } from '../../src';
import {
  basicCtPolicy,
  basicDirectOcspPolicy,
  basicStaplingOcspPolicy,
  cfsslCaBundle,
} from '../../src/default-options';

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

interface FailureScenario {
  domain: string;
  behaviorDescription: string;
  failureDescription: string;
  expectedError: string | RegExp;
  agentOptions: Partial<HardenedHttpsAgentOptions>;
}

const SCENARIOS: FailureScenario[] = [
  {
    domain: 'https://expired.badssl.com/',
    behaviorDescription: 'Node.js native behavior',
    failureDescription: 'an expired certificate',
    expectedError: /certificate has expired/,
    agentOptions: {}, // Relies on Node.js native behavior
  },
  {
    domain: 'https://wrong.host.badssl.com/',
    behaviorDescription: 'Node.js native behavior',
    failureDescription: 'a certificate with a hostname mismatch',
    expectedError: /Hostname\/IP does not match certificate's altnames/,
    agentOptions: {}, // Relies on Node.js native behavior
  },
  {
    domain: 'https://untrusted-root.badssl.com/',
    behaviorDescription: 'Node.js native behavior',
    failureDescription: 'a certificate signed by an untrusted CA',
    expectedError: /self-signed certificate in certificate chain/,
    agentOptions: {}, // Relies on Node.js native behavior
  },
  {
    domain: 'https://revoked.badssl.com/',
    behaviorDescription: 'OCSP Stapling',
    failureDescription: 'a revoked certificate',
    expectedError: /\[OCSPStaplingValidator\] Empty OCSP stapling response\./,
    agentOptions: { ocspPolicy: basicStaplingOcspPolicy() },
  },
  {
    domain: 'https://revoked.badssl.com/',
    behaviorDescription: 'OCSP Direct',
    failureDescription: 'a revoked certificate',
    expectedError: /\[OCSPDirectValidator\] Certificate does not contain OCSP url/,
    agentOptions: { ocspPolicy: basicDirectOcspPolicy() },
  },
  {
    domain: 'https://no-sct.badssl.com/',
    behaviorDescription: 'Certificate Transparency',
    failureDescription: 'a certificate without any SCTs',
    expectedError: /No SCTs found in the certificate/,
    agentOptions: {
      ctPolicy: basicCtPolicy(),
    },
  },
  {
    domain: 'https://invalid-expected-sct.badssl.com/',
    behaviorDescription: 'Certificate Transparency',
    failureDescription: 'a certificate with invalid SCTs',
    expectedError: /Certificate has 0 valid embedded SCTs \(out of 1 found\), but policy requires at least 2\./,
    agentOptions: {
      ctPolicy: basicCtPolicy(),
      rejectUnauthorized: false, // We expect the certificate to be expired, so we don't want to reject it
    },
  },
  // TODO: Add scenarios for CRLs and CRLSet (need to find a way to test this against live targets)
];

describe('End-to-end policy validation on known failure scenarios', () => {
  jest.setTimeout(15000); // 15 seconds timeout for network requests

  test.each(SCENARIOS)(
    '$behaviorDescription: should reject $domain due to $failureDescription',
    async ({ domain, behaviorDescription, failureDescription, expectedError, agentOptions }) => {
      console.log(`[E2E] Starting test: ${behaviorDescription} should reject ${domain} due to ${failureDescription}`);
      await delay(1500); // Avoid network congestion and rate limiting

      const agent = new HardenedHttpsAgent({
        ca: cfsslCaBundle(),
        ...agentOptions,
        enableLogging: true,
      });

      const config: AxiosRequestConfig = {
        httpsAgent: agent,
      };

      await expect(spoofedAxios.get(domain, config)).rejects.toThrow(expectedError);
      console.log(`[E2E] ${behaviorDescription} successfully rejected ${domain} due to ${failureDescription}`);
    },
  );
});
