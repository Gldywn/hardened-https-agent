import axios, { type AxiosRequestConfig } from 'axios';
import { delay } from '../utils';
import {
  basicCtPolicy,
  basicDirectOcspPolicy,
  basicStaplingOcspPolicy,
  cfsslCaBundle,
  HardenedHttpsAgent,
  type HardenedHttpsAgentOptions,
} from '../../src';
import { spoofedAxios } from '../utils/spoofedAxios';

// Note: This test file is not completely stable because it relies on network.
// If the remote server (e.g. google.com) updates its certificates and our local CA bundle becomes outdated,
// these tests may fail due to certificate validation errors unrelated to our code.
// Additionally, these tests may also fail for many other network-related reasons, such as DNS resolution issues, temporary server downtime, rate limiting, etc.
// For this reason, this file is excluded from CI environments.

interface AcceptanceScenario {
  domains: string[];
  behaviorDescription: string;
  agentOptions: Partial<HardenedHttpsAgentOptions>;
}

const SCENARIOS: AcceptanceScenario[] = [
  {
    domains: ['https://google.com', 'https://github.com', 'https://microsoft.com', 'https://bitcoin.org'],
    behaviorDescription: 'Certificate Transparency',
    agentOptions: {
      ctPolicy: basicCtPolicy(),
    },
  },
  {
    // Google.com and github.com don't support OCSP stapling, so we skip them
    domains: ['https://microsoft.com', 'https://bitcoin.org'],
    behaviorDescription: 'OCSP Stapling',
    agentOptions: {
      ocspPolicy: basicStaplingOcspPolicy(),
    },
  },
  {
    domains: ['https://google.com', 'https://github.com', 'https://microsoft.com', 'https://bitcoin.org'],
    behaviorDescription: 'OCSP Direct',
    agentOptions: {
      ocspPolicy: basicDirectOcspPolicy(),
    },
  },
  /*
   TODO: Add scenarios for:
   - CRLs and CRLSet (need to find a way to test this against live targets)
   - `defaultAgentOptions` (when `basicMixedOcspPolicy()` is implemented)
  */
];

describe('End-to-end policy validation on known acceptance scenarios', () => {
  jest.setTimeout(15000); // 15 seconds timeout for network requests

  test.each(SCENARIOS)(
    '$behaviorDescription: should successfully connect to $domains',
    async ({ domains, behaviorDescription, agentOptions }) => {
      console.log(`[E2E] Starting test: ${behaviorDescription} should successfully connect to ${domains}`);
      await delay(1500); // Avoid network congestion and rate limiting

      const agent = new HardenedHttpsAgent({
        ca: cfsslCaBundle(),
        ...agentOptions,
        enableLogging: true,
      });

      const config: AxiosRequestConfig = {
        httpsAgent: agent,
      };

      for (const domain of domains) {
        try {
          const response = await spoofedAxios.get(domain, config);
          expect(response.status).toBe(200);
          console.log(`[E2E] ${behaviorDescription} successfully connected to ${domain}`);
        } catch (error: any) {
          if (axios.isAxiosError(error) && !error.response && error.code) {
            console.warn(
              `[E2E] Network error (${error.code}) for ${domain}. This might be a temporary issue. Please try running the test again.`,
            );
          } else if (axios.isAxiosError(error) && error.response && error.response.status === 403) {
            console.warn(
              `[E2E] Received HTTP status ${error.response.status} from ${domain}. This likely indicates TLS fingerprinting by the server.`,
            );
          }
          throw new Error(
            `[E2E] ${behaviorDescription} failed for domain: ${domain}\nError: ${error && error.message ? error.message : error}`,
          );
        }
      }
    },
  );
});
