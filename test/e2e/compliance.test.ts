import axios, { type AxiosRequestConfig } from 'axios';
import { delay, getTestTlsPolicyAgent, DEFAULT_CT_POLICY } from '../utils';
import { type OCSPPolicy } from '../../src';

// Note: This test file is not completely stable because it relies on network.
// If the remote server (e.g. google.com) updates its certificates and our local CA bundle becomes outdated,
// these tests may fail due to certificate validation errors unrelated to our code.
// Additionally, these tests may also fail for many other network-related reasons, such as DNS resolution issues, temporary server downtime, rate limiting, etc.
// For this reason, this file is excluded from CI environments.

const DOMAINS = [
  'https://bitcoin.org',
  'https://ethereum.org',
  'https://app.uniswap.org',
  'https://google.com',
  'https://cloudflare.com',
  'https://github.com',
  'https://microsoft.com',
  'https://apple.com',
  'https://amazon.com',
  'https://wikipedia.org',
  'https://stackoverflow.com',
  'https://nodejs.org',
  'https://vercel.com',
  'https://jpmorganchase.com',
  'https://bankofamerica.com',
  'https://wellsfargo.com',
  'https://mastercard.com',
];

const spoofedAxios = axios.create({
  headers: {
    'User-Agent':
      'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
    Accept:
      'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'Accept-Encoding': 'gzip, deflate, br',
    'Accept-Language': 'en-US,en;q=0.9',
    'Sec-Ch-Ua': '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
    'Sec-Ch-Ua-Mobile': '?0',
    'Sec-Ch-Ua-Platform': '"Linux"',
    'Sec-Fetch-Dest': 'document',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-Site': 'none',
    'Sec-Fetch-User': '?1',
    'Upgrade-Insecure-Requests': '1',
  },
});

describe('End-to-end TLS policy validation on major production domains', () => {
  jest.setTimeout(15000); // 15 seconds timeout for network requests

  test.each(DOMAINS)('should successfully connect to %s with Chrome CT policy', async (domain) => {
    console.log(`[E2E] Starting connection test for ${domain}...`);
    await delay(500); // Avoid network congestion

    const ocspPolicy: OCSPPolicy = {
      mode: 'stapling',
      failHard: true,
    };

    const agent = getTestTlsPolicyAgent({ ctPolicy: DEFAULT_CT_POLICY, ocspPolicy, enableLogging: true });

    const config: AxiosRequestConfig = {
      httpsAgent: agent,
    };

    try {
      const response = await spoofedAxios.get(domain, config);
      expect(response.status).toBe(200);
      console.log(`[E2E] Successfully connected to ${domain}.`);
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
      throw error; // Re-throw to ensure the test fails as expected
    }
  });
});
