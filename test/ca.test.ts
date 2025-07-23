import { type AxiosRequestConfig } from 'axios';
import { TlsPolicyAgent } from '../src';
import { getTestTlsPolicyAgent } from './utils';
import axios from 'axios';

// Note: This test file is not completely stable because it relies on live network access.
// If the remote server (such as Google) updates its certificates and our local CA bundle becomes outdated,
// these tests may fail due to certificate validation errors unrelated to our code.
// For this reason, this file is excluded from CI environments.
describe('CA validation', () => {
  it('should throw an error if no CA is provided', () => {
    // @ts-expect-error
    expect(() => new TlsPolicyAgent({})).toThrow('The `ca` property cannot be empty.');
  });

  it('should successfully connect to a valid host with the correct CA', async () => {
    const agent = getTestTlsPolicyAgent();

    const config: AxiosRequestConfig = {
      httpsAgent: agent,
    };

    const response = await axios.get('https://google.com', config);
    expect(response.status).toBe(200);
  });

  it('should fail to connect to a valid host with an incorrect CA', async () => {
    const agent = getTestTlsPolicyAgent({
      ca: '-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----',
    });

    const config: AxiosRequestConfig = {
      httpsAgent: agent,
    };

    await expect(axios.get('https://google.com', config)).rejects.toThrow();
  });
});
