import { type AxiosRequestConfig } from 'axios';
import { TlsPolicyAgent } from '../src';
import { getTestTlsPolicyAgent } from './utils';
import axios from 'axios';

describe('CA validation', () => {
  it('should throw an error if no CA is provided', () => {
    // @ts-expect-error
    expect(() => new TlsPolicyAgent({})).toThrow('The `ca` property cannot be empty.');
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
