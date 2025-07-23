import axios from 'axios';
import * as tls from 'node:tls';
import { Duplex } from 'stream';
import { getTestTlsPolicyAgent } from './utils';

jest.mock('node:tls');

describe('Axios integration', () => {
  afterEach(() => {
    jest.restoreAllMocks();
  });

  it("should route requests through the agent's createConnection method", async () => {
    const agent = getTestTlsPolicyAgent();
    const createConnectionSpy = jest.spyOn(agent, 'createConnection');

    jest.spyOn(tls, 'connect').mockImplementation(((options: tls.ConnectionOptions) => {
      const mockSocket = new Duplex({
        read() {},
        write(_chunk, _encoding, callback) {
          callback();
        },
      });
      (mockSocket as any).setKeepAlive = jest.fn();
      (mockSocket as any).servername = options.host;

      // Postpone the error emission to the next tick to allow axios to set up its listeners
      process.nextTick(() => {
        // Destroy the socket with an error to simulate a connection reset
        mockSocket.destroy(new Error('ECONNRESET'));
      });
      return mockSocket as tls.TLSSocket;
    }) as any);

    const client = axios.create({ httpsAgent: agent });

    await expect(client.get('https://google.com')).rejects.toThrow('ECONNRESET');
    expect(createConnectionSpy).toHaveBeenCalledTimes(1);

    const [options] = createConnectionSpy.mock.calls[0];
    expect(options).toMatchObject({
      host: 'google.com',
      port: 443,
    });
  });
});
