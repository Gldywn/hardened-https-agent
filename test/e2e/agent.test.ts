import https from 'node:https';
import axios from 'axios';
import { HardenedHttpsAgent } from '../../src/agent';
import { getCa, startTlsServer } from '../utils/server';

describe('End-to-end HardenedHttpsAgent integration', () => {
  let server: ReturnType<typeof startTlsServer>;
  let agent: HardenedHttpsAgent;

  beforeAll(() => {
    server = startTlsServer();
  });

  afterAll(() => {
    server.close();
  });

  beforeEach(() => {
    agent = new HardenedHttpsAgent({
      ca: getCa(),
    });
  });

  afterEach(() => {
    agent.destroy();
  });

  describe('with axios', () => {
    it("should route requests through the agent's createConnection method", async () => {
      const createConnectionSpy = jest.spyOn(agent, 'createConnection');
      const client = axios.create({
        httpsAgent: agent,
      });

      const response = await client.get(`https://localhost:${server.port}`);

      expect(response.status).toBe(200);
      expect(createConnectionSpy).toHaveBeenCalledTimes(1);

      const [options] = createConnectionSpy.mock.calls[0];
      expect(options).toMatchObject({
        host: 'localhost',
        port: String(server.port),
      });
    });
  });

  describe('with native https module', () => {
    it("should route requests through the agent's createConnection method", (done) => {
      const createConnectionSpy = jest.spyOn(agent, 'createConnection');

      const req = https.get(
        {
          hostname: 'localhost',
          port: server.port,
          agent,
          ca: getCa(),
        },
        (res) => {
          expect(res.statusCode).toBe(200);
          res.on('data', () => {}); // Consume data to allow 'end' event to fire
          res.on('end', () => {
            expect(createConnectionSpy).toHaveBeenCalledTimes(1);
            const [options] = createConnectionSpy.mock.calls[0];
            expect(options).toMatchObject({
              host: 'localhost',
              port: server.port,
            });
            done();
          });
        },
      );

      req.on('error', (err) => {
        done(err);
      });
    });
  });
});
