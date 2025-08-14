import https from 'node:https';
import tls from 'node:tls';
import { HardenedHttpsValidationKit } from '../../src/validation-kit';
import { getCa, startTlsServer } from '../utils';
import { basicCtPolicy } from '../../src/options';

jest.mock('../../src/validators/ct', () => ({
  CTValidator: class {
    shouldRun = () => true;
    onBeforeConnect = (opts: any) => opts;
    validate = () => Promise.resolve();
  },
}));

describe('End-to-end HardenedHttpsValidationKit integration', () => {
  let server: ReturnType<typeof startTlsServer>;

  beforeAll(() => {
    server = startTlsServer();
  });

  afterAll(() => {
    server.close();
  });

  test('should allow ValidationKit to be attached to a standard https.Agent', (done) => {
    const kit = new HardenedHttpsValidationKit({
      ctPolicy: basicCtPolicy(),
      enableLogging: false,
    });
    const agent = new https.Agent({
      ca: getCa(),
    });

    kit.attachToAgent(agent);

    const req = https.get(
      {
        hostname: 'localhost',
        port: server.port,
        agent,
      },
      (res) => {
        expect(res.statusCode).toBe(200);
        res.on('data', () => {}); // Consume data
        res.on('end', () => {
          agent.destroy();
          done();
        });
      },
    );

    req.on('error', (err) => {
      done(err);
    });
  });

  test('should allow ValidationKit to be attached directly to a TLSSocket', (done) => {
    const kit = new HardenedHttpsValidationKit({
      ctPolicy: basicCtPolicy(),
      enableLogging: false,
    });

    const socket = tls.connect({
      host: 'localhost',
      port: server.port,
      ca: getCa(),
      servername: 'localhost',
    });

    kit.attachToSocket(socket);

    socket.on('secureConnect', () => {
      socket.write('GET / HTTP/1.1\r\nHost: localhost\r\n\r\n');
    });

    socket.on('data', (data) => {
      expect(data.toString()).toContain('HTTP/1.1 200 OK');
      socket.end();
    });

    socket.on('close', () => {
      done();
    });

    socket.on('error', (err) => {
      done(err);
    });
  });
});