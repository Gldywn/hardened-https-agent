import tls, { TLSSocket } from 'node:tls';
import { HardenedHttpsAgent } from '../src/agent';
import { HardenedHttpsAgentOptions } from '../src/interfaces';
import { HardenedHttpsValidationKit } from '../src/validation-kit';
import { createMockSocket } from './utils';

jest.mock('../src/validation-kit');
jest.mock('node:tls', () => ({
  ...jest.requireActual('node:tls'),
  connect: jest.fn(),
}));

const MockedValidationKit = HardenedHttpsValidationKit as jest.MockedClass<typeof HardenedHttpsValidationKit>;
const mockedTlsConnect = tls.connect as jest.Mock;

describe('HardenedHttpsAgent', () => {
  let mockSocket: TLSSocket;
  let mockValidationKit: jest.Mocked<HardenedHttpsValidationKit>;

  const baseOptions: HardenedHttpsAgentOptions = {
    ca: 'a-valid-ca',
  };

  beforeEach(() => {
    jest.clearAllMocks();

    mockSocket = createMockSocket();
    mockedTlsConnect.mockReturnValue(mockSocket);

    // Set up a default mock implementation for the validation kit
    MockedValidationKit.mockImplementation(() => {
      const kit = {
        applyBeforeConnect: jest.fn((opts) => opts),
        attachToSocket: jest.fn(),
      };
      // Assign the mock instance to our variable so we can assert calls on it
      mockValidationKit = kit as unknown as jest.Mocked<HardenedHttpsValidationKit>;
      return kit as any;
    });
  });

  test('should throw an error if "ca" property is not provided', () => {
    expect(() => new HardenedHttpsAgent({} as HardenedHttpsAgentOptions)).toThrow('The `ca` property cannot be empty.');
  });

  test('should throw an error if "ca" property is an empty array', () => {
    expect(() => new HardenedHttpsAgent({ ca: [] })).toThrow('The `ca` property cannot be empty.');
  });

  test('should instantiate ValidationKit with the correct options', () => {
    new HardenedHttpsAgent(baseOptions);
    expect(MockedValidationKit).toHaveBeenCalledWith(
      {
        ctPolicy: baseOptions.ctPolicy,
        ocspPolicy: baseOptions.ocspPolicy,
        crlSetPolicy: baseOptions.crlSetPolicy,
        loggerOptions: baseOptions.loggerOptions,
      }
    );
  });

  test('should call applyBeforeConnect on the validation kit', () => {
    const agent = new HardenedHttpsAgent(baseOptions);
    const connOpts = { host: 'example.com' };
    agent.createConnection(connOpts, jest.fn());

    expect(mockValidationKit.applyBeforeConnect).toHaveBeenCalledWith(connOpts);
  });

  test('should call attachToSocket on the validation kit', () => {
    const agent = new HardenedHttpsAgent(baseOptions);
    agent.createConnection({}, jest.fn());

    expect(mockValidationKit.attachToSocket).toHaveBeenCalledWith(mockSocket);
  });

  test('should use the connection options returned by applyBeforeConnect', () => {
    const agent = new HardenedHttpsAgent(baseOptions);
    const initialOpts = { host: 'initial' };
    const modifiedOpts = { host: 'modified' };
    mockValidationKit.applyBeforeConnect.mockReturnValue(modifiedOpts);

    agent.createConnection(initialOpts, jest.fn());
    expect(mockedTlsConnect).toHaveBeenCalledWith(modifiedOpts);
  });

  test('should handle socket errors during connection setup', (done) => {
    const agent = new HardenedHttpsAgent(baseOptions);
    const connectionError = new Error('TLS connection failed');

    const callback = jest.fn((err, stream) => {
      expect(err).toBe(connectionError);
      expect(stream).toBeUndefined();
      done();
    });

    agent.createConnection({}, callback);

    // Simulate the error event on the next tick
    process.nextTick(() => mockSocket.emit('error', connectionError));
  });
});
