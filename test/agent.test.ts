import { Duplex } from 'node:stream';
import tls, { TLSSocket } from 'node:tls';
import { TlsPolicyAgent } from '../src/agent';
import { TlsPolicyAgentOptions } from '../src/interfaces';
import { CTValidator, OCSPStaplingValidator } from '../src/validators';

jest.mock('../src/validators/ct');
jest.mock('../src/validators/ocsp-stapling');
jest.mock('node:tls', () => ({
  ...jest.requireActual('node:tls'),
  connect: jest.fn(),
}));

const MockedCTValidator = CTValidator as jest.MockedClass<typeof CTValidator>;
const MockedOCSPStaplingValidator = OCSPStaplingValidator as jest.MockedClass<typeof OCSPStaplingValidator>;
const mockedTlsConnect = tls.connect as jest.Mock;

type MockValidator = {
  shouldRun: jest.Mock<boolean, [TlsPolicyAgentOptions]>;
  onBeforeConnect: jest.Mock<tls.ConnectionOptions, [tls.ConnectionOptions]>;
  validate: jest.Mock<Promise<void>, [TLSSocket, TlsPolicyAgentOptions]>;
  constructor: { name: string };
};

const createMockValidator = (name: string): MockValidator => ({
  shouldRun: jest.fn().mockReturnValue(false),
  onBeforeConnect: jest.fn((opts) => opts),
  validate: jest.fn().mockResolvedValue(undefined),
  constructor: { name },
});

describe('TlsPolicyAgent', () => {
  let mockSocket: jest.Mocked<TLSSocket>;
  let mockCtValidator: MockValidator;
  let mockOcspValidator: MockValidator;

  const baseOptions: TlsPolicyAgentOptions = {
    ca: 'a-valid-ca',
    enableLogging: false,
  };

  beforeEach(() => {
    jest.clearAllMocks();

    const duplex = new Duplex({ read() {}, write() {} });
    mockSocket = Object.assign(duplex, {
      on: jest.fn(),
      once: jest.fn(),
      destroy: jest.fn(),
    }) as unknown as jest.Mocked<TLSSocket>;
    mockedTlsConnect.mockReturnValue(mockSocket);

    mockCtValidator = createMockValidator('CTValidator');
    mockOcspValidator = createMockValidator('OCSPStaplingValidator');

    MockedCTValidator.mockImplementation(() => mockCtValidator as any);
    MockedOCSPStaplingValidator.mockImplementation(() => mockOcspValidator as any);
  });

  test('should throw an error if "ca" property is not provided', () => {
    expect(() => new TlsPolicyAgent({} as TlsPolicyAgentOptions)).toThrow('The `ca` property cannot be empty.');
  });

  test('should throw an error if "ca" property is an empty array', () => {
    expect(() => new TlsPolicyAgent({ ca: [] })).toThrow('The `ca` property cannot be empty.');
  });

  test('should check all validators to see if they should run', () => {
    const agent = new TlsPolicyAgent(baseOptions);
    agent.createConnection({}, jest.fn());

    expect(mockCtValidator.shouldRun).toHaveBeenCalledWith(baseOptions);
    expect(mockOcspValidator.shouldRun).toHaveBeenCalledWith(baseOptions);
  });

  test('should only run validation for validators where shouldRun returns true', () => {
    mockCtValidator.shouldRun.mockReturnValue(true);
    mockOcspValidator.shouldRun.mockReturnValue(false);

    const agent = new TlsPolicyAgent(baseOptions);
    agent.createConnection({}, jest.fn());

    expect(mockCtValidator.validate).toHaveBeenCalled();
    expect(mockOcspValidator.validate).not.toHaveBeenCalled();
  });

  test('should run validation for all validators when all shouldRun return true', () => {
    mockCtValidator.shouldRun.mockReturnValue(true);
    mockOcspValidator.shouldRun.mockReturnValue(true);

    const agent = new TlsPolicyAgent(baseOptions);
    agent.createConnection({}, jest.fn());

    expect(mockCtValidator.validate).toHaveBeenCalled();
    expect(mockOcspValidator.validate).toHaveBeenCalled();
  });

  test('should proceed with native TLS validation if no validators are active', (done) => {
    mockCtValidator.shouldRun.mockReturnValue(false);
    mockOcspValidator.shouldRun.mockReturnValue(false);

    const agent = new TlsPolicyAgent(baseOptions);
    const callback = jest.fn((err, stream) => {
      expect(err).toBeNull();
      expect(stream).toBe(mockSocket);
      done();
    });

    agent.createConnection({}, callback);

    expect(mockCtValidator.validate).not.toHaveBeenCalled();
    expect(mockOcspValidator.validate).not.toHaveBeenCalled();
    expect(mockSocket.once).toHaveBeenCalledWith('secureConnect', expect.any(Function));

    // Simulate the 'secureConnect' event to trigger the callback
    const secureConnectCallback = mockSocket.once.mock.calls[0][1];
    secureConnectCallback(Buffer.from(''));
  });

  test('should release the socket when all active validators pass successfully', async () => {
    mockCtValidator.shouldRun.mockReturnValue(true);
    mockOcspValidator.shouldRun.mockReturnValue(true);

    const ctPromise = Promise.resolve();
    const ocspPromise = Promise.resolve();
    mockCtValidator.validate.mockReturnValue(ctPromise);
    mockOcspValidator.validate.mockReturnValue(ocspPromise);

    const agent = new TlsPolicyAgent(baseOptions);
    const callback = jest.fn();

    agent.createConnection({}, callback);

    // Wait for all validation promises to resolve
    await Promise.all([ctPromise, ocspPromise]);
    // Allow the promise chain in the agent to resolve
    await new Promise(process.nextTick);

    expect(callback).toHaveBeenCalledWith(null, mockSocket);
  });

  test('should destroy the socket if any active validator fails', async () => {
    const validationError = new Error('Validation failed');
    mockCtValidator.shouldRun.mockReturnValue(true);
    mockCtValidator.validate.mockRejectedValue(validationError);

    const agent = new TlsPolicyAgent(baseOptions);
    const callback = jest.fn();

    agent.createConnection({}, callback);

    // Allow promise rejection to propagate
    await new Promise(process.nextTick);

    expect(mockSocket.destroy).toHaveBeenCalledWith(validationError);
    expect(callback).toHaveBeenCalledWith(validationError, undefined);
  });

  test('should pass modified options from one validator to the next', () => {
    const initialConnOpts = { host: 'example.com' };
    const ctModifiedOpts = { ...initialConnOpts, ctOption: true };
    const ocspModifiedOpts = { ...ctModifiedOpts, ocspOption: true };

    mockCtValidator.shouldRun.mockReturnValue(true);
    mockOcspValidator.shouldRun.mockReturnValue(true);

    mockCtValidator.onBeforeConnect.mockReturnValue(ctModifiedOpts);
    mockOcspValidator.onBeforeConnect.mockReturnValue(ocspModifiedOpts);

    const agent = new TlsPolicyAgent(baseOptions);
    agent.createConnection(initialConnOpts, jest.fn());

    expect(mockCtValidator.onBeforeConnect).toHaveBeenCalledWith(initialConnOpts);
    expect(mockOcspValidator.onBeforeConnect).toHaveBeenCalledWith(ctModifiedOpts);
    expect(mockedTlsConnect).toHaveBeenCalledWith(ocspModifiedOpts);
  });

  test('should handle socket errors during connection setup', (done) => {
    const agent = new TlsPolicyAgent(baseOptions);
    const connectionError = new Error('TLS connection failed');

    const callback = jest.fn((err, stream) => {
      expect(err).toBe(connectionError);
      expect(stream).toBeUndefined();
      done();
    });

    agent.createConnection({}, callback);

    // Find the error handler. Using .find() is safer than assuming the order of .on() calls.
    const onErrorCallback = (mockSocket.on as jest.Mock).mock.calls.find((call: any[]) => call[0] === 'error')?.[1];
    if (onErrorCallback) {
      onErrorCallback(connectionError);
    } else {
      done(new Error('onError callback was not registered on the socket.'));
    }
  });
});
