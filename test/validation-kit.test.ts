import tls, { TLSSocket } from 'node:tls';
import { HardenedHttpsValidationKit } from '../src/validation-kit';
import { HardenedHttpsValidationKitOptions } from '../src/interfaces';
import {
  CTValidator,
  OCSPStaplingValidator,
  OCSPDirectValidator,
  OCSPMixedValidator,
  CRLSetValidator,
} from '../src/validators';
import { createMockSocket } from './utils';

jest.mock('../src/validators/ct');
jest.mock('../src/validators/ocsp-stapling');
jest.mock('../src/validators/ocsp-direct');
jest.mock('../src/validators/ocsp-mixed');
jest.mock('../src/validators/crlset');

const MockedCTValidator = CTValidator as jest.MockedClass<typeof CTValidator>;
const MockedOCSPStaplingValidator = OCSPStaplingValidator as jest.MockedClass<typeof OCSPStaplingValidator>;
const MockedOCSPDirectValidator = OCSPDirectValidator as jest.MockedClass<typeof OCSPDirectValidator>;
const MockedOCSPMixedValidator = OCSPMixedValidator as jest.MockedClass<typeof OCSPMixedValidator>;
const MockedCRLSetValidator = CRLSetValidator as jest.MockedClass<typeof CRLSetValidator>;

type MockValidator = {
  shouldRun: jest.Mock<boolean, [any]>;
  onBeforeConnect: jest.Mock<tls.ConnectionOptions, [tls.ConnectionOptions]>;
  validate: jest.Mock<Promise<void>, [TLSSocket, any]>;
  constructor: { name: string };
};

const createMockValidator = (name: string): MockValidator => ({
  shouldRun: jest.fn().mockReturnValue(false),
  onBeforeConnect: jest.fn((opts) => opts),
  validate: jest.fn().mockResolvedValue(undefined),
  constructor: { name },
});

describe('HardenedHttpsValidationKit', () => {
  let mockSocket: TLSSocket;
  let mockCtValidator: MockValidator;
  let mockOcspStaplingValidator: MockValidator;
  let mockOcspDirectValidator: MockValidator;
  let mockOcspMixedValidator: MockValidator;
  let mockCrlSetValidator: MockValidator;

  const baseOptions: HardenedHttpsValidationKitOptions = {
    enableLogging: false,
  };

  beforeEach(() => {
    jest.clearAllMocks();

    mockSocket = createMockSocket();

    mockCtValidator = createMockValidator('CTValidator');
    mockOcspStaplingValidator = createMockValidator('OCSPStaplingValidator');
    mockOcspDirectValidator = createMockValidator('OCSPDirectValidator');
    mockOcspMixedValidator = createMockValidator('OCSPMixedValidator');
    mockCrlSetValidator = createMockValidator('CRLSetValidator');

    MockedCTValidator.mockImplementation(() => mockCtValidator as any);
    MockedOCSPStaplingValidator.mockImplementation(() => mockOcspStaplingValidator as any);
    MockedOCSPDirectValidator.mockImplementation(() => mockOcspDirectValidator as any);
    MockedOCSPMixedValidator.mockImplementation(() => mockOcspMixedValidator as any);
    MockedCRLSetValidator.mockImplementation(() => mockCrlSetValidator as any);
  });

  test('should check all validators to see if they should run', () => {
    const kit = new HardenedHttpsValidationKit(baseOptions);
    kit.attachToSocket(mockSocket);

    expect(mockCtValidator.shouldRun).toHaveBeenCalledWith(baseOptions);
    expect(mockOcspStaplingValidator.shouldRun).toHaveBeenCalledWith(baseOptions);
    expect(mockOcspDirectValidator.shouldRun).toHaveBeenCalledWith(baseOptions);
    expect(mockOcspMixedValidator.shouldRun).toHaveBeenCalledWith(baseOptions);
    expect(mockCrlSetValidator.shouldRun).toHaveBeenCalledWith(baseOptions);
  });

  test('should only run validation for validators where shouldRun returns true', () => {
    mockCtValidator.shouldRun.mockReturnValue(true);
    mockOcspStaplingValidator.shouldRun.mockReturnValue(false);

    const kit = new HardenedHttpsValidationKit(baseOptions);
    kit.attachToSocket(mockSocket);

    expect(mockCtValidator.validate).toHaveBeenCalled();
    expect(mockOcspStaplingValidator.validate).not.toHaveBeenCalled();
  });

  test('should run validation for all validators when all shouldRun return true', () => {
    mockCtValidator.shouldRun.mockReturnValue(true);
    mockOcspStaplingValidator.shouldRun.mockReturnValue(true);

    const kit = new HardenedHttpsValidationKit(baseOptions);
    kit.attachToSocket(mockSocket);

    expect(mockCtValidator.validate).toHaveBeenCalled();
    expect(mockOcspStaplingValidator.validate).toHaveBeenCalled();
  });

  test('should not pause/resume the socket if no validators are active', () => {
    mockCtValidator.shouldRun.mockReturnValue(false);
    mockOcspStaplingValidator.shouldRun.mockReturnValue(false);

    const kit = new HardenedHttpsValidationKit(baseOptions);
    kit.attachToSocket(mockSocket);

    expect(mockCtValidator.validate).not.toHaveBeenCalled();
    expect(mockOcspStaplingValidator.validate).not.toHaveBeenCalled();
    expect(mockSocket.pause).not.toHaveBeenCalled();
    expect(mockSocket.resume).not.toHaveBeenCalled();
  });

  test('should pause and resume the socket when all active validators pass successfully', (done) => {
    mockCtValidator.shouldRun.mockReturnValue(true);
    mockOcspStaplingValidator.shouldRun.mockReturnValue(true);

    mockCtValidator.validate.mockResolvedValue(undefined);
    mockOcspStaplingValidator.validate.mockResolvedValue(undefined);

    const kit = new HardenedHttpsValidationKit(baseOptions);
    mockSocket.on('hardened:validation:success', () => {
      expect(mockSocket.pause).toHaveBeenCalled();
      expect(mockSocket.resume).toHaveBeenCalled();
      done();
    });
    kit.attachToSocket(mockSocket);
  });

  test('should destroy the socket if any active validator fails', (done) => {
    // Mock the socket.destroy method to avoid unhandled error propagation
    mockSocket.destroy = jest.fn();

    const validationError = new Error('Validation failed');
    mockCtValidator.shouldRun.mockReturnValue(true);
    mockCtValidator.validate.mockRejectedValue(validationError);

    const kit = new HardenedHttpsValidationKit(baseOptions);
    mockSocket.on('hardened:validation:error', (err) => {
      // Check on the next tick to allow the `destroy` method to be called by the kit
      process.nextTick(() => {
        expect(err).toBe(validationError);
        expect(mockSocket.resume).not.toHaveBeenCalled();
        expect(mockSocket.destroy).toHaveBeenCalledWith(validationError);

        done();
      });
    });
    kit.attachToSocket(mockSocket);
  });

  test('should pass modified options from one validator to the next during onBeforeConnect', () => {
    const initialConnOpts = { host: 'example.com' };
    const ctModifiedOpts = { ...initialConnOpts, ctOption: true };
    const ocspModifiedOpts = { ...ctModifiedOpts, ocspOption: true };

    mockCtValidator.shouldRun.mockReturnValue(true);
    mockOcspStaplingValidator.shouldRun.mockReturnValue(true);

    mockCtValidator.onBeforeConnect.mockReturnValue(ctModifiedOpts);
    mockOcspStaplingValidator.onBeforeConnect.mockReturnValue(ocspModifiedOpts);

    const kit = new HardenedHttpsValidationKit(baseOptions);
    const finalOpts = kit.applyBeforeConnect(initialConnOpts);

    expect(mockCtValidator.onBeforeConnect).toHaveBeenCalledWith(initialConnOpts);
    expect(mockOcspStaplingValidator.onBeforeConnect).toHaveBeenCalledWith(ctModifiedOpts);
    expect(finalOpts).toEqual(ocspModifiedOpts);
  });

  test('should not run validation twice on the same socket', () => {
    const kit = new HardenedHttpsValidationKit(baseOptions);
    mockCtValidator.shouldRun.mockReturnValue(true);

    kit.attachToSocket(mockSocket);
    kit.attachToSocket(mockSocket);

    expect(mockCtValidator.validate).toHaveBeenCalledTimes(1);
  });
});
