import type { OCSPPolicy } from '../src/interfaces';
import * as tls from 'node:tls';
import { loadTestCertsChain, getTestTlsPolicyAgent } from './utils';
import { createMockSocket, createMockPeerCertificate } from './utils/createMock';
import * as easyOcsp from 'easy-ocsp';
import { OCSPStaplingValidator } from '../src/validators';

jest.mock('node:tls');
jest.mock('easy-ocsp');
jest.mock('../src/validators/ocsp-direct');

const mockParseOCSPResponse = easyOcsp.parseOCSPResponse as jest.Mock;
const mockGetCertURLs = easyOcsp.getCertURLs as jest.Mock;

describe('OCSP stapling validation', () => {
  beforeEach(() => {
    mockGetCertURLs.mockReturnValue({ ocspUrl: 'http://ocsp.digicert.com' });
  });

  afterEach(() => {
    jest.restoreAllMocks();
    mockParseOCSPResponse.mockClear();
    mockGetCertURLs.mockClear();
  });

  const failHardPolicy: OCSPPolicy = {
    mode: 'stapling',
    failHard: true,
  };

  const failSoftPolicy: OCSPPolicy = {
    mode: 'stapling',
    failHard: false,
  };

  // We're using a single hostname for all tests
  const hostname = 'google.com';
  const { pkiCerts } = loadTestCertsChain(hostname);
  const leafPkiCert = pkiCerts[0];
  const issuerPkiCert = pkiCerts[1];
  const leafMockCert = createMockPeerCertificate(leafPkiCert);
  const issuerMockCert = createMockPeerCertificate(issuerPkiCert);

  const peerCertificate: tls.DetailedPeerCertificate = {
    ...leafMockCert,
    issuerCertificate: issuerMockCert as tls.DetailedPeerCertificate,
  };

  it('should pass when a valid OCSP staple is provided', (done) => {
    mockParseOCSPResponse.mockResolvedValue({ status: 'good' });
    const mockSocket = createMockSocket(peerCertificate);
    jest.spyOn(tls, 'connect').mockReturnValue(mockSocket);

    const agent = getTestTlsPolicyAgent({ ocspPolicy: failHardPolicy });
    agent.createConnection({ ...agent.options }, (err, socket) => {
      expect(err).toBeNull();
      expect(socket).toBe(mockSocket);
      expect(mockParseOCSPResponse).toHaveBeenCalledTimes(1);
      done();
    });

    process.nextTick(() => {
      mockSocket.emit('OCSPResponse', Buffer.from('valid staple'));
      mockSocket.emit('secureConnect');
    });
  });

  it('should fail when no OCSP staple is received and policy is failHard', (done) => {
    const mockSocket = createMockSocket(peerCertificate);
    jest.spyOn(tls, 'connect').mockReturnValue(mockSocket);

    const agent = getTestTlsPolicyAgent({ ocspPolicy: failHardPolicy });

    // Simulate the secureConnect event on the next tick
    process.nextTick(() => mockSocket.emit('secureConnect'));

    agent.createConnection({ ...agent.options }, (err) => {
      expect(err).not.toBeNull();
      expect(err?.message).toBe('[OCSPStaplingValidator] OCSP stapling response required but not received.');
      done();
    });
  });

  it('should pass when no OCSP staple is received and policy is failSoft', (done) => {
    const mockSocket = createMockSocket(peerCertificate);
    jest.spyOn(tls, 'connect').mockReturnValue(mockSocket);

    const agent = getTestTlsPolicyAgent({ ocspPolicy: failSoftPolicy });
    agent.createConnection({ ...agent.options }, (err, socket) => {
      expect(err).toBeNull();
      expect(socket).toBe(mockSocket);
      done();
    });

    process.nextTick(() => mockSocket.emit('secureConnect'));
  });

  it('should fail when an empty OCSP response is received', (done) => {
    const mockSocket = createMockSocket(peerCertificate);
    jest.spyOn(tls, 'connect').mockReturnValue(mockSocket);

    const agent = getTestTlsPolicyAgent({ ocspPolicy: failHardPolicy });
    agent.createConnection({ ...agent.options }, (err) => {
      expect(err).not.toBeNull();
      expect(err?.message).toBe('[OCSPStaplingValidator] Empty OCSP stapling response.');
      done();
    });

    process.nextTick(() => mockSocket.emit('OCSPResponse', Buffer.alloc(0)));
  });

  it('should fail if the OCSP status is not "good"', (done) => {
    mockParseOCSPResponse.mockResolvedValue({ status: 'revoked' });
    const mockSocket = createMockSocket(peerCertificate);
    jest.spyOn(tls, 'connect').mockReturnValue(mockSocket);

    const agent = getTestTlsPolicyAgent({ ocspPolicy: failHardPolicy });
    agent.createConnection({ ...agent.options }, (err) => {
      expect(err).not.toBeNull();
      expect(err?.message).toBe('[OCSPStaplingValidator] Invalid certificate revocation status: revoked.');
      expect(mockParseOCSPResponse).toHaveBeenCalledTimes(1);
      done();
    });

    process.nextTick(() => mockSocket.emit('OCSPResponse', Buffer.from('staple for revoked cert')));
  });

  it('should fail if the OCSP status is not "good", even if policy is failSoft', (done) => {
    mockParseOCSPResponse.mockResolvedValue({ status: 'revoked' });
    const mockSocket = createMockSocket(peerCertificate);
    jest.spyOn(tls, 'connect').mockReturnValue(mockSocket);

    const agent = getTestTlsPolicyAgent({ ocspPolicy: failSoftPolicy });
    agent.createConnection({ ...agent.options }, (err) => {
      expect(err).not.toBeNull();
      expect(err?.message).toBe('[OCSPStaplingValidator] Invalid certificate revocation status: revoked.');
      expect(mockParseOCSPResponse).toHaveBeenCalledTimes(1);
      done();
    });

    process.nextTick(() => mockSocket.emit('OCSPResponse', Buffer.from('staple for revoked cert')));
  });

  it('should fail if OCSP response parsing fails', (done) => {
    const parsingError = new Error('Failed to parse OCSP response');
    mockParseOCSPResponse.mockRejectedValue(parsingError);
    const mockSocket = createMockSocket(peerCertificate);
    jest.spyOn(tls, 'connect').mockReturnValue(mockSocket);

    const agent = getTestTlsPolicyAgent({ ocspPolicy: failHardPolicy });
    agent.createConnection({ ...agent.options }, (err) => {
      expect(err).not.toBeNull();
      expect(err?.message).toBe(`[OCSPStaplingValidator] ${parsingError.message}`);
      done();
    });

    process.nextTick(() => mockSocket.emit('OCSPResponse', Buffer.from('malformed staple')));
  });

  it('should fail when the issuer certificate is missing', (done) => {
    const mockSocket = createMockSocket({
      ...peerCertificate,
      issuerCertificate: undefined,
    } as unknown as tls.DetailedPeerCertificate);
    jest.spyOn(tls, 'connect').mockReturnValue(mockSocket);

    const agent = getTestTlsPolicyAgent({ ocspPolicy: failHardPolicy });
    agent.createConnection({ ...agent.options }, (err) => {
      expect(err).not.toBeNull();
      expect(err?.message).toBe('[OCSPStaplingValidator] Could not find issuer certificate in the chain.');
      done();
    });

    process.nextTick(() => mockSocket.emit('OCSPResponse', Buffer.from('some staple')));
  });

  it('should not run when ocspPolicy is not defined', (done) => {
    const mockSocket = createMockSocket(peerCertificate);
    jest.spyOn(tls, 'connect').mockReturnValue(mockSocket);
    const ocspValidatorSpy = jest.spyOn(OCSPStaplingValidator.prototype, 'validate');

    const agent = getTestTlsPolicyAgent({ ocspPolicy: undefined });
    agent.createConnection({ ...agent.options }, (err, socket) => {
      expect(err).toBeNull();
      expect(socket).toBe(mockSocket);
      expect(ocspValidatorSpy).not.toHaveBeenCalled();
      done();
    });

    process.nextTick(() => mockSocket.emit('secureConnect'));
  });

  it("should not run when ocspPolicy mode is not 'stapling'", (done) => {
    const mockSocket = createMockSocket(peerCertificate);
    jest.spyOn(tls, 'connect').mockReturnValue(mockSocket);
    const ocspValidatorSpy = jest.spyOn(OCSPStaplingValidator.prototype, 'validate');

    const agent = getTestTlsPolicyAgent({ ocspPolicy: { mode: 'direct', failHard: true } });
    agent.createConnection({ ...agent.options }, (err, socket) => {
      expect(err).toBeNull();
      expect(socket).toBe(mockSocket);
      expect(ocspValidatorSpy).not.toHaveBeenCalled();
      done();
    });

    process.nextTick(() => mockSocket.emit('secureConnect'));
  });
});
