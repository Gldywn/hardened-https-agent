import type { OCSPPolicy } from '../src/interfaces';
import * as tls from 'node:tls';
import { loadTestCertsChain, getTestTlsPolicyAgent } from './utils';
import { createMockSocket, createMockPeerCertificate } from './utils/createMock';
import * as easyOcsp from 'easy-ocsp';
import { OCSPDirectValidator } from '../src/validators';
import { WrappedError } from '../src/validators/base';

jest.mock('node:tls');
jest.mock('easy-ocsp');
jest.mock('../src/validators/ocsp-stapling');

const mockGetCertStatus = easyOcsp.getCertStatus as jest.Mock;

describe('OCSP direct validation', () => {
  afterEach(() => {
    jest.restoreAllMocks();
    mockGetCertStatus.mockClear();
  });

  const failHardPolicy: OCSPPolicy = {
    mode: 'direct',
    failHard: true,
  };

  const failSoftPolicy: OCSPPolicy = {
    mode: 'direct',
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

  it('should pass when the certificate status is "good"', (done) => {
    mockGetCertStatus.mockResolvedValue({ status: 'good' });
    const mockSocket = createMockSocket(peerCertificate);
    jest.spyOn(tls, 'connect').mockReturnValue(mockSocket);

    const agent = getTestTlsPolicyAgent({ ocspPolicy: failHardPolicy });
    agent.createConnection({ ...agent.options }, (err, socket) => {
      expect(err).toBeNull();
      expect(socket).toBe(mockSocket);
      expect(mockGetCertStatus).toHaveBeenCalledTimes(1);
      done();
    });

    process.nextTick(() => {
      mockSocket.emit('secureConnect');
    });
  });

  it('should fail when getCertStatus throws and policy is failHard', (done) => {
    const ocspError = new Error('OCSP request failed');
    mockGetCertStatus.mockRejectedValue(ocspError);
    const mockSocket = createMockSocket(peerCertificate);
    jest.spyOn(tls, 'connect').mockReturnValue(mockSocket);

    const agent = getTestTlsPolicyAgent({ ocspPolicy: failHardPolicy });

    agent.createConnection({ ...agent.options }, (err) => {
      expect(err).not.toBeNull();
      expect(err?.message).toBe(`[OCSPDirectValidator] ${ocspError.message}`);
      done();
    });

    process.nextTick(() => mockSocket.emit('secureConnect'));
  });

  it('should pass when getCertStatus throws and policy is failSoft', (done) => {
    const ocspError = new Error('OCSP request failed');
    mockGetCertStatus.mockRejectedValue(ocspError);
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

  it('should fail if the OCSP status is "revoked" when policy is failHard', (done) => {
    mockGetCertStatus.mockResolvedValue({ status: 'revoked' });
    const mockSocket = createMockSocket(peerCertificate);
    jest.spyOn(tls, 'connect').mockReturnValue(mockSocket);
    const agent = getTestTlsPolicyAgent({ ocspPolicy: failHardPolicy });

    agent.createConnection({ ...agent.options }, (err) => {
      expect(err).not.toBeNull();
      expect(err?.message).toBe('[OCSPDirectValidator] Invalid certificate revocation status: revoked.');
      done();
    });

    process.nextTick(() => mockSocket.emit('secureConnect'));
  });

  it('should fail if the OCSP status is "revoked" when policy is failSoft', (done) => {
    mockGetCertStatus.mockResolvedValue({ status: 'revoked' });
    const mockSocket = createMockSocket(peerCertificate);
    jest.spyOn(tls, 'connect').mockReturnValue(mockSocket);
    const agent = getTestTlsPolicyAgent({ ocspPolicy: failSoftPolicy });

    agent.createConnection({ ...agent.options }, (err) => {
      expect(err).not.toBeNull();
      expect(err?.message).toBe('[OCSPDirectValidator] Invalid certificate revocation status: revoked.');
      done();
    });

    process.nextTick(() => mockSocket.emit('secureConnect'));
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
      expect(err?.message).toBe('[OCSPDirectValidator] Could not find issuer certificate in the chain.');
      done();
    });

    process.nextTick(() => mockSocket.emit('secureConnect'));
  });

  it('should not run when ocspPolicy is not defined', (done) => {
    const mockSocket = createMockSocket(peerCertificate);
    jest.spyOn(tls, 'connect').mockReturnValue(mockSocket);
    const ocspValidatorSpy = jest.spyOn(OCSPDirectValidator.prototype, 'validate');

    const agent = getTestTlsPolicyAgent({ ocspPolicy: undefined });
    agent.createConnection({ ...agent.options }, (err, socket) => {
      expect(err).toBeNull();
      expect(socket).toBe(mockSocket);
      expect(ocspValidatorSpy).not.toHaveBeenCalled();
      done();
    });

    process.nextTick(() => mockSocket.emit('secureConnect'));
  });

  it("should not run when ocspPolicy mode is not 'direct'", (done) => {
    const mockSocket = createMockSocket(peerCertificate);
    jest.spyOn(tls, 'connect').mockReturnValue(mockSocket);
    const ocspValidatorSpy = jest.spyOn(OCSPDirectValidator.prototype, 'validate');

    const agent = getTestTlsPolicyAgent({ ocspPolicy: { mode: 'stapling', failHard: true } });
    agent.createConnection({ ...agent.options }, (err, socket) => {
      expect(err).toBeNull();
      expect(socket).toBe(mockSocket);
      expect(ocspValidatorSpy).not.toHaveBeenCalled();
      done();
    });

    process.nextTick(() => mockSocket.emit('secureConnect'));
  });
});