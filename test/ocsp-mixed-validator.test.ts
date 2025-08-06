import type { OCSPPolicy } from '../src/interfaces';
import * as tls from 'node:tls';
import { loadTestCertsChain, getTestHardenedHttpsAgent } from './utils';
import { createMockSocket, createMockPeerCertificate } from './utils/createMock';
import * as easyOcsp from 'easy-ocsp';

jest.mock('node:tls');
jest.mock('easy-ocsp');
jest.mock('../src/validators/ocsp-stapling');
jest.mock('../src/validators/ocsp-direct');

const mockParseOCSPResponse = easyOcsp.parseOCSPResponse as jest.Mock;
const mockGetCertStatus = easyOcsp.getCertStatus as jest.Mock;

describe('OCSP mixed validation', () => {
  afterEach(() => {
    jest.restoreAllMocks();
    mockParseOCSPResponse.mockClear();
    mockGetCertStatus.mockClear();
  });

  const failHardPolicy: OCSPPolicy = { mode: 'mixed', failHard: true };
  const failSoftPolicy: OCSPPolicy = { mode: 'mixed', failHard: false };

  const { pkiCerts } = loadTestCertsChain('google.com');
  const peerCertificate: tls.DetailedPeerCertificate = {
    ...createMockPeerCertificate(pkiCerts[0]),
    issuerCertificate: createMockPeerCertificate(pkiCerts[1]) as tls.DetailedPeerCertificate,
  };

  it('should pass if a valid OCSP staple is provided', (done) => {
    mockParseOCSPResponse.mockResolvedValue({ status: 'good' });
    const mockSocket = createMockSocket(peerCertificate);
    jest.spyOn(tls, 'connect').mockReturnValue(mockSocket);
    const agent = getTestHardenedHttpsAgent({ ocspPolicy: failHardPolicy });

    agent.createConnection({ ...agent.options }, (err, socket) => {
      expect(err).toBeNull();
      expect(socket).toBe(mockSocket);
      expect(mockParseOCSPResponse).toHaveBeenCalledTimes(1);
      expect(mockGetCertStatus).not.toHaveBeenCalled();
      done();
    });

    process.nextTick(() => mockSocket.emit('OCSPResponse', Buffer.from('valid staple')));
    setTimeout(() => mockSocket.emit('secureConnect'), 100);
  });

  it('should fail if the stapled response shows a revoked certificate', (done) => {
    mockParseOCSPResponse.mockResolvedValue({ status: 'revoked' });
    const mockSocket = createMockSocket(peerCertificate);
    jest.spyOn(tls, 'connect').mockReturnValue(mockSocket);
    const agent = getTestHardenedHttpsAgent({ ocspPolicy: failSoftPolicy });

    agent.createConnection({ ...agent.options }, (err) => {
      expect(err).not.toBeNull();
      expect(err?.message).toContain('Certificate is revoked');
      expect(mockGetCertStatus).not.toHaveBeenCalled();
      done();
    });

    process.nextTick(() => mockSocket.emit('OCSPResponse', Buffer.from('revoked staple')));
  });

  it('should pass on fallback if no staple is provided and direct check is good', (done) => {
    mockGetCertStatus.mockResolvedValue({ status: 'good' });
    const mockSocket = createMockSocket(peerCertificate);
    jest.spyOn(tls, 'connect').mockReturnValue(mockSocket);
    const agent = getTestHardenedHttpsAgent({ ocspPolicy: failHardPolicy });

    agent.createConnection({ ...agent.options }, (err, socket) => {
      expect(err).toBeNull();
      expect(socket).toBe(mockSocket);
      expect(mockParseOCSPResponse).not.toHaveBeenCalled();
      expect(mockGetCertStatus).toHaveBeenCalledTimes(1);
      done();
    });

    process.nextTick(() => mockSocket.emit('secureConnect'));
  });

  it('should pass on fallback if stapling fails and direct check is good', (done) => {
    mockParseOCSPResponse.mockRejectedValue(new Error('Invalid staple format'));
    mockGetCertStatus.mockResolvedValue({ status: 'good' });
    const mockSocket = createMockSocket(peerCertificate);
    jest.spyOn(tls, 'connect').mockReturnValue(mockSocket);
    const agent = getTestHardenedHttpsAgent({ ocspPolicy: failHardPolicy });

    agent.createConnection({ ...agent.options }, (err, socket) => {
      expect(err).toBeNull();
      expect(socket).toBe(mockSocket);
      expect(mockParseOCSPResponse).toHaveBeenCalledTimes(1);
      expect(mockGetCertStatus).toHaveBeenCalledTimes(1);
      done();
    });

    process.nextTick(() => mockSocket.emit('OCSPResponse', Buffer.from('invalid staple')));
    setTimeout(() => mockSocket.emit('secureConnect'), 100);
  });

  it('should fail on fallback if no staple is provided and direct check fails with failHard', (done) => {
    mockGetCertStatus.mockRejectedValue(new Error('Direct OCSP check failed'));
    const mockSocket = createMockSocket(peerCertificate);
    jest.spyOn(tls, 'connect').mockReturnValue(mockSocket);
    const agent = getTestHardenedHttpsAgent({ ocspPolicy: failHardPolicy });

    agent.createConnection({ ...agent.options }, (err) => {
      expect(err).not.toBeNull();
      expect(err?.message).toContain('Direct OCSP check failed');
      expect(mockGetCertStatus).toHaveBeenCalledTimes(1);
      done();
    });

    process.nextTick(() => mockSocket.emit('secureConnect'));
  });

  it('should pass on fallback if no staple is provided and direct check fails with failSoft', (done) => {
    mockGetCertStatus.mockRejectedValue(new Error('Direct OCSP check failed'));
    const mockSocket = createMockSocket(peerCertificate);
    jest.spyOn(tls, 'connect').mockReturnValue(mockSocket);
    const agent = getTestHardenedHttpsAgent({ ocspPolicy: failSoftPolicy });

    agent.createConnection({ ...agent.options }, (err, socket) => {
      expect(err).toBeNull();
      expect(socket).toBe(mockSocket);
      expect(mockGetCertStatus).toHaveBeenCalledTimes(1);
      done();
    });

    process.nextTick(() => mockSocket.emit('secureConnect'));
  });

  it('should fail on fallback if direct check shows revoked certificate', (done) => {
    mockGetCertStatus.mockResolvedValue({ status: 'revoked' });
    const mockSocket = createMockSocket(peerCertificate);
    jest.spyOn(tls, 'connect').mockReturnValue(mockSocket);
    const agent = getTestHardenedHttpsAgent({ ocspPolicy: failSoftPolicy });

    agent.createConnection({ ...agent.options }, (err) => {
      expect(err).not.toBeNull();
      expect(err?.message).toContain('Certificate is revoked');
      done();
    });

    process.nextTick(() => mockSocket.emit('secureConnect'));
  });

  it('should fail on fallback if stapling fails and direct check also fails with failHard', (done) => {
    mockParseOCSPResponse.mockRejectedValue(new Error('Invalid staple format'));
    mockGetCertStatus.mockRejectedValue(new Error('Direct OCSP check failed'));
    const mockSocket = createMockSocket(peerCertificate);
    jest.spyOn(tls, 'connect').mockReturnValue(mockSocket);
    const agent = getTestHardenedHttpsAgent({ ocspPolicy: failHardPolicy });

    agent.createConnection({ ...agent.options }, (err) => {
      expect(err).not.toBeNull();
      expect(err?.message).toContain('Direct OCSP check failed');
      expect(mockParseOCSPResponse).toHaveBeenCalledTimes(1);
      expect(mockGetCertStatus).toHaveBeenCalledTimes(1);
      done();
    });

    process.nextTick(() => mockSocket.emit('OCSPResponse', Buffer.from('invalid staple')));
    setTimeout(() => mockSocket.emit('secureConnect'), 100);
  });

  it('should fail on fallback if stapling fails and direct check finds a revoked certificate', (done) => {
    mockParseOCSPResponse.mockRejectedValue(new Error('Invalid staple format'));
    mockGetCertStatus.mockResolvedValue({ status: 'revoked' });
    const mockSocket = createMockSocket(peerCertificate);
    jest.spyOn(tls, 'connect').mockReturnValue(mockSocket);
    const agent = getTestHardenedHttpsAgent({ ocspPolicy: failSoftPolicy });

    agent.createConnection({ ...agent.options }, (err) => {
      expect(err).not.toBeNull();
      expect(err?.message).toContain('Certificate is revoked');
      expect(mockParseOCSPResponse).toHaveBeenCalledTimes(1);
      expect(mockGetCertStatus).toHaveBeenCalledTimes(1);
      done();
    });

    process.nextTick(() => mockSocket.emit('OCSPResponse', Buffer.from('invalid staple')));
    setTimeout(() => mockSocket.emit('secureConnect'), 100);
  });
});
