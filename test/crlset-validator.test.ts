import * as tls from 'node:tls';
import {
  createMockPeerCertificate,
  createMockSocket,
  getTestHardenedHttpsAgent,
  loadTestCertsChain,
} from './utils';
import { CRLSetValidator } from '../src/validators';
import { CRLSet, RevocationStatus, loadLatestCRLSet, type CRLSetHeader } from '@gldywn/crlset.js';
import { createHash } from 'crypto';

jest.mock('node:tls');
jest.mock('@gldywn/crlset.js', () => ({
  ...jest.requireActual('@gldywn/crlset.js'),
  loadLatestCRLSet: jest.fn(),
}));

const mockedLoadLatestCRLSet = loadLatestCRLSet as jest.Mock;

describe('CRLSetValidator', () => {
  afterEach(() => {
    jest.restoreAllMocks();
    mockedLoadLatestCRLSet.mockClear();
  });

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

  const issuerSpkiBer = issuerPkiCert.subjectPublicKeyInfo.toSchema().toBER(false);
  const issuerSpkiHash = createHash('sha256').update(Buffer.from(issuerSpkiBer)).digest('hex');
  const leafSerialNumber = Buffer.from(leafPkiCert.serialNumber.valueBlock.valueHex).toString('hex');

  const baseHeader: CRLSetHeader = {
    Version: 0,
    ContentType: 'CRLSet',
    Sequence: 123,
    DeltaFrom: 0,
    NumParents: 1,
    BlockedSPKIs: [],
    KnownInterceptionSPKIs: [],
    BlockedInterceptionSPKIs: [],
    NotAfter: 4102444800, // 2100-01-01
  };

  const mockCrlSet = new CRLSet(baseHeader, new Map());

  it('should not run when no crlSetPolicy option is provided', (done) => {
    const mockSocket = createMockSocket({ peerCertificate });
    jest.spyOn(tls, 'connect').mockReturnValue(mockSocket);

    const validateSpy = jest.spyOn(CRLSetValidator.prototype, 'validate');
    const agent = getTestHardenedHttpsAgent({ crlSetPolicy: undefined });

    process.nextTick(() => mockSocket.emit('secureConnect'));

    agent.createConnection({ ...agent.options }, (err, socket) => {
      expect(err).toBeNull();
      expect(socket).toBe(mockSocket);
      expect(validateSpy).not.toHaveBeenCalled();
      done();
    });
  });

  it('should pass when certificate is not revoked', (done) => {
    jest.spyOn(mockCrlSet, 'check').mockReturnValue(RevocationStatus.OK);

    const mockSocket = createMockSocket({ peerCertificate });
    jest.spyOn(tls, 'connect').mockReturnValue(mockSocket);

    const agent = getTestHardenedHttpsAgent({ crlSetPolicy: { crlSet: mockCrlSet } });

    process.nextTick(() => mockSocket.emit('secureConnect'));

    agent.createConnection({ ...agent.options }, (err, socket) => {
      expect(err).toBeNull();
      expect(socket).toBe(mockSocket);
      expect(mockCrlSet.check).toHaveBeenCalledWith(issuerSpkiHash, leafSerialNumber);
      done();
    });
  });

  it('should fail when certificate is revoked by serial number', (done) => {
    const mockRevokedCrlSet = new CRLSet(
      mockCrlSet.header,
      new Map([[issuerSpkiHash, new Set([leafSerialNumber])]]),
    );

    const mockSocket = createMockSocket({ peerCertificate });
    jest.spyOn(tls, 'connect').mockReturnValue(mockSocket);

    const agent = getTestHardenedHttpsAgent({ crlSetPolicy: { crlSet: mockRevokedCrlSet } });

    process.nextTick(() => mockSocket.emit('secureConnect'));

    agent.createConnection({ ...agent.options }, (err, socket) => {
      expect(err).toBeInstanceOf(Error);
      expect((err as Error).message).toContain(
        `Certificate is revoked according to CRLSet ${mockRevokedCrlSet.sequence}. Status: ${
          RevocationStatus[RevocationStatus.REVOKED_BY_SERIAL]
        }`,
      );
      expect(socket).toBeUndefined();
      done();
    });
  });

  it('should fail when certificate is revoked by SPKI', (done) => {
    const mockRevokedCrlSet = new CRLSet({ ...baseHeader, BlockedSPKIs: [issuerSpkiHash] }, new Map());
    jest.spyOn(mockRevokedCrlSet, 'check').mockReturnValue(RevocationStatus.REVOKED_BY_SPKI);

    const mockSocket = createMockSocket({ peerCertificate });
    jest.spyOn(tls, 'connect').mockReturnValue(mockSocket);

    const agent = getTestHardenedHttpsAgent({ crlSetPolicy: { crlSet: mockRevokedCrlSet } });

    process.nextTick(() => mockSocket.emit('secureConnect'));

    agent.createConnection({ ...agent.options }, (err, socket) => {
      expect(err).toBeInstanceOf(Error);
      expect((err as Error).message).toContain(
        `Certificate is revoked according to CRLSet ${mockRevokedCrlSet.sequence}. Status: ${
          RevocationStatus[RevocationStatus.REVOKED_BY_SPKI]
        }`,
      );
      expect(socket).toBeUndefined();
      done();
    });
  });

  it('should download latest CRLSet when policy requires fetching', (done) => {
    jest.spyOn(mockCrlSet, 'check').mockReturnValue(RevocationStatus.OK);
    mockedLoadLatestCRLSet.mockResolvedValue(mockCrlSet);

    const mockSocket = createMockSocket({ peerCertificate });
    jest.spyOn(tls, 'connect').mockReturnValue(mockSocket);

    const agent = getTestHardenedHttpsAgent({ crlSetPolicy: { verifySignature: true, updateStrategy: 'always' } });

    process.nextTick(() => mockSocket.emit('secureConnect'));

    agent.createConnection({ ...agent.options }, (err, socket) => {
      expect(err).toBeNull();
      expect(socket).toBe(mockSocket);
      expect(mockedLoadLatestCRLSet).toHaveBeenCalledTimes(1);
      expect(mockedLoadLatestCRLSet).toHaveBeenCalledWith({ verifySignature: true, updateStrategy: 'always' });
      expect(mockCrlSet.check).toHaveBeenCalledWith(issuerSpkiHash, leafSerialNumber);
      done();
    });
  });

  it('should fail if downloading latest CRLSet fails', (done) => {
    const downloadError = new Error('Download failed');
    mockedLoadLatestCRLSet.mockRejectedValue(downloadError);

    const mockSocket = createMockSocket({ peerCertificate });
    jest.spyOn(tls, 'connect').mockReturnValue(mockSocket);

    const agent = getTestHardenedHttpsAgent({ crlSetPolicy: { verifySignature: true, updateStrategy: 'always' } });

    process.nextTick(() => mockSocket.emit('secureConnect'));

    agent.createConnection({ ...agent.options }, (err, socket) => {
      expect(err).toBeInstanceOf(Error);
      expect((err as Error).message).toBe(`[CRLSetValidator] ${downloadError.message}`);
      expect(socket).toBeUndefined();
      expect(mockedLoadLatestCRLSet).toHaveBeenCalledTimes(1);
      expect(mockedLoadLatestCRLSet).toHaveBeenCalledWith({ verifySignature: true, updateStrategy: 'always' });
      done();
    });
  });

  it('should fail when the issuer certificate is missing', (done) => {
    const mockSocket = createMockSocket({
      peerCertificate: {
        ...peerCertificate,
        issuerCertificate: undefined,
      } as unknown as tls.DetailedPeerCertificate,
    });
    jest.spyOn(tls, 'connect').mockReturnValue(mockSocket);

    const agent = getTestHardenedHttpsAgent({ crlSetPolicy: { crlSet: mockCrlSet } });

    process.nextTick(() => mockSocket.emit('secureConnect'));

    agent.createConnection({ ...agent.options }, (err, socket) => {
      expect(err).toBeInstanceOf(Error);
      expect((err as Error).message).toBe('[CRLSetValidator] Could not find issuer certificate in the chain.');
      expect(socket).toBeUndefined();
      done();
    });
  });
});
