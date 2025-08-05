import type { CertificateTransparencyPolicy } from '../src/interfaces';
import * as tls from 'node:tls';
import { loadTestCertsChain, getTestHardenedHttpsAgent, TEST_CT_POLICY } from './utils';
import { TEST_CERT_HOSTS } from '../scripts/constants';
import { SCT_EXTENSION_OID_V1 } from '@gldywn/sct.js';
import { createMockSocket, createMockPeerCertificate, delay } from './utils';
import { CTValidator } from '../src/validators';

jest.mock('node:tls');

describe('Certificate transparency validation', () => {
  afterEach(() => {
    jest.restoreAllMocks();
  });

  // CT Policy that requires more SCTs than available
  const strictSctCountPolicy: CertificateTransparencyPolicy = {
    ...TEST_CT_POLICY,
    minEmbeddedScts: 3,
  };

  // CT Policy that requires more distinct operators than available
  const strictOperatorPolicy: CertificateTransparencyPolicy = {
    ...TEST_CT_POLICY,
    minDistinctOperators: 3,
  };

  TEST_CERT_HOSTS.forEach((hostname) => {
    it(`should pass for ${hostname} when the issuer certificate is present and SCTs are valid`, (done) => {
      const { pkiCerts } = loadTestCertsChain(hostname);
      const leafPkiCert = pkiCerts[0];
      const issuerPkiCert = pkiCerts[1];
      const leafMockCert = createMockPeerCertificate(leafPkiCert);
      const issuerMockCert = createMockPeerCertificate(issuerPkiCert);

      const peerCertificate: tls.DetailedPeerCertificate = {
        ...leafMockCert,
        issuerCertificate: issuerMockCert as tls.DetailedPeerCertificate,
      };

      const mockSocket = createMockSocket(peerCertificate);
      jest.spyOn(tls, 'connect').mockReturnValue(mockSocket);

      const validateSctSpy = jest.spyOn(CTValidator.prototype as any, 'validateCertificateTransparency');
      const agent = getTestHardenedHttpsAgent({ ctPolicy: TEST_CT_POLICY });

      // Simulate the secureConnect event on the next tick
      process.nextTick(() => mockSocket.emit('secureConnect'));

      agent.createConnection({ ...agent.options }, (err, socket) => {
        expect(err).toBeNull();
        expect(socket).toBe(mockSocket);
        expect(validateSctSpy).toHaveBeenCalledTimes(1);

        done();
      });
    });
  });

  // We're using a single hostname for the following tests
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

  it('should pass when no policy is provided', (done) => {
    const mockSocket = createMockSocket(peerCertificate);
    jest.spyOn(tls, 'connect').mockReturnValue(mockSocket);

    const validateSctSpy = jest.spyOn(CTValidator.prototype as any, 'validateCertificateTransparency');
    const agent = getTestHardenedHttpsAgent({ ctPolicy: undefined });

    // Simulate the secureConnect event on the next tick
    process.nextTick(() => mockSocket.emit('secureConnect'));

    agent.createConnection({ ...agent.options }, (err, socket) => {
      expect(err).toBeNull();
      expect(socket).toBe(mockSocket);
      expect(validateSctSpy).not.toHaveBeenCalled();

      done();
    });
  });

  it('should fail when the issuer certificate is missing', (done) => {
    // Remove the issuer certificate from the peer certificate
    const mockSocket = createMockSocket({
      ...peerCertificate,
      issuerCertificate: undefined,
    } as unknown as tls.DetailedPeerCertificate);
    jest.spyOn(tls, 'connect').mockReturnValue(mockSocket);

    const validateSctSpy = jest.spyOn(CTValidator.prototype as any, 'validateCertificateTransparency');
    const agent = getTestHardenedHttpsAgent({ ctPolicy: TEST_CT_POLICY });

    // Simulate the secureConnect event on the next tick
    process.nextTick(() => mockSocket.emit('secureConnect'));

    agent.createConnection({ ...agent.options }, (err, socket) => {
      expect(err).toBeInstanceOf(Error);
      expect((err as Error).message).toBe('[CTValidator] Could not find issuer certificate in the chain.');
      expect(socket).toBeUndefined();
      expect(validateSctSpy).toHaveBeenCalledTimes(1);

      done();
    });
  });

  it('should fail when policy requires more SCTs than available', (done) => {
    const mockSocket = createMockSocket(peerCertificate);
    jest.spyOn(tls, 'connect').mockReturnValue(mockSocket);

    const validateSctSpy = jest.spyOn(CTValidator.prototype as any, 'validateCertificateTransparency');
    const agent = getTestHardenedHttpsAgent({ ctPolicy: strictSctCountPolicy });

    // Simulate the secureConnect event on the next tick
    process.nextTick(() => mockSocket.emit('secureConnect'));

    agent.createConnection({ ...agent.options }, (err, socket) => {
      expect(err).toBeInstanceOf(Error);
      expect((err as Error).message).toBe(
        'Certificate has 2 valid embedded SCTs (out of 2 found), but policy requires at least 3.',
      );
      // Socket has been destroyed by the agent, so it must be undefined
      expect(socket).toBeUndefined();
      expect(validateSctSpy).toHaveBeenCalledTimes(1);

      done();
    });
  });

  it('should fail when policy requires more distinct operators than available', (done) => {
    const mockSocket = createMockSocket(peerCertificate);
    jest.spyOn(tls, 'connect').mockReturnValue(mockSocket);

    const validateSctSpy = jest.spyOn(CTValidator.prototype as any, 'validateCertificateTransparency');
    const agent = getTestHardenedHttpsAgent({ ctPolicy: strictOperatorPolicy });

    // Simulate the secureConnect event on the next tick
    process.nextTick(() => mockSocket.emit('secureConnect'));

    agent.createConnection({ ...agent.options }, (err, socket) => {
      expect(err).toBeInstanceOf(Error);
      expect((err as Error).message).toBe(
        'Certificate has SCTs from 2 distinct operators, but policy requires at least 3.',
      );
      expect(socket).toBeUndefined();
      expect(validateSctSpy).toHaveBeenCalledTimes(1);

      done();
    });
  });

  it('should fail when the certificate has no embedded SCTs', (done) => {
    // Reload certs locally to avoid mutating the shared objects from the parent describe block
    const { pkiCerts: localPkiCerts } = loadTestCertsChain(hostname);
    const leafPkiCert = localPkiCerts[0];

    // Filter out the SCT extension from the local copy of the certificate
    leafPkiCert.extensions = leafPkiCert.extensions?.filter((ext) => ext.extnID !== SCT_EXTENSION_OID_V1);

    const leafMockCertWithoutSct = createMockPeerCertificate(leafPkiCert);

    const detailedCertMock: tls.DetailedPeerCertificate = {
      ...leafMockCertWithoutSct,
      issuerCertificate: issuerMockCert as tls.DetailedPeerCertificate,
    };

    const mockSocket = createMockSocket(detailedCertMock);
    jest.spyOn(tls, 'connect').mockReturnValue(mockSocket);

    const validateSctSpy = jest.spyOn(CTValidator.prototype as any, 'validateCertificateTransparency');
    const agent = getTestHardenedHttpsAgent({ ctPolicy: TEST_CT_POLICY });

    // Simulate the secureConnect event on the next tick
    process.nextTick(() => mockSocket.emit('secureConnect'));

    agent.createConnection({ ...agent.options }, (err, socket) => {
      expect(err).toBeInstanceOf(Error);
      expect((err as Error).message).toBe('[CTValidator] No SCTs found in the certificate.');
      expect(socket).toBeUndefined();
      expect(validateSctSpy).toHaveBeenCalledTimes(1);

      done();
    });
  });

  it('should fail when the certificate is malformed', (done) => {
    const malformedPeerCertificate = {
      ...peerCertificate,
      raw: Buffer.from('not a real certificate'),
    };

    const mockSocket = createMockSocket(malformedPeerCertificate);
    jest.spyOn(tls, 'connect').mockReturnValue(mockSocket);

    const agent = getTestHardenedHttpsAgent({ ctPolicy: TEST_CT_POLICY });

    // Simulate the secureConnect event on the next tick
    process.nextTick(() => mockSocket.emit('secureConnect'));

    agent.createConnection({ ...agent.options }, (err) => {
      expect(err).toBeInstanceOf(Error);
      expect((err as Error).message).toBe('[CTValidator] Failed to parse certificate for SCT validation.');
      done();
    });
  });

  it('should fail when the SCT list is malformed', (done) => {
    const { pkiCerts: localPkiCerts } = loadTestCertsChain(hostname);
    const leafPkiCert = localPkiCerts[0];
    const sctExtension = leafPkiCert.extensions?.find((ext) => ext.extnID === SCT_EXTENSION_OID_V1);

    if (sctExtension) {
      // Replace the valid SCT list with a corrupted one
      sctExtension.extnValue = new (require('asn1js').OctetString)({ valueHex: Buffer.from('corrupted') });
    }

    const leafMockCertWithCorruptedSctList = createMockPeerCertificate(leafPkiCert);
    const detailedCertMock: tls.DetailedPeerCertificate = {
      ...leafMockCertWithCorruptedSctList,
      issuerCertificate: issuerMockCert as tls.DetailedPeerCertificate,
    };

    const mockSocket = createMockSocket(detailedCertMock);
    jest.spyOn(tls, 'connect').mockReturnValue(mockSocket);
    const agent = getTestHardenedHttpsAgent({ ctPolicy: TEST_CT_POLICY });

    // Simulate the secureConnect event on the next tick
    process.nextTick(() => mockSocket.emit('secureConnect'));

    agent.createConnection({ ...agent.options }, (err) => {
      expect(err).toBeInstanceOf(Error);
      expect((err as Error).message).toBe('[CTValidator] Failed to parse inner SCT extension value.');
      done();
    });
  });

  it('should continue validation when some SCTs are corrupted', (done) => {
    const { pkiCerts: localPkiCerts } = loadTestCertsChain(hostname);
    const leafPkiCert = localPkiCerts[0];
    const sctExtension = leafPkiCert.extensions?.find((ext) => ext.extnID === SCT_EXTENSION_OID_V1);

    if (sctExtension) {
      const { fromBER, OctetString } = require('asn1js');
      const innerAsn1 = fromBER(sctExtension.extnValue.getValue());
      const sctListBuffer = Buffer.from((innerAsn1.result as typeof OctetString).getValue());

      // Prepend a corrupted SCT to the existing list of valid SCTs
      const corruptedSct = Buffer.from('this is not a valid sct');
      const newSctList = Buffer.concat([
        Buffer.from([0, corruptedSct.length]), // Length prefix for corrupted SCT
        corruptedSct,
        sctListBuffer.subarray(2), // The original list, excluding its length prefix
      ]);

      const newListContainer = Buffer.alloc(2 + newSctList.length);
      newListContainer.writeUInt16BE(newSctList.length, 0);
      newSctList.copy(newListContainer, 2);

      const innerOctetString = new OctetString({ valueHex: newListContainer });
      sctExtension.extnValue = new OctetString({ valueHex: innerOctetString.toBER() });
    }

    const leafMockCertWithOneCorruptedSct = createMockPeerCertificate(leafPkiCert);
    const detailedCertMock: tls.DetailedPeerCertificate = {
      ...leafMockCertWithOneCorruptedSct,
      issuerCertificate: issuerMockCert as tls.DetailedPeerCertificate,
    };

    const mockSocket = createMockSocket(detailedCertMock);
    jest.spyOn(tls, 'connect').mockReturnValue(mockSocket);

    // The policy should still pass, as the original 2 SCTs are still present and valid.
    const agent = getTestHardenedHttpsAgent({ ctPolicy: TEST_CT_POLICY });

    // Simulate the secureConnect event on the next tick
    process.nextTick(() => mockSocket.emit('secureConnect'));

    agent.createConnection({ ...agent.options }, (err) => {
      expect(err).toBeNull();
      done();
    });
  });

  it('should fail when no SCTs are valid for the given log list', (done) => {
    const mockSocket = createMockSocket(peerCertificate);
    jest.spyOn(tls, 'connect').mockReturnValue(mockSocket);

    const warnSpy = jest.spyOn(console, 'warn').mockImplementation();

    // Provide a policy with an empty log list, so no SCTs can be verified
    const agent = getTestHardenedHttpsAgent({ ctPolicy: { logList: { operators: [] } } });

    // Simulate the secureConnect event on the next tick
    process.nextTick(() => mockSocket.emit('secureConnect'));

    agent.createConnection({ ...agent.options }, (err) => {
      expect(err).toBeInstanceOf(Error);
      expect((err as Error).message).toBe('[CTValidator] Empty trusted CT log list.');

      warnSpy.mockRestore();
      done();
    });
  });
});
