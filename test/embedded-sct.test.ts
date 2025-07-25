import type { CertificateTransparencyPolicy } from '../src/interfaces';
import * as tls from 'node:tls';
import { loadTestCertsChain, getTestTlsPolicyAgent, CT_POLICY_CHROME } from './utils';
import { TEST_CERT_HOSTS } from '../scripts/constants';
import { SCT_EXTENSION_OID_V1 } from '@gldywn/sct.js';
import { createMockSocket, createMockPeerCertificate } from './utils/createMock';

jest.mock('node:tls');

describe('Embedded SCT validation', () => {
  afterEach(() => {
    jest.restoreAllMocks();
  });

  // CT Policy that requires more SCTs than available
  const strictSctCountPolicy: CertificateTransparencyPolicy = {
    ...CT_POLICY_CHROME,
    minEmbeddedScts: 3,
  };

  // CT Policy that requires more distinct operators than available
  const strictOperatorPolicy: CertificateTransparencyPolicy = {
    ...CT_POLICY_CHROME,
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

      const agent = getTestTlsPolicyAgent();
      const validateSctSpy = jest.spyOn(agent as any, 'validateCertificateTransparency');

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

    const agent = getTestTlsPolicyAgent({ ctPolicy: undefined });
    const validateSctSpy = jest.spyOn(agent as any, 'validateCertificateTransparency');

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

    const agent = getTestTlsPolicyAgent();
    const validateSctSpy = jest.spyOn(agent as any, 'validateCertificateTransparency');

    agent.createConnection({ ...agent.options }, (err, socket) => {
      expect(err).toBeInstanceOf(Error);
      expect((err as Error).message).toBe('Could not find issuer certificate in the chain.');
      expect(socket).toBeUndefined();
      expect(validateSctSpy).toHaveBeenCalledTimes(1);

      done();
    });
  });

  it('should fail when policy requires more SCTs than available', (done) => {
    const mockSocket = createMockSocket(peerCertificate);
    jest.spyOn(tls, 'connect').mockReturnValue(mockSocket);

    const agent = getTestTlsPolicyAgent({ ctPolicy: strictSctCountPolicy });
    const validateSctSpy = jest.spyOn(agent as any, 'validateCertificateTransparency');

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

    const agent = getTestTlsPolicyAgent({ ctPolicy: strictOperatorPolicy });
    const validateSctSpy = jest.spyOn(agent as any, 'validateCertificateTransparency');

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

    const agent = getTestTlsPolicyAgent();
    const validateSctSpy = jest.spyOn(agent as any, 'validateCertificateTransparency');

    agent.createConnection({ ...agent.options }, (err, socket) => {
      expect(err).toBeInstanceOf(Error);
      expect((err as Error).message).toBe('No SCTs found in the certificate.');
      expect(socket).toBeUndefined();
      expect(validateSctSpy).toHaveBeenCalledTimes(1);

      done();
    });
  });
});
