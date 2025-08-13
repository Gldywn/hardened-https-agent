import { createHash } from 'node:crypto';
import { Certificate, GeneralNames, BasicConstraints } from 'pkijs';
import { fromBER } from 'asn1js';
import * as tls from 'node:tls';
import { Duplex } from 'stream';

export function createMockSocket(
  {
    peerCertificate,
    servername,
  }: {
    peerCertificate?: tls.DetailedPeerCertificate;
    servername?: string;
  } = {},
): tls.TLSSocket {
  const socket = new Duplex({
    read() {},
    write(_chunk, _encoding, callback) {
      callback();
    },
  });

  const tlsSocket = socket as unknown as tls.TLSSocket;

  jest.spyOn(socket, 'emit');
  tlsSocket.setKeepAlive = jest.fn();
  jest.spyOn(socket, 'pause');
  jest.spyOn(socket, 'resume');
  jest.spyOn(socket, 'destroy');
  if (peerCertificate) tlsSocket.getPeerCertificate = jest.fn().mockReturnValue(peerCertificate);

  return tlsSocket;
}

export const createMockPeerCertificate = (pkiCert: Certificate): tls.PeerCertificate => {
  // Use the exact DER encoding from the parsed certificate
  const der = Buffer.from(pkiCert.toSchema(true).toBER());

  let isCa = false;
  const basicConstraintsExt = pkiCert.extensions?.find(
    (ext) => ext.extnID === '2.5.29.19', // OID for Basic Constraints
  );
  if (basicConstraintsExt) {
    try {
      const asn1 = fromBER(basicConstraintsExt.extnValue.getValue());
      if (asn1.offset !== -1) {
        const basicConstraints = new BasicConstraints({ schema: asn1.result });
        isCa = basicConstraints.cA;
      }
    } catch (error) {
      // Silently ignore parsing errors, default to false.
    }
  }

  return {
    subject: {
      C: getSubjectField(pkiCert.subject, '2.5.4.6') as string,
      ST: getSubjectField(pkiCert.subject, '2.5.4.8') as string,
      L: getSubjectField(pkiCert.subject, '2.5.4.7') as string,
      O: getSubjectField(pkiCert.subject, '2.5.4.10') as string,
      OU: getSubjectField(pkiCert.subject, '2.5.4.11') as string,
      CN: getSubjectField(pkiCert.subject, '2.5.4.3') as string,
    },
    issuer: {
      C: getSubjectField(pkiCert.issuer, '2.5.4.6') as string,
      ST: getSubjectField(pkiCert.issuer, '2.5.4.8') as string,
      L: getSubjectField(pkiCert.issuer, '2.5.4.7') as string,
      O: getSubjectField(pkiCert.issuer, '2.5.4.10') as string,
      OU: getSubjectField(pkiCert.issuer, '2.5.4.11') as string,
      CN: getSubjectField(pkiCert.issuer, '2.5.4.3') as string,
    },
    subjectaltname: getSubjectAltNames(pkiCert.extensions || []),
    raw: der,
    valid_from: pkiCert.notBefore.value.toISOString(),
    valid_to: pkiCert.notAfter.value.toISOString(),
    serialNumber: Buffer.from(pkiCert.serialNumber.valueBlock.valueHexView).toString('hex'),
    fingerprint: getFingerprint(der, 'sha1'),
    fingerprint256: getFingerprint(der, 'sha256'),
    fingerprint512: getFingerprint(der, 'sha512'),
    ca: isCa,
  };
};

const getSubjectField = (subject: any, shortName: string): string | string[] => {
  const field = subject.typesAndValues.find((f: any) => f.type === shortName);
  return field ? field.value.valueBlock.value : '';
};

const getSubjectAltNames = (extensions: any[]): string => {
  const sanExtension = extensions.find((ext) => ext.extnID === '2.5.29.17');
  if (!sanExtension) return '';
  const asn1 = fromBER(sanExtension.extnValue.getValue());
  if (asn1.offset === -1) return '';
  const generalNames = new GeneralNames({ schema: asn1.result });
  return generalNames.names
    .filter((name: any) => name.type === 2)
    .map((name: any) => `DNS:${name.value}`)
    .join(', ');
};

const getFingerprint = (buffer: Buffer, algorithm: string): string => {
  const hash = createHash(algorithm).update(buffer).digest('hex');
  return hash.replace(/(.{2})(?!$)/g, '$1:').toUpperCase();
};
