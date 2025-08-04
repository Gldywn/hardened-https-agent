import * as tls from 'tls';

export function getLeafAndIssuerCertificates(socket: tls.TLSSocket): {
  leafCert: tls.DetailedPeerCertificate;
  issuerCert: tls.DetailedPeerCertificate;
} {
  const certChain = socket.getPeerCertificate(true);

  if (!certChain) {
    throw new Error('Could not get peer certificate chain.');
  }

  const leafCert = certChain;
  const issuerCert = certChain.issuerCertificate;

  if (!issuerCert) {
    throw new Error('Could not find issuer certificate in the chain.');
  }

  return { leafCert, issuerCert };
}
