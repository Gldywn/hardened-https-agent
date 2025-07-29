import * as tls from 'tls';
import { convertToPkijsCert, getCertStatus, getCertURLs, OCSPStatusConfig } from 'easy-ocsp';
import { BaseValidator } from './base';
import { TlsPolicyAgentOptions } from '../interfaces';
import { getLeafAndIssuerCertificates } from '../utils';

export class OCSPDirectValidator extends BaseValidator {
  /**
   * This validator should only run if the ocspPolicy mode is 'direct'.
   */
  public shouldRun(options: TlsPolicyAgentOptions): boolean {
    return options.ocspPolicy?.mode === 'direct';
  }

  /**
   * Performs a direct OCSP request to check the revocation status of the server's certificate.
   * If the check fails, the connection is aborted if `failHard` is true.
   */
  public validate(socket: tls.TLSSocket, options: TlsPolicyAgentOptions): Promise<void> {
    const ocspPolicy = options.ocspPolicy!; // Safe due to shouldRun check

    return new Promise((resolve, reject) => {
      socket.once('secureConnect', async () => {
        this.log('Secure connection established, performing validation...');

        try {
          const { leafCert, issuerCert } = getLeafAndIssuerCertificates(socket);
          const leafCertPki = convertToPkijsCert(leafCert.raw);

          const ocspConfig: OCSPStatusConfig = {
            ca: issuerCert.raw,
          };

          const ocspResponse = await getCertStatus(leafCertPki, ocspConfig);
          if (ocspResponse.status !== 'good') {
            return reject(this.wrapError(new Error(`Invalid certificate revocation status: ${ocspResponse.status}.`)));
          }

          this.log(`Successfully validated certificate revocation status.`);
          resolve();
        } catch (err: any) {
          if (ocspPolicy.failHard) {
            reject(this.wrapError(err));
          } else {
            this.warn(`Failed to validate certificate revocation status: ${err.message}.`);
            resolve();
          }
        }
      });
    });
  }
}
