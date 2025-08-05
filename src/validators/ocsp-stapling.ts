import * as tls from 'tls';
import { BaseValidator } from './base';
import { HardenedHttpsAgentOptions } from '../interfaces';
import { convertToPkijsCert, getCertURLs, parseOCSPResponse, type OCSPStatusConfig } from 'easy-ocsp';
import { getLeafAndIssuerCertificates } from '../utils';

export class OCSPStaplingValidator extends BaseValidator {
  /**
   * Overrides the base implementation to set the `requestOCSP` option to `true`,
   * which is required to trigger the 'OCSPResponse' event on the TLS socket.
   */
  public override onBeforeConnect(options: tls.ConnectionOptions): tls.ConnectionOptions {
    return {
      ...options,
      requestOCSP: true,
    } as tls.ConnectionOptions;
  }

  /**
   * This validator should only run if the ocspPolicy mode is 'stapling'.
   */
  public shouldRun(options: HardenedHttpsAgentOptions): boolean {
    return options.ocspPolicy?.mode === 'stapling';
  }

  /**
   * Waits for the 'OCSPResponse' event on the TLS socket and validates the stapled OCSP response.
   * If no OCSP staple is received, applies the OCSP stapling policy to determine whether to fail or allow the connection.
   */
  public validate(socket: tls.TLSSocket, options: HardenedHttpsAgentOptions): Promise<void> {
    const ocspPolicy = options.ocspPolicy!; // Safe due to shouldRun check

    return new Promise((resolve, reject) => {
      let ocspReceived = false;

      socket.once('OCSPResponse', async (response: Buffer) => {
        this.log('OCSP stapling response received, performing validation...');
        ocspReceived = true;

        if (!response || response.length === 0) {
          return reject(this.wrapError(new Error('Empty OCSP stapling response.')));
        }

        try {
          const { leafCert, issuerCert } = getLeafAndIssuerCertificates(socket);
          const leafCertPki = convertToPkijsCert(leafCert.raw);
          const issuerCertPki = convertToPkijsCert(issuerCert.raw);

          const ocspConfig: OCSPStatusConfig = {
            ca: issuerCert.raw,
            // Nonce must be disabled for OCSP stapling to allow the use of cached OCSP responses.
            enableNonce: false,
          };

          const ocspResponse = await parseOCSPResponse(response, leafCertPki, issuerCertPki, ocspConfig, null);
          if (ocspResponse.status !== 'good') {
            return reject(this.wrapError(new Error(`Certificate is revoked. Status: ${ocspResponse.status}.`)));
          }

          this.log(`Certificate is not revoked.`);
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

      // Handle the case where the server doesn't send an OCSP staple.
      socket.once('secureConnect', () => {
        if (!ocspReceived) {
          if (ocspPolicy.failHard) {
            reject(this.wrapError(new Error('OCSP stapling response required but not received.')));
          } else {
            this.warn('OCSP stapling response expected but not received.');
            resolve();
          }
        }
      });
    });
  }
}