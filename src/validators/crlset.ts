import * as tls from 'tls';
import { convertToPkijsCert } from 'easy-ocsp';
import { BaseValidator } from './base';
import { TlsPolicyAgentOptions } from '../interfaces';
import { getLeafAndIssuerCertificates } from '../utils';
import { Buffer } from 'buffer';
import { CRLSet, loadLatestCRLSet, RevocationStatus } from '@gldywn/crlset.js';
import { createHash } from 'crypto';

export class CRLSetValidator extends BaseValidator {
  /**
   * This validator should only run if the crlSet option is provided.
   */
  public shouldRun(options: TlsPolicyAgentOptions): boolean {
    return !!options.crlSet;
  }

  /**
   * Checks the revocation status of the server's certificate using a specified CRLSet.
   * If the check fails, the connection is aborted.
   */
  public validate(socket: tls.TLSSocket, options: TlsPolicyAgentOptions): Promise<void> {
    const maybeCrlSet = options.crlSet!; // Safe due to shouldRun check

    return new Promise((resolve, reject) => {
      socket.once('secureConnect', async () => {
        this.log('Secure connection established, performing validation...');

        try {
          const { leafCert, issuerCert } = getLeafAndIssuerCertificates(socket);

          const leafCertPki = convertToPkijsCert(leafCert.raw);
          const issuerCertPki = convertToPkijsCert(issuerCert.raw);

          const issuerSpkiBer = issuerCertPki.subjectPublicKeyInfo.toSchema().toBER(false);
          const issuerSpkiHash = createHash('sha256').update(Buffer.from(issuerSpkiBer)).digest('hex');

          const leafSerialNumber = Buffer.from(leafCertPki.serialNumber.valueBlock.valueHex).toString('hex');

          let crlSet: CRLSet;
          if (typeof maybeCrlSet !== 'string') {
            crlSet = maybeCrlSet;
          } else {
            this.log('Downloading latest CRLSet...');
            crlSet = await loadLatestCRLSet();
            this.log('Latest CRLSet downloaded successfully.');
          }

          const revocationStatus = crlSet.check(issuerSpkiHash, leafSerialNumber);
          if (revocationStatus !== RevocationStatus.OK) {
            return reject(
              this.wrapError(
                new Error(
                  `Certificate is revoked according to CRLSet ${crlSet.sequence}. Status: ${RevocationStatus[revocationStatus]}`,
                ),
              ),
            );
          }

          this.log(`Certificate is not revoked according to CRLSet ${crlSet.sequence}.`);
          resolve();
        } catch (err: any) {
          reject(this.wrapError(err));
        }
      });
    });
  }
}
