import * as tls from 'tls';
import { convertToPkijsCert, getCertStatus, parseOCSPResponse, type OCSPStatusConfig } from 'easy-ocsp';
import { getLeafAndIssuerCertificates } from '../utils';
import { BaseValidator } from './base';

/**
 * A custom error type to specifically represent a revoked certificate status.
 */
export class CertificateRevokedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CertificateRevokedError';
  }
}

/**
 * An abstract base class for all OCSP-based validators, providing shared logic.
 */
export abstract class OCSPBaseValidator extends BaseValidator {
  /**
   * Handles OCSP validation errors, always failing on revoked certificates
   * and respecting the `failHard` policy for other errors.
   */
  protected _handleOCSPError(
    err: any,
    failHard: boolean,
    reject: (reason?: any) => void,
    resolve: (value: void | PromiseLike<void>) => void,
  ): void {
    if (err instanceof CertificateRevokedError) {
      return reject(this.wrapError(err));
    }
    
    if (failHard) {
      reject(this.wrapError(err));
    } else {
      this.warn(`Failed to validate: ${err.message}.`);
      resolve();
    }
  }

  /**
   * Validates a stapled OCSP response.
   */
  protected async _validateStapledResponse(response: Buffer, socket: tls.TLSSocket): Promise<void> {
    if (!response || response.length === 0) {
      throw new Error('Empty OCSP stapling response.');
    }

    const { leafCert, issuerCert } = getLeafAndIssuerCertificates(socket);
    const leafCertPki = convertToPkijsCert(leafCert.raw);
    const issuerCertPki = convertToPkijsCert(issuerCert.raw);

    const ocspConfig: OCSPStatusConfig = {
      ca: issuerCert.raw,
      enableNonce: false,
    };

    const ocspResponse = await parseOCSPResponse(response, leafCertPki, issuerCertPki, ocspConfig, null);

    if (ocspResponse.status !== 'good') {
      throw new CertificateRevokedError(`Certificate is revoked. Status: ${ocspResponse.status}.`);
    }
  }

  /**
   * Performs a direct OCSP check against the CA's responder.
   */
  protected async _performDirectOCSPCheck(socket: tls.TLSSocket): Promise<void> {
    const { leafCert, issuerCert } = getLeafAndIssuerCertificates(socket);
    const leafCertPki = convertToPkijsCert(leafCert.raw);

    const ocspConfig: OCSPStatusConfig = {
      ca: issuerCert.raw,
    };

    const ocspResponse = await getCertStatus(leafCertPki, ocspConfig);
    if (ocspResponse.status !== 'good') {
      throw new CertificateRevokedError(`Certificate is revoked. Status: ${ocspResponse.status}.`);
    }
  }
}
