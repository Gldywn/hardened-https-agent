import * as tls from 'tls';
import { HardenedHttpsValidationKitOptions } from '../interfaces';
import { OCSPBaseValidator, CertificateRevokedError } from './ocsp-base';

export class OCSPMixedValidator extends OCSPBaseValidator {
  /**
   * Overrides the base implementation to set the `requestOCSP` option to `true`,
   * which is required to trigger the 'OCSPResponse' event for the initial stapling attempt.
   */
  public override onBeforeConnect(options: tls.ConnectionOptions): tls.ConnectionOptions {
    return {
      ...options,
      requestOCSP: true,
    } as tls.ConnectionOptions;
  }

  /**
   * This validator should only run if the ocspPolicy mode is 'mixed'.
   */
  public shouldRun(options: HardenedHttpsValidationKitOptions): boolean {
    return options.ocspPolicy?.mode === 'mixed';
  }

  /**
   * The 'mixed' OCSP validation strategy works as follows:
   * 1. First, it tries to validate using a stapled OCSP response.
   * 2. If stapling fails for any reason except a revoked certificate, it falls back to a direct OCSP check.
   * 3. The `failHard` policy is enforced only for the result of the final direct check.
   */
  public validate(socket: tls.TLSSocket, options: HardenedHttpsValidationKitOptions): Promise<void> {
    const { failHard } = options.ocspPolicy!; // Safe due to shouldRun check

    return new Promise((resolve, reject) => {
      let staplingAttempted = false;
      let validationComplete = false;

      // First, try to validate a stapled response.
      socket.once('OCSPResponse', async (response: Buffer) => {
        staplingAttempted = true;
        this.debug('OCSP stapling response received, performing validation...');

        try {
          await this._validateStapledResponse(response, socket);
          this.debug('OCSP stapling validation succeeded. Certificate is not revoked.');
          validationComplete = true;
          resolve();
        } catch (err: any) {
          if (err instanceof CertificateRevokedError) {
            validationComplete = true;
            return reject(this.wrapError(err));
          }
          // For any other stapling error, we warn and prepare to fall back.
          this.warn(`OCSP stapling validation failed: ${err.message}.`);
        }
      });

      // If no staple is received, or if stapling failed, fall back to a direct check.
      socket.once('secureConnect', async () => {
        if (validationComplete) {
          return;
        }

        const fallbackLogMessage = staplingAttempted
          ? 'Falling back to direct OCSP check after failed stapling attempt.'
          : 'No OCSP staple received. Falling back to direct OCSP check.';
        this.debug(fallbackLogMessage);

        try {
          await this._performDirectOCSPCheck(socket);
          this.debug('Direct OCSP validation succeeded. Certificate is not revoked.');
          resolve();
        } catch (err: any) {
          this._handleOCSPError(err, failHard, reject, resolve);
        }
      });
    });
  }
}
