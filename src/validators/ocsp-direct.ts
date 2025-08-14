import * as tls from 'tls';
import { HardenedHttpsValidationKitOptions } from '../interfaces';
import { OCSPBaseValidator } from './ocsp-base';

export class OCSPDirectValidator extends OCSPBaseValidator {
  /**
   * This validator should only run if the ocspPolicy mode is 'direct'.
   */
  public shouldRun(options: HardenedHttpsValidationKitOptions): boolean {
    return options.ocspPolicy?.mode === 'direct';
  }

  /**
   * Performs a direct OCSP request to check the revocation status of the server's certificate.
   * If the check fails, the connection is aborted if `failHard` is true.
   */
  public validate(socket: tls.TLSSocket, options: HardenedHttpsValidationKitOptions): Promise<void> {
    const { failHard } = options.ocspPolicy!; // Safe due to shouldRun check

    return new Promise((resolve, reject) => {
      socket.once('secureConnect', async () => {
        this.debug('Secure connection established, performing direct OCSP validation...');

        try {
          await this._performDirectOCSPCheck(socket);
          this.debug(`Certificate is not revoked.`);
          resolve();
        } catch (err: any) {
          this._handleOCSPError(err, failHard, reject, resolve);
        }
      });
    });
  }
}
