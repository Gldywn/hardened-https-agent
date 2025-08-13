import * as tls from 'tls';
import { HardenedHttpsValidationKitOptions } from '../interfaces';
import { OCSPBaseValidator } from './ocsp-base';

export class OCSPStaplingValidator extends OCSPBaseValidator {
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
  public shouldRun(options: HardenedHttpsValidationKitOptions): boolean {
    return options.ocspPolicy?.mode === 'stapling';
  }

  /**
   * Waits for the 'OCSPResponse' event on the TLS socket and validates the stapled OCSP response.
   * If no OCSP staple is received, applies the OCSP stapling policy to determine whether to fail or allow the connection.
   */
  public validate(socket: tls.TLSSocket, options: HardenedHttpsValidationKitOptions): Promise<void> {
    const { failHard } = options.ocspPolicy!; // Safe due to shouldRun check

    return new Promise((resolve, reject) => {
      let ocspReceived = false;

      socket.once('OCSPResponse', async (response: Buffer) => {
        this.log('OCSP stapling response received, performing validation...');
        ocspReceived = true;

        try {
          await this._validateStapledResponse(response, socket);
          this.log(`Certificate is not revoked.`);
          resolve();
        } catch (err: any) {
          this._handleOCSPError(err, failHard, reject, resolve);
        }
      });

      // Handle the case where the server doesn't send an OCSP staple.
      socket.once('secureConnect', () => {
        if (!ocspReceived) {
          const err = new Error('OCSP stapling response required but not received.');
          this._handleOCSPError(err, failHard, reject, resolve);
        }
      });
    });
  }
}
