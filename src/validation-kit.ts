import http from 'node:http';
import https from 'node:https';
import tls from 'node:tls';
import { Logger } from './logger';
import type { HardenedHttpsValidationKitOptions } from './interfaces';
import { BaseValidator } from './validators/base';
import {
  CTValidator,
  OCSPStaplingValidator,
  OCSPDirectValidator,
  OCSPMixedValidator,
  CRLSetValidator,
} from './validators';

export class HardenedHttpsValidationKit {
  private readonly options: Omit<HardenedHttpsValidationKitOptions, 'loggerOptions'>;
  private readonly logger: Logger | undefined;
  private readonly validators: BaseValidator[];
  private readonly validatedSockets: WeakSet<tls.TLSSocket> = new WeakSet();

  constructor({ loggerOptions, ...options }: HardenedHttpsValidationKitOptions) {
    this.options = options;
    if (loggerOptions) this.logger = new Logger(this.constructor.name, loggerOptions);

    this.validators = [
      new CTValidator(this.logger),
      new OCSPStaplingValidator(this.logger),
      new OCSPDirectValidator(this.logger),
      new OCSPMixedValidator(this.logger),
      new CRLSetValidator(this.logger),
    ];
  }

  private getActiveValidators(): BaseValidator[] {
    return this.validators.filter((v) => v.shouldRun(this.options));
  }

  public applyBeforeConnect<T extends tls.ConnectionOptions>(options: T): T {
    const active = this.getActiveValidators();
    if (active.length === 0) return options;
    let finalOptions: tls.ConnectionOptions = options;
    for (const validator of active) {
      const mutated = validator.onBeforeConnect(finalOptions);
      finalOptions = { ...finalOptions, ...mutated };
    }
    return finalOptions as T;
  }

  private runValidation(tlsSocket: tls.TLSSocket): void {
    if (this.validatedSockets.has(tlsSocket)) return;
    this.validatedSockets.add(tlsSocket);

    const active = this.getActiveValidators();
    if (active.length === 0) {
      tlsSocket.emit('hardened:validation:success');
      return;
    }

    let shouldResume = false;
    try {
      // TODO: Check if best to pause the socket right after `secureConnect` event
      tlsSocket.pause();
      this.logger?.debug('Socket read paused');
      shouldResume = true;
    } catch (err) {
      /* istanbul ignore next */
      this.logger?.warn('Failed to pause socket', err);
    }

    Promise.all(active.map((v) => v.validate(tlsSocket, this.options)))
      .then(() => {
        this.logger?.info('All enabled validators passed.');
        if (shouldResume) {
          try {
            tlsSocket.resume();
            this.logger?.debug('Socket read resumed');
          } catch (err) {
            /* istanbul ignore next */
            this.logger?.warn('Failed to resume socket', err);
          }
        }
        tlsSocket.emit('hardened:validation:success');
      })
      .catch((err: Error) => {
        this.logger?.error('An error occurred during validation', err);
        tlsSocket.emit('hardened:validation:error', err);
        tlsSocket.destroy(err); // Destroy the socket to prevent further use (and force error propagation to eventual attached agent)
      });
  }

  public attachToSocket(tlsSocket: tls.TLSSocket): void {
    if (this.validatedSockets.has(tlsSocket)) return;
    this.runValidation(tlsSocket);
  }

  /* istanbul ignore next */
  public attachToAgent(agent: http.Agent | https.Agent): void {
    agent.on('keylog', (_line: Buffer, tlsSocket: tls.TLSSocket) => this.attachToSocket(tlsSocket));
  }
}
