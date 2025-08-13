import tls from 'node:tls';
import https from 'node:https';
import http from 'node:http';
import { Logger, LogSink } from './logger';
import type { HardenedHttpsValidationKitOptions } from './interfaces';
import { BaseValidator } from './validators/base';
import {
  CTValidator,
  OCSPStaplingValidator,
  OCSPDirectValidator,
  OCSPMixedValidator,
  CRLSetValidator,
} from './validators';
import { Duplex } from 'node:stream';

export class HardenedHttpsValidationKit {
  private readonly options: HardenedHttpsValidationKitOptions;
  private readonly logger: Logger | undefined;
  private readonly validators: BaseValidator[];
  private readonly validatedSockets: WeakSet<tls.TLSSocket> = new WeakSet();

  constructor(options: HardenedHttpsValidationKitOptions, sink?: LogSink) {
    this.options = options;
    if (options.enableLogging) this.logger = new Logger(this.constructor.name, sink);

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

  private runValidation(tlsSocket: tls.TLSSocket, callback?: (err: Error | null, stream: Duplex) => void): void {
    if (this.validatedSockets.has(tlsSocket)) return;
    this.validatedSockets.add(tlsSocket);

    const active = this.getActiveValidators();
    if (active.length === 0) return callback?.(null, tlsSocket);

    let shouldResume = false;
    try {
      // TODO: Check if best to pause the socket right after `secureConnect` event
      tlsSocket.pause();
      this.logger?.log('Socket read paused');
      shouldResume = true;
    } catch (err) {
      /* istanbul ignore next */
      this.logger?.warn('Failed to pause socket', err);
    }

    Promise.all(active.map((v) => v.validate(tlsSocket, this.options)))
      .then(() => {
        this.logger?.log('All enabled validators passed.');
        if (shouldResume) {
          try {
            tlsSocket.resume();
            this.logger?.log('Socket read resumed');
          } catch (err) {
            /* istanbul ignore next */
            this.logger?.warn('Failed to resume socket', err);
          }
        }
        callback?.(null, tlsSocket);
      })
      .catch((err: Error) => {
        this.logger?.error('An error occurred during validation', err);
        callback?.(err, undefined as any);
        // TODO: tlsSocket.destroy(err); ?
      });
  }

  public attachToSocket(tlsSocket: tls.TLSSocket, callback?: (err: Error | null, stream: Duplex) => void): void {
    if (this.validatedSockets.has(tlsSocket)) return;
    this.runValidation(tlsSocket, callback);
  }

  /* istanbul ignore next */
  public attachToAgent(agent: http.Agent | https.Agent): void {
    agent.on('keylog', (_line: Buffer, tlsSocket: tls.TLSSocket) => this.attachToSocket(tlsSocket));
  }
}
