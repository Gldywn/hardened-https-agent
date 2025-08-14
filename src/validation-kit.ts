import http from 'node:http';
import https from 'node:https';
import tls from 'node:tls';
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
import { EventEmitter } from 'node:events';

export type ValidationKitEvents = {
  'validation:success': (tlsSocket: tls.TLSSocket) => void;
  'validation:error': (error: Error) => void;
};

/* istanbul ignore next */
class TypedEventEmitter<Events extends Record<string, (...args: any[]) => void>> extends EventEmitter {
  public override on<K extends keyof Events & string>(eventName: K, listener: Events[K]): this {
    return super.on(eventName, listener as (...args: any[]) => void);
  }
  public override once<K extends keyof Events & string>(eventName: K, listener: Events[K]): this {
    return super.once(eventName, listener as (...args: any[]) => void);
  }
  public override off<K extends keyof Events & string>(eventName: K, listener: Events[K]): this {
    return super.off(eventName, listener as (...args: any[]) => void);
  }
  public override emit<K extends keyof Events & string>(eventName: K, ...args: Parameters<Events[K]>): boolean {
    return super.emit(eventName, ...args);
  }
}

export class HardenedHttpsValidationKit extends TypedEventEmitter<ValidationKitEvents> {
  private readonly options: HardenedHttpsValidationKitOptions;
  private readonly logger: Logger | undefined;
  private readonly validators: BaseValidator[];
  private readonly validatedSockets: WeakSet<tls.TLSSocket> = new WeakSet();

  constructor(options: HardenedHttpsValidationKitOptions, sink?: LogSink) {
    super();
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

  private runValidation(tlsSocket: tls.TLSSocket): void {
    if (this.validatedSockets.has(tlsSocket)) return;
    this.validatedSockets.add(tlsSocket);

    const active = this.getActiveValidators();
    if (active.length === 0) {
      this.emit('validation:success', tlsSocket);
      return;
    }

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
        this.emit('validation:success', tlsSocket);
      })
      .catch((err: Error) => {
        this.logger?.error('An error occurred during validation', err);
        tlsSocket.destroy(err); // Destroy the socket to prevent further use (and force error propagation to eventual attached agent)
        this.emit('validation:error', err);
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
