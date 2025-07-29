import { Agent } from 'node:https';
import tls from 'node:tls';
import type { Duplex } from 'node:stream';
import { TlsPolicyAgentOptions } from './interfaces';
import { CTValidator, OCSPStaplingValidator, OCSPDirectValidator } from './validators';
import { BaseValidator } from './validators/base';

/* istanbul ignore next */
export class Logger {
  private options: TlsPolicyAgentOptions;
  constructor(options: TlsPolicyAgentOptions) {
    this.options = options;
  }

  public log(message: string, ...args: any[]): void {
    if (this.options.enableLogging) {
      console.log(`[Debug] TlsPolicyAgent: ${message}`, ...args);
    }
  }

  public warn(message: string, ...args: any[]): void {
    if (this.options.enableLogging) {
      console.warn(`[Warning] TlsPolicyAgent: ${message}`, ...args);
    }
  }

  public error(message: string, ...args: any[]): void {
    if (this.options.enableLogging) {
      console.error(`[Error] TlsPolicyAgent: ${message}`, ...args);
    }
  }
}

export class TlsPolicyAgent extends Agent {
  #options: TlsPolicyAgentOptions;
  #logger: Logger;
  #validators: BaseValidator[];

  constructor(options: TlsPolicyAgentOptions) {
    super(options);
    this.#options = options;
    if (!this.#options.ca || (Array.isArray(this.#options.ca) && this.#options.ca.length === 0)) {
      throw new Error('The `ca` property cannot be empty.');
    }

    this.#logger = new Logger(options);

    this.#validators = [
      new CTValidator(this.#logger),
      new OCSPStaplingValidator(this.#logger),
      new OCSPDirectValidator(this.#logger),
    ];
  }

  override createConnection(
    options: tls.ConnectionOptions,
    callback: (err: Error | null, stream: Duplex) => void,
  ): Duplex {
    this.#logger.log('Initiating new TLS connection...');

    const activeValidators = this.#validators.filter((validator) => {
      const shouldRun = validator.shouldRun(this.#options);
      if (shouldRun) {
        this.#logger.log(`Validator "${validator.constructor.name}" is enabled for this connection.`);
      }
      return shouldRun;
    });

    // Allow active validators to modify the connection options
    const finalOptions = activeValidators.reduce(
      (currentOptions, validator) => validator.onBeforeConnect(currentOptions),
      options,
    );
    const socket = tls.connect(finalOptions);

    // Dynamically build the list of validation promises based on the agent's policies.
    const validationPromises = activeValidators.map((validator) => validator.validate(socket, this.#options));

    // If no validators are active for this connection, we only need to wait
    // for the standard 'secureConnect' event before handing off the socket.
    if (validationPromises.length === 0) {
      this.#logger.log('No extra validators enabled. Proceeding with native TLS validation.');
      socket.once('secureConnect', () => {
        callback(null, socket);
      });
    } else {
      // If some validators are active, we wait for them to complete before releasing the socket if they all pass only.
      Promise.all(validationPromises)
        .then(() => {
          this.#logger.log('All enabled validators passed. Releasing the socket.');
          callback(null, socket);
        })
        .catch((err: Error) => {
          this.#logger.error('An error occurred during validation', err);
          socket.destroy(err);
          callback(err, undefined as any);
        });
    }

    socket.on('error', (err: Error) => {
      this.#logger.error('A socket error occurred during connection setup.', err);
      callback(err, undefined as any);
    });

    return socket;
  }
}
