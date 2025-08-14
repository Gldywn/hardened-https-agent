import * as tls from 'tls';
import { Logger } from '../logger';
import { HardenedHttpsValidationKitOptions } from '../interfaces';

export class WrappedError extends Error {
  public cause?: unknown;

  constructor(message: string, cause?: unknown) {
    super(message);
    this.name = 'WrappedError';
    this.cause = cause;
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, WrappedError);
    }
  }
}

/**
 * An abstract base class for all security policy validators.
 * It handles the injection of the agent context, which provides access
 * to logging and other shared agent methods.
 */
/* istanbul ignore next */
export abstract class BaseValidator {
  private logger: Logger | undefined;

  constructor(logger?: Logger) {
    this.logger = logger;
  }

  protected debug(message: string, ...args: any[]): void {
    this.logger?.debug(`[${this.constructor.name}] ${message}`, ...args);
  }

  protected info(message: string, ...args: any[]): void {
    this.logger?.info(`[${this.constructor.name}] ${message}`, ...args);
  }

  protected warn(message: string, ...args: any[]): void {
    this.logger?.warn(`[${this.constructor.name}] ${message}`, ...args);
  }

  protected wrapError(error: Error): WrappedError {
    return new WrappedError(`[${this.constructor.name}] ${error.message}`, error);
  }

  /**
   * Allows the validator to modify the TLS connection options before the connection is established.
   * By default, it returns the options without modification.
   */
  public onBeforeConnect(options: tls.ConnectionOptions): tls.ConnectionOptions {
    return options;
  }

  /**
   * Checks if this validation should run based on the agent's options.
   * This must be implemented by all concrete validator classes.
   */
  abstract shouldRun(options: HardenedHttpsValidationKitOptions): boolean;

  /**
   * Runs the validation logic for this validator.
   * Returns a Promise that resolves if validation passes, or rejects if it fails.
   * This must be implemented by all concrete validator classes.
   */
  abstract validate(socket: tls.TLSSocket, options: HardenedHttpsValidationKitOptions): Promise<void>;
}
