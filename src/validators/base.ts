import * as tls from 'tls';
import { Logger } from '../agent';
import { TlsPolicyAgentOptions } from '../interfaces';

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
export abstract class BaseValidator {
  private logger: Logger;

  constructor(logger: Logger) {
    this.logger = logger;
  }

  protected log(message: string, ...args: any[]): void {
    this.logger.log(`[${this.constructor.name}] ${message}`, ...args);
  }

  protected warn(message: string, ...args: any[]): void {
    this.logger.warn(`[${this.constructor.name}] ${message}`, ...args);
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
  abstract shouldRun(options: TlsPolicyAgentOptions): boolean;

  /**
   * Runs the validation logic for this validator.
   * Returns a Promise that resolves if validation passes, or rejects if it fails.
   * This must be implemented by all concrete validator classes.
   */
  abstract validate(socket: tls.TLSSocket, options: TlsPolicyAgentOptions): Promise<void>;
}
