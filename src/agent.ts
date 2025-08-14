import { Agent } from 'node:https';
import tls from 'node:tls';
import type { Duplex } from 'node:stream';
import { Logger, LogSink } from './logger';
import { HardenedHttpsAgentOptions } from './interfaces';
import { HardenedHttpsValidationKit } from './validation-kit';
import { NODE_DEFAULT_CA_SENTINEL } from './options';

export class HardenedHttpsAgent extends Agent {
  #options: HardenedHttpsAgentOptions;
  #logger: Logger | undefined;
  #kit: HardenedHttpsValidationKit;

  constructor(options: HardenedHttpsAgentOptions, sink?: LogSink) {
    const useNodeDefaultCaBundle = (options as any)?.ca === NODE_DEFAULT_CA_SENTINEL;
    const optionsForSuper = useNodeDefaultCaBundle ? (({ ca, ...rest }) => rest)(options as any) : options;
    super(optionsForSuper);

    this.#options = options;
    if (
      !useNodeDefaultCaBundle &&
      (!this.#options.ca || (Array.isArray(this.#options.ca) && this.#options.ca.length === 0))
    ) {
      throw new Error('The `ca` property cannot be empty.');
    }

    const { enableLogging, ctPolicy, ocspPolicy, crlSetPolicy } = this.#options;
    if (enableLogging) this.#logger = new Logger(this.constructor.name, sink);
    this.#kit = new HardenedHttpsValidationKit({ enableLogging, ctPolicy, ocspPolicy, crlSetPolicy }, sink);
  }

  override createConnection(
    options: tls.ConnectionOptions,
    callback: (err: Error | null, stream: Duplex) => void,
  ): Duplex {
    this.#logger?.log('Initiating new TLS connection...');

    // Handle validation success
    this.#kit.once('validation:success', (tlsSocket) => {
      callback(null, tlsSocket);
    });

    // Allow validators to modify the connection options
    const finalOptions = this.#kit.applyBeforeConnect(options);

    // Create the socket
    const tlsSocket = tls.connect(finalOptions);
    // Handle validation success
    tlsSocket.on('hardened:validation:success', () => {
      callback(null, tlsSocket);
    });
    // Handle socket errors
    tlsSocket.on('error', (err: Error) => {
      this.#logger?.error('A socket error occurred during connection setup.', err);
      callback(err, undefined as any);
    });

    // Attach the validation kit to the socket
    this.#kit.attachToSocket(tlsSocket);

    return undefined as any;
  }
}
