import { Agent } from 'node:https';
import tls from 'node:tls';
import type { Duplex } from 'node:stream';
import { Logger } from './logger';
import { HardenedHttpsAgentOptions } from './interfaces';
import { HardenedHttpsValidationKit } from './validation-kit';
import { NODE_DEFAULT_CA_SENTINEL } from './options';

export class HardenedHttpsAgent extends Agent {
  #options: HardenedHttpsAgentOptions;
  #logger: Logger | undefined;
  #kit: HardenedHttpsValidationKit;

  constructor(options: HardenedHttpsAgentOptions) {
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

    const { ctPolicy, ocspPolicy, crlSetPolicy, loggerOptions } = this.#options;
    if (loggerOptions) this.#logger = new Logger(this.constructor.name, loggerOptions);
    this.#kit = new HardenedHttpsValidationKit({ ctPolicy, ocspPolicy, crlSetPolicy, loggerOptions });
  }

  override createConnection(
    options: tls.ConnectionOptions,
    callback: (err: Error | null, stream: Duplex) => void,
  ): Duplex {
    this.#logger?.info('Initiating new TLS connection...');

    // Allow validators to modify the connection options
    const finalOptions = this.#kit.applyBeforeConnect(options);

    // Create the socket
    const tlsSocket = tls.connect(finalOptions);
    // Handle validation success
    tlsSocket.on('hardened:validation:success', () => {
      this.#logger?.info('TLS connection established and validated.');
      callback(null, tlsSocket);
    });
    // Handle socket errors
    tlsSocket.on('error', (err: Error) => {
      this.#logger?.error('An error occurred during TLS connection setup', err);
      callback(err, undefined as any);
    });

    // Attach the validation kit to the socket
    this.#kit.attachToSocket(tlsSocket);

    return undefined as any;
  }
}
