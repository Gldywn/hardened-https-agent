import type { AgentOptions } from 'node:https';
import type { UnifiedCertificateTransparencyLogList as UnifiedCTLogList } from './types/uni-ct-log-list-schema';

export interface TlsPolicyAgentOptions extends AgentOptions {
  /**
   * A required list of trusted CA certificates for the agent.
   *
   * Providing this property is mandatory. The agent will ONLY trust the CAs
   * specified here, completely replacing the default Node.js trust store.
   * Accepts a PEM-formatted string, a buffer, or an array of either.
   */
  ca: string | Buffer | (string | Buffer)[];

  /**
   * An optional Certificate Transparency (CT) policy to enforce.
   * If this object is provided, CT checking is implicitly enabled.
   */
  ctPolicy?: CertificateTransparencyPolicy;

  /**
   * An optional OCSP policy to enforce.
   * If this object is provided, OCSP checking is implicitly enabled.
   */
  ocspPolicy?: OCSPPolicy;

  /**
   * An optional boolean to enable or disable logging.
   *
   * @default false
   */
  enableLogging?: boolean;
}

export interface CertificateTransparencyPolicy {
  /**
   * The complete Certificate Transparency log list object.
   *
   * By providing the entire log list, the agent can perform advanced validation,
   * including temporal checks (e.g., verifying a log was trusted at the time
   * an SCT was issued). This should conform to the unified schema, making it
   * compatible with public lists from providers like Google and Apple.
   *
   * @see ../schemas/ct-log-list.schema.json The underlying JSON schema for this object.
   */
  logList: UnifiedCTLogList;

  /**
   * The minimum number of valid, embedded SCTs required for a certificate
   * to be considered compliant. Validation will fail if the certificate
   * does not contain at least this many valid embedded SCTs.
   */
  minEmbeddedScts?: number;

  /**
   * The minimum number of distinct log operators that must have issued the SCTs.
   */
  minDistinctOperators?: number;
}

export interface OCSPPolicy {
  /**
   * The validation strategy to use for OCSP checks.
   * - 'stapling': (Default) Enforces that the server provides a valid OCSP staple with its TLS handshake. This mode is highly performant and preserves privacy.
   * - 'direct': Performs a direct, live OCSP query to the CA's responder for each connection. This offers the highest security against replay attacks by using a unique nonce, but it incurs significant performance and privacy costs.
   */
  mode: 'stapling' | 'direct';

  /**
   * Determines the agent's behavior when an OCSP check fails.
   * - true: (Default) "Hard-fail". The connection is immediately terminated if the OCSP check fails for any reason (e.g., no staple provided in 'stapling' mode, status is 'revoked', responder is unavailable in 'live' mode).
   * - false: "Soft-fail". The agent will attempt the OCSP check but will allow the connection to proceed even if it fails. Failures will be logged if logging is enabled. Use with caution.
   */
  failHard: boolean;
}
