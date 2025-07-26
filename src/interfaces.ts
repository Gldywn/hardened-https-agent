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
