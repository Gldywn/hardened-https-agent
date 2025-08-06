import type { AgentOptions } from 'node:https';
import type { UnifiedCertificateTransparencyLogList as UnifiedCTLogList } from './types/uni-ct-log-list-schema';
import type { CRLSet } from '@gldywn/crlset.js';

export interface HardenedHttpsAgentOptions extends AgentOptions {
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
   * Enables CRLSet-based revocation checking if provided.
   * - If set to "downloadLatest", the agent will automatically download the latest CRLSet using the `downloadLatestCRLSetCrx` function from the library and will verify its signature internally.
   *   In this case, signature verification ensures the CRLSet is an authentic Chrome component signed by Google. The agent checks that the CRX3 file is signed with the official Google key associated with the CRLSet component ID (hfnkpimlhhgieaddgfemjhofmfblmnib), and that the public key in the signature matches the expected component.
   * - If a custom CRLSet object is provided, it will be used as-is for revocation checks. In this case, the user is responsible for constructing and trusting the CRLSet.
   */
  crlSet?: 'downloadLatest' | CRLSet;

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
   * - 'mixed': (Default) First tries to validate using a stapled OCSP response. If stapling fails for any reason except a revoked certificate, it falls back to a direct OCSP check.
   * - 'stapling': Enforces that the server provides a valid OCSP staple with its TLS handshake. This mode is highly performant and preserves privacy.
   * - 'direct': Performs a direct, live OCSP query to the CA's responder for each connection. This offers the highest security against replay attacks by using a unique nonce, but it incurs significant performance and privacy costs.
   */
  mode: 'mixed' | 'stapling' | 'direct';

  /**
   * Determines the agent's behavior when an OCSP check fails.
   * - true: (Default) "Hard-fail". The connection is immediately terminated if the OCSP check fails for any reason (e.g., network error, no staple provided in 'stapling' mode, responder is unavailable in 'live' mode, etc.).
   *   In 'mixed' mode, "hard-fail" is only enforced for the final direct OCSP check. If stapling fails for any reason except a revoked certificate, the agent falls back to a direct OCSP check, and only the result of that check determines whether the connection is terminated.
   * - false: "Soft-fail". The agent will attempt the OCSP check and allow the connection to proceed if the check itself fails (e.g., network error, responder unavailable, etc.), but will still block the connection if a valid OCSP response is received indicating the certificate is revoked. Failures will be logged if logging is enabled. Use with caution.
   *
   * @default true
   */
  failHard: boolean;
}
