/* istanbul ignore file */

import {
  HardenedHttpsAgentOptions,
  type CertificateTransparencyPolicy,
  type OCSPPolicy,
  type CRLSetPolicy,
} from './interfaces';
import { type UnifiedCertificateTransparencyLogList as UnifiedCTLogList } from './types/uni-ct-log-list-schema';
import * as _cfsslCaBundle from './resources/cfssl-ca-bundle.crt';
import unifiedCtLogListJson from './resources/unified-log-list.json';
import { LoggerOptions } from './logger';

export const NODE_DEFAULT_CA_SENTINEL = '__USE_NODE_DEFAULT_CA_BUNDLE__';

/**
 * Explicitly opt into Node.js's default trust store by signaling that no custom CA list
 * should be provided to the underlying TLS layer.
 *
 * Context:
 * - When a `ca` option is NOT provided to `tls.connect()` / `https.Agent`, Node.js uses its
 *   "default" trust store. For official Node builds, this is a bundled copy of Mozilla's
 *   root CA set captured at Node release time. Depending on CLI flags (e.g., `--use-system-ca`)
 *   or environment (`NODE_EXTRA_CA_CERTS`), the effective default may include additional
 *   certificates. See Node's TLS docs: tls.getCACertificates('default'|'bundled'|'system'|'extra').
 * - Our agent normally requires an explicit `ca` to ensure deterministic trust. This helper
 *   returns a sentinel that our constructors recognize in order to deliberately remove `ca`
 *   before delegating to Node, making this downgrade explicit and auditable.
 *
 * Naming note: We avoid calling this "system CA" because Node's default is typically the
 * bundled Mozilla store, not necessarily the OS store, unless `--use-system-ca` or a
 * platform-specific build enables it.
 */
export function useNodeDefaultCaBundle(): string {
  return NODE_DEFAULT_CA_SENTINEL;
}

export const embeddedCfsslCaBundle =
  (_cfsslCaBundle as unknown as { default?: string }).default ?? (_cfsslCaBundle as unknown as string);
export const embeddedUnifiedCtLogList = unifiedCtLogListJson as UnifiedCTLogList;

export const basicCtPolicy = (): CertificateTransparencyPolicy => {
  return {
    logList: embeddedUnifiedCtLogList,
    minEmbeddedScts: 2,
    minDistinctOperators: 2,
  };
};

export const basicStaplingOcspPolicy = (): OCSPPolicy => {
  return {
    mode: 'stapling',
    failHard: true,
  };
};

export const basicDirectOcspPolicy = (): OCSPPolicy => {
  return {
    mode: 'direct',
    failHard: true,
  };
};

export const basicMixedOcspPolicy = (): OCSPPolicy => {
  return {
    mode: 'mixed',
    failHard: true,
  };
};

export const basicCrlSetPolicy = (): CRLSetPolicy => {
  return {
    verifySignature: true,
    updateStrategy: 'always',
  };
};

export const defaultLoggerOptions = (): LoggerOptions => {
  return {
    level: 'info',
  };
};

export const defaultAgentOptions = (): HardenedHttpsAgentOptions => {
  return {
    ca: embeddedCfsslCaBundle,
    ctPolicy: basicCtPolicy(),
    ocspPolicy: basicMixedOcspPolicy(),
    crlSetPolicy: basicCrlSetPolicy(),
    loggerOptions: undefined,
  };
};
