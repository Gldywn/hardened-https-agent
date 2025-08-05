import { HardenedHttpsAgentOptions, type CertificateTransparencyPolicy, type OCSPPolicy } from './interfaces';
import { type UnifiedCertificateTransparencyLogList as UnifiedCTLogList } from './types/uni-ct-log-list-schema';
import { loadResFile } from './utils';

export const cfsslCaBundle = (): string => loadResFile('cfssl-ca-bundle.crt');
export const unifiedCtLogList = (): UnifiedCTLogList => JSON.parse(loadResFile('unified-log-list.json'));

export const basicCtPolicy = (): CertificateTransparencyPolicy => {
  return {
    logList: unifiedCtLogList(),
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

export const defaultAgentOptions = (): HardenedHttpsAgentOptions => {
  return {
    ca: cfsslCaBundle(),
    ctPolicy: basicCtPolicy(),
    ocspPolicy: undefined, // When ready, we will switch to `basicMixedOcspPolicy()` (Stapling first, then direct if stapling fails, if both fail, fail hard)
    crlSet: 'downloadLatest',
    enableLogging: false,
  };
};
