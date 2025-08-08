import { HardenedHttpsAgentOptions, type CertificateTransparencyPolicy, type OCSPPolicy, type CRLSetPolicy } from './interfaces';
import { type UnifiedCertificateTransparencyLogList as UnifiedCTLogList } from './types/uni-ct-log-list-schema';
import * as cfsslCaBundle from './resources/cfssl-ca-bundle.crt';
import unifiedCtLogListJson from './resources/unified-log-list.json';

export { cfsslCaBundle };
export const unifiedCtLogList = unifiedCtLogListJson as UnifiedCTLogList;

export const basicCtPolicy = (): CertificateTransparencyPolicy => {
  return {
    logList: unifiedCtLogList,
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

export const defaultAgentOptions = (): HardenedHttpsAgentOptions => {
  return {
    ca: cfsslCaBundle,
    ctPolicy: basicCtPolicy(),
    ocspPolicy: basicMixedOcspPolicy(),
    crlSetPolicy: basicCrlSetPolicy(),
    enableLogging: false,
  };
};
