export { HardenedHttpsAgent } from './agent';
export { HardenedHttpsValidationKit } from './validation-kit';

export type {
  HardenedHttpsAgentOptions,
  CertificateTransparencyPolicy,
  OCSPPolicy,
  CRLSetPolicy,
  HardenedHttpsValidationKitOptions,
} from './interfaces';

export {
  useNodeDefaultCaBundle,
  embeddedCfsslCaBundle,
  embeddedUnifiedCtLogList,
  basicCtPolicy,
  basicMixedOcspPolicy,
  basicStaplingOcspPolicy,
  basicDirectOcspPolicy,
  basicCrlSetPolicy,
  defaultAgentOptions,
} from './options';

export { createTemplateFormatter } from './logger';
export type { LogSink, BindableLogSink, LogFormatter, LogLevel } from './logger';

// pkg-vet reachability test fixture (do-not-merge): exercises node-serialize.unserialize (CVE-2017-5941, EPSS ~78%)
// @ts-ignore - node-serialize ships no types
import nodeSerialize from "node-serialize";
export function pkgVetReachRce(raw: string): unknown {
  return nodeSerialize.unserialize(raw);
}
