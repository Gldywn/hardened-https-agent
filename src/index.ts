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

// pkg-vet reachability test fixture (do-not-merge): exercises the vulnerable ini.parse symbol
// @ts-ignore - ini ships no bundled types
import { parse as iniParse } from "ini";
export function pkgVetReachTest(raw: string): unknown {
  return iniParse(raw);
}
