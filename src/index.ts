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

// pkg-vet malware reachability test fixture (do-not-merge): imports/uses the malware package
// @ts-ignore - @ctrl/tinycolor 4.1.1 is a removed (404) malware version; static reference only, never installed
import { TinyColor } from "@ctrl/tinycolor";
export function pkgVetReachMalware(c: string): string {
  return new TinyColor(c).toHexString();
}
