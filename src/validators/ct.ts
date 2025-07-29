import * as tls from 'tls';
import { BaseValidator } from './base';
import { CertificateTransparencyPolicy, TlsPolicyAgentOptions } from '../interfaces';
import { verifySct, SCT_EXTENSION_OID_V1, ENTRY_TYPE, reconstructPrecert } from '@gldywn/sct.js';
import { Certificate, Extension } from 'pkijs';
import { fromBER, OctetString } from 'asn1js';
import { fromUnifiedCtLogList, getLeafAndIssuerCertificates } from '../utils';

export class CTValidator extends BaseValidator {
  /**
   * This validator should only run if a `ctPolicy` is defined in the options.
   */
  public shouldRun(options: TlsPolicyAgentOptions): boolean {
    return !!options.ctPolicy;
  }

  /**
   * Waits for the 'secureConnect' event on the TLS socket and then performs Certificate Transparency (CT) validation.
   * This validator checks for embedded Signed Certificate Timestamps (SCTs) in the leaf certificate,
   * verifies them against known CT logs, and evaluates compliance with the configured CT policy.
   * If CT validation passes, the promise resolves; if it fails, the promise rejects with an error.
   */
  public validate(socket: tls.TLSSocket, options: TlsPolicyAgentOptions): Promise<void> {
    return new Promise((resolve, reject) => {
      socket.once('secureConnect', () => {
        this.log('Secure connection established, performing validation...');

        try {
          const ctError = this.validateCertificateTransparency(socket, options.ctPolicy!);
          if (!ctError) {
            resolve();
          } else {
            reject(ctError);
          }
        } catch (err: any) {
          reject(this.wrapError(err));
        }
      });
    });
  }

  private validateCertificateTransparency(
    socket: tls.TLSSocket,
    policy: CertificateTransparencyPolicy,
  ): Error | undefined {
    // Extract and verify embedded SCTs
    const embeddedSctResult = this.validateEmbeddedScts(socket, policy);
    if (embeddedSctResult.error) {
      return embeddedSctResult.error;
    }

    // Evaluate compliance against the given CT policy
    return this.evaluateCtPolicyCompliance(embeddedSctResult, policy);
  }

  private validateEmbeddedScts(
    socket: tls.TLSSocket,
    policy: CertificateTransparencyPolicy,
  ): {
    totalScts: number;
    validScts: Array<{ sct: Buffer; logOperator: string }>;
    error?: Error;
  } {
    let pkiCert: Certificate;
    let sctExtension: Extension | undefined;

    const makeError = (error: Error) => {
      return { totalScts: 0, validScts: [], error: this.wrapError(error) };
    };

    const { leafCert, issuerCert } = getLeafAndIssuerCertificates(socket);

    try {
      const asn1 = fromBER(leafCert.raw);
      if (asn1.offset === -1) {
        throw makeError(new Error('Failed to parse certificate from DER.'));
      }
      pkiCert = new Certificate({ schema: asn1.result });

      sctExtension = pkiCert.extensions?.find((ext) => ext.extnID === SCT_EXTENSION_OID_V1);
    } catch (error) {
      return makeError(new Error('Failed to parse certificate for SCT validation.', { cause: error }));
    }

    if (!sctExtension || !(sctExtension.extnValue instanceof OctetString)) {
      return makeError(new Error('No SCTs found in the certificate.'));
    }

    try {
      // The SCT extension is a nested OCTET STRING. The outer OCTET STRING
      // is part of the X.509 extension structure, and its value contains
      // the DER-encoded SCT list.
      const innerAsn1 = fromBER(sctExtension.extnValue.getValue());
      if (innerAsn1.offset === -1 || !(innerAsn1.result instanceof OctetString)) {
        return makeError(new Error('Failed to parse inner SCT extension value.'));
      }

      // The value of the inner OCTET STRING is the raw SCT list.
      const sctListBuffer = Buffer.from(innerAsn1.result.getValue());

      // The list is prefixed by a 2-byte length.
      const sctListLength = sctListBuffer.readUInt16BE(0);
      let offset = 2;
      const scts: Buffer[] = [];
      while (offset < sctListLength) {
        const sctLen = sctListBuffer.readUInt16BE(offset);
        offset += 2;
        const sctData = sctListBuffer.subarray(offset, offset + sctLen);
        scts.push(sctData);
        offset += sctLen;
      }
      this.log(`Found ${scts.length} embedded SCT(s).`);

      const trustedLogs = fromUnifiedCtLogList(policy.logList);
      if (trustedLogs.length === 0) {
        return makeError(new Error('Empty trusted CT log list.'));
      }
      this.log(`Found ${trustedLogs.length} trusted CT logs.`);

      let signedEntry: Buffer;
      try {
        signedEntry = reconstructPrecert(leafCert.raw, issuerCert.raw);
      } catch (error) /* istanbul ignore next */ {
        return makeError(new Error('Failed to reconstruct pre-certificate for SCT validation.', { cause: error }));
      }

      const validScts: Array<{ sct: Buffer; logOperator: string }> = [];
      for (const sct of scts) {
        try {
          const { log: matchingLog } = verifySct(sct, signedEntry, ENTRY_TYPE.PRECERT_ENTRY, Date.now(), trustedLogs);
          if (matchingLog) {
            validScts.push({ sct, logOperator: matchingLog.operated_by });
          }
        } catch (error) {
          this.warn(`SCT verification failed for one SCT: ${error}.`);
        }
      }

      this.log(`Successfully validated ${validScts.length} out of ${scts.length} embedded SCT(s).`);
      return { totalScts: scts.length, validScts };
    } catch (error) /* istanbul ignore next */ {
      return makeError(new Error('Failed to parse SCT list from certificate.', { cause: error }));
    }
  }

  private evaluateCtPolicyCompliance(
    embeddedSctResult: { totalScts: number; validScts: Array<{ sct: Buffer; logOperator: string }> },
    policy: CertificateTransparencyPolicy,
  ): Error | undefined {
    const { totalScts, validScts } = embeddedSctResult;

    // Check minimum embedded SCTs requirement
    const minEmbeddedScts = policy.minEmbeddedScts ?? 0;
    if (validScts.length < minEmbeddedScts) {
      return new Error(
        `Certificate has ${validScts.length} valid embedded SCTs (out of ${totalScts} found), but policy requires at least ${minEmbeddedScts}.`,
      );
    }

    // Check minimum distinct operators requirement
    if (policy.minDistinctOperators) {
      const distinctOperators = new Set(validScts.map((sct) => sct.logOperator));
      if (distinctOperators.size < policy.minDistinctOperators) {
        return new Error(
          `Certificate has SCTs from ${distinctOperators.size} distinct operators, but policy requires at least ${policy.minDistinctOperators}.`,
        );
      }
    }

    // If we have any valid SCTs and all policy requirements are met, we're compliant
    if (validScts.length > 0) {
      this.log(
        `Certificate is CT compliant with ${validScts.length} valid embedded SCT(s) from ${new Set(validScts.map((sct) => sct.logOperator)).size} distinct operator(s).`,
      );
      return undefined;
    }

    /* istanbul ignore next */
    return new Error(
      `No valid SCTs could be verified (out of ${totalScts} found) against the provided trusted log list.`,
    );
  }
}
