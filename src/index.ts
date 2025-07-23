import { Agent } from 'node:https';
import type { DetailedPeerCertificate } from 'node:tls';
import tls from 'node:tls';
import type { Duplex } from 'node:stream';
import { CertificateTransparencyPolicy, TlsPolicyAgentOptions } from './interfaces';
import { verifySct, SCT_EXTENSION_OID_V1, ENTRY_TYPE, reconstructPrecert } from '@gldywn/sct.js';
import { Certificate, Extension } from 'pkijs';
import { fromBER, OctetString } from 'asn1js';
import { fromUnifiedCTLogList } from './utils';

export class TlsPolicyAgent extends Agent {
  #options: TlsPolicyAgentOptions;

  constructor(options: TlsPolicyAgentOptions) {
    super(options);
    this.#options = options;
    if (!this.#options.ca || (Array.isArray(this.#options.ca) && this.#options.ca.length === 0)) {
      throw new Error('The `ca` property cannot be empty.');
    }
  }

  private log(message: string, ...args: any[]): void {
    if (this.#options.enableLogging) {
      console.log(`[Debug] TlsPolicyAgent: ${message}`, ...args);
    }
  }

  private error(message: string, ...args: any[]): void {
    if (this.#options.enableLogging) {
      console.error(`[Error] TlsPolicyAgent: ${message}`, ...args);
    }
  }

  override createConnection(
    options: tls.ConnectionOptions,
    callback?: (err: Error | null, stream: Duplex) => void,
  ): Duplex {
    const socket = tls.connect(options);

    socket.on('secureConnect', () => {
      const cert = socket.getPeerCertificate(true);

      if (this.#options.ctPolicy) {
        const ctError = this.validateCertificateTransparency(cert, this.#options.ctPolicy);

        if (ctError) {
          this.error('CT policy validation failed, closing connection.', ctError);
          callback?.(ctError, undefined as any);
          socket.destroy(ctError);
          return;
        }
        this.log('CT policy validation successful.');
      }

      // If all checks pass, we can proceed with the connection
      callback?.(null, socket);
    });

    socket.on('error', (err) => {
      // Pass errors to the callback to ensure they are handled
      callback?.(err, undefined as any);
    });

    return socket;
  }

  private validateCertificateTransparency(
    cert: DetailedPeerCertificate,
    policy: CertificateTransparencyPolicy,
  ): Error | undefined {
    this.log('Starting Certificate Transparency (CT) policy validation');

    // Extract and verify embedded SCTs
    const embeddedSctResult = this.validateEmbeddedScts(cert, policy);
    if (embeddedSctResult.error) {
      return embeddedSctResult.error;
    }

    // TODO: Extract and verify OCSP SCTs
    // const ocspSctResult = this.validateOcspScts(cert, policy);

    // TODO: Extract and verify TLS extension SCTs
    // const tlsExtensionSctResult = this.validateTlsExtensionScts(cert, policy);

    // Evaluate compliance against the given CT policy
    return this.evaluateCtPolicyCompliance(embeddedSctResult, policy);
  }

  private validateEmbeddedScts(
    cert: DetailedPeerCertificate,
    policy: CertificateTransparencyPolicy,
  ): { validScts: Array<{ sct: Buffer; logOperator: string }>; error?: Error } {
    this.log('Validating embedded SCTs...');
    let pkiCert: Certificate;
    let sctExtension: Extension | undefined;

    try {
      const asn1 = fromBER(cert.raw);
      if (asn1.offset === -1) {
        throw new Error('Failed to parse certificate from DER.');
      }
      pkiCert = new Certificate({ schema: asn1.result });

      sctExtension = pkiCert.extensions?.find((ext) => ext.extnID === SCT_EXTENSION_OID_V1);
    } catch (error) {
      this.error('Error during certificate parsing.', error);
      return { validScts: [], error: new Error('Failed to parse certificate for SCT validation.') };
    }

    if (!sctExtension || !(sctExtension.extnValue instanceof OctetString)) {
      return { validScts: [], error: new Error('No SCTs found in the certificate.') };
    }

    try {
      // The SCT extension is a nested OCTET STRING. The outer OCTET STRING
      // is part of the X.509 extension structure, and its value contains
      // the DER-encoded SCT list.
      const innerAsn1 = fromBER(sctExtension.extnValue.getValue());
      if (innerAsn1.offset === -1 || !(innerAsn1.result instanceof OctetString)) {
        return { validScts: [], error: new Error('Failed to parse inner SCT extension value') };
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

      const trustedLogs = fromUnifiedCTLogList(policy.logList);
      if (trustedLogs.length === 0) {
        return { validScts: [], error: new Error('No trusted CT logs available for verification.') };
      }

      this.log(`Found ${trustedLogs.length} trusted CT logs.`);

      // Embedded SCTs are signatures of the pre-certificate. We must reconstruct
      // the pre-certificate from the leaf and issuer certificates to verify them.
      const issuerCert = cert.issuerCertificate;
      if (!issuerCert) {
        return { validScts: [], error: new Error('Could not find issuer certificate in the chain.') };
      }

      let signedEntry: Buffer;
      try {
        signedEntry = reconstructPrecert(cert.raw, issuerCert.raw);
      } catch (error) {
        this.error('Error reconstructing the pre-certificate signed entry.', error);
        return { validScts: [], error: new Error('Failed to reconstruct pre-certificate for SCT validation.') };
      }

      const validScts: Array<{ sct: Buffer; logOperator: string }> = [];
      for (const sct of scts) {
        try {
          const matchingLog = verifySct(sct, signedEntry, ENTRY_TYPE.PRECERT_ENTRY, Date.now(), trustedLogs);
          if (matchingLog) {
            validScts.push({ sct, logOperator: matchingLog.operated_by });
          }
        } catch (error) {
          this.log(`SCT verification failed for one SCT: ${error}`);
        }
      }

      this.log(`Successfully verified ${validScts.length} embedded SCT(s).`);
      return { validScts };
    } catch (error) {
      this.error('Error parsing the SCT list from the certificate extension.', error);
      return { validScts: [], error: new Error('Failed to parse SCT list from certificate.') };
    }
  }

  private evaluateCtPolicyCompliance(
    embeddedSctResult: { validScts: Array<{ sct: Buffer; logOperator: string }> },
    policy: CertificateTransparencyPolicy,
  ): Error | undefined {
    this.log('Evaluating overall CT policy compliance...');
    const { validScts } = embeddedSctResult;

    // Check minimum embedded SCTs requirement
    const minEmbeddedScts = policy.minEmbeddedScts ?? 0;
    if (validScts.length < minEmbeddedScts) {
      return new Error(
        `Certificate has ${validScts.length} valid embedded SCTs, but policy requires at least ${minEmbeddedScts}.`,
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

    return new Error('No valid SCTs could be verified against the provided trusted log list.');
  }
}
