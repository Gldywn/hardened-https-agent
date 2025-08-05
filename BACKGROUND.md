# Why a Hardened HTTPS Agent? Understanding Node.js's Default TLS Limitations

`hardened-https-agent` was developed to bridge the gap between the standard TLS/SSL security provided by Node.js and the advanced, robust validation checks expected of modern, security-conscious applications. While Node.js offers a solid foundation for HTTPS connections, it does not, by default, implement several critical security mechanisms that are now standard in web browsers.

This document details what Node.js handles out-of-the-box and, more importantly, what it's missing.

## Default TLS Verifications in Node.js

Node.js relies on the OpenSSL library for its TLS implementation. This means that certificate verification is largely delegated to OpenSSL's standard mechanisms. By default, Node.js performs several fundamental checks for any HTTPS connection:

1.  **Chain of Trust**: It verifies that the server's certificate is signed by a trusted Certificate Authority (CA). Node.js maintains its own built-in list of trusted root CAs rather than using the operating system's trust store. The chain is validated up to one of these roots.
2.  **Temporal Validity**: It ensures the certificate is not expired and is currently within its validity period.
3.  **X.509 Constraints**: It respects certificate attributes like `Basic Constraints` and `Key Usage`. For instance, an intermediate certificate must be marked as a CA to be able to issue other certificates.
4.  **Hostname Verification**: It checks that the hostname you are connecting to matches the `Subject Alternative Name` (or `Common Name`) in the certificate, preventing man-in-the-middle attacks.

If any of these checks fail, the connection is aborted. These verifications provide a baseline level of security, ensuring the cryptographic integrity of the certificate chain and the server's identity.

## The Gaps: What Node.js Doesn't Check by Default

The primary motivation for `hardened-https-agent` lies in what Node.js _omits_ for the sake of simplicity and performance. These omissions, while understandable for a general-purpose runtime, can be critical security risks in sensitive environments.

### 1. No Automatic Certificate Revocation Checking

**A certificate that passes all the checks above could still be compromised.** If a private key is stolen, the CA will revoke the corresponding certificate. However, Node.js **does not automatically check for revocation**.

- **CRL (Certificate Revocation List)**: Node.js can check a certificate against a CRL, but only if the developer manually provides the CRL file via the `crl` option. It will not automatically download or consult CRLs on its own.
- **OCSP (Online Certificate Status Protocol)**: Node.js can request an OCSP staple from the server (`requestOCSP` option), which is a signed assertion of the certificate's status from the CA. However, Node.js only provides the raw OCSP response to the developer. It is up to the application code to parse the response, verify its signature, and act on the status (e.g., terminate the connection if `revoked`). It does not do this automatically.
- **CRLSet/CRLite**: Modern browsers like Google Chrome use aggregated, compressed lists of revoked certificates (CRLSet) to quickly block known-bad certificates without the high overhead of traditional CRL/OCSP checks. Node.js has no equivalent mechanism.

**This is where `hardened-https-agent` steps in**, handling both OCSP stapling (via [`easy-ocsp`](https://github.com/timokoessler/easy-ocsp)) and modern CRLSet-based checks (via [`crlset.js`](https://github.com/Gldywn/crlset.js)) to provide comprehensive revocation coverage.

### 2. No Certificate Transparency (CT) Enforcement

**Certificate Transparency (CT)** is a critical defense against CA mis-issuance or rogue CAs. It requires that all issued certificates be published in public, append-only, and auditable logs. Web browsers enforce this by requiring valid **Signed Certificate Timestamps (SCTs)** as proof of publication. Without the required number of SCTs from trusted logs, a browser will reject the certificate.

**Node.js does not perform any Certificate Transparency checks.** A certificate that would be rejected by Chrome for lacking valid SCTs will be accepted by a default Node.js HTTPS client.

**`hardened-https-agent` solves this problem** by leveraging libraries like [`sct.js`](https://github.com/Gldywn/sct.js) to parse, verify, and enforce a configurable Certificate Transparency policy on all TLS connections, ensuring that only publicly logged and audited certificates are trusted.

### 3. Enforced Custom Trust Store

While Node.js allows developers to provide a custom Certificate Authority (CA) trust store via the `ca` option, it does not require it. Developers often rely on the built-in CA list, which may not align with their organization's specific security policies.

`hardened-https-agent` **enforces** the use of an explicit trust store. This design decision compels developers to be deliberate about who they trust. To ease maintenance, the agent will also provide options to use well-maintained, trusted CA bundles from sources like Cloudflare's CFSSL.
