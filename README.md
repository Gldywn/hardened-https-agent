<p align="center">
  <img src="./assets/header.png" alt="hardened-https-agent"/>
</p>

# hardened-https-agent

A security-first `https.Agent` for Node.js with advanced certificate validation: Custom CA, Certificate Transparency (CT), OCSP, and CRLSet.

## What is hardened-https-agent?

A quick search on GitHub reveals a recurring pattern: developers are surprised to learn that **Node.js does not validate TLS certificates the same way a browser does**. Issues have been raised in popular projects like [got](https://github.com/sindresorhus/got/issues/1994) and [Uptime Kuma](https://github.com/louislam/uptime-kuma/issues/1254) when users discover that connections to servers with _revoked certificates succeed without any warning_.

This behavior is, in fact, (more or less) intentional. As explained in the Node.js repository itself ([#16338](https://github.com/nodejs/node/issues/16338)), performing robust, browser-grade checks for things like certificate revocation is a complex task with performance and privacy trade-offs. Node.js provides the necessary cryptographic building blocks, but leaves the responsibility of implementing these advanced security policies entirely up to the developer.

This is where `hardened-https-agent` comes in: an enhanced `https.Agent` for Node.js that does the heavy lifting to bridge this gap, providing modern security policies for your outbound TLS connections.

### Default Node.js Behavior vs. `hardened-https-agent`

| Verification Check            | Default Node.js (`https.Agent`) |   `hardened-https-agent`    |
| ----------------------------- | :-----------------------------: | :-------------------------: |
| **Trust Model**               |                                 |                             |
| Custom CA Store               |    ⚠️ (Optional `ca` prop.)     | ✅ (Enforced, with helpers) |
| **Certificate Revocation**    |                                 |                             |
| OCSP Stapling                 | ⚠️ (Raw staple, not validated)  |             ✅              |
| OCSP Direct                   |               ❌                |             ✅              |
| CRLs                          |    ⚠️ (Manual CRL file only)    |             ✅              |
| CRLSet                        |               ❌                |             ✅              |
| **Certificate Integrity**     |                                 |                             |
| Certificate Transparency (CT) |               ❌                |             ✅              |

For a detailed technical explanation of the gaps in Node.js's default behavior, see [Why a Hardened Agent?](./BACKGROUND.md).

## Use Cases

This agent is designed for any Node.js application or library that needs to **reliably verify the authenticity of a remote server**. Its primary goal is to protect against connecting to servers using _revoked or mis-issued certificates_—a check that Node.js does not perform by default. It is essential for securing backend services, hardening client libraries (like SDKs), or protecting applications in zero-trust environments like TEEs or AI agents. The library ships with a **set of pre-defined policies** for common needs, while **also providing complete control to create a tailored policy** that fits your exact security requirements.

## Features

### Implemented

- [x] **[Certificate Transparency (CT)](https://certificate.transparency.dev/)** (via Embedded SCTs)
- [x] **[OCSP "Stapling"](https://en.wikipedia.org/wiki/OCSP_stapling)** (Checks the OCSP response provided by the server during the TLS handshake)
- [x] **[OCSP "Direct"](https://fr.wikipedia.org/wiki/Online_Certificate_Status_Protocol)** (Client sends an OCSP request directly to the CA)
- [x] **[CRLSet](https://www.chromium.org/Home/chromium-security/crlsets/)** (Fast and efficient revocation checks using Google Chrome's aggregated CRL lists)

### Roadmap

- [ ] **Hybrid OCSP Mode**: Use OCSP Stapling with a fallback to a direct OCSP request if the staple is not provided or if stapling fails.
- [ ] **[Classic CRLs](https://en.wikipedia.org/wiki/Certificate_revocation_list)**: Support for checking CRLs from Distribution Points extracted from the certificate.
- [ ] **Enforce CT Pre-Publication**: Add an option to require that certificates have been publicly logged in CT for a minimum duration before being trusted, making mis-issuance nearly impossible.
- [ ] **[CRLite](https://blog.mozilla.org/security/2020/01/09/crlite-part-1-all-web-pki-revocations-compressed/)**: Support for lightweight, aggregated CRLs (an alternative to Chrome's CRLSet, developed by Mozilla).

## Installation

```sh
npm install hardened-https-agent
```

## Usage

_Coming soon..._

## Testing

This project includes a comprehensive test suite to ensure correctness and stability.

### Updating Test Data

The repository includes pre-fetched test data. To update these fixtures, run:

```sh
npm run test:update-test-data
```

### Running Tests

This project includes both unit and end-to-end tests. Unit tests are self-contained and run locally, while end-to-end tests perform live requests and may be unstable due to network conditions or remote server configuration changes.

#### Unit Tests

To run the unit tests:

```sh
npm test
```

#### End-to-End Tests

To run the end-to-end tests:

```sh
npm run test:e2e
```

Note: Due to their reliance on external network conditions, these tests are not executed in CI environments.

## Related Works

- [**sct.js**](https://github.com/Gldywn/sct.js): SCT.js is a low-level TypeScript library for Node.js that parses and verifies Signed Certificate Timestamps (SCTs).
- [**crlset.js**](https://github.com/Gldywn/crlset.js): CRLSet.js is a lightweight CRLSet parser and verifier in TypeScript for Node.js. It fetches and parses the latest Chrome CRLSet in memory, with support for checking whether a certificate or its issuer has been revoked.
- [**easy-ocsp**](https://github.com/timokoessler/easy-ocsp): An easy-to-use OCSP client for Node.js

## License

`hardened-https-agent` is distributed under the MIT license.
