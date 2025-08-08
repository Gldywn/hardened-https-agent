<p align="center">
  <img src="./assets/header.png" alt="hardened-https-agent"/>
</p>

# hardened-https-agent

A security-first `https.Agent` for Node.js with advanced certificate validation: Custom CA, Certificate Transparency (CT), OCSP, and CRLSet.

[![Build Status](https://github.com/Gldywn/hardened-https-agent/actions/workflows/build.yml/badge.svg)](https://github.com/Gldywn/hardened-https-agent/actions/workflows/build.yml)
[![Coverage Status (codecov.io)](https://codecov.io/gh/Gldywn/hardened-https-agent/branch/main/graph/badge.svg)](https://codecov.io/gh/Gldywn/hardened-https-agent)
[![npm](https://img.shields.io/npm/v/hardened-https-agent.svg)](https://www.npmjs.com/package/hardened-https-agent)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

## What is hardened-https-agent?

A quick search on GitHub reveals a recurring pattern: developers are surprised to learn that **Node.js does not validate TLS certificates the same way a browser does**. Issues have been raised in popular projects like [got](https://github.com/sindresorhus/got/issues/1994) and [Uptime Kuma](https://github.com/louislam/uptime-kuma/issues/1254) when users discover that connections to servers with _revoked certificates succeed without any warning_.

This behavior is, in fact, (more or less) intentional. As explained in the Node.js repository itself ([#16338](https://github.com/nodejs/node/issues/16338)), performing robust, browser-grade checks for things like certificate revocation is a complex task with performance and privacy trade-offs. Node.js provides the necessary cryptographic building blocks, but leaves the responsibility of implementing these advanced security policies entirely up to the developer.

This is where `hardened-https-agent` comes in: an enhanced `https.Agent` for Node.js that does the heavy lifting to bridge this gap, providing modern security policies for your outbound TLS connections.

It is a drop-in replacement that works with any library supporting the standard `https.Agent`, including [`axios`](https://axios-http.com/), [`got`](https://github.com/sindresorhus/got), [`node-fetch`](https://github.com/node-fetch/node-fetch), [`needle`](https://github.com/tomas/needle), and more.

### Default Node.js Behavior vs. `hardened-https-agent`

| Verification Check            | Default Node.js (`https.Agent`) |   `hardened-https-agent`    |
| ----------------------------- | :-----------------------------: | :-------------------------: |
| **Trust Model**               |                                 |                             |
| [Custom CA Store](https://en.wikipedia.org/wiki/Root_certificate)               |    ⚠️ (Optional `ca` prop.)     | ✅ (Enforced, with helpers) |
| **Certificate Revocation**    |                                 |                             |
| [OCSP Stapling](https://en.wikipedia.org/wiki/OCSP_stapling)                 | ⚠️ (Raw staple, not validated)  |             ✅              |
| [OCSP Direct](https://fr.wikipedia.org/wiki/Online_Certificate_Status_Protocol)                   |               ❌                |             ✅              |
| [CRLs](https://en.wikipedia.org/wiki/Certificate_revocation_list)                          |    ⚠️ (Manual CRL file only)    |         ⏳ (Planned)         |
| [CRLSet](https://www.chromium.org/Home/chromium-security/crlsets/)                        |               ❌                |             ✅              |
| [CRLite](https://blog.mozilla.org/security/2020/01/09/crlite-part-1-all-web-pki-revocations-compressed/)                        |               ❌                |         ⏳ (Planned)         |
| **Certificate Integrity**     |                                 |                             |
| [Certificate Transparency (CT)](https://certificate.transparency.dev/) |               ❌                |             ✅              |

See **[BACKGROUND.md: Why a Hardened Agent?](./BACKGROUND.md)** for a detailed technical explanation of the gaps in Node.js's default behavior.

## Use Cases

This agent is designed for any Node.js application or library that needs to **reliably verify the authenticity of a remote server**. Its primary goal is to protect against connecting to servers using _revoked or mis-issued certificates_, a check that Node.js does not perform by default. It is essential for securing backend services, hardening client libraries (like SDKs), or protecting applications in trust-minimized environments like TEEs or AI agents. The library ships with a **set of pre-defined policies** for common needs, while **also providing complete control to create a tailored policy** that fits your exact security requirements.

## Features

### Implemented

- [x] **Certificate Transparency (CT)** (via Embedded SCTs)
- [x] **OCSP "Stapling"** (Checks the OCSP response provided by the server during the TLS handshake)
- [x] **OCSP "Direct"** (Client sends an OCSP request directly to the CA)
- [x] **OCSP "Mixed"** (Use OCSP Stapling with a fallback to a direct OCSP request if the staple is not provided or fails.)
- [x] **CRLSet** (Fast and efficient revocation checks using Google Chrome's aggregated CRL lists)

### Roadmap

- [ ] **Classic CRLs**: Support for checking CRLs from Distribution Points extracted from the certificate.
- [ ] **Enforce CT Pre-Publication**: Add an option to require that certificates have been publicly logged in CT for a minimum duration before being trusted, making mis-issuance nearly impossible.
- [ ] **CRLite**: Support for lightweight, aggregated CRLs (an alternative to Chrome's CRLSet, developed by Mozilla).

## Installation

```sh
npm install hardened-https-agent
```

## Usage

You can integrate this agent with HTTPS clients that support providing a Node.js `https.Agent` instance (e.g., axios, got, needle, etc.).

### Basic Example: Axios with Default Options

By simply using this setup, you immediately benefit from all the built-in security layers: CA validation using the Cloudflare bundle, certificate revocation checks via OCSP (stapling and direct), CRLSet-based revocation with signature verification (using the latest Google CRLSet), and enforcement that the presented certificate is properly published in Certificate Transparency logs. All of this is enabled out of the box—no extra configuration required.

```typescript
import axios from 'axios';
import { HardenedHttpsAgent, defaultAgentOptions } from 'hardened-https-agent';

const agent = new HardenedHttpsAgent({
  ...defaultAgentOptions(),
});

const client = axios.create({ httpsAgent: agent, timeout: 15000 });
await client.get('https://example.com');
```

**Additional real-world examples (axios, got, native https module, custom policies and more) are available in the [examples](./examples/) directory.**  
If your preferred client is missing, feel free to open an issue to request an example or confirm compatibility.

### Options

| **Property**       | **Type**                                        | **Required / Variants**                                                                                                                                                                                                                 | **Helper(s)** |
|--------------------|--------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|---------------|
| `ca`               | `string \| Buffer \| Array<string \| Buffer>` | Required. Custom trust store that replaces Node.js defaults. Accepts PEM string, `Buffer`, or an array of either.                                                                                                                       | `cfsslCaBundle`, `defaultAgentOptions().ca` |
| `ctPolicy`         | `CertificateTransparencyPolicy`                 | Optional. Enables CT when present. Fields: `logList: UnifiedCTLogList`, `minEmbeddedScts?: number`, `minDistinctOperators?: number`.                                                                                                   | `basicCtPolicy()`, `unifiedCtLogList` |
| `ocspPolicy`       | `OCSPPolicy`                                     | Optional. Enables OCSP when present. Fields: `mode: 'mixed' \| 'stapling' \| 'direct'`, `failHard: boolean`.                                                                                                                          | `basicStaplingOcspPolicy()`, `basicDirectOcspPolicy()` |
| `crlSetPolicy`     | `CRLSetPolicy`                                   | Optional. Enables CRLSet when present. Fields: `crlSet?: CRLSet`, `verifySignature?: boolean`, `updateStrategy?: 'always' \| 'on-expiry'`.                                                                                             | `basicCrlSetPolicy()` |
| `enableLogging`    | `boolean`                                        | Optional (default: `false`).                                                                                                                                                                                                            |  |
| Standard HTTPS opts| `https.AgentOptions`                              | Optional. Any standard Node.js `https.Agent` options (e.g., `keepAlive`, `maxSockets`, `timeout`, `maxFreeSockets`, `maxCachedSessions`) can be merged alongside the hardened options.                                                 |  |

*All options are thoroughly documented directly in the library via JSDoc comments for easy in-editor reference and autocomplete.*

Import convenience presets and building blocks as needed:

```typescript
import {
  defaultAgentOptions,
  cfsslCaBundle,
  unifiedCtLogList,
  basicCtPolicy,
  basicMixedOcspPolicy,
  basicStaplingOcspPolicy,
  basicDirectOcspPolicy,
  basicCrlSetPolicy,
} from 'hardened-https-agent';
```

### Customization (quick recipes)

Bring your own CA bundle:

```typescript
new HardenedHttpsAgent({
  ...defaultAgentOptions(),
  ca: myPemStringOrBuffer,
});
```

Tune standard agent behavior:

```typescript
new HardenedHttpsAgent({
  ...defaultAgentOptions(),
  keepAlive: true,
  maxSockets: 50,
});
```

Use a custom CT policy:

```typescript
new HardenedHttpsAgent({
  ...defaultAgentOptions(),
  ctPolicy: {
    logList: unifiedCtLogList,
    minEmbeddedScts: 3,
    minDistinctOperators: 3,
  },
});
```

Use a custom OCSP policy:

```typescript
new HardenedHttpsAgent({
  ...defaultAgentOptions(),
  ocspPolicy: { mode: 'stapling', failHard: true },
});
```

USe a custom CRLSet policy:

```typescript
new HardenedHttpsAgent({
  ...defaultAgentOptions(),
  crlSetPolicy: {
    verifySignature: true,
    updateStrategy: 'always',
  },
});
```

Enable detailed logs:

```typescript
new HardenedHttpsAgent({
  ...defaultAgentOptions(),
  enableLogging: true,
});
```

## Contributing

We welcome contributions of all kinds! A great place to start is by checking out the [Roadmap](#roadmap) for planned features or looking at the open [issues](https://github.com/Gldywn/hardened-https-agent/issues) for bugs and feature requests.

Before you get started, please take a moment to review our **[CONTRIBUTING.md](./CONTRIBUTING.md)** guide, which contains all the information you need to set up your environment and submit your changes.

## Related Works

- [**@gldywn/sct.js**](https://github.com/Gldywn/sct.js): SCT.js is a low-level TypeScript library for Node.js that parses and verifies Signed Certificate Timestamps (SCTs).
- [**@gldywn/crlset.js**](https://github.com/Gldywn/crlset.js): CRLSet.js is a lightweight CRLSet parser and verifier in TypeScript for Node.js. It fetches and parses the latest Chrome CRLSet in memory, with support for checking whether a certificate or its issuer has been revoked.
- [**@timokoessler/easy-ocsp**](https://github.com/timokoessler/easy-ocsp): An easy-to-use OCSP client for Node.js

## License

`hardened-https-agent` is distributed under the MIT license.
