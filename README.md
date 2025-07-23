# axios-tls-policy-agent

A configurable HTTPS agent for Axios enforcing advanced TLS certificate validation: custom root store, Certificate Transparency policy, CRLSet/CRLite-style revocation checks, and OCSP stapling.

## What Is It?

`TlsPolicyAgent` is an enhanced `https.Agent` for Node.js designed to add layers of modern security policy validation on top of the standard TLS checks. While Node's native agent verifies the certificate chain and hostname, this agent goes further by allowing you to enforce stricter, configurable security policies that are not available by default.

### Current Features

- **Custom CA Trust Store**: The agent requires you to provide a list of trusted Certificate Authorities (CAs).
- **Certificate Transparency (CT) Policy**: Enforces that a server's certificate has been publicly disclosed in a trusted, append-only log. This helps protect against certificate mis-issuance.
  - Currently supports SCTs delivered **embedded in the X.509 certificate**.

### Planned Features

- SCTs delivered via **TLS Extension** and **OCSP Stapling**.
- Certificate revocation checks via CRLSet and/or CRLite.

## Installation

```sh
npm install axios-tls-policy-agent
```

## Usage

The following example demonstrates how to create an `axios` instance that uses the `TlsPolicyAgent` to enforce a custom Certificate Authority (CA) list and a given Certificate Transparency (CT) policy.

## Testing

This project includes a comprehensive test suite to ensure correctness and stability.

### Updating Test Data

The repository includes pre-generated test data. To update these fixtures, run:

```sh
npm run test:setup
```

### Running Tests

To run the complete test suite:

```sh
npm test
```

## License

`axios-tls-policy-agent` is distributed under the MIT license.
