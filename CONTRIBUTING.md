# Contributing to hardened-https-agent

First off, thank you for considering contributing to `hardened-https-agent`! We welcome any and all contributions, from bug reports to new features. This project is a community effort, and we're excited to have you on board.

This document provides a set of guidelines to help you contribute effectively.

## How Can I Contribute?

There are many ways to contribute, and all are appreciated:

- **Reporting Bugs**: If you find a bug, please open an issue and provide as much detail as possible, including steps to reproduce it.
- **Suggesting Enhancements**: If you have an idea for a new feature or an improvement to an existing one, please open an issue to discuss it. This allows us to coordinate our efforts and prevent duplication of work.
- **Submitting Pull Requests**: If you've fixed a bug or implemented a new feature, we'd be happy to review your pull request.

## Getting Started

To get started, clone the repository and install the dependencies:

```sh
git clone https://github.com/YOUR_USERNAME/hardened-https-agent.git
cd hardened-https-agent
npm install
```

This project uses a specific version of Node.js, which is defined in the `.nvmrc` file. We recommend using a version manager like `nvm` to ensure you are using the correct Node.js version.

## Testing

This project includes a comprehensive test suite to ensure correctness and stability. Before submitting any changes, please make sure that all tests pass.

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

## Submitting Changes

When you are ready to submit your changes, please follow these steps:

1.  **Create a new branch** for your changes.
2.  **Make your changes** and commit them with a clear and descriptive message.
3.  **Push your branch** to your fork on GitHub.
4.  **Open a pull request** from your fork to the `main` branch of the original repository.
5.  In the pull request description, **provide a detailed overview** of the changes you've made and reference any related issues.

## Coding Style

To maintain consistency throughout the codebase, the project uses Prettier for automated code formatting. The configuration is located in the `.prettierrc` file. Please ensure your code adheres to this style before submitting a pull request.

- **Write clear and concise code**. Add comments only when the logic is complex and requires explanation.
- **Ensure your code is well-tested**. Add new tests for any new features or bug fixes.

Thank you again for your interest in contributing to `hardened-https-agent`. We look forward to your contributions!
