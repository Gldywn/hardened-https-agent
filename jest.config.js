module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  testMatch: ['**/test/**/*.test.ts', '!**/test/e2e/**/*.test.ts'],
  collectCoverageFrom: ['src/**/*.ts'],
};
