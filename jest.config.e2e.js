const baseConfig = require('./jest.config.js');

module.exports = {
  ...baseConfig,
  testMatch: ['**/test/e2e/**/*.test.ts'],
}; 