// These constants are exported to ensure that test scripts and fixtures always reference the same hosts and log list sources.
// This allows tests to remain consistent and up-to-date when the underlying data changes.

export const LOG_LISTS = [
  {
    name: 'google-log-list.json',
    schemaUrl: 'https://www.gstatic.com/ct/log_list/v3/log_list_schema.json',
    sourceUrl: 'https://www.gstatic.com/ct/log_list/v3/log_list.json',
  },
  {
    name: 'apple-log-list.json',
    schemaUrl: 'https://valid.apple.com/ct/log_list/schema_versions/log_list_schema_v4.json',
    sourceUrl: 'https://valid.apple.com/ct/log_list/current_log_list.json',
  },
];

export const CFSSL_CA_BUNDLE_URL = 'https://raw.githubusercontent.com/cloudflare/cfssl_trust/master/ca-bundle.crt';

export const TEST_CERT_HOSTS = ['google.com', 'www.apple.com', 'ethereum.org'];
