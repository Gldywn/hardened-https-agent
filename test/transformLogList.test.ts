import { fromUnifiedCTLogList } from '../src/utils';
import type { UnifiedCertificateTransparencyLogList as UnifiedCTLogList } from '../src/types/uni-ct-log-list-schema';
import { UNIFIED_LOG_LIST } from './utils';

describe('fromUnifiedCTLogList', () => {
  it('should transform a valid log list into an array of Log objects', () => {
    const transformedLogs = fromUnifiedCTLogList(UNIFIED_LOG_LIST);

    expect(Array.isArray(transformedLogs)).toBe(true);
    expect(transformedLogs.length).toBeGreaterThan(0);

    const log = transformedLogs[0];
    expect(typeof log.description).toBe('string');
    expect(typeof log.operated_by).toBe('string');
    expect(typeof log.url).toBe('string');
    expect(typeof log.max_merge_delay).toBe('number');
    expect(log.id).toBeInstanceOf(Buffer);
    expect(log.key).toHaveProperty('asymmetricKeyType');
  });

  it('should return an empty array for a log list with no operators', () => {
    const emptyList: UnifiedCTLogList = { operators: [] };
    const transformedLogs = fromUnifiedCTLogList(emptyList);
    expect(transformedLogs).toEqual([]);
  });

  it('should correctly handle an operator with no logs', () => {
    const list: UnifiedCTLogList = {
      operators: [{ name: 'Test Operator', logs: [] }],
    };
    const transformedLogs = fromUnifiedCTLogList(list);
    expect(transformedLogs).toEqual([]);
  });

  it('should ignore logs that are not in a usable, readonly, or qualified state', () => {
    const dummyBase64Key =
      'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfahLEimAoz2t01p3uMziiLOl/fHTDM0YDOhBRuiBARsV4UvxG2LdNgoIGLrtCzWE0J5APC2em4JlvR8EEEFMoA==';
    const list: UnifiedCTLogList = {
      operators: [
        {
          name: 'Test Operator',
          logs: [
            {
              log_id: 'pLkJkLQYWBSHuxOizGdwCjw1mAT5G9+443fNDsgN3BA=',
              key: dummyBase64Key,
              mmd: 86400,
              url: 'https://ct.googleapis.com/pilot/',
              description: 'Retired Log',
              state: { retired: { timestamp: '2020-01-01T00:00:00Z' } },
            },
            {
              log_id: '7ku9t3XOYLrhQmkfq+GeZqMPfl+wctiDAMR7iXqo/cs=',
              key: dummyBase64Key,
              mmd: 86400,
              url: 'https://ct.googleapis.com/rocketeer/',
              description: 'Usable Log',
              state: { usable: { timestamp: '2020-01-01T00:00:00Z' } },
            },
          ],
        },
      ],
    };

    const transformedLogs = fromUnifiedCTLogList(list);
    expect(transformedLogs.length).toBe(1);
    expect(transformedLogs[0].description).toBe('Usable Log');
  });

  it('should ignore logs with missing essential properties', () => {
    const dummyBase64Key =
      'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfahLEimAoz2t01p3uMziiLOl/fHTDM0YDOhBRuiBARsV4UvxG2LdNgoIGLrtCzWE0J5APC2em4JlvR8EEEFMoA==';
    const list: UnifiedCTLogList = {
      operators: [
        {
          name: 'Test Operator',
          logs: [
            {
              // This one is missing a `key`
              log_id: 'pLkJkLQYWBSHuxOizGdwCjw1mAT5G9+443fNDsgN3BA=',
              mmd: 86400,
              url: 'https://ct.googleapis.com/pilot/',
              description: 'Log with missing key',
              state: { usable: { timestamp: '2020-01-01T00:00:00Z' } },
            },
            {
              // This one is valid
              log_id: '7ku9t3XOYLrhQmkfq+GeZqMPfl+wctiDAMR7iXqo/cs=',
              key: dummyBase64Key,
              mmd: 86400,
              url: 'https://ct.googleapis.com/rocketeer/',
              description: 'Valid Log',
              state: { usable: { timestamp: '2020-01-01T00:00:00Z' } },
            },
          ],
        },
      ],
    };
    const transformedLogs = fromUnifiedCTLogList(list);
    expect(transformedLogs.length).toBe(1);
    expect(transformedLogs[0].description).toBe('Valid Log');
  });
});
