import { fromUnifiedCTLogList } from '../src/utils';
import type { UnifiedCertificateTransparencyLogList as UnifiedCTLogList } from '../src/types/uni-ct-log-list-schema';
import { UNIFIED_LOG_LIST } from './utils';

describe('Unified log list parsing', () => {
  beforeAll(() => {
    jest.spyOn(console, 'warn').mockImplementation();
  });

  afterAll(() => {
    jest.spyOn(console, 'warn').mockRestore();
  });

  it('should transform a valid log list into an array of Log objects', () => {
    const logs = fromUnifiedCTLogList(UNIFIED_LOG_LIST);

    expect(Array.isArray(logs)).toBe(true);
    expect(logs.length).toBeGreaterThan(0);

    const log = logs[0];
    expect(typeof log.description).toBe('string');
    expect(typeof log.operated_by).toBe('string');
    expect(typeof log.url).toBe('string');
    expect(typeof log.max_merge_delay).toBe('number');
    expect(log.id).toBeInstanceOf(Buffer);
    expect(log.key).toHaveProperty('asymmetricKeyType');
  });

  it('should return an empty array for a log list with no operators', () => {
    const emptyList: UnifiedCTLogList = { operators: [] };
    const logs = fromUnifiedCTLogList(emptyList);
    expect(logs).toEqual([]);
  });

  it('should correctly handle an operator with no logs', () => {
    const list: UnifiedCTLogList = {
      operators: [{ name: 'Test Operator', logs: [] }],
    };
    const logs = fromUnifiedCTLogList(list);
    expect(logs).toEqual([]);
  });

  it('should correctly process logs with different states', () => {
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

    const logs = fromUnifiedCTLogList(list);
    expect(logs.length).toBe(2);

    const retiredLog = logs.find((log) => log.description === 'Retired Log');
    expect(retiredLog).toBeDefined();
    if (retiredLog?.status === 'retired') {
      expect(retiredLog.status).toBe('retired');
      expect(retiredLog.retirement_date).toBe(new Date('2020-01-01T00:00:00Z').getTime());
    }

    const usableLog = logs.find((log) => log.description === 'Usable Log');
    expect(usableLog).toBeDefined();
    expect(usableLog?.status).toBe('usable');
  });

  it('should ignore logs with an unsupported state', () => {
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
              description: 'Pending Log',
              state: { pending: { timestamp: '2020-01-01T00:00:00Z' } },
            },
          ],
        },
      ],
    };

    const logs = fromUnifiedCTLogList(list);
    expect(logs.length).toBe(0);
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
    const logs = fromUnifiedCTLogList(list);
    expect(logs.length).toBe(1);
    expect(logs[0].description).toBe('Valid Log');
  });
});
