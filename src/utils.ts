import { type Log } from '@gldywn/sct.js';
import {
  type UnifiedCertificateTransparencyLogList as UnifiedCTLogList,
  type Log as CTLog,
} from './types/uni-ct-log-list-schema';
import { createPublicKey } from 'node:crypto';

export function fromUnifiedCTLogList(logList: UnifiedCTLogList): Log[] {
  const transformedLogs: Log[] = [];

  if (!logList.operators) {
    return transformedLogs;
  }

  for (const operator of logList.operators) {
    if (!operator.logs) {
      continue;
    }

    for (const log of operator.logs as CTLog[]) {
      const state = log.state as { [key: string]: { timestamp: string } } | undefined;
      const isLogUsable = state && (state.usable || state.readonly || state.qualified);

      if (isLogUsable && log.log_id && log.key && log.mmd && log.url && log.description && operator.name) {
        const logId = Buffer.from(log.log_id, 'base64');
        const logKey = createPublicKey({
          key: Buffer.from(log.key, 'base64'),
          format: 'der',
          type: 'spki',
        });
        transformedLogs.push({
          description: log.description,
          url: log.url,
          operated_by: operator.name,
          key: logKey,
          id: logId,
          max_merge_delay: log.mmd,
        });
      }
    }
  }

  return transformedLogs;
}
