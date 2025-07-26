import { type Log } from '@gldywn/sct.js';
import {
  type UnifiedCertificateTransparencyLogList as UnifiedCTLogList,
  type Log as CTLog,
} from './types/uni-ct-log-list-schema';
import { createPublicKey } from 'node:crypto';

export function fromUnifiedCTLogList(logList: UnifiedCTLogList): Log[] {
  const transformedLogs: Log[] = [];

  if (!logList.operators || logList.operators.length === 0) {
    console.warn(`[Warning] The log list is missing the 'operators' property or is empty.`);
    return transformedLogs;
  }

  for (const operator of logList.operators) {
    if (!operator.logs) /* istanbul ignore next */ {
      console.warn(`[Warning] Skipping operator with no logs defined. (operator: ${operator.name || 'N/A'})`);
      continue;
    }

    for (const ctLog of operator.logs as CTLog[]) {
      const state = ctLog.state as { [key: string]: { timestamp: string } } | undefined;
      const canBeUsed = state && (state.usable || state.readonly || state.qualified || state.retired);
      if (!canBeUsed) continue; // If the log is not in a usable state, skip it

      if (ctLog.log_id && ctLog.key && ctLog.mmd && ctLog.url && ctLog.description && operator.name) {
        const logId = Buffer.from(ctLog.log_id, 'base64');
        const logKey = createPublicKey({
          key: Buffer.from(ctLog.key, 'base64'),
          format: 'der',
          type: 'spki',
        });

        const baseLog = {
          description: ctLog.description,
          url: ctLog.url,
          operated_by: operator.name,
          key: logKey,
          id: logId,
          max_merge_delay: ctLog.mmd,
        };

        let log: Log;

        if (state.retired) {
          log = { ...baseLog, status: 'retired', retirement_date: new Date(state.retired.timestamp).getTime() };
        } else if (state.qualified) {
          log = { ...baseLog, status: 'qualified' };
        } else if (state.usable) {
          log = { ...baseLog, status: 'usable' };
        } else {
          log = { ...baseLog, status: 'readonly' };
        }
        transformedLogs.push(log);
      } else {
        const missingFields: string[] = [];
        if (!ctLog.log_id) missingFields.push('log_id');
        if (!ctLog.key) missingFields.push('key');
        if (!ctLog.mmd) missingFields.push('mmd');
        if (!ctLog.url) missingFields.push('url');
        if (!ctLog.description) missingFields.push('description');
        if (!operator.name) missingFields.push('operator.name');
        const logIdShort = ctLog.log_id ? shortenLogId(ctLog.log_id) : 'N/A';
        console.warn(
          `[Warning] Skipping log due to missing or invalid fields. (log_id: ${logIdShort}, issues: ${missingFields.join(', ')})`,
        );
      }
    }
  }

  return transformedLogs;
}

export function shortenLogId(logId: string): string {
  return logId.substring(0, 16) + '...';
}
