/* istanbul ignore file */

import { LogLevel } from './interfaces';
import type { LogAdapter, LogObject } from './interfaces';

export class Logger {
  private readonly name: string;
  private readonly adapter: LogAdapter;

  constructor(name: string, adapter?: LogAdapter) {
    this.name = name;
    this.adapter =
      adapter ??
      (({ level, message, args }) => {
        const timestamp = new Date().toISOString();
        const levelString = LogLevel[level].toUpperCase();
        console[LogLevel[level]]?.(
          `[${timestamp}] [${this.name}] [${levelString}] ${message}`,
          ...(args ?? [])
        );
      });
  }

  private log(level: LogLevel, message: string, ...args: unknown[]): void {
    this.adapter({
      level,
      message,
      args,
      name: this.name,
    });
  }

  public info(message: string, ...args: unknown[]): void {
    this.log(LogLevel.info, message, ...args);
  }

  public warn(message: string, ...args: unknown[]): void {
    this.log(LogLevel.warn, message, ...args);
  }

  public error(message: string, ...args: unknown[]): void {
    this.log(LogLevel.error, message, ...args);
  }

  public debug(message: string, ...args: unknown[]): void {
    this.log(LogLevel.debug, message, ...args);
  }
}
