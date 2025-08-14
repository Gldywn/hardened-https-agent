/* istanbul ignore file */

const DEFAULT_TEMPLATE = '{time} [{name}] {level}: {message}';
export class Logger {
  private readonly name: string;
  private readonly sink: LogSink;
  private readonly formatter?: LogFormatter;
  private readonly minLevel: EffectiveLogLevel;

  constructor(name: string, options?: LoggerOptions) {
    this.name = name;

    const sink = options?.sink;
    const formatter =
      options?.formatter ??
      (options?.template ? createTemplateFormatter(options.template) : createTemplateFormatter(DEFAULT_TEMPLATE));
    this.minLevel = options?.level ?? 'info';

    if (sink && typeof (sink as any).bind === 'function') {
      const bound = (sink as BindableLogSink).bind(this.name);
      this.sink = bound;
    } else {
      this.sink = sink ?? console;
    }

    this.formatter = formatter;
  }

  public debug(message: any, ...args: any[]): void {
    if (!this.shouldLog('debug')) return;
    const { outMessage, outArgs } = this.prepare('debug', message, args);
    if (typeof this.sink.debug === 'function') {
      this.sink.debug(outMessage, ...outArgs);
    } else {
      this.sink.info(outMessage, ...outArgs);
    }
  }

  public info(message: any, ...args: any[]): void {
    if (!this.shouldLog('info')) return;
    const { outMessage, outArgs } = this.prepare('info', message, args);
    this.sink.info(outMessage, ...outArgs);
  }

  public warn(message: any, ...args: any[]): void {
    if (!this.shouldLog('warn')) return;
    const { outMessage, outArgs } = this.prepare('warn', message, args);
    this.sink.warn(outMessage, ...outArgs);
  }

  public error(message: any, ...args: any[]): void {
    if (!this.shouldLog('error')) return;
    const { outMessage, outArgs } = this.prepare('error', message, args);
    this.sink.error(outMessage, ...outArgs);
  }

  private prepare(level: LogLevel, message: any, args: any[]) {
    if (!this.formatter) throw new Error('No formatter set');

    const { message: formatted, args: formattedArgs } = this.formatter(level, this.name, message, args);
    return { outMessage: formatted, outArgs: formattedArgs };
  }

  private shouldLog(level: LogLevel): boolean {
    return priority(level) >= priority(this.minLevel);
  }
}

export type LogLevel = 'debug' | 'info' | 'warn' | 'error';
export type EffectiveLogLevel = LogLevel | 'silent';

export interface LogSink {
  debug?(message: any, ...args: any[]): void;
  info(message: any, ...args: any[]): void;
  warn(message: any, ...args: any[]): void;
  error(message: any, ...args: any[]): void;
}

export interface BindableLogSink extends LogSink {
  bind(component: string): LogSink;
}

export type LogFormatter = (
  level: LogLevel,
  component: string,
  message: any,
  args: any[],
) => { message: any; args: any[] };

export interface LoggerOptions {
  sink?: LogSink | BindableLogSink;
  formatter?: LogFormatter;
  template?: string;
  level?: EffectiveLogLevel;
}

export function createTemplateFormatter(template: string): LogFormatter {
  return (level, component, message, args) => {
    const now = new Date().toISOString();
    const tokens: Record<string, string> = {
      time: now,
      level: level.toUpperCase(),
      name: component,
      message: toSingleLineString(message, args),
    };

    const out = template.replace(/\{(time|level|name|message)\}/g, (_, key: keyof typeof tokens) => tokens[key]);
    return { message: out, args: [] };
  };
}

function toSingleLineString(message: any, args: any[]): string {
  const parts = [message, ...args].map((v) => formatValue(v));
  return parts.join(' ');
}

function formatValue(v: any): string {
  if (typeof v === 'string') return v;
  if (v instanceof Error) return v.stack || v.message || String(v);
  try {
    return JSON.stringify(v);
  } catch {
    return String(v);
  }
}

function priority(level: EffectiveLogLevel): number {
  switch (level) {
    case 'silent':
      return 99;
    case 'error':
      return 40;
    case 'warn':
      return 30;
    case 'info':
      return 20;
    case 'debug':
      return 10;
    default:
      return 20;
  }
}
