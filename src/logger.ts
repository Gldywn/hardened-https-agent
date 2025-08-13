/* istanbul ignore next */
export class Logger {
  private name: string;
  private sink: LogSink;
  constructor(name: string, sink?: LogSink) {
    this.name = name;
    this.sink = sink ?? console;
  }

  public log(message: string, ...args: any[]): void {
    this.sink.log(`[Log] ${this.name}: ${message}`, ...args);
  }

  public warn(message: string, ...args: any[]): void {
    this.sink.warn(`[Warning] ${this.name}: ${message}`, ...args);
  }

  public error(message: string, ...args: any[]): void {
    this.sink.error(`[Error] ${this.name}: ${message}`, ...args);
  }
}

export interface LogSink {
  log(message: string, ...args: any[]): void;
  warn(message: string, ...args: any[]): void;
  error(message: string, ...args: any[]): void;
}
