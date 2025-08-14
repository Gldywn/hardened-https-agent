import 'node:tls';
import type tls from 'node:tls';

declare module 'node:tls' {
  interface TLSSocket {
    on(event: 'hardened:validation:success', listener: () => void): this;
    once(event: 'hardened:validation:success', listener: () => void): this;
    off(event: 'hardened:validation:success', listener: () => void): this;

    on(event: 'hardened:validation:error', listener: (err: Error) => void): this;
    once(event: 'hardened:validation:error', listener: (err: Error) => void): this;
    off(event: 'hardened:validation:error', listener: (err: Error) => void): this;

    emit(event: 'hardened:validation:success'): boolean;
    emit(event: 'hardened:validation:error', err: Error): boolean;
  }
}
