import { join } from 'node:path';

export function getTestDataDir(): string {
  return join(__dirname, '..', 'test', 'testdata');
}

export function getResDir(): string {
  return join(__dirname, '..', 'resources');
}

export function getSchemaDir(): string {
  return join(__dirname, '..', 'schemas');
}
