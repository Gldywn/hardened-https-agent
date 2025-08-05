import * as fs from 'node:fs';
import * as path from 'node:path';

const RES_DIR = path.join(__dirname, '..', '..', 'resources');

export function loadResFile(filename: string): string {
  return fs.readFileSync(path.join(RES_DIR, filename), 'utf8');
}
