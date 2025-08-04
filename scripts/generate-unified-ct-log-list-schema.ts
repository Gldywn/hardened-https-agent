import Ajv from 'ajv';
import addFormats from 'ajv-formats';
import axios from 'axios';
import { exec } from 'child_process';
import { join } from 'node:path';
import { mkdir, writeFile } from 'node:fs/promises';
import mergeJsonSchema from 'json-schema-merge-allof';
import { promisify } from 'util';
import { LOG_LISTS } from './constants';
import { getSchemaDir } from './utils';

const SCHEMA_DIR = getSchemaDir();

const execAsync = promisify(exec);

async function fetchJson(url: string): Promise<any> {
  try {
    const response = await axios.get(url);
    return response.data;
  } catch (error) {
    console.error(`[-] Error fetching JSON from ${url}:`, error);
    throw error;
  }
}

/**
 * Recursively removes all 'required' keywords from a JSON schema object.
 * This is necessary because the log lists from different providers have
 * different sets of required fields, and our unified type must treat
 * any field that isn't present in all lists as optional.
 * @param schema The schema object to clean.
 */
function removeRequired(schema: any): any {
  if (typeof schema !== 'object' || schema === null) {
    return schema;
  }

  // eslint-disable-next-line @typescript-eslint/no-dynamic-delete
  delete schema.required;

  for (const key in schema) {
    if (Object.prototype.hasOwnProperty.call(schema, key)) {
      schema[key] = removeRequired(schema[key]);
    }
  }

  return schema;
}

/**
 * Recursively replaces all 'oneOf' keywords with 'anyOf'.
 * This is necessary because the schemas from different providers have
 * overlapping definitions that cause 'oneOf' validation to fail, as a
 * single data object can match multiple sub-schemas once 'required'
 * fields are removed. 'anyOf' correctly validates if the object
 * matches at least one sub-schema.
 * @param schema The schema object to modify.
 */
function replaceOneOfWithAnyOf(schema: any): any {
  if (typeof schema !== 'object' || schema === null) {
    return schema;
  }

  if (schema.oneOf) {
    schema.anyOf = schema.oneOf;
    // eslint-disable-next-line @typescript-eslint/no-dynamic-delete
    delete schema.oneOf;
  }

  for (const key in schema) {
    if (Object.prototype.hasOwnProperty.call(schema, key)) {
      schema[key] = replaceOneOfWithAnyOf(schema[key]);
    }
  }

  return schema;
}

async function generateUnifiedSchema(): Promise<void> {
  try {
    console.log('[*] Fetching schemas...');
    const schemas = await Promise.all(LOG_LISTS.map(({ schemaUrl }) => fetchJson(schemaUrl)));

    // Before merging, remove the conflicting ID keys from each schema
    const cleanedSchemas = schemas.map((schema) => {
      // eslint-disable-next-line @typescript-eslint/no-dynamic-delete
      delete (schema as any).id;
      // eslint-disable-next-line @typescript-eslint/no-dynamic-delete
      delete (schema as any).$id;
      // Recursively remove all 'required' constraints to make all properties optional
      // in the final merged schema, reflecting the inconsistencies between providers.
      return removeRequired(schema);
    });

    console.log('[*] Merging schemas...');
    let mergedSchema = mergeJsonSchema({ allOf: cleanedSchemas });
    mergedSchema = replaceOneOfWithAnyOf(mergedSchema);

    mergedSchema.$id = 'UnifiedCertificateTransparencyLogList';

    await mkdir(SCHEMA_DIR, { recursive: true });

    const unifiedSchemaPath = join(SCHEMA_DIR, 'uni-ct-log-list.schema.json');
    console.log(`[+] Writing unified schema to ${unifiedSchemaPath}...`);
    await writeFile(unifiedSchemaPath, JSON.stringify(mergedSchema, null, 2));

    console.log('[+] Unified schema generated successfully.');

    console.log('[*] Validating unified schema against source lists...');
    const ajv = new Ajv({ allErrors: true, strict: false });
    addFormats(ajv);
    const validate = ajv.compile(mergedSchema);

    const sourceLists = await Promise.all(LOG_LISTS.map(({ sourceUrl }) => fetchJson(sourceUrl)));

    for (let i = 0; i < LOG_LISTS.length; i++) {
      const { name } = LOG_LISTS[i];
      const sourceList = sourceLists[i];
      const isValid = validate(sourceList);

      if (isValid) {
        console.log(`[+] Validation successful for ${name} log list.`);
      } else {
        console.error(`[-] Validation failed for ${name} log list:`);
        console.error(validate.errors);
        throw new Error(`Schema validation failed for ${name}.`);
      }
    }

    console.log('[*] Running type generation...');
    const { stderr } = await execAsync(
      'npx json2ts --input schemas/uni-ct-log-list.schema.json --output src/types/uni-ct-log-list-schema.d.ts --silent',
    );
    if (stderr) {
      console.error('[-] Error during type generation:', stderr);
    } else {
      console.log('[+] Type definitions updated successfully.');
    }
  } catch (error) {
    console.error('[-] An error occurred during the script execution:', error);
    process.exit(1);
  }
}

async function main() {
  await generateUnifiedSchema();
}

main();
