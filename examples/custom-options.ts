import axios from 'axios';
import https from 'node:https';
import { HardenedHttpsAgent, unifiedCtLogList, defaultAgentOptions } from '../dist';

async function main() {
  // Customize standard agent options if required
  const httpsAgentOptions: https.AgentOptions = {
    keepAlive: true,
    timeout: 55000,
    maxSockets: 20,
    maxFreeSockets: 5,
    maxCachedSessions: 500,
  };

  // Merge standard agent options with hardened defaults and some custom policies
  // Here we use values from the default options, but you can customize them as you want
  const agent = new HardenedHttpsAgent({
    ...httpsAgentOptions,
    ca: defaultAgentOptions().ca,
    ctPolicy: {
      logList: unifiedCtLogList,
      minEmbeddedScts: 2,
      minDistinctOperators: 2,
    },
    ocspPolicy: {
      mode: 'mixed', // or 'stapling' or 'direct'
      failHard: true,
    },
    crlSetPolicy: {
      verifySignature: true,
      updateStrategy: 'always', // or 'on-expiry'
    },
    enableLogging: true,
  });

  const client = axios.create({ httpsAgent: agent, timeout: 15000 });
  try {
    await client.get('https://example.com');
    console.log('Congrats! You have successfully performed a more secure request with hardened-https-agent.');
  } catch (error) {
    console.error('An error occurred while performing the request', error);
  }
}

main();
