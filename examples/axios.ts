import axios from 'axios';
import { HardenedHttpsAgent, defaultAgentOptions } from '../dist';
import https from 'node:https';

async function main() {
  // Customize standard agent options if required
  const httpsAgentOptions: https.AgentOptions = {
    keepAlive: true,
    timeout: 55000,
    maxSockets: 20,
    maxFreeSockets: 5,
    maxCachedSessions: 500,
  };

  // Merge standard agent options with hardened defaults
  const agent = new HardenedHttpsAgent({
    ...httpsAgentOptions,
    ...defaultAgentOptions(),
    loggerOptions: {
      level: 'debug',
    }
  });

  const client = axios.create({ httpsAgent: agent, timeout: 15000 });

  try {
    console.log('\n> Performing request...');
    await client.get('https://example.com');
    console.log('> Congrats! You have successfully performed a more secure request with hardened-https-agent.');
  } catch (error) {
    console.error('> An error occurred while performing the request', error);
  }
}

main();
