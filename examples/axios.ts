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

  // Merge standard agent options with hardened defaultss
  const agent = new HardenedHttpsAgent({
    ...httpsAgentOptions,
    ...defaultAgentOptions(),
  });

  const client = axios.create({ httpsAgent: agent, timeout: 15000 });

  try {
    await client.get('https://example.com');
    console.log('\nCongrats! You have successfully performed a more secure request with hardened-https-agent.');
  } catch (error) {
    console.error('\nAn error occurred while performing the request', error);
  }
}

main();
