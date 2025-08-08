
import got from 'got';
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
  });

  const client = got.extend({
    agent: { https: agent },
    timeout: { request: 15000 },
    http2: false,
  });

  try {
    await client.get('https://example.com');
    console.log('\nCongrats! You have successfully performed a more secure request with hardened-https-agent.');
  } catch (error) {
    console.error('\nAn error occurred while performing the request', error);
  }
}

main();


