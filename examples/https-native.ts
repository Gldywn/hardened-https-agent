import https from 'node:https';
import { HardenedHttpsAgent, defaultAgentOptions } from '../dist';

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
    ...defaultAgentOptions(),
    ...httpsAgentOptions,
  });

  try {
    await new Promise<void>((resolve, reject) => {
      const req = https.request(
        'https://example.com',
        { method: 'GET', agent, timeout: 15000 },
        (res) => {
          const status = res.statusCode ?? 0;
          if (status >= 200 && status < 300) {
            resolve();
          } else {
            reject(new Error(`Unexpected status ${status}`));
          }
          res.resume();
        },
      );
      req.on('error', reject);
      req.end();
    });

    console.log('Congrats! You have successfully performed a more secure request with hardened-https-agent.');
  } catch (error) {
    console.error('An error occurred while performing the request', error);
  }
}

main();


