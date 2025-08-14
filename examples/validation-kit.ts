import * as http from 'http';
import * as https from 'https';
import { HttpsProxyAgent, HttpsProxyAgentOptions } from 'https-proxy-agent';
import { HardenedHttpsValidationKit, defaultAgentOptions } from '../dist';

async function main() {
  // Create a validation kit with hardened defaults
  const kit = new HardenedHttpsValidationKit({
    ...defaultAgentOptions(),
    loggerOptions: {
      level: 'debug',
    }
  });

  // Define your HTTPS proxy agent options as usual
  const httpsProxyAgentOpts: HttpsProxyAgentOptions<'https'> = {
    keepAlive: true,
  };
  
  // Create the proxy agent, applying validation kit to options before passing them
  const agent = new HttpsProxyAgent('http://127.0.0.1:3128', kit.applyBeforeConnect(httpsProxyAgentOpts));

  // Attach the validation kit to the agent
  kit.attachToAgent(agent as http.Agent);

  try {
    console.log('\n> Performing request...');
    await new Promise<void>((resolve, reject) => {
      const req = https.request(
        'https://example.com',
        { method: 'GET', agent: agent as http.Agent, timeout: 15000 },
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

    console.log('> Congrats! You have successfully performed a more secure request with hardened-https-agent.');
  } catch (error) {
    console.error('> An error occurred while performing the request', error);
  }
}

main();
