import tls from 'node:tls';
import selfsigned from 'selfsigned';

let pems: selfsigned.GenerateResult;

export function startTlsServer() {
  pems = selfsigned.generate(
    [{ name: 'commonName', value: 'localhost' }],
    { days: 1 },
  );

  const server = tls.createServer(
    {
      key: pems.private,
      cert: pems.cert,
      ca: pems.public,
    },
    (socket) => {
      socket.write('HTTP/1.1 200 OK\r\n');
      socket.write('Content-Type: text/plain\r\n');
      socket.write('\r\n');
      socket.write('Hello, world!');
      socket.end();
    },
  );

  server.listen(0); // Listen on a random free port

  return {
    // @ts-expect-error - address() can return a string
    port: server.address()?.port as number,
    close: () => server.close(),
  };
}

export function getCa() {
  return pems.cert;
}
