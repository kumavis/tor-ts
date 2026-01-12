/**
 * Chutney integration test for Hidden Service Hosting
 *
 * This test starts a hidden service using our TypeScript implementation,
 * then connects to it using the existing client-side hidden service code.
 */

import { HiddenServiceHost } from '../src/hidden-service-host.ts';
import { connectToHiddenServiceOverChutney } from '../src/hidden-service.ts';

async function withTimeout<T>(label: string, ms: number, promise: Promise<T>): Promise<T> {
  let timeout: NodeJS.Timeout | undefined;
  const timeoutP = new Promise<never>((_resolve, reject) => {
    timeout = setTimeout(() => reject(new Error(`${label} timed out after ${ms}ms`)), ms);
  });
  try {
    return await Promise.race([promise, timeoutP]);
  } finally {
    if (timeout) clearTimeout(timeout);
  }
}

async function main() {
  const expectedBody = 'hello-from-tor-ts-hidden-service-host';

  const overallTimeoutMs = 10 * 60_000;
  const perStepTimeoutMs = 120_000;

  // Create hidden service host
  const hsHost = new HiddenServiceHost();
  console.log(`Generated onion address: ${hsHost.onionAddress}`);

  // Track rendezvous circuits
  const rendezvousCircuits: any[] = [];
  hsHost.on('rendezvous', ({ circuit }) => {
    console.log('hs-host-test: rendezvous circuit established');
    rendezvousCircuits.push(circuit);

    // Set up handler for incoming streams
    circuit.on('relay', async (evt: { streamId: number; relayCommand: number; data: Buffer }) => {
      // Handle BEGIN cells
      if (evt.relayCommand === 1 /* BEGIN */) {
        console.log(`hs-host-test: received BEGIN for stream ${evt.streamId}`);
        // Send CONNECTED response
        await circuit.sendRelayMessage({
          streamId: evt.streamId,
          relayCommand: 4, // CONNECTED
          data: Buffer.alloc(8), // TTL + address (simplified)
        });
      }

      // Handle DATA cells
      if (evt.relayCommand === 2 /* DATA */) {
        const requestText = evt.data.toString('utf8');
        console.log(`hs-host-test: received DATA: ${requestText.slice(0, 50)}...`);

        // If this looks like an HTTP request, send a response
        if (requestText.includes('GET ') || requestText.includes('HTTP')) {
          const body = expectedBody;
          const response = Buffer.from(
            `HTTP/1.1 200 OK\r\n` +
              `Content-Type: text/plain\r\n` +
              `Content-Length: ${body.length}\r\n` +
              `Connection: close\r\n` +
              `\r\n` +
              body,
            'utf8'
          );

          await circuit.sendRelayMessage({
            streamId: evt.streamId,
            relayCommand: 2, // DATA
            data: response,
          });

          // Send END
          await circuit.sendRelayMessage({
            streamId: evt.streamId,
            relayCommand: 3, // END
            data: Buffer.from([6]), // REASON_DONE
          });
        }
      }
    });
  });

  try {
    // Start the hidden service
    console.log('Starting hidden service...');
    await withTimeout(
      'start hidden service',
      overallTimeoutMs,
      hsHost.startOverChutney({
        numIntroPoints: 3,
        overallTimeoutMs: perStepTimeoutMs,
      })
    );
    console.log(`Hidden service started at ${hsHost.onionAddress}`);

    // Wait a bit for descriptor to propagate
    console.log('Waiting for descriptor propagation...');
    await new Promise((r) => setTimeout(r, 10000));

    // Connect to our own hidden service using the client code
    console.log('Connecting to hidden service as client...');
    const { circuit, stream } = await withTimeout(
      'connect to hidden service',
      overallTimeoutMs,
      connectToHiddenServiceOverChutney({
        onionAddress: hsHost.onionAddress,
        port: 80,
        overallTimeoutMs: perStepTimeoutMs,
      })
    );
    console.log('Connected to hidden service!');

    // Send HTTP request
    const responseChunks: Buffer[] = [];
    stream.on('data', (data: Buffer) => {
      responseChunks.push(Buffer.from(data));
    });

    const responseCompleteP = (async () => {
      const start = Date.now();
      while (Date.now() - start < overallTimeoutMs) {
        const buf = Buffer.concat(responseChunks);
        const headerEnd = buf.indexOf('\r\n\r\n');
        if (headerEnd !== -1) {
          const headersText = buf.subarray(0, headerEnd).toString('utf8');
          const m = headersText.match(/\r?\ncontent-length:\s*(\d+)\s*\r?\n/i);
          if (m?.[1]) {
            const contentLength = Number.parseInt(m[1], 10);
            const bodyStart = headerEnd + 4;
            if (buf.length >= bodyStart + contentLength) return;
          }
        }
        await new Promise((r) => setTimeout(r, 50));
      }
      throw new Error('Timed out waiting for complete HTTP response');
    })();

    const requestText =
      `GET / HTTP/1.1\r\n` + `Host: ${hsHost.onionAddress}\r\n` + `Connection: close\r\n` + `\r\n`;

    console.log('Sending HTTP request...');
    await withTimeout(
      'write request',
      perStepTimeoutMs,
      stream.write(Buffer.from(requestText, 'ascii'))
    );

    console.log('Waiting for response...');
    await withTimeout('read response', overallTimeoutMs, responseCompleteP);

    const responseText = Buffer.concat(responseChunks).toString('utf8');
    console.log('Response received:', responseText.slice(0, 200));

    if (!responseText.includes('200')) {
      throw new Error(`Expected HTTP 200 in response, got:\n${responseText}`);
    }
    if (!responseText.includes(expectedBody)) {
      throw new Error(`Expected body "${expectedBody}" in response, got:\n${responseText}`);
    }

    console.log('Test passed! Hidden service hosting works correctly.');

    // Cleanup
    stream.destroy();
    circuit.destroy();
  } finally {
    hsHost.stop();
    for (const c of rendezvousCircuits) {
      try {
        c.destroy();
      } catch {
        // ignore
      }
    }
  }
}

main().catch((err) => {
  console.error('Hidden service host test failed:', err);
  process.exitCode = 1;
});
