const modulesToImport = [
  './src/aes.ts',
  './src/util.ts',
  './src/tls.ts',
  './src/time.ts',
  './src/messaging.ts',
  './src/relay-cell.ts',
  './src/ntor.ts',
  './src/cert.ts',
  './src/channel.ts',
  './src/circuit.ts',
  './src/build-circuit/directory.ts',
  './src/build-circuit/util.ts',
  './src/build-circuit/chutney.ts',
  './src/build-circuit/mainnet.ts',
  './src/index.ts',
];

async function main() {
  for (const modulePath of modulesToImport) {
    try {
      await import(`../${modulePath}`);
    } catch (err) {
      console.error(`IMPORT FAIL: ${modulePath}`);
      console.error(err);
      process.exitCode = 1;
      return;
    }
  }
  console.log(`import check ok (${modulesToImport.length} modules)`);
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
