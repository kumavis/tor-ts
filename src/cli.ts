import { Command } from 'commander';
import { version } from '../package.json';
import { createProfile, loadProfile, loadKeyInfo } from './profiles';
import { testHandshake } from './channel';


const program = new Command();

program
  .name('node-tor')
  .description('CLI to node-tor')
  .version(version);

program.command('create')
  .description('Create a profile')
  .option('-n, --name <string>', 'profile name', 'default')
  .option('-v, --version <string>', 'version', version)
  .option('-i, --ip <string>', 'ip address', '0.0.0.0')
  .option('-p, --port <string>', 'port number', '10101')
  .option('-c, --contact <string>', 'contact info', 'admin@example.com')
  .action((options: any) => {
    const routerConfig = {
      OR_name: options.name,
      OR_ip: options.ip,
      OR_port: options.port,
      OR_contact: options.contact,
      version: options.version,
    };
    console.log('creating router profile with the following configuration:', routerConfig);
    createProfile(routerConfig);
  });

// program.command('publish')
//   .description('Publish a profile')
//   .action((options: any) => {
//     const { routerConfig } = loadProfile(options.name)
//     const { keyInfo } = loadKeyInfo(options.name)
//     console.log('publishing router profile with the following configuration:', routerConfig);
//     publish(routerConfig, keyInfo);
//   });

// program.command('update')
//   .description('Update relay info')
//   .option('-n, --name <string>', 'profile name', 'default')
//   .option('-d, --directory', 'update directories')
//   .option('-r, --relay', 'update relay index')
//   .action(async (options: any) => {
//     const { keyInfo } = loadKeyInfo(options.name)
//     if (options.directory) {
//       console.log('building directories...')
//       await buildDirectories();
//     }
//     if (options.relay) {
//       console.log('downloading relay index...')
//       await buildRelaysIndex();
//     }
//     console.log('checking relays for viability...')
//     const relayNodesResponse = JSON.parse(fs.readFileSync(__dirname+'/../lib/relayNodesIndex.json', 'utf8'));
//     await buildRelaysAndDirs(relayNodesResponse, keyInfo);
//   });

program.command('start')
  .description('Start the tor node')
  .option('-n, --name <string>', 'profile name', 'default')
  .action((options: any) => {
    // const { routerConfig } = loadProfile(options.name)
    const { keyInfo } = loadKeyInfo(options.name);
    
    console.log('starting Tor node');
    testHandshake({ keyInfo })
  });
  

program.parse();