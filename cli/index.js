const fs = require('fs');
const { Command } = require('commander');
const { version } = require('../package.json')
const { create, publish, loadProfile, loadKeyInfo } = require('../lib/publish.js');
const { buildDirectories, buildRelaysIndex, buildRelaysAndDirs } = require('../lib/update-relays.js');
const { Tor } = require('../lib/src/circuits.js')

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
  .option('-p, --port <number>', 'port number', 10101)
  .option('-c, --contact <string>', 'contact info', 'admin@example.com')
  .action((options) => {
    const routerConfig = {
      OR_name: options.name,
      OR_ip: options.ip,
      OR_port: options.port,
      OR_contact: options.contact,
      version: options.version,
    };
    console.log('creating router profile with the following configuration:', routerConfig);
    create(routerConfig);
  });

program.command('publish')
  .description('Publish a profile')
  .action((options) => {
    const { routerConfig } = loadProfile(options.name)
    const { keyInfo } = loadKeyInfo(options.name)
    console.log('publishing router profile with the following configuration:', routerConfig);
    publish(routerConfig, keyInfo);
  });

program.command('update')
  .description('Update relay info')
  .option('-n, --name <string>', 'profile name', 'default')
  .option('-d, --directory', 'update directories')
  .option('-r, --relay', 'update relay index')
  .action(async (options) => {
    const { keyInfo } = loadKeyInfo(options.name)
    if (options.directory) {
      console.log('building directories...')
      await buildDirectories();
    }
    if (options.relay) {
      console.log('downloading relay index...')
      await buildRelaysIndex();
    }
    console.log('checking relays for viability...')
    const relayNodesResponse = JSON.parse(fs.readFileSync(__dirname+'/../lib/relayNodesIndex.json', 'utf8'));
    await buildRelaysAndDirs(relayNodesResponse, keyInfo);
  });

program.command('start')
  .description('Start the tor node')
  .option('-n, --name <string>', 'profile name', 'default')
  .action((options) => {
    const { routerConfig } = loadProfile(options.name)
    const { OR_port, OR_name } = routerConfig;
    const { keyInfo } = loadKeyInfo(options.name);
    
    console.log('starting Tor node');
    // Tor({
    //   params_: {
    //     port: OR_port,
    //     keyInfo,
    //   }
    // });

    // pollute global with Tor state and configuration
    require('../lib/node-tor.js')
    globalThis.one_OR = undefined;
    globalThis.OR_name = OR_name;
    globalThis.keyInfo = keyInfo;
    Tor({
      params_: {
        keyInfo,
        nb_hop: 3,
        OP: true,
        // db: true,
        // ws: this,
      }
    });
  });
  

program.parse();