import { loadProfile, loadKeyInfo } from './profiles.ts';
import { debug } from './debug.ts';

const { routerConfig } = loadProfile('default')
const { keyInfo } = loadKeyInfo('default');
const { OR_port, OR_name } = routerConfig;

// pollute global with Tor state and configuration
// require('../lib/node-tor.js')
// globalThis.one_OR = undefined;
// globalThis.OR_name = OR_name;
// globalThis.keyInfo = keyInfo;

debug({ keyInfo })
