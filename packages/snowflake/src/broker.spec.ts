import test from 'ava';
import { SnowflakeBrokerClient } from './broker.ts';

test('SnowflakeBrokerClient defaults to Tor Project broker URL', (t) => {
  const client = new SnowflakeBrokerClient();
  t.is(client.brokerUrl, 'https://snowflake-broker.torproject.net/');
  t.is(client.natType, 'unknown');
  t.is(client.numRelayAddresses, 1);
});

test('SnowflakeBrokerClient defaults to Fastly CDN domain fronting', (t) => {
  const client = new SnowflakeBrokerClient();
  // Default matches Snowflake browser extension (Fastly CDN via StackExchange)
  t.is(client.frontDomain, 'cdn.sstatic.net');
});

test('SnowflakeBrokerClient accepts custom broker URL', (t) => {
  const client = new SnowflakeBrokerClient({
    brokerUrl: 'https://custom-broker.example.com/',
  });
  t.is(client.brokerUrl, 'https://custom-broker.example.com/');
});

test('SnowflakeBrokerClient accepts custom domain fronting config', (t) => {
  const client = new SnowflakeBrokerClient({
    frontDomain: 'www.fastly.com',
  });
  t.is(client.frontDomain, 'www.fastly.com');
});

test('SnowflakeBrokerClient can disable domain fronting', (t) => {
  const client = new SnowflakeBrokerClient({
    disableDomainFronting: true,
  });
  t.is(client.frontDomain, undefined);
});

test('SnowflakeBrokerClient accepts NAT type config', (t) => {
  const clientUnknown = new SnowflakeBrokerClient({ natType: 'unknown' });
  t.is(clientUnknown.natType, 'unknown');

  const clientRestricted = new SnowflakeBrokerClient({ natType: 'restricted' });
  t.is(clientRestricted.natType, 'restricted');

  const clientUnrestricted = new SnowflakeBrokerClient({ natType: 'unrestricted' });
  t.is(clientUnrestricted.natType, 'unrestricted');
});
