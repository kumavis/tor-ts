// pm2 config
module.exports = {
  apps: [
    {
      name: 'tor-dev',
      script: './src/test-chutney.ts',
      interpreter: 'node',
      node_args: ['--experimental-transform-types'],
      watch: true,
    },
  ],
};
