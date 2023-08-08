// pm2 config
module.exports = {
  apps: [{
    name: "tor-dev",
    script: "./src/test-chutney.ts",
    interpreter: "tsx",
    watch: true,
  }]
}
