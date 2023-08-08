// pm2 config
module.exports = {
  apps: [{
    name: "tor-test-dev",
    script: "./node_modules/.bin/ava",
    args: ["--match='src/**/*.spec.ts'"],
    interpreter: "tsx",
    watch: true,
    autorestart: false,
  }]
}
