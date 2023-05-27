this doesnt actually work atm

### setup

- create keys
```bash
node cli create
```

- publish (optional, skip this)
```bash
node cli publish
```

- get directory servers
- get guards and exits (this is broken, due to directory lookup protocol changing)
```bash
node cli update --directory --relay
```

### start

this doesnt work, fails on `TypeError: this.stream_tor_.parse is not a function`
```bash
node cli start
```