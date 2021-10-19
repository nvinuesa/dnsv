# dnsv
Simple dns spoofer to validate your current dns resolver against a list of validators.

It works very basically by listening to dns (udp on port 53) packets, this is why it has to be run with elevated privileges. 
For the packets that correspond to a dns query then it extracts the query hostname and performs the same query on the provided list of (external dns servers) validators. If some of those validators respond with a different address than the current default dns, then it logs with `warn` level, if *all* the validators respond with a different address then it logs with `error` level.

### Build
The project uses makefile, to build simply run: 

```bash
make all
```

and to test it simply run:

```bash
make test
```

## Usage
Provided the following config file (on the same folder as the executable):

```
device: any
validators:
  - 1.1.1.1
  - 8.8.8.8
  - 208.67.222.222
  - 9.9.9.9
```

then `dnsv` will try to validate all your dns traffic agains those four well known validators.

```
sudo dnsv
```