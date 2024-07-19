# mysql-audit

## Disclaimer

This project is a demo for auditing mysql traffic, It has not been rigorously tested.
The analysis of the mysql protocol is based on [MySQL Source Code Documentation
](https://dev.mysql.com/doc/dev/mysql-server/latest/) not souce code, so the correctness cannot be guaranteed.

If you want to perform MySQL auditing in a production environment, you can try the following MySQL plugin:

- https://github.com/trellix-enterprise/mysql-audit
- https://github.com/aws/audit-plugin-for-mysql

The purpose of this project is to write a statically linked program that can run on all x64 Linux platforms, so the program is compiled using clang in alpine docker.

The program runs on a Linux host with mysql-server deployed.
It captures traffic(by [libtins](https://github.com/mfontanini/libtins)) from port 3306 and then parses the mysql protocol.



## Support Versions

| MySQL Variant       | Support Versions  | 
| -------- | --- |
| MySQL     | 8.1.x、8.0.x、5.7.x、5.6.x、5.5.x | 
| MariaDB     | 11.2.x、11.1.x、10.x、5.5.x | 
| Percona | 8.0.x、5.7.x | 

> support zlib and zstd compression

It also support PostgreSQL and Redis.

## Usage

```bash
# build compilation environment
make env

# build program
make all

# run foregroud
./src/mysql-audit -m mysql -f -b -d 4
```

It will generate audit log(json format) in `/var/log/mysql-audit.json`.

## TODO

### TLS Decryption 

> https://wiki.wireshark.org/TLS

This project support TLS decryption using an RSA private key.
However, the most commonly used TLS cipher suite is (EC)DHE which can't be decrypted by RSA Private key.
If you want to use this feature, you need to lower TLS security by setting the mysql configuration.

```bash
[mysqld]
ssl_cipher="AES128-SHA:AES256-SHA:AES128-SHA256:AES256-SHA256"
```

Maybe [ecapture](https://github.com/gojue/ecapture) is the best way to decrypt TLS traffic. 

### MySQL Statements Type

Currently [hyperscan](https://github.com/intel/hyperscan) is used to identify the type of statements, but [antlr4](https://github.com/antlr/antlr4) should be a better choice.


## LICENSE

MIT
