# Json Web Key to PEM Converter

his program converts a RSA Public key from Json Web Key to PEM format.

## Installation

If you have the go compile installed you can use:

```shell
go get -u github.com/mpsinfo/jwks-to-pem
```

## Usage

You can specify an file or pass the content via pipe, the result will be printed on standard output

Examples:

```shell
jwks-to-pem example.jwks
```

```shell
cat example.jwks | jwks-to-pem
```
