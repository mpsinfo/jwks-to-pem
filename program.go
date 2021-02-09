package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math"
	"math/big"
	"os"
)

func main() {
	var js []byte
	var err error
	if len(os.Args) == 2 {
		js, err = ioutil.ReadFile(os.Args[1])
	} else {
		js, err = ioutil.ReadAll(os.Stdin)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v", err)
		os.Exit(1)
	}

	jwk := map[string]string{}
	err = json.Unmarshal(js, &jwk)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v", err)
		os.Exit(1)
	}

	if jwk["kty"] != "RSA" {
		fmt.Fprintf(os.Stderr, "error: invalid key type: %s", jwk["kty"])
		os.Exit(1)
	}

	nb, err := base64.RawURLEncoding.DecodeString(jwk["n"])
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v", err)
		os.Exit(1)
	}

	eb, err := base64.RawURLEncoding.DecodeString(jwk["e"])
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v", err)
		os.Exit(1)
	}
	ebig := new(big.Int).SetBytes(eb)
	if !ebig.IsInt64() || ebig.Int64() > math.MaxInt32 {
		fmt.Fprintf(os.Stderr, "error: exponent too big")
		os.Exit(1)
	}
	e := int(ebig.Int64())

	pk := &rsa.PublicKey{
		N: new(big.Int).SetBytes(nb),
		E: e,
	}

	der, err := x509.MarshalPKIXPublicKey(pk)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v", err)
		os.Exit(1)
	}

	block := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: der,
	}

	var out bytes.Buffer
	pem.Encode(&out, block)
	fmt.Println(out.String())
}
