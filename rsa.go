package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
)

func RsaEncrypt(publicKey string, plainData []byte) ([]byte, error) {
	block, _ := pem.Decode([]byte(publicKey))
	if block == nil {
		return nil, fmt.Errorf("pem.Decode public key error")
	}

	var pub *rsa.PublicKey
	if block.Type == "PUBLIC KEY" {
		// pks8 format
		pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		pub = pubInterface.(*rsa.PublicKey)
	} else if block.Type == "RSA PUBLIC KEY" {
		// pks1 format
		pub = &rsa.PublicKey{}
		_, err := asn1.Unmarshal(block.Bytes, pub)
		if err != nil {
			return nil, err
		}
	} else {
		return nil, fmt.Errorf("not supported public key,type:%s", block.Type)
	}
	return rsa.EncryptPKCS1v15(rand.Reader, pub, plainData)
}

func RsaDecrypt(PrivateKey string, cryptoData []byte) ([]byte, error) {
	block, _ := pem.Decode([]byte(PrivateKey))
	if block == nil {
		return nil, fmt.Errorf("pem.Decode private key error")
	}

	if block.Type == "PRIVATE KEY" {
		// pks8 format
		privInterface, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return rsa.DecryptPKCS1v15(rand.Reader, privInterface.(*rsa.PrivateKey), cryptoData)
	} else if block.Type == "RSA PRIVATE KEY" {
		// pks1 format
		priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return rsa.DecryptPKCS1v15(rand.Reader, priv, cryptoData)
	} else {
		return nil, fmt.Errorf("not supported private key,type:%s", block.Type)
	}
}
