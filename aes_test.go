package main

import (
	"encoding/base64"
	"testing"
)

func TestAesEncrypt(t *testing.T) {
	key, iv, err := generateAesKeyAndIV()
	if err != nil {
		t.Fatal(err)
	}
	t.Log(base64.StdEncoding.EncodeToString(key))
	t.Log(base64.StdEncoding.EncodeToString(iv))

	originData := "15651859999"
	encrypt, err := AesEncrypt([]byte(originData), key, iv)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(encrypt))
	t.Log(base64.StdEncoding.EncodeToString(encrypt))

	decrypt, err := AesEncrypt(encrypt, key, iv)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(decrypt))
}
