package main

import (
	"testing"
)

func TestAesEncrypt(t *testing.T) {
	key, iv, err := generateAesKeyAndIV()
	if err != nil {
		t.Fatal(err)
	}

	originData := "15651859999"
	encrypt, err := AesEncrypt([]byte(originData), key, iv)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(encrypt))

	decrypt, err := AesEncrypt(encrypt, key, iv)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(decrypt))
}
