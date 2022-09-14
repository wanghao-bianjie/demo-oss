package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	math_rand "math/rand"
	"time"
)

func AesEncrypt(origData, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	encrypter := cipher.NewCTR(block, iv)
	//decrypter := cipher.NewCTR(block, iv)

	dst := make([]byte, len(origData), len(origData))
	encrypter.XORKeyStream(dst, origData)
	return dst, nil
}

const (
	keyLen = 32
	ivLen  = 16
)

func generateAesKeyAndIV() (key, iv []byte, err error) {
	math_rand.Seed(time.Now().UnixNano())

	// Key
	key = make([]byte, keyLen)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, nil, err
	}

	// sizeof uint64
	if ivLen < 8 {
		return nil, nil, fmt.Errorf("ivLen:%d less than 8", ivLen)
	}

	// IV:reserve 8 bytes
	iv = make([]byte, ivLen)
	if _, err := io.ReadFull(rand.Reader, iv[0:ivLen-8]); err != nil {
		return nil, nil, err
	}

	// only use 4 byte,in order not to overflow when SeekIV()
	randNumber := math_rand.Uint32()
	ivLen := len(iv)
	binary.BigEndian.PutUint64(iv[ivLen-8:], uint64(randNumber))

	return key, iv, nil
}
