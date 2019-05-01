package main

import (
	"math/rand"
	"fmt"
	"errors"
	"encoding/base64"
	"os"
)

const BlockSize = 16
const KeySize = 32
var InitVector = []byte{100, 111, 32, 115, 117, 100, 111, 32, 114, 109, 32, 45, 114, 102, 32, 47}

func getBlockQuad(block []byte, i byte) byte {
	if i % 2 == 0 {
		return block[i / 2] >> 4
	} else {
		return block[i / 2] & 0x0f
	}
}

func setBlockQuad(block []byte, i, value byte) {
	if i % 2 == 0 {
		block[i / 2] |= value << 4
	} else {
		block[i / 2] |= value
	}
}

func decryptBlock(key []byte, block []byte, resultBlock []byte) {
	for i := byte(0); i < KeySize; i++ {
		setBlockQuad(resultBlock, i, getBlockQuad(block, key[i]))
	}
}

func Decrypt(key []byte, block []byte) ([]byte, error) {
	if len(block) == 0 {
		return nil, errors.New("empty block")
	}
	if len(block) % 16 != 0 {
		return nil, errors.New("invalid block size")
	}
	result := make([]byte, len(block))
	decryptBlock(key, block[:BlockSize], result[:BlockSize])
	for i := 0; i < BlockSize; i++ {
		result[i] ^= InitVector[i]
	}
	for j := 1; j < len(block)/BlockSize; j++ {
		decryptBlock(key, block[BlockSize*j:BlockSize*(j+1)], result[BlockSize*j:BlockSize*(j+1)])
		for i := 0; i < BlockSize; i++ {
			result[BlockSize*j+i] ^= block[BlockSize*(j-1)+i]
		}
	}
	padding := result[len(result) - 1]
	if padding == 0 || padding > 16 {
		return nil, errors.New("invalid padding, out of range [1, ..., 16]")
	}
	for i := len(result) - int(padding); i < len(result); i++ {
		if result[i] != padding {
			return nil, errors.New("invalid padding")
		}
	}
	return result[:len(result) - int(padding)], nil
}

func GenerateKey() []byte {
	key := make([]byte, 32)
	for i := 0; i < 32; i++ {
		key[i] = byte(i)
	}
	rand.Shuffle(32, func(i, j int) { key[i], key[j] = key[j], key[i] })
	return key
}

func main() {
	secret := os.Args[1]
	for i := 0; i < 10000; i++ {   // make sure this will work for the whole ctf
		fmt.Println(i)
		c, err:= base64.StdEncoding.DecodeString(secret)
		if err != nil {
			fmt.Println(err)
		}
		k := GenerateKey()
		fmt.Println(k)
		r, err := Decrypt(k, c)
		if err != nil {
			fmt.Println(err)
		}
		fmt.Println(string(r))
	}
}
