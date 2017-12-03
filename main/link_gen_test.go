package main

import (
	"fmt"
	"testing"
)

const (
	data = "me@here.com|32948|111111111"
)

var (
	rc4Key = []byte("Q3DK3Y6231")
	aesKey = []byte("uSliqqttENtG+VTv0LeqzlN3IT9vAoIu")
)

func TestBadKeys(t *testing.T) {
	badRc4Key := []byte("")
	badAesKey := []byte("some bad key ")

	if err := encryptDerypt(aesCrypt, badAesKey, t); err == nil {
		t.Fatal("expected error, got nil")
	}

	if err := encryptDerypt(rc4Crypt, badRc4Key, t); err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestAESCryptDecrypt(t *testing.T) {
	if err := encryptDerypt(aesCrypt, aesKey, t); err != nil {
		t.Fatal(err)
	}
}

func TestRc4CryptDecrypt(t *testing.T) {
	if err := encryptDerypt(rc4Crypt, rc4Key, t); err != nil {
		t.Fatal(err)
	}
}

func encryptDerypt(algoName string, key []byte, t *testing.T) error {
	encrypted, err := doCrypt(algoName, key, data, true)
	if err != nil {
		return err
	}
	t.Logf("%s [key=%s] ecnryption: %s -> %s", algoName, key, data, encrypted)

	decrypted, err := doCrypt(algoName, key, encrypted, false)
	if err != nil {
		return err
	}
	t.Logf("%s [key=%s] decryption: %s -> %s", algoName, key, decrypted, data)

	if data != decrypted {
		return fmt.Errorf("decrypted [%s] is not the same as input [%s] string", decrypted, data)
	}

	return nil
}
