package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/qedmedia/rc4-base64-wrapped"
)

var (
	flagAlgo    string
	flagKey     string
	flagEncrypt string
	flagDecrypt string
)

const (
	rc4Crypt = "rc4"
	aesCrypt = "aes"
)

func main() {
	flag.StringVar(&flagAlgo, "t", "", "cypher type, one of: aes, rc4")
	flag.StringVar(&flagKey, "k", "", "cypher key")
	flag.StringVar(&flagEncrypt, "e", "", "string to encrypt")
	flag.StringVar(&flagDecrypt, "d", "", "string to decrypt")
	flag.Parse()

	err := validateFlags()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	str := flagDecrypt
	encrypt := flagEncrypt != ""
	if encrypt {
		str = flagEncrypt
	}

	res, err := doCrypt(flagAlgo, []byte(flagKey), str, encrypt)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(res)
}

func validateFlags() error {
	if flagAlgo == "" {
		return errors.New("encryption algorithm is not specified")
	}

	if flagAlgo != rc4Crypt && flagAlgo != aesCrypt {
		return fmt.Errorf("unsupported encryption algorithm: %s", flagAlgo)
	}

	if flagKey == "" {
		return errors.New("encryption key is not specified")
	}

	if flagEncrypt == "" && flagDecrypt == "" {
		return errors.New("missing input mode and data")
	} else if flagEncrypt != "" && flagDecrypt != "" {
		return errors.New("should be encrypt or decrypt, cannot use both `-e` and `-d`")
	}

	return nil
}

func doCrypt(algo string, key []byte, data string, encrypt bool) (string, error) {
	crypter, err := createCrypter(algo, key)
	if err != nil {
		return "", fmt.Errorf("failed create crypter: %s", err.Error())
	}

	if encrypt {
		return crypter.Encrypt([]byte(data)), nil
	} else {
		return crypter.Decrypt(data)
	}
}

func createCrypter(algo string, key []byte) (crypter, error) {
	if algo == rc4Crypt {
		return crypt_base64_wrapped.NewRc4Coder(key)
	} else {
		return crypt_base64_wrapped.NewAesCoder(key)
	}
}

type crypter interface {
	Encrypt(data []byte) string
	Decrypt(s string) (string, error)
}
