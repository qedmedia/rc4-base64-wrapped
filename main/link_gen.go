package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/qedmedia/rc4-base64-wrapped"
	"time"
)

var (
	flagAlgo     string
	flagKey      string
	flagEncrypt  string
	flagDecrypt  string
	flagRepeatsN int
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
	flag.IntVar(&flagRepeatsN, "n", 1, "number of links to generate")
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

	crypter, err := createCrypter(flagAlgo, []byte(flagKey))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	if encrypt {
		data := []byte(str)
		for i := 0; i < flagRepeatsN; i++ {
			res := crypter.Encrypt(data)
			fmt.Println(res)

			// don't remove this sleep, otherwise Go compiler
			// will optimize Encrypt() call returning the same string on each iteration
			time.Sleep(1 * time.Nanosecond)
		}
	} else {
		d, err := crypter.Decrypt(str)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error decrypting: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(d)
	}
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

	if flagDecrypt != "" && flagRepeatsN != 1 {
		return errors.New("`-n` can be used only in encryption mode")
	}

	return nil
}

type crypter interface {
	Encrypt(data []byte) string
	Decrypt(s string) (string, error)
}

func createCrypter(algo string, key []byte) (crypter, error) {
	if algo == rc4Crypt {
		return crypt_base64_wrapped.NewRc4Coder(key)
	} else {
		return crypt_base64_wrapped.NewAesCoder(key)
	}
}

