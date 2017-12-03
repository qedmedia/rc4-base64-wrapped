package crypt_base64_wrapped

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"io"
)

type aesBase64Wrapped struct {
	block   cipher.Block
	wrapper *base64.Encoding
}

// Creates new coder using AES-key provided and web-safe base64 encoder.
func NewAesCoder(key []byte) (*aesBase64Wrapped, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	return &aesBase64Wrapped{
		block:   block,
		wrapper: base64.RawURLEncoding,
	}, nil
}

//Encodes string using AES crypto algorithm
// and wraps resulting bytes using web-safe base64 encoding
func (c *aesBase64Wrapped) Encrypt(data []byte) string {
	ciphertext := make([]byte, aes.BlockSize+len(data))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return string(data)
	}

	encrypter := cipher.NewCTR(c.block, iv)
	encrypter.XORKeyStream(ciphertext[aes.BlockSize:], data)

	encoded := c.wrapper.EncodeToString(ciphertext)

	return sprinkle(encoded)
}

//Unwraps string using web-safe base64 encoding
// and decrypts result using AES cipher
func (c *aesBase64Wrapped) Decrypt(s string) (string, error) {
	unsprinkled := unsprinkle(s)

	data, err := c.wrapper.DecodeString(unsprinkled)
	if err != nil {
		return "", err
	}

	iv := data[:aes.BlockSize]
	plaintext := make([]byte, len(data)-aes.BlockSize)

	decrypter := cipher.NewCTR(c.block, iv)
	decrypter.XORKeyStream(plaintext, data[aes.BlockSize:])

	return string(plaintext), nil
}
