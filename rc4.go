package crypt_base64_wrapped

import (
	"crypto/rc4"
	"encoding/base64"
	"errors"
)

type rc4Base64Wrapped struct {
	key     []byte
	wrapper *base64.Encoding
}

// Creates new coder using RC4-key provided and web-safe base64 encoder.
func NewRc4Coder(key []byte) (*rc4Base64Wrapped, error) {
	var coder rc4Base64Wrapped

	coder.key = key
	if len(coder.key) < 1 || len(coder.key) > 256 {
		return nil, errors.New("Invalid RC4 crypto key size.")
	}

	coder.wrapper = base64.RawURLEncoding

	return &coder, nil
}

//Encodes string using RC4 crypto algorithm
// and wraps resulting bytes using web-safe base64 encoding
func (c *rc4Base64Wrapped) Encrypt(data []byte) string {
	encrypted := make([]byte, len(data))

	cipher, _ := rc4.NewCipher(c.key)
	cipher.XORKeyStream(encrypted, data)

	encoded := c.wrapper.EncodeToString(encrypted)

	return sprinkle(encoded)
}

//Unwraps string using web-safe base64 encoding
// and decrypts result using RC4 cipher
func (c *rc4Base64Wrapped) Decrypt(s string) (string, error) {
	unsprinkled := unsprinkle(s)
	decoded, err := c.wrapper.DecodeString(unsprinkled)
	if err != nil {
		return "", err
	}

	cipher, err := rc4.NewCipher(c.key)
	if err != nil {
		return "", err
	}

	decrypted := make([]byte, len(decoded))
	cipher.XORKeyStream(decrypted, decoded)

	return string(decrypted), nil
}
