package crypt_base64_wrapped

import (
	"testing"
	"strings"
)

var TEST_RC4_KEY = []byte("S3FL3Y8450")

func TestWebSafeBase64(t *testing.T) {
	t.Log("Coder should output web-safe base64 encoded string")

	c, _ := NewRc4Coder(TEST_RC4_KEY)
	encoded := c.Encrypt("link-D5a1Z-user@yahoo.com")

	if strings.ContainsAny(encoded, "+,=") {
		t.Errorf("Expected URl-safe string, but it was %s instead.", encoded)
	}
}

func TestRc4EncodingDecoding(t *testing.T) {
	t.Log("Encoding and decoding encoded string should give an original input sequence")

	str := "link-D5a1Z-user@yahoo.com"
	c, _ := NewRc4Coder(TEST_RC4_KEY)

	encoded := c.Encrypt(str)
	decoded, _ := c.Decrypt(encoded)

	if decoded != str {
		t.Errorf("Expected decoded string to be [%s], but it was [%s] instead.", str, decoded)
	}
}

func encodeDecodeRc4NTimes(s string, n int) string {
	decoded := ""

	c, _ := NewRc4Coder(TEST_RC4_KEY)
	for i := 0; i < n; i++ {
		encoded := c.Encrypt(s)
		decoded, _ = c.Decrypt(encoded)
	}
	return decoded
}

func BenchmarkRc4EncodingDecoding(b *testing.B) {
	links := []string{
		"link-D5a1Z-small@gmail.com",
		"link-Adn54-medium.length@yahoo.com",
		"link-5MN6j-very_long_name.123@mailboxhostname.com",
	}

	for n := 0; n < b.N; n++ {
		encodeDecodeRc4NTimes(links[n%3], 1000)
	}
}

func encodeRc4NTimes(s string, n int) string {
	encoded := ""

	c, _ := NewRc4Coder(TEST_RC4_KEY)
	for i := 0; i < n; i++ {
		encoded = c.Encrypt(s)
	}
	return encoded
}

func BenchmarkRc4Encoding1Million(b *testing.B) {
	link :=	"link-Adn54-medium.length@yahoo.com"

	for n := 0; n < b.N; n++ {
		encodeRc4NTimes(link, 1000000)
	}
}
