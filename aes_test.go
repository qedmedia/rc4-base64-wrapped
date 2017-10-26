package crypt_base64_wrapped

import (
	"testing"
	"fmt"
)

var TEST_AES_KEY = []byte("uSliqqttENtG+VTv0LeqzlN3IT9vAoIu")

func TestAesEncodingDecoding(t *testing.T) {
	t.Log("Encoding and decoding encoded string should give an original input sequence")

	str := "link-D5a1Z-user@yahoo.com"
	c, _ := NewAesCoder(TEST_AES_KEY)

	encoded := c.Encrypt(str)
	fmt.Println("ENCODED: ", encoded)
	decoded, _ := c.Decrypt(encoded)
	fmt.Println("decoded: ", decoded)

	if decoded != str {
		t.Errorf("Expected decoded string to be [%s], but it was [%s] instead.", str, decoded)
	}
}

func encodeAesDecodeNTimes(s string, n int) string {
	decoded := ""

	c, _ := NewAesCoder(TEST_AES_KEY)
	for i := 0; i < n; i++ {
		encoded := c.Encrypt(s)
		decoded, _ = c.Decrypt(encoded)
	}
	return decoded
}

func BenchmarkAesEncodingDecoding(b *testing.B) {
	links := []string{
		"link-D5a1Z-small@gmail.com",
		"link-Adn54-medium.length@yahoo.com",
		"link-5MN6j-very_long_name.123@mailboxhostname.com",
	}

	for n := 0; n < b.N; n++ {
		encodeAesDecodeNTimes(links[n%3], 1000)
	}
}

func encodeAesNTimes(s string, n int) string {
	encoded := ""

	c, _ := NewAesCoder(TEST_AES_KEY)
	for i := 0; i < n; i++ {
		encoded = c.Encrypt(s)
	}
	return encoded
}

func BenchmarkAesEncoding1Million(b *testing.B) {
	link := "link-Adn54-medium.length@yahoo.com"

	for n := 0; n < b.N; n++ {
		encodeAesNTimes(link, 1000000)
	}
}
