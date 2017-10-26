package crypt_base64_wrapped

import (
	"testing"
)

var TestAesKey = []byte("uSliqqttENtG+VTv0LeqzlN3IT9vAoIu")

func TestAesEncodingDecoding(t *testing.T) {
	t.Log("Encoding and decoding encoded string should give an original input sequence")

	str := "link-D5a1Z-user@yahoo.com"
	c, _ := NewAesCoder(TestAesKey)

	encoded := c.Encrypt([]byte(str))
	decoded, _ := c.Decrypt(encoded)

	if decoded != str {
		t.Errorf("Expected decoded string to be [%s], but it was [%s] instead.", str, decoded)
	}
}

func encodeAesDecodeNTimes(data []byte, n int) string {
	decoded := ""

	c, _ := NewAesCoder(TestAesKey)
	for i := 0; i < n; i++ {
		encoded := c.Encrypt(data)
		decoded, _ = c.Decrypt(encoded)
	}
	return decoded
}

func BenchmarkAesEncodingDecoding(b *testing.B) {
	links := [][]byte{
		[]byte("link-D5a1Z-small@gmail.com"),
		[]byte("link-Adn54-medium.length@yahoo.com"),
		[]byte("link-5MN6j-very_long_name.123@mailboxhostname.com"),
	}

	for n := 0; n < b.N; n++ {
		encodeAesDecodeNTimes(links[n%3], 1000)
	}
}

func encodeAesNTimes(data []byte, n int) string {
	encoded := ""

	c, _ := NewAesCoder(TestAesKey)
	for i := 0; i < n; i++ {
		encoded = c.Encrypt(data)
	}
	return encoded
}

func BenchmarkAesEncoding1Million(b *testing.B) {
	link := []byte("link-Adn54-medium.length@yahoo.com")

	for n := 0; n < b.N; n++ {
		encodeAesNTimes(link, 1000000)
	}
}
