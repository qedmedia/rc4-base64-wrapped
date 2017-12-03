package crypt_base64_wrapped

import (
	"bytes"
	"math/rand"
	"sort"
	"strings"
	"time"
)

const sprinkleChar = "/"

func contains(idx []int, v int) bool {
	for _, elem := range idx {
		if elem == v {
			return true
		}
	}

	return false
}

func sprinklingIndices(l int) []int {
	rand.Seed(time.Now().UnixNano())

	n := rand.Intn(l/3) + 1
	idx := make([]int, 1, n)
	for i := 0; i < n; i++ {
		v := rand.Intn(l-2) + 1
		if !contains(idx, v) {
			idx = append(idx, v)
		}
	}

	sort.Ints(idx)
	return idx
}

func sprinkle(s string) string {
	idx := sprinklingIndices(len(s))

	var buffer bytes.Buffer

	buffer.WriteString(s[:idx[0]])
	for i := 1; i < len(idx); i++ {
		l := idx[i-1]
		r := idx[i]
		buffer.WriteString(s[l:r])
		buffer.WriteString(sprinkleChar)
	}

	sprinkled := buffer.String()
	left := s[idx[len(idx)-1]:]

	return sprinkled + left
}

func unsprinkle(s string) string {
	return strings.Replace(s, sprinkleChar, "", -1)
}
