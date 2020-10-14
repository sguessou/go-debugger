package main

import (
	"crypto/sha256"
	"encoding/base64"
	"math/rand"
	"strings"
	"time"
)

type codeVerifier struct {
	Value string
}

const (
	length = 43
)

func base64URLEncode(str []byte) string {
	encoded := base64.StdEncoding.EncodeToString(str)
	encoded = strings.Replace(encoded, "+", "-", -1)
	encoded = strings.Replace(encoded, "/", "_", -1)
	encoded = strings.Replace(encoded, "=", "", -1)
	return encoded
}

func verifier() (*codeVerifier, error) {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	b := make([]byte, length, length)
	for i := 0; i < length; i++ {
		b[i] = byte(r.Intn(255))
	}
	return CreateCodeVerifierFromBytes(b)
}

func CreateCodeVerifierFromBytes(b []byte) (*codeVerifier, error) {
	return &codeVerifier{
		Value: base64URLEncode(b),
	}, nil
}

func (v *codeVerifier) CodeChallengeS256() string {
	h := sha256.New()
	h.Write([]byte(v.Value))
	return base64URLEncode(h.Sum(nil))
}
