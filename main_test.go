package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"math/big"
	"testing"
)

func TestEnvelopeLayoutAndSignature(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for profile, flags := range map[string]uint32{"maximum": 5, "low-interference": 1, "disabled": 0} {
		blob, err := signPolicy(key, profile, 1788860000001, 1788860000, 86400)
		if err != nil {
			t.Fatal(err)
		}
		if len(blob) != 184 {
			t.Fatal("invalid envelope size")
		}
		if binary.LittleEndian.Uint32(blob[8:12]) != 2 {
			t.Fatal("wrong command")
		}
		if binary.LittleEndian.Uint32(blob[80:84]) != flags {
			t.Fatal("wrong policy flags")
		}
		if binary.LittleEndian.Uint32(blob[76:80]) != 0 {
			t.Fatal("unexpected directory objects")
		}
		digest := sha256.Sum256(blob[:120])
		if !ecdsa.Verify(&key.PublicKey, digest[:], new(big.Int).SetBytes(blob[120:152]), new(big.Int).SetBytes(blob[152:])) {
			t.Fatal("signature failed")
		}
	}
}

func TestRejectUnknownAndInvalidLifetime(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	for _, profile := range []string{"arbitrary", "maximum; echo secret"} {
		if _, err := signPolicy(key, profile, 1, 1, 10); err == nil {
			t.Fatal("unknown profile accepted")
		}
	}
	if _, err := signPolicy(key, "maximum", 1, 1, 0); err == nil {
		t.Fatal("zero TTL accepted")
	}
}
