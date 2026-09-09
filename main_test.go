package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"testing"
)

func TestEnvelopeLayoutAndSignature(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for profile, flags := range map[string]uint32{"maximum": 5, "low-interference": 1, "disabled": 0} {
		payloadSize := 72
		if flags&4 != 0 {
			payloadSize = 92
		}
		blob, err := signPolicy(key, profile, 1788860000001, 1788860000, 86400)
		if err != nil {
			t.Fatal(err)
		}
		if len(blob) != 48+payloadSize+64 {
			t.Fatal("invalid envelope size")
		}
		if binary.LittleEndian.Uint32(blob[0:4]) != 0x4f52504b || binary.LittleEndian.Uint16(blob[4:6]) != 4 ||
			binary.LittleEndian.Uint16(blob[6:8]) != 48 || binary.LittleEndian.Uint32(blob[12:16]) != uint32(payloadSize) ||
			binary.LittleEndian.Uint32(blob[16:20]) != 64 || binary.LittleEndian.Uint32(blob[20:24]) != 20260531 {
			t.Fatal("invalid header ABI")
		}
		for _, offset := range []int{32, 40, 48} {
			if binary.LittleEndian.Uint64(blob[offset:offset+8]) != 1788860000001 {
				t.Fatal("version/sequence mismatch")
			}
		}
		if binary.LittleEndian.Uint64(blob[24:32]) != 0x4b50524f414c4552 ||
			binary.LittleEndian.Uint64(blob[56:64]) != 1788860000 || binary.LittleEndian.Uint64(blob[64:72]) != 1788946400 ||
			binary.LittleEndian.Uint32(blob[72:76]) != 3 {
			t.Fatal("invalid policy ABI")
		}
		if flags&4 != 0 {
			if binary.LittleEndian.Uint32(blob[84:88]) != 72 ||
				binary.LittleEndian.Uint32(blob[120:124]) != 0x5845504b ||
				binary.LittleEndian.Uint16(blob[124:126]) != 1 ||
				binary.LittleEndian.Uint16(blob[126:128]) != 20 ||
				binary.LittleEndian.Uint32(blob[128:132]) != 20 ||
				binary.LittleEndian.Uint64(blob[132:140]) != 0 {
				t.Fatal("missing required empty risk-block extension")
			}
		} else if binary.LittleEndian.Uint32(blob[84:88]) != 0 {
			t.Fatal("unexpected extension")
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
		signedLength := len(blob) - 64
		digest := sha256.Sum256(blob[:signedLength])
		if !ecdsa.Verify(&key.PublicKey, digest[:], new(big.Int).SetBytes(blob[signedLength:signedLength+32]), new(big.Int).SetBytes(blob[signedLength+32:])) {
			t.Fatal("signature failed")
		}
	}
}

func TestMalformedOrWrongKeyRejected(t *testing.T) {
	for _, value := range []string{"", "not-base64", base64.StdEncoding.EncodeToString([]byte("{}"))} {
		t.Setenv("KPRO_POLICY_PRIVATE_KEY_B64", value)
		if _, err := loadKey(); err == nil {
			t.Fatal("malformed key accepted")
		}
		if os.Getenv("KPRO_POLICY_PRIVATE_KEY_B64") != "" {
			t.Fatal("key env not removed")
		}
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	doc, _ := json.Marshal(map[string]any{"keyVersion": 20260531, "d": hex.EncodeToString(key.D.FillBytes(make([]byte, 32))),
		"x": hex.EncodeToString(key.X.FillBytes(make([]byte, 32))), "y": hex.EncodeToString(key.Y.FillBytes(make([]byte, 32)))})
	t.Setenv("KPRO_POLICY_PRIVATE_KEY_B64", base64.StdEncoding.EncodeToString(doc))
	if _, err := loadKey(); err == nil {
		t.Fatal("wrong public identity accepted")
	}
}

func TestWorkflowGate(t *testing.T) {
	values := map[string]string{"GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "workflow_dispatch",
		"GITHUB_REF": "refs/heads/main", "GITHUB_REPOSITORY": "YSheldon/KProPolicySigning"}
	for k, v := range values {
		t.Setenv(k, v)
	}
	if !authorizedWorkflow() {
		t.Fatal("valid workflow rejected")
	}
	for k, v := range values {
		t.Setenv(k, "untrusted")
		if authorizedWorkflow() {
			t.Fatal("invalid workflow accepted")
		}
		t.Setenv(k, v)
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
