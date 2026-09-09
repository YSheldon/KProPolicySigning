package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

const expectedPublicSHA256 = "d0601d687d57fc3813733c2df71d8aab08b91339e04d659750da230816b2c8df"
const keyVersion uint32 = 20260531

func loadKey() (*ecdsa.PrivateKey, error) {
	encoded := os.Getenv("KPRO_POLICY_PRIVATE_KEY_B64")
	os.Unsetenv("KPRO_POLICY_PRIVATE_KEY_B64")
	if len(encoded) == 0 || len(encoded) > 16384 {
		return nil, errors.New("key unavailable")
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, errors.New("key unavailable")
	}
	defer clear(raw)
	var doc struct {
		KeyVersion uint32 `json:"keyVersion"`
		X          string `json:"x"`
		Y          string `json:"y"`
		D          string `json:"d"`
	}
	if json.Unmarshal(bytes.TrimPrefix(raw, []byte{0xef, 0xbb, 0xbf}), &doc) != nil || doc.KeyVersion != keyVersion {
		return nil, errors.New("key unavailable")
	}
	d, ok := new(big.Int).SetString(doc.D, 16)
	if !ok || d.Sign() <= 0 || d.Cmp(elliptic.P256().Params().N) >= 0 {
		return nil, errors.New("key unavailable")
	}
	x, y := elliptic.P256().ScalarBaseMult(d.Bytes())
	point := append(x.FillBytes(make([]byte, 32)), y.FillBytes(make([]byte, 32))...)
	digest := sha256.Sum256(point)
	if hex.EncodeToString(digest[:]) != expectedPublicSHA256 ||
		hex.EncodeToString(point[:32]) != doc.X || hex.EncodeToString(point[32:]) != doc.Y {
		return nil, errors.New("key identity mismatch")
	}
	return &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, D: d}, nil
}

func signPolicy(key *ecdsa.PrivateKey, profile string, version, now uint64, ttl uint32) ([]byte, error) {
	var flags uint32
	switch profile {
	case "maximum":
		flags = 5
	case "low-interference":
		flags = 1
	case "disabled":
		flags = 0
	default:
		return nil, errors.New("unsupported profile")
	}
	if version == 0 || now == 0 || ttl == 0 || ttl > 31536000 {
		return nil, errors.New("invalid lifetime/version")
	}
	policyID := "kpro-consumer-" + profile
	var canonical bytes.Buffer
	binary.Write(&canonical, binary.LittleEndian, uint32(len(policyID)))
	canonical.WriteString(policyID)
	for _, v := range []any{version, uint32(3), ttl, flags, uint32(0)} {
		binary.Write(&canonical, binary.LittleEndian, v)
	}
	policyHash := sha256.Sum256(canonical.Bytes())
	var blob bytes.Buffer
	// Public ABI: 48-byte header, 72-byte snapshot, 64-byte P1363 signature.
	for _, v := range []any{uint32(0x4f52504b), uint16(4), uint16(48), uint32(2), uint32(72), uint32(64), keyVersion,
		uint64(0x4b50524f414c4552), version, version, version, now, now + uint64(ttl), uint32(3), uint32(0), flags, uint32(0)} {
		binary.Write(&blob, binary.LittleEndian, v)
	}
	blob.Write(policyHash[:])
	digest := sha256.Sum256(blob.Bytes())
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		return nil, errors.New("sign failed")
	}
	if !ecdsa.Verify(&key.PublicKey, digest[:], r, s) {
		return nil, errors.New("self-verification failed")
	}
	blob.Write(r.FillBytes(make([]byte, 32)))
	blob.Write(s.FillBytes(make([]byte, 32)))
	return blob.Bytes(), nil
}

func run() error {
	profile := flag.String("profile", "maximum", "maximum, low-interference, disabled")
	output := flag.String("output", "signed-output", "new output directory")
	flag.Parse()
	// Production key use is restricted to the protected manually-approved job.
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("GITHUB_EVENT_NAME") != "workflow_dispatch" ||
		os.Getenv("GITHUB_REF") != "refs/heads/main" || os.Getenv("GITHUB_REPOSITORY") != "YSheldon/KProPolicySigning" {
		return errors.New("protected GitHub workflow required")
	}
	key, err := loadKey()
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	blob, err := signPolicy(key, *profile, uint64(now.UnixMilli()), uint64(now.Unix()), 31536000)
	if err != nil {
		return err
	}
	if err = os.Mkdir(*output, 0700); err != nil {
		return errors.New("output directory must be new")
	}
	if err = os.WriteFile(filepath.Join(*output, "default-policy.hex"), []byte(hex.EncodeToString(blob)), 0600); err != nil {
		return err
	}
	digest := sha256.Sum256(blob)
	receipt := map[string]any{"schema": "KProPolicySigningReceipt/v1", "profile": *profile, "protocolVersion": 4,
		"keyVersion": keyVersion, "policyVersion": uint64(now.UnixMilli()), "notAfterUnixSeconds": now.Unix() + 31536000,
		"policyFlags": binary.LittleEndian.Uint32(blob[80:84]), "protectedObjectCount": 0, "envelopeSha256": hex.EncodeToString(digest[:]),
		"publicKeySha256": expectedPublicSHA256, "signatureVerified": true, "driverAcceptanceTested": false}
	encoded, _ := json.MarshalIndent(receipt, "", "  ")
	return os.WriteFile(filepath.Join(*output, "receipt.json"), encoded, 0600)
}

func main() {
	if run() != nil {
		fmt.Fprintln(os.Stderr, "Policy signing failed; no secret data emitted.")
		os.Exit(1)
	}
	fmt.Println("Signed policy and public receipt generated.")
}
