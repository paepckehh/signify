package signify

import (
	"bytes"
	"crypto/ed25519"
	"strings"
	"testing"
)

func testSeedToken(seed, fingerprint byte) [SeedTokenSize]byte {
	var token [SeedTokenSize]byte
	for i := range SeedSize {
		token[i] = seed
	}
	for i := SeedSize; i < SeedTokenSize; i++ {
		token[i] = fingerprint
	}
	return token
}

func TestGeneratePKFromSeedDeterministic(t *testing.T) {
	token := testSeedToken(0x42, 0x17)
	a := GeneratePKFromSeed(token)
	b := GeneratePKFromSeed(token)

	if a.Raw.RawKey != b.Raw.RawKey {
		t.Fatal("same seed produced different private keys")
	}
	if a.Raw.Fingerprint != b.Raw.Fingerprint {
		t.Fatal("same seed produced different fingerprints")
	}
	want := ed25519.NewKeyFromSeed(token[:SeedSize])
	if !bytes.Equal(a.Raw.RawKey[:], want) {
		t.Fatal("private key does not match ed25519.NewKeyFromSeed")
	}
	pub := a.GetPublicKey()
	if !bytes.Equal(pub.Raw.RawKey[:], want.Public().(ed25519.PublicKey)) {
		t.Fatal("derived public key does not match ed25519 public key")
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	pk := GeneratePKFromSeed(testSeedToken(0x01, 0x02))
	pub := pk.GetPublicKey()

	msg := &Message{Raw: []byte("hello signify")}
	if err := msg.Sign(pk); err != nil {
		t.Fatalf("sign: %v", err)
	}
	if msg.Signature.Base64 == _empty {
		t.Fatal("sign did not encode the signature")
	}
	ok, err := msg.Verify(pub)
	if err != nil || !ok {
		t.Fatalf("verify: ok=%v err=%v", ok, err)
	}

	tampered := &Message{Raw: append([]byte(nil), msg.Raw...)}
	tampered.Raw[0] ^= 0xff
	tampered.Signature = msg.Signature
	if ok, err := tampered.Verify(pub); ok || err == nil {
		t.Fatal("tampered message verified")
	}
}

func TestSignVerifyWithBase64Keys(t *testing.T) {
	pk := GeneratePKFromSeed(testSeedToken(0x03, 0x04))
	if err := pk.Encode(); err != nil {
		t.Fatalf("encode private key: %v", err)
	}
	if err := pk.Decode(); err != nil {
		t.Fatalf("decode private key: %v", err)
	}

	pub := pk.GetPublicKey()
	if err := pub.Encode(); err != nil {
		t.Fatalf("encode public key: %v", err)
	}

	msg := &Message{Base64: "aGVsbG8gYmFzZTY0"}
	if err := msg.Sign(PrivateKey{Base64: pk.Base64}); err != nil {
		t.Fatalf("sign with base64 private key: %v", err)
	}

	loaded := &Message{Base64: msg.Base64, Signature: Signature{Base64: msg.Signature.Base64}}
	if ok, err := loaded.Verify(PublicKey{Base64: pub.Base64}); !ok || err != nil {
		t.Fatalf("verify with base64 keys: ok=%v err=%v", ok, err)
	}
}

func TestSignatureDecodeRoundTrip(t *testing.T) {
	pk := GeneratePKFromSeed(testSeedToken(0x05, 0x06))
	msg := &Message{Raw: []byte("roundtrip")}
	if err := msg.Sign(pk); err != nil {
		t.Fatalf("sign: %v", err)
	}

	decoded := Signature{Base64: msg.Signature.Base64}
	if err := decoded.Decode(); err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	if decoded.Raw != msg.Signature.Raw {
		t.Fatal("signature raw representation changed across decode")
	}
}

func TestGetPubKeyFile(t *testing.T) {
	pk := GeneratePKFromSeed(testSeedToken(0x07, 0x08))
	data, err := pk.GetPubKeyFile("test key")
	if err != nil {
		t.Fatalf("get public key file: %v", err)
	}
	text := string(data)
	if !strings.HasPrefix(text, _untrustedComment+_pubUT+" test key"+_linefeed) {
		t.Fatalf("unexpected public key file framing: %q", text)
	}
	if strings.Count(text, _linefeed) != 2 || !strings.HasSuffix(text, _linefeed) {
		t.Fatalf("public key file must be two newline terminated lines: %q", text)
	}
}

func TestGetSigFile(t *testing.T) {
	pk := GeneratePKFromSeed(testSeedToken(0x09, 0x0a))
	msg := &Message{Raw: []byte("signed file"), UntrustedComment: " test signature"}
	data, err := msg.GetSigFile(pk)
	if err != nil {
		t.Fatalf("get signature file: %v", err)
	}
	lines := strings.Split(strings.TrimSuffix(string(data), _linefeed), _linefeed)
	if len(lines) != 2 {
		t.Fatalf("signature file must have two lines, got %d", len(lines))
	}
	if lines[0] != _untrustedComment+" test signature" {
		t.Fatalf("unexpected comment line: %q", lines[0])
	}
	if lines[1] != msg.Signature.Base64 {
		t.Fatal("signature line does not match encoded signature")
	}
}

func TestRejectsMissingOrWrongKeys(t *testing.T) {
	msg := &Message{Raw: []byte("payload")}
	if err := msg.Sign(PrivateKey{}); err == nil {
		t.Fatal("sign accepted an empty private key")
	}
	if ok, err := msg.Verify(PublicKey{}); ok || err == nil {
		t.Fatal("verify accepted an empty public key")
	}
	if _, err := (PublicKey{}).GetPubKeyFile("x"); err == nil {
		t.Fatal("public key file accepted an empty public key")
	}
	if _, err := (PrivateKey{}).GetPubKeyFile("x"); err == nil {
		t.Fatal("public key file accepted an empty private key")
	}

	pk := GeneratePKFromSeed(testSeedToken(0x0b, 0x0c))
	if err := msg.Sign(pk); err != nil {
		t.Fatalf("sign: %v", err)
	}
	other := GeneratePKFromSeed(testSeedToken(0x0d, 0x0e))
	if ok, err := msg.Verify(other.GetPublicKey()); ok || err == nil {
		t.Fatal("message verified with an unrelated public key")
	}
}

func TestDecodeRejectsInvalidSizes(t *testing.T) {
	if err := (&PublicKey{Base64: "AAAA"}).Decode(); err == nil {
		t.Fatal("public key decode accepted invalid size")
	}
	if err := (&PrivateKey{Base64: "AAAA"}).Decode(); err == nil {
		t.Fatal("private key decode accepted invalid size")
	}
	if err := (&Signature{Base64: "AAAA"}).Decode(); err == nil {
		t.Fatal("signature decode accepted invalid size")
	}
	if err := (&Message{}).Decode(); err == nil {
		t.Fatal("message decode accepted an empty base64 message")
	}
}

func TestReSignResetsSignature(t *testing.T) {
	pk := GeneratePKFromSeed(testSeedToken(0x0f, 0x10))
	msg := &Message{Raw: []byte("first")}
	if err := msg.Sign(pk); err != nil {
		t.Fatalf("sign: %v", err)
	}
	first := msg.Signature.Base64

	msg.Raw = []byte("second")
	if err := msg.Sign(pk); err != nil {
		t.Fatalf("re-sign: %v", err)
	}
	if msg.Signature.Base64 == first {
		t.Fatal("re-sign kept the previous signature")
	}
	if ok, err := msg.Verify(pk.GetPublicKey()); !ok || err != nil {
		t.Fatalf("re-signed message does not verify: ok=%v err=%v", ok, err)
	}
}

func TestVerifyPrefersRawSignatureOverStaleBase64(t *testing.T) {
	pk := GeneratePKFromSeed(testSeedToken(0x11, 0x12))
	pub := pk.GetPublicKey()

	msgA := &Message{Raw: []byte("message A")}
	if err := msgA.Sign(pk); err != nil {
		t.Fatalf("sign: %v", err)
	}
	msgB := &Message{Raw: []byte("message B")}
	if err := msgB.Sign(pk); err != nil {
		t.Fatalf("sign: %v", err)
	}

	// Live Raw signature for A, stale wire form for B: Raw must win,
	// the wire form is only decoded when Raw is empty.
	hybrid := &Message{Raw: []byte("message A")}
	hybrid.Signature.Raw = msgA.Signature.Raw
	hybrid.Signature.Base64 = msgB.Signature.Base64

	if ok, err := hybrid.Verify(pub); !ok || err != nil {
		t.Fatalf("verify used the stale base64 signature instead of raw: ok=%v err=%v", ok, err)
	}
}
