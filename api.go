// Package signify creates and verifies OpenBSD signify and minisign compatible signatures.
package signify

import (
	"crypto/ed25519"
	"errors"
	"strings"
)

//
// CONSTANTS
//

const (
	// PrivateKeySize ...
	PrivateKeySize = ed25519.PrivateKeySize
	// PublicKeySize ...
	PublicKeySize = ed25519.PublicKeySize
	// SignatureSize ...
	SignatureSize = ed25519.SignatureSize
	// PrivatePublicKeyOffset ...
	PrivatePublicKeyOffset = PrivateKeySize - PublicKeySize
	// SeedSize ...
	SeedSize = ed25519.SeedSize
	// FingerPrintSize ...
	FingerPrintSize = 8
	// KeyAlgoSize ...
	KeyAlgoSize = 2
	// SeedTokenSize ...
	SeedTokenSize = SeedSize + FingerPrintSize
)

// KeyAlgo ...
type KeyAlgo [KeyAlgoSize]byte

// FingerPrint ...
type FingerPrint [FingerPrintSize]byte

//
// SIGNATURE
//

// Signature ...
type Signature struct {
	Base64 string
	Raw    RawSignature
}

// RawSignature ...
type RawSignature struct {
	PKAlgo      KeyAlgo
	Fingerprint FingerPrint
	RawSig      [SignatureSize]byte
}

// NewSignature ...
func NewSignature() Signature {
	return Signature{Raw: RawSignature{PKAlgo: _algoEd25519}}
}

//
// PUBLIC KEY
//

// PublicKey ...
type PublicKey struct {
	Base64 string
	Raw    RawPublicKey
}

// RawPublicKey ...
type RawPublicKey struct {
	PKAlgo      KeyAlgo
	Fingerprint FingerPrint
	RawKey      [PublicKeySize]byte
}

// NewPublicKey ...
func NewPublicKey() PublicKey {
	return PublicKey{Raw: RawPublicKey{PKAlgo: _algoEd25519}}
}

// GetPubKeyFile from PublicKey encodes and assembles an OpenBSD Signify compatible publickey file
func (pub PublicKey) GetPubKeyFile(addUntrusted string) ([]byte, error) {
	if pub.Base64 == _empty {
		if pub.Raw.RawKey == ([PublicKeySize]byte{}) {
			return nil, errors.New("gen publickey file: no public key")
		}
		if err := pub.Encode(); err != nil {
			return nil, errors.New("internal error: gen publickey file: encode public key: " + err.Error())
		}
	}
	var s strings.Builder
	s.WriteString(_untrustedComment)
	s.WriteString(_pubUT)
	s.WriteString(_space)
	s.WriteString(addUntrusted)
	s.WriteString(_linefeed)
	s.WriteString(pub.Base64)
	s.WriteString(_linefeed)
	return []byte(s.String()), nil
}

// Encode PublicKey
func (pub *PublicKey) Encode() error {
	var err error
	pub.Base64, err = encodeRaw(pub.Raw)
	return err
}

// Decode PublicKey
func (pub *PublicKey) Decode() error {
	return decodeRaw(pub.Base64, KeyAlgoSize+FingerPrintSize+PublicKeySize, "public key", &pub.Raw)
}

//
// PRIVATE KEY
//

// PrivateKey ...
type PrivateKey struct {
	Base64 string
	Raw    RawPrivateKey
}

// RawPrivateKey ...
type RawPrivateKey struct {
	PKAlgo      KeyAlgo
	Fingerprint FingerPrint
	RawKey      [PrivateKeySize]byte
}

// NewPrivateKey ...
func NewPrivateKey() PrivateKey {
	return PrivateKey{Raw: RawPrivateKey{PKAlgo: _algoEd25519}}
}

// Encode PrivateKey
func (pk *PrivateKey) Encode() error {
	var err error
	pk.Base64, err = encodeRaw(pk.Raw)
	return err
}

// Decode PrivateKey
func (pk *PrivateKey) Decode() error {
	return decodeRaw(pk.Base64, KeyAlgoSize+FingerPrintSize+PrivateKeySize, "private key", &pk.Raw)
}

// decodeIfNeeded fills Raw from Base64 when only the wire form is present
func (pk *PrivateKey) decodeIfNeeded() error {
	if pk.Raw != (RawPrivateKey{}) || pk.Base64 == _empty {
		return nil
	}
	return pk.Decode()
}

// GeneratePKFromSeed generates a new deterministic, reproduceable PrivateKey from seed
func GeneratePKFromSeed(seedToken [SeedTokenSize]byte) PrivateKey {
	pk := NewPrivateKey()
	copy(pk.Raw.Fingerprint[:], seedToken[SeedSize:])
	copy(pk.Raw.RawKey[:], ed25519.NewKeyFromSeed(seedToken[:SeedSize]))
	msg := Message{Raw: []byte(_verifyThisKeyGenMessage)}
	if err := msg.Sign(pk); err != nil {
		panic("internal: generate keypair: " + err.Error()) // do not recover!
	}
	return pk
}

// GetPublicKey from PrivateKey
func (pk PrivateKey) GetPublicKey() PublicKey {
	pub := NewPublicKey()
	pub.Raw.Fingerprint = pk.Raw.Fingerprint
	copy(pub.Raw.RawKey[:], pk.Raw.RawKey[PrivatePublicKeyOffset:])
	return pub
}

// GetPubKeyFile from PrivateKey encodes and assembles an OpenBSD Signify compatible publickey file
func (pk PrivateKey) GetPubKeyFile(addUntrusted string) ([]byte, error) {
	if err := pk.decodeIfNeeded(); err != nil {
		return nil, errors.New("gen publickey file: no private key and " + err.Error())
	}
	if pk.Raw.RawKey == (RawPrivateKey{}.RawKey) {
		return nil, errors.New("gen publickey file: no private key")
	}
	return pk.GetPublicKey().GetPubKeyFile(addUntrusted)
}

//
// MESSAGE
//

// Message ...
type Message struct {
	Base64           string
	Raw              []byte
	UntrustedComment string
	Signature        Signature
	PublicKey        PublicKey
}

// NewMessage ...
func NewMessage() *Message {
	return &Message{Signature: NewSignature(), PublicKey: NewPublicKey()}
}

// Sign a message decodes, when nessesary, the Message and generates an encoded signature
func (msg *Message) Sign(pk PrivateKey) error {
	if err := pk.decodeIfNeeded(); err != nil {
		return errors.New("sign failed: no private key and " + err.Error())
	}
	if pk.Raw.RawKey == (RawPrivateKey{}.RawKey) {
		return errors.New("sign failed: no private key found")
	}
	if msg.Raw == nil {
		if err := msg.Decode(); err != nil {
			return errors.New("sign failed: no raw message and " + err.Error())
		}
	}
	msg.PublicKey = pk.GetPublicKey()
	msg.Signature = NewSignature()
	msg.Signature.Raw.Fingerprint = pk.Raw.Fingerprint
	switch {
	case pk.Raw.PKAlgo == _algoEd25519:
		copy(msg.Signature.Raw.RawSig[:], ed25519.Sign(ed25519.PrivateKey(pk.Raw.RawKey[:]), msg.Raw))
	default:
		return errors.New("sign failed: unknown signature algo")
	}
	if _, err := msg.Verify(msg.PublicKey); err != nil {
		return errors.New("sign failed: verify after sign: " + err.Error())
	}
	if err := msg.Signature.Encode(); err != nil {
		return errors.New("sign failed: unable to encode signature: " + err.Error())
	}
	return nil
}

// Verify a message decodes, when nessesary, the Message, the Signature and the PublicKey and verifies the signature
func (msg *Message) Verify(pub PublicKey) (bool, error) {
	if pub.Base64 != _empty && pub.Raw.RawKey == ([PublicKeySize]byte{}) {
		if err := pub.Decode(); err != nil {
			return false, errors.New("verify failed: " + err.Error())
		}
	}
	if pub.Raw.RawKey == ([PublicKeySize]byte{}) {
		return false, errors.New("verify failed: no public key found")
	}
	if msg.Raw == nil {
		if err := msg.Decode(); err != nil {
			return false, errors.New("verify failed: no raw message and " + err.Error())
		}
	}
	if msg.Signature.Base64 != _empty && msg.Signature.Raw.RawSig == ([SignatureSize]byte{}) {
		if err := msg.Signature.Decode(); err != nil {
			return false, errors.New("verify failed: " + err.Error())
		}
	}
	if msg.Signature.Raw.Fingerprint != pub.Raw.Fingerprint {
		return false, errors.New("verify failed: fingerprint mismatch: wrong public key for message")
	}
	switch {
	case msg.Signature.Raw.PKAlgo == _algoEd25519 && pub.Raw.PKAlgo == _algoEd25519:
		if !ed25519.Verify(pub.Raw.RawKey[:], msg.Raw, msg.Signature.Raw.RawSig[:]) {
			return false, errors.New("verify failed: ed25519 signature verification failed")
		}
	default:
		return false, errors.New("verify failed: unknown signature algo")
	}
	return true, nil
}

// GetSigFile signs an message (raw or encoded) and provides an OpenBSD Signify compatible signature file
func (msg *Message) GetSigFile(pk PrivateKey) ([]byte, error) {
	if err := msg.Sign(pk); err != nil {
		return nil, errors.New("generate sig file: " + err.Error())
	}
	return []byte(_untrustedComment + msg.UntrustedComment + _linefeed + msg.Signature.Base64 + _linefeed), nil
}

// Encode Raw Message to Base64
func (msg *Message) Encode() error {
	var err error
	msg.Base64, err = enc(msg.Raw)
	return err
}

// Decode Base64 Message to Raw Message
func (msg *Message) Decode() error {
	var err error
	msg.Raw, err = dec(msg.Base64)
	return err
}

//
// SIGNATURE
//

// Encode Raw Signature to Base64
func (sig *Signature) Encode() error {
	var err error
	sig.Base64, err = encodeRaw(sig.Raw)
	return err
}

// Decode Base64 Signature to Raw
func (sig *Signature) Decode() error {
	return decodeRaw(sig.Base64, KeyAlgoSize+FingerPrintSize+SignatureSize, "signature", &sig.Raw)
}
