// Package signify creates and verifies OpenBSD signify and minisign compatible signatures.
package signify

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
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
		if err := pub.Encode(); err != nil {
			return nil, errors.New("internal error: gen publickey file: decode public key: " + err.Error())
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
	var buf bytes.Buffer
	err := binary.Write(&buf, binary.BigEndian, pub.Raw)
	if err != nil {
		return err
	}
	pub.Base64, err = enc(buf.Bytes())
	if err != nil {
		return err
	}
	return nil
}

// Decode PublicKey
func (pub *PublicKey) Decode() (err error) {
	s, err := dec(pub.Base64)
	if err != nil {
		return err
	}
	if len(s) != KeyAlgoSize+FingerPrintSize+PublicKeySize {
		return errors.New("invalid base64 pulic key size")
	}
	pub.Raw.PKAlgo, err = sliceTo2(s[:KeyAlgoSize])
	if err != nil {
		return err
	}
	pub.Raw.Fingerprint, err = sliceTo8(s[KeyAlgoSize : KeyAlgoSize+FingerPrintSize])
	if err != nil {
		return err
	}
	pub.Raw.RawKey, err = sliceTo32(s[KeyAlgoSize+FingerPrintSize:])
	return err
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

// GeneratePKFromSeed generates a new deterministic, reproduceable PrivateKey from seed
func GeneratePKFromSeed(seedToken [SeedTokenSize]byte) PrivateKey {
	var err error
	pk := NewPrivateKey()
	pk.Raw.Fingerprint, err = sliceTo8(seedToken[ed25519.SeedSize:])
	if err != nil {
		panic("internal: generate keypair: " + err.Error()) // do not recover!
	}
	pk.Raw.RawKey, err = sliceTo64(ed25519.NewKeyFromSeed(seedToken[:SeedSize]))
	if err != nil {
		panic("internal: generate keypair: " + err.Error()) // do not recover!
	}
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
	if len(pk.Raw.RawKey[:]) != PrivateKeySize {
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
func (msg *Message) Sign(pk PrivateKey) (err error) {
	switch {
	case pk.Raw.RawKey[:] == nil:
		return errors.New("sign failed: no private key found")
	case msg.Raw == nil:
		if err := msg.Decode(); err != nil {
			return errors.New("sign failed: no raw message and " + err.Error())
		}
	}
	msg.PublicKey = pk.GetPublicKey()
	msg.Signature.Raw.Fingerprint = pk.Raw.Fingerprint
	switch {
	case pk.Raw.PKAlgo == _algoEd25519:
		msg.Signature.Raw.PKAlgo = _algoEd25519
		key := ed25519.Sign(ed25519.PrivateKey(pk.Raw.RawKey[:]), msg.Raw)
		if msg.Signature.Raw.RawSig, err = sliceTo64(key); err != nil {
			return err
		}
	default:
		return errors.New("unknown signature Algo")
	}
	if ok, err := msg.Verify(pk.GetPublicKey()); !ok {
		return errors.New("sign failed: verify after sign: " + err.Error())
	}
	if err := msg.Signature.Encode(); err != nil {
		return errors.New("sign failed: unable to encode signature: " + err.Error())
	}
	return nil
}

// Verify a message decodes, when nessesary, the Message and the PublicKey and verifies the signature
func (msg *Message) Verify(pub PublicKey) (bool, error) {
	switch {
	case pub.Raw.RawKey[:] == nil:
		if err := pub.Decode(); err != nil {
			return false, errors.New("verify failed: no public key found")
		}
	case msg.Raw == nil:
		if err := msg.Decode(); err != nil {
			return false, errors.New("verify failed: no raw message and " + err.Error())
		}
	}
	if msg.Signature.Raw.Fingerprint != msg.PublicKey.Raw.Fingerprint {
		return false, errors.New("fingerprint matching failed: wrong public key for message")
	}
	switch {
	case msg.Signature.Raw.PKAlgo == _algoEd25519 && pub.Raw.PKAlgo == _algoEd25519:
		if !ed25519.Verify(pub.Raw.RawKey[:], msg.Raw, msg.Signature.Raw.RawSig[:]) {
			return false, errors.New("ed25519 signature verification failed")
		}
	default:
		return false, errors.New("unknown signature Algo")
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
func (msg *Message) Encode() (err error) {
	msg.Base64, err = enc(msg.Raw[:])
	return err
}

// Decode Base64 Message to Raw Message
func (msg *Message) Decode() (err error) {
	msg.Raw, err = dec(msg.Base64)
	return err
}

//
// SIGNATURE
//

// Encode Raw Signature to Base64
func (sig *Signature) Encode() error {
	var buf bytes.Buffer
	err := binary.Write(&buf, binary.BigEndian, sig.Raw)
	if err != nil {
		return err
	}
	sig.Base64, err = enc(buf.Bytes())
	if err != nil {
		return err
	}
	return nil
}

// Decode Base64 Signature to Raw
func (sig *Signature) Decode() (err error) {
	s, err := dec(sig.Base64)
	if err != nil {
		return err
	}
	if len(s) != KeyAlgoSize+FingerPrintSize+SignatureSize {
		return errors.New("invalid base64 signature size")
	}
	sig.Raw.PKAlgo, err = sliceTo2(s[:KeyAlgoSize])
	if err != nil {
		return err
	}
	sig.Raw.Fingerprint, err = sliceTo8(s[KeyAlgoSize : KeyAlgoSize+FingerPrintSize])
	if err != nil {
		return err
	}
	sig.Raw.RawSig, err = sliceTo64(s[KeyAlgoSize+FingerPrintSize:])
	return err
}
