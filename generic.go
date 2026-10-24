package signify

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
)

const (
	_pubUT                   = " signify public key"
	_empty                   = ""
	_space                   = " "
	_linefeed                = "\n"
	_untrustedComment        = "untrusted comment:"
	_verifyThisKeyGenMessage = "Nachts sind alle blauen Katzen grau!"
)

var (
	_algoEd25519 = [2]byte{'E', 'd'}

// _pkUnlockBcrypt   = [2]byte{'B', 'k'}
// _pkUnlockExternal = [2]byte{'E', 'x'}
)

//
// INTERNAL LITTLE HELPER
//

// enc ...
func enc(raw []byte) (string, error) {
	if len(raw) == 0 {
		return _empty, errors.New("base64 encode: no raw message")
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}

// dec ...
func dec(b64 string) ([]byte, error) {
	if b64 == _empty {
		return nil, errors.New("base64 decode: no base64 message")
	}
	return base64.StdEncoding.DecodeString(b64)
}

// encodeRaw encodes a raw key or signature struct as base64
func encodeRaw(raw any) (string, error) {
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.BigEndian, raw); err != nil {
		return _empty, err
	}
	return enc(buf.Bytes())
}

// decodeRaw decodes base64 into a raw key or signature struct, checking its wire size
func decodeRaw(b64 string, size int, kind string, raw any) error {
	s, err := dec(b64)
	if err != nil {
		return err
	}
	if len(s) != size {
		return errors.New("decode " + kind + " failed: invalid base64 size")
	}
	return binary.Read(bytes.NewReader(s), binary.BigEndian, raw)
}
