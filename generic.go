package signify

import (
	"encoding/base64"
	"errors"
)

const (
	_pubUT                   = " signify public key"
	_pkUT                    = " signify private key"
	_empty                   = ""
	_space                   = " "
	_linefeed                = "\n"
	_variableSize            = 0
	_untrustedComment        = "untrusted comment:"
	_verifyThisKeyGenMessage = "Nachts sind alle blauen Katzen grau!"
)

var (
	_algoEd25519      = [2]byte{'E', 'd'}
	_pkUnlockBcrypt   = [2]byte{'B', 'k'}
	_pkUnlockExternal = [2]byte{'E', 'x'}
)

//
// INTERNAL LITTLE HELPER
//

// enc ...
func enc(raw []byte) (string, error) {
	if raw == nil {
		return _empty, errors.New("base64 encode: no raw message")
	}
	s := base64.StdEncoding.EncodeToString(raw)
	return s, nil
}

// dec ...
func dec(b64 string) ([]byte, error) {
	if b64 == _empty {
		return nil, errors.New("base64 decode: no base64 message")
	}
	return base64.StdEncoding.DecodeString(b64)
}

// sliceTo64
func sliceTo64(in []byte) (r [64]byte, err error) {
	if len(in) != 64 {
		return r, errors.New("internal: sliceTo64 failed, input lengh")
	}
	// for i := 0; i < 64; i++ {
	//	r[i] = in[i]
	// }
	copy(r[:], in[:])
	return r, nil
}

// sliceTo32
func sliceTo32(in []byte) (r [32]byte, err error) {
	if len(in) != 32 {
		return r, errors.New("internal: sliceTo32 failed, input lengh")
	}
	// for i := 0; i < 32; i++ {
	//	r[i] = in[i]
	// }
	copy(r[:], in[:])
	return r, nil
}

// sliceTo8
func sliceTo8(in []byte) (r [8]byte, err error) {
	if len(in) != 8 {
		return r, errors.New("internal: sliceTo8 failed, input lengh")
	}
	// for i := 0; i < 8; i++ {
	//	r[i] = in[i]
	// }
	copy(r[:], in[:])
	return r, nil
}

// sliceTo82
func sliceTo2(in []byte) (r [2]byte, err error) {
	if len(in) != 2 {
		return r, errors.New("internal: sliceTo2 failed, input lengh")
	}
	// for i := 0; i < 2; i++ {
	// 	r[i] = in[i]
	// }
	copy(r[:], in[:])
	return r, nil
}
