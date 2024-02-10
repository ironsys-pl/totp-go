package totp

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
)

const (
	HashAlgoSha1   = "SHA1"
	HashAlgoSha256 = "SHA256"
	HashAlgoSha512 = "SHA512"
)

func calculateHmac(secret, timeStep []byte, hashAlgo string) []byte {
	if hashAlgo != HashAlgoSha1 && hashAlgo != HashAlgoSha256 && hashAlgo != HashAlgoSha512 {
		panic(fmt.Sprintf("invalid hash algo %s", hashAlgo))
	}

	var h hash.Hash

	switch hashAlgo {
	case HashAlgoSha256:
		h = hmac.New(sha256.New, secret)
	case HashAlgoSha512:
		h = hmac.New(sha512.New, secret)
	default:
		h = hmac.New(sha1.New, secret)
	}

	_, err := h.Write(timeStep)

	if err != nil {
		panic(err)
	}

	return h.Sum(nil)
}
