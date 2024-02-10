package totp

import (
	"encoding/hex"
	"fmt"
	"math"
	"strconv"
	"time"
)

// Totp calculates time based one time password as described in RFC 6238.
//
// Password is calculated based on secret, time, timeStepSize (in seconds, 30 is the recommended
// value, has to be in range of [1, 31622400]), hashing algorithm (SHA1, SHA256 and SHA512 are accepted)
// and digits (6, 7 or 8). Digits parameter also determines result password length.
func Totp(secret []byte, t time.Time, timeStepSize int, hashAlgo string, digits int) string {
	if digits > 8 || digits < 6 {
		panic(fmt.Sprintf("invalid digits %d", digits))
	}

	timeStep := timeStep(t, timeStepSize)
	h := calculateHmac(secret, timeStep, hashAlgo)
	dt := dynamicTruncation(h)
	dtInt, err := strconv.ParseInt(hex.EncodeToString(dt), 16, 64)

	if err != nil {
		panic(err)
	}

	p := int(dtInt % int64(math.Pow10(digits)))

	return fmt.Sprintf("%0*d", digits, p)
}

func dynamicTruncation(hmac []byte) []byte {
	hmacLen := len(hmac)
	if hmacLen != 20 && hmacLen != 32 && hmacLen != 64 {
		panic(fmt.Sprintf("invalid hmac length %d", hmacLen))
	}

	o := hmac[hmacLen-1] & 0xf
	p := hmac[o : o+4]
	p[0] &= 0x7f

	return p
}
