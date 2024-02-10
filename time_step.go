package totp

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"time"
)

const TimeStepSizeDefault = 30
const TimeStepSizeMin = 1
const TimeStepSizeMax = 31622400

func timeStepInt(t time.Time, s int) int64 {
	if s < TimeStepSizeMin || s > TimeStepSizeMax {
		panic("time step size out of range")
	}
	return t.Unix() / int64(s)
}

func timeStepHex(t time.Time, s int) string {
	i := timeStepInt(t, s)
	h := strconv.FormatInt(i, 16)

	return fmt.Sprintf("%016s", h)
}

func timeStep(t time.Time, s int) []byte {
	h := timeStepHex(t, s)
	b, err := hex.DecodeString(h)

	if err != nil {
		panic(err)
	}

	return b
}
