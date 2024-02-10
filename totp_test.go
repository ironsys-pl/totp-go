package totp_test

import (
	"testing"
	"time"

	"github.com/ironsys-pl/totp-go"
)

const (
	SecretSha1   = "12345678901234567890"
	SecretSha256 = "12345678901234567890123456789012"
	SecretSha512 = "1234567890123456789012345678901234567890123456789012345678901234"
)

type totpTestCase struct {
	s   string
	t   time.Time
	ha  string
	exp string
}

// test cases as in RFC 6238 (page 15)
func TestTotp(t *testing.T) {
	time1970 := time.Date(1970, 1, 1, 0, 0, 59, 0, time.UTC)
	time2005 := time.Date(2005, 3, 18, 1, 58, 29, 0, time.UTC)
	time2005b := time.Date(2005, 3, 18, 1, 58, 31, 0, time.UTC)
	time2009 := time.Date(2009, 2, 13, 23, 31, 30, 0, time.UTC)
	time2033 := time.Date(2033, 5, 18, 3, 33, 20, 0, time.UTC)
	time2603 := time.Date(2603, 10, 11, 11, 33, 20, 0, time.UTC)

	testCases := []totpTestCase{
		//SHA1
		{
			s:   SecretSha1,
			t:   time1970,
			ha:  totp.HashAlgoSha1,
			exp: "94287082",
		},
		{
			s:   SecretSha1,
			t:   time2005,
			ha:  totp.HashAlgoSha1,
			exp: "07081804",
		},
		{
			s:   SecretSha1,
			t:   time2005b,
			ha:  totp.HashAlgoSha1,
			exp: "14050471",
		},
		{
			s:   SecretSha1,
			t:   time2009,
			ha:  totp.HashAlgoSha1,
			exp: "89005924",
		},
		{
			s:   SecretSha1,
			t:   time2033,
			ha:  totp.HashAlgoSha1,
			exp: "69279037",
		},
		{
			s:   SecretSha1,
			t:   time2603,
			ha:  totp.HashAlgoSha1,
			exp: "65353130",
		},
		//SHA256
		{
			s:   SecretSha256,
			t:   time1970,
			ha:  totp.HashAlgoSha256,
			exp: "46119246",
		},
		{
			s:   SecretSha256,
			t:   time2005,
			ha:  totp.HashAlgoSha256,
			exp: "68084774",
		},
		{
			s:   SecretSha256,
			t:   time2005b,
			ha:  totp.HashAlgoSha256,
			exp: "67062674",
		},
		{
			s:   SecretSha256,
			t:   time2009,
			ha:  totp.HashAlgoSha256,
			exp: "91819424",
		},
		{
			s:   SecretSha256,
			t:   time2033,
			ha:  totp.HashAlgoSha256,
			exp: "90698825",
		},
		{
			s:   SecretSha256,
			t:   time2603,
			ha:  totp.HashAlgoSha256,
			exp: "77737706",
		},
		//SHA512
		{
			s:   SecretSha512,
			t:   time1970,
			ha:  totp.HashAlgoSha512,
			exp: "90693936",
		},
		{
			s:   SecretSha512,
			t:   time2005,
			ha:  totp.HashAlgoSha512,
			exp: "25091201",
		},
		{
			s:   SecretSha512,
			t:   time2005b,
			ha:  totp.HashAlgoSha512,
			exp: "99943326",
		},
		{
			s:   SecretSha512,
			t:   time2009,
			ha:  totp.HashAlgoSha512,
			exp: "93441116",
		},
		{
			s:   SecretSha512,
			t:   time2033,
			ha:  totp.HashAlgoSha512,
			exp: "38618901",
		},
		{
			s:   SecretSha512,
			t:   time2603,
			ha:  totp.HashAlgoSha512,
			exp: "47863826",
		},
	}

	for i, tc := range testCases {
		res := totp.Totp([]byte(tc.s), tc.t, totp.TimeStepSizeDefault, tc.ha, 8)

		if res != tc.exp {
			t.Errorf("expected %s, got %s (test case %d)", tc.exp, res, i)
		}
	}
}
