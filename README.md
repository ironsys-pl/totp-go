[![Go Reference](https://pkg.go.dev/badge/github.com/ironsys-pl/totp-go.svg)](https://pkg.go.dev/github.com/ironsys-pl/totp-go)
[![Go Report Card](https://goreportcard.com/badge/github.com/ironsys-pl/totp-go)](https://goreportcard.com/report/github.com/ironsys-pl/totp-go)

# totp-go
TOTP (Time-based one-time password) for GO according to RFC 6238 [https://datatracker.ietf.org/doc/html/rfc6238](https://datatracker.ietf.org/doc/html/rfc6238).

Supports SHA1, SHA256 and SHA512 hashing. Generates 6,7 or 8 digits long passwords. 

## Example usage

```go
package main

import (
	"fmt"
	"os"

	"github.com/ironsys-pl/totp-go"
)

func main() {
    secret := "1234567890"
    timeStepSize := 30 // 30 seconds, recommended in RFC
    hashAlgo := totp.HashAlgoSha1
    digits := 6
    // produces 6 digit password, different output every 30 seconds
    pass  := totp.Totp([]byte(secret), time.Now(), timeStepSize, hashAlgo, digits)
}
```