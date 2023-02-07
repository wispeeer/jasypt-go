package jasypt

import (
	"strings"

	"github.com/wispeeer/jasypt-go/internal/crypto"
)

var New = getResolver()

type resolver struct {
	Prefix string
	Suffix string
}

func getResolver() *resolver {
	return &resolver{
		Prefix: "ENC~[",
		Suffix: "]",
	}
}

func (r *resolver) Encrypt(data string, passphrase string) string {
	esr := crypto.Encrypt([]byte(data), passphrase)
	return r.Prefix + esr + r.Suffix
}

func (r *resolver) Decrypt(text string, passphrase string) ([]byte, error) {
	if strings.HasPrefix(text, r.Prefix) && strings.HasSuffix(text, r.Suffix) {
		s := len(r.Prefix)
		e := len(text) - len(r.Suffix)
		dsr, err := crypto.Decrypt(text[s:e], passphrase)
		return dsr, err
	}
	return nil, nil
}
