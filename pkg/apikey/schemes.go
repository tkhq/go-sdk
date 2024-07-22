package apikey

import (
	"strings"

	"github.com/pkg/errors"
)

type Curve string

type signatureScheme string

const (
	CurveP256      = Curve("p256")
	CurveSecp256k1 = Curve("secp256k1")
	CurveEd25519   = Curve("ed25519")

	SchemeUnsupported = signatureScheme("")
	SchemeP256        = signatureScheme("SIGNATURE_SCHEME_TK_API_P256")
	SchemeSECP256K1   = signatureScheme("SIGNATURE_SCHEME_TK_API_SECP256K1")
	SchemeED25519     = signatureScheme("SIGNATURE_SCHEME_TK_API_ED25519")
)

func CurveToScheme(curve Curve) signatureScheme {
	symbolMap := map[Curve]signatureScheme{
		CurveP256:      SchemeP256,
		CurveSecp256k1: SchemeSECP256K1,
		CurveEd25519:   SchemeED25519,
	}

	scheme, ok := symbolMap[curve]
	if ok {
		return scheme
	}

	return SchemeUnsupported
}

// ExtractSignatureSchemeFromSuffixedPrivateKey infers the signature type from a suffix appended to the end
// of the private key data (e.g. "deadbeef0123:secp256k1")
func ExtractSignatureSchemeFromSuffixedPrivateKey(data string) (string, signatureScheme, error) {
	pieces := strings.Split(data, ":")

	if len(pieces) == 1 {
		return pieces[0], SchemeP256, nil
	}

	scheme := CurveToScheme(Curve(pieces[1]))
	if scheme == SchemeUnsupported {
		return "", SchemeUnsupported, errors.New("improperly formatted raw key string or unsupported scheme")
	}

	return pieces[0], scheme, nil
}
