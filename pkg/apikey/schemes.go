package apikey

import (
	"strings"

	"github.com/pkg/errors"
)

// Curve is a wrapped abbreviated version of curve; use with CurveToScheme to produce
// signatureScheme, which is non-exported to limit options.
type Curve string

type signatureScheme string

const (
	// CurveP256 is the wrapped form of the shorthand for the p256 curve.
	CurveP256 = Curve("p256")
	// CurveSecp256k1 is the wrapped form of the shorthand for the secp256k1 curve.
	CurveSecp256k1 = Curve("secp256k1")
	// CurveEd25519 is the wrapped form of the shorthand for the ed25519 curve.
	CurveEd25519 = Curve("ed25519")

	// SchemeUnsupported is a placeholder for scheme not supported by the API, returned
	// if invalid Curve value is supplied to CurveToScheme.
	SchemeUnsupported = signatureScheme("")
	// SchemeP256 is the API enum value for p256 curve.
	SchemeP256 = signatureScheme("SIGNATURE_SCHEME_TK_API_P256")
	// SchemeSECP256K1 is the API enum value for secp256k1 curve.
	SchemeSECP256K1 = signatureScheme("SIGNATURE_SCHEME_TK_API_SECP256K1")
	// SchemeSECP256K1EIP191 is the API enum value for secp256k1 curve with EIP-191 message signing.
	SchemeSECP256K1EIP191 = signatureScheme("SIGNATURE_SCHEME_TK_API_SECP256K1_EIP191")
	// SchemeED25519 is the API enum value for ed25519 curve.
	SchemeED25519 = signatureScheme("SIGNATURE_SCHEME_TK_API_ED25519")

	defaultSignatureScheme = SchemeP256
)

// ToScheme returns a Curve's associated signatureScheme.
func (c Curve) ToScheme() signatureScheme {
	symbolMap := map[Curve]signatureScheme{
		CurveP256:      SchemeP256,
		CurveSecp256k1: SchemeSECP256K1,
		CurveEd25519:   SchemeED25519,
	}

	scheme, ok := symbolMap[c]
	if ok {
		return scheme
	}

	return SchemeUnsupported
}

// ExtractSignatureSchemeFromSuffixedPrivateKey infers the signature type from a suffix appended to the end
// of the private key data (e.g. "deadbeef0123:secp256k1").
func ExtractSignatureSchemeFromSuffixedPrivateKey(data string) (string, signatureScheme, error) {
	pieces := strings.Split(data, ":")

	if len(pieces) == 1 {
		return pieces[0], SchemeP256, nil
	}

	scheme := Curve(pieces[1]).ToScheme()
	if scheme == SchemeUnsupported {
		return "", SchemeUnsupported, errors.New("improperly formatted raw key string or unsupported scheme")
	}

	return pieces[0], scheme, nil
}
