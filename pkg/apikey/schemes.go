package apikey

type Curve string

type signatureScheme string

const (
	CurveP256      = Curve("p256")
	CurveSecp256k1 = Curve("secp256k1")

	SchemeUnsupported = signatureScheme("")
	SchemeP256        = signatureScheme("SIGNATURE_SCHEME_TK_API_P256")
	SchemeSECP256K1   = signatureScheme("SIGNATURE_SCHEME_TK_API_SECP256K1")
)

func CurveToScheme(curve Curve) signatureScheme {
	symbolMap := map[Curve]signatureScheme{
		CurveP256:      SchemeP256,
		CurveSecp256k1: SchemeSECP256K1,
	}

	scheme, ok := symbolMap[curve]
	if ok {
		return scheme
	}

	return SchemeUnsupported
}
