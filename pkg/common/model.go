package common

type Curve string

const (
	CurveDefault   = Curve("")
	CurveP256      = Curve("p256")
	CurveSecp256k1 = Curve("secp256k1")
)
