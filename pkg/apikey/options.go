package apikey

type optionFunc func(k *Key)

func WithScheme(scheme signatureScheme) optionFunc {
	return func(k *Key) {
		k.scheme = scheme
	}
}
