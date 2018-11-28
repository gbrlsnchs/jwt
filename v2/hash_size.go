package jwt

func hashSize(s Signer) int {
	switch s.String() {
	case MethodHS256:
		return enc.EncodedLen(32)
	case MethodHS384:
		return enc.EncodedLen(48)
	case MethodHS512, MethodES256:
		return enc.EncodedLen(64)
	case MethodES384:
		return enc.EncodedLen(96)
	case MethodES512:
		return enc.EncodedLen(132)
	case MethodRS256, MethodRS384, MethodRS512:
		return enc.EncodedLen(256)
	}
	return 0
}
