package jwt

func decodeToBytes(sig []byte) ([]byte, error) {
	decSig := make([]byte, enc.DecodedLen(len(sig)))
	if _, err := enc.Decode(decSig, sig); err != nil {
		return nil, err
	}
	return decSig, nil
}
