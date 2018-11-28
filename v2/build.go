package jwt

func build(s Signer, payload, sig []byte) []byte {
	psize := len(payload)
	token := make([]byte, psize+1+hashSize(s))
	n := copy(token, payload)
	token[n] = '.'
	enc.Encode(token[n+1:], sig)
	return token
}
